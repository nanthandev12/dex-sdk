//! Source-IP-bound alloy provider constructors.
//!
//! alloy's `ProviderBuilder::connect` has no hook to bind outbound sockets to a
//! specific local (elastic) IP. The helpers in this module build the underlying
//! transports ourselves — a `reqwest::Client` with `.local_address(addr)` for
//! HTTP, and a bound `tokio::net::TcpStream` wrapped in tungstenite's TLS layer
//! for WebSocket — and hand them to `ProviderBuilder`, so all JSON-RPC traffic
//! (reads, `eth_call`, `getLogs`, tx submission, `monadNewHeads` subscriptions)
//! egresses from the configured source IP.
//!
//! When `local_address` is `None` the helpers fall back to alloy's default
//! transport, so behaviour is identical to `ProviderBuilder::connect`.
//!
//! # Features
//!
//! - [`http_provider`] / [`http_provider_with_wallet`] are always available
//!   when the `transport` feature is enabled.
//! - [`ws_provider`] requires the `ws` feature (which pulls in alloy's
//!   `provider-ws` + `tokio-tungstenite`).

use std::net::IpAddr;
use std::time::Duration;

use alloy::providers::{DynProvider, Provider, ProviderBuilder};

use crate::error::{DexError, ProviderError};

/// Default keepalive interval for WS connections (matches alloy's `WsConnect`).
const DEFAULT_KEEPALIVE: Duration = Duration::from_secs(10);

/// Build a `reqwest::Client` bound to `local_address` (or the default).
fn reqwest_client(local_address: Option<IpAddr>) -> Result<reqwest::Client, DexError> {
    let mut builder = reqwest::Client::builder();
    if let Some(addr) = local_address {
        builder = builder.local_address(addr);
    }
    builder
        .build()
        .map_err(|e| DexError::Provider(ProviderError::Transport(format!("http client: {e}"))))
}

/// Parse a URL string into a `reqwest::Url`.
fn parse_url(url: &str) -> Result<reqwest::Url, DexError> {
    reqwest::Url::parse(url).map_err(|e| {
        DexError::Provider(ProviderError::InvalidRequest(format!("bad url {url}: {e}")))
    })
}

/// Build an HTTP alloy [`DynProvider`] for `url`, optionally bound to
/// `local_address`.
///
/// All reads (snapshot build, `getLogs`, `eth_call`) egress from the configured
/// source IP. When `local_address` is `None` this is equivalent to
/// `ProviderBuilder::new().connect(url)`.
pub fn http_provider(url: &str, local_address: Option<IpAddr>) -> Result<DynProvider, DexError> {
    let parsed = parse_url(url)?;
    let client = reqwest_client(local_address)?;
    Ok(ProviderBuilder::new().connect_reqwest(client, parsed).erased())
}

/// Build an HTTP alloy [`DynProvider`] with a wallet filler (for tx signing),
/// optionally bound to `local_address`.
///
/// This is the signing counterpart of [`http_provider`]: the wallet filler
/// handles nonce / gas / chain-id filling, and the underlying `reqwest::Client`
/// is bound to `local_address` so submitted transactions egress from the
/// configured elastic IP.
pub fn http_provider_with_wallet<W>(
    url: &str,
    local_address: Option<IpAddr>,
    wallet: W,
) -> Result<DynProvider, DexError>
where
    W: alloy::providers::network::IntoWallet,
    W::NetworkWallet: Clone + 'static,
{
    let parsed = parse_url(url)?;
    let client = reqwest_client(local_address)?;
    Ok(ProviderBuilder::new().wallet(wallet).connect_reqwest(client, parsed).erased())
}

// ──────────────────────────────────────────────────────────────────────
//  WebSocket
// ──────────────────────────────────────────────────────────────────────

#[cfg(feature = "ws")]
mod ws_impl {
    use super::*;

    use alloy::pubsub::{ConnectionHandle, PubSubConnect};
    use alloy::transports::ws::WsBackend;
    use alloy::transports::{impl_future, TransportResult};
    use tokio::net::TcpStream;
    use tokio_tungstenite::{
        client_async_tls_with_config, tungstenite::client::IntoClientRequest, MaybeTlsStream,
        WebSocketStream,
    };

    type TungsteniteStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

    /// A [`PubSubConnect`] that opens a WebSocket bound to a specific source IP.
    ///
    /// Modelled on alloy's `WsConnect` but with a `local_address` hook: instead
    /// of `tokio_tungstenite::connect_async` (which lets the OS pick the source
    /// address) it binds a `TcpStream` to `local_address`, then hands it to
    /// `client_async_tls_with_config` for the WS+TLS handshake. The resulting
    /// socket is driven by alloy's [`WsBackend`] exactly as alloy's own
    /// `WsConnect` does, so reconnect / keepalive / dispatch behaviour is
    /// identical. Reconnect / keepalive parameters use the same defaults as
    /// alloy's `WsConnect` (10 retries, 3s retry interval, 10s keepalive).
    #[derive(Clone, Debug)]
    pub struct LocalWsConnect {
        url: String,
        local_address: IpAddr,
    }

    /// Max reconnect attempts before giving up (matches alloy's `WsConnect`).
    const MAX_RETRIES: u32 = 10;
    /// Base interval between reconnect attempts (matches alloy's `WsConnect`).
    const RETRY_INTERVAL: Duration = Duration::from_secs(3);

    impl LocalWsConnect {
        /// Create a new bound WS connector for `url` sourced from `local_address`.
        pub fn new<S: Into<String>>(url: S, local_address: IpAddr) -> Self {
            Self { url: url.into(), local_address }
        }

        /// Resolve the host (for TLS SNI / connect) and port from the URL.
        fn host_port(&self) -> Result<(String, u16), DexError> {
            let parsed = url::Url::parse(&self.url).map_err(|e| {
                DexError::Provider(ProviderError::InvalidRequest(format!("bad ws url: {e}")))
            })?;
            let host = parsed.host_str().ok_or_else(|| {
                DexError::Provider(ProviderError::InvalidRequest(format!(
                    "ws url missing host: {}",
                    self.url
                )))
            })?;
            let port = parsed
                .port_or_known_default()
                .unwrap_or_else(|| if parsed.scheme() == "wss" { 443 } else { 80 });
            Ok((host.to_string(), port))
        }

        /// Open a TCP socket bound to `local_address` and connect to `(host, port)`.
        async fn connect_socket(&self, host: &str, port: u16) -> Result<TcpStream, DexError> {
            use tokio::net::TcpSocket;

            let mut addrs = tokio::net::lookup_host((host, port)).await.map_err(|e| {
                DexError::Provider(ProviderError::Transport(format!(
                    "ws resolve {host}:{port}: {e}"
                )))
            })?;
            let dest = addrs.next().ok_or_else(|| {
                DexError::Provider(ProviderError::Transport(format!(
                    "ws resolve {host}:{port}: no addresses"
                )))
            })?;

            // Bind a socket to the configured local (elastic) IP. The socket
            // family must match the destination.
            let socket = match (self.local_address, dest) {
                (std::net::IpAddr::V4(local), std::net::SocketAddr::V4(_)) => {
                    let s = TcpSocket::new_v4().map_err(|e| {
                        DexError::Provider(ProviderError::Transport(format!(
                            "ws v4 socket: {e}"
                        )))
                    })?;
                    s.bind(std::net::SocketAddr::new(std::net::IpAddr::V4(local), 0))
                        .map_err(|e| {
                            DexError::Provider(ProviderError::Transport(format!(
                                "ws bind {local}: {e}"
                            )))
                        })?;
                    s
                }
                (std::net::IpAddr::V6(local), std::net::SocketAddr::V6(_)) => {
                    let s = TcpSocket::new_v6().map_err(|e| {
                        DexError::Provider(ProviderError::Transport(format!(
                            "ws v6 socket: {e}"
                        )))
                    })?;
                    s.bind(std::net::SocketAddr::new(std::net::IpAddr::V6(local), 0))
                        .map_err(|e| {
                            DexError::Provider(ProviderError::Transport(format!(
                                "ws bind {local}: {e}"
                            )))
                        })?;
                    s
                }
                (local, dest) => {
                    return Err(DexError::Provider(ProviderError::InvalidRequest(format!(
                        "ws: local address family ({local}) does not match destination ({dest})"
                    ))));
                }
            };

            let stream = socket.connect(dest).await.map_err(|e| {
                DexError::Provider(ProviderError::Transport(format!(
                    "ws tcp connect {dest}: {e}"
                )))
            })?;
            // Disable Nagle — RPC frames are small and latency-sensitive.
            let _ = stream.set_nodelay(true);
            Ok(stream)
        }
    }

    impl IntoClientRequest for LocalWsConnect {
        fn into_client_request(
            self,
        ) -> tokio_tungstenite::tungstenite::Result<
            tokio_tungstenite::tungstenite::handshake::client::Request,
        > {
            self.url.into_client_request()
        }
    }

    impl PubSubConnect for LocalWsConnect {
        fn is_local(&self) -> bool {
            alloy::transports::utils::guess_local_url(&self.url)
        }

        fn connect(&self) -> impl_future!(<Output = TransportResult<ConnectionHandle>>) {
            async move {
                // Match alloy's WsConnect: ensure a rustls crypto provider is
                // installed before the TLS handshake, otherwise rustls 0.23
                // panics on the first handshake if none is set.
                install_default_crypto_provider();

                let (host, port) = self.host_port().map_err(|e| {
                    alloy::transports::TransportErrorKind::custom_str(&e.to_string())
                })?;
                let socket = self.connect_socket(&host, port).await.map_err(|e| {
                    alloy::transports::TransportErrorKind::custom_str(&e.to_string())
                })?;

                let request = self.clone().into_client_request();
                let req = request.map_err(|e| {
                    alloy::transports::TransportErrorKind::custom_str(&e.to_string())
                })?;

                // `config = None` uses tungstenite's default WS config, and
                // `connector = None` lets tokio-tungstenite use its default
                // rustls connector with webpki-roots (enabled via the
                // `rustls-tls-webpki-roots` feature). For `ws://` URLs it
                // falls back to a plain (non-TLS) stream.
                let (stream, _resp) = client_async_tls_with_config(req, socket, None, None)
                    .await
                    .map_err(|e| {
                        alloy::transports::TransportErrorKind::custom_str(&e.to_string())
                    })?;

                let (handle, interface) = ConnectionHandle::new();
                let backend: WsBackend<TungsteniteStream> =
                    WsBackend::from_socket(stream, interface, DEFAULT_KEEPALIVE);
                backend.spawn();

                Ok(handle
                    .with_max_retries(MAX_RETRIES)
                    .with_retry_interval(RETRY_INTERVAL))
            }
        }

        fn try_reconnect(&self) -> impl_future!(<Output = TransportResult<ConnectionHandle>>) {
            self.connect()
        }
    }

    /// Install a default rustls crypto provider if none is set.
    ///
    /// Required since rustls 0.23+ no longer auto-installs one. Mirrors
    /// alloy-transport-ws's `install_default_crypto_provider`.
    fn install_default_crypto_provider() {
        if rustls::crypto::CryptoProvider::get_default().is_some() {
            return;
        }
        // alloy's `reqwest-rustls-tls` feature resolves to aws-lc-rs, so use
        // that as the default provider to match the rest of the process.
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let _ = rustls::crypto::CryptoProvider::install_default(provider);
    }
}

/// Build a WebSocket alloy provider for `url`, optionally bound to
/// `local_address`.
///
/// Requires the `ws` feature. When `local_address` is `None` this is equivalent
/// to `ProviderBuilder::new().connect_ws(WsConnect::new(url))`.
#[cfg(feature = "ws")]
pub async fn ws_provider(url: &str, local_address: Option<IpAddr>) -> Result<DynProvider, DexError> {
    match local_address {
        Some(addr) => {
            let connect = ws_impl::LocalWsConnect::new(url, addr);
            ProviderBuilder::new()
                .connect_pubsub_with(connect)
                .await
                .map(|p| p.erased())
                .map_err(|e| {
                    DexError::Provider(ProviderError::Transport(format!("ws connect: {e}")))
                })
        }
        None => {
            use alloy::transports::ws::WsConnect;
            ProviderBuilder::new()
                .connect_ws(WsConnect::new(url))
                .await
                .map(|p| p.erased())
                .map_err(|e| {
                    DexError::Provider(ProviderError::Transport(format!("ws connect: {e}")))
                })
        }
    }
}
