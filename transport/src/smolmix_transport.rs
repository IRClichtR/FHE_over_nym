use smolmix::{Recipient, TcpStream, Tunnel};
use std::net::SocketAddr;

use crate::error::TransportError;

pub struct SmolmixTransport {
    tunnel: Tunnel,
}

impl SmolmixTransport {
    pub async fn new(maybe_ipr: Option<&str>) -> Result<Self, TransportError> {
        let mut builder = Tunnel::builder();
        if let Some(ipr) = maybe_ipr {
            let ipr: Recipient = ipr.parse().map_err(|e| {
                TransportError::InitializationError(format!(
                    "smolmix: failed to parse IPR address: {e}"
                ))
            })?;
            builder = builder.ipr_address(ipr);
        }
        let tunnel = builder.build().await.map_err(TransportError::Smolmix)?;
        Ok(SmolmixTransport { tunnel })
    }

    // Open a TCP connection through the mixnet to dest (e.g. "1.1.1.1:443").
    // The returned TcpStream implements AsyncRead + AsyncWrite and composes
    // with tokio-rustls, hyper, and the rest of the async ecosystem.
    pub async fn tcp_connect(&self, dest: SocketAddr) -> Result<TcpStream, TransportError> {
        self.tunnel.tcp_connect(dest).await.map_err(TransportError::Smolmix)
    }

    pub async fn shutdown(&self) {
        self.tunnel.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use http_body_util::{BodyExt, Empty};
    use hyper::body::Bytes;
    use hyper::Request;
    use hyper_util::rt::TokioIo;
    use rustls::pki_types::ServerName;
    use tokio_rustls::TlsConnector;

    const HOST: &str = "cloudflare.com";
    const PATH: &str = "/cdn-cgi/trace";
    const CF_ADDR: &str = "1.1.1.1:443"; // Cloudflare's anycast — stable for testing

    fn tls_connector() -> TlsConnector {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        TlsConnector::from(Arc::new(config))
    }

    // Extract the ip= line from Cloudflare's trace response body.
    fn extract_ip(body: &str) -> Option<String> {
        body.lines()
            .find(|l| l.starts_with("ip="))
            .map(|l| l[3..].trim().to_string())
    }

    // Perform GET /cdn-cgi/trace over TLS on any AsyncRead+AsyncWrite stream.
    // Works identically for a clearnet tokio::net::TcpStream and a smolmix::TcpStream.
    async fn cloudflare_trace_ip<S>(stream: S) -> String
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let domain = ServerName::try_from(HOST).unwrap().to_owned();
        let tls = tls_connector().connect(domain, stream).await.unwrap();
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.unwrap();
        tokio::spawn(conn);
        let req = Request::get(PATH)
            .header("Host", HOST)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8_lossy(&bytes).into_owned();
        extract_ip(&body).expect("no ip= field in Cloudflare trace response")
    }

    // Hits Cloudflare's /cdn-cgi/trace twice: once directly (clearnet) and once
    // through the smolmix mixnet tunnel. Cloudflare reports the IP it sees; if
    // the tunnel works, the two IPs must differ because the exit is a Nym gateway,
    // not this machine.
    // Skipped in CI; run with: cargo test -- --include-ignored
    #[tokio::test]
    #[ignore = "requires live Nym mixnet"]
    async fn ip_is_masked_through_mixnet() {
        // Install ring as the global rustls crypto provider (idempotent).
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Clearnet baseline: direct TCP to Cloudflare.
        let clearnet_tcp = tokio::net::TcpStream::connect(CF_ADDR).await.unwrap();
        let clearnet_ip = cloudflare_trace_ip(clearnet_tcp).await;

        // Mixnet path: same request, TCP routed through the Nym mixnet.
        let transport = SmolmixTransport::new(None).await.unwrap();
        let mixnet_tcp = transport.tcp_connect(CF_ADDR.parse().unwrap()).await.unwrap();
        let mixnet_ip = cloudflare_trace_ip(mixnet_tcp).await;
        transport.shutdown().await;

        println!("Clearnet IP : {clearnet_ip}");
        println!("Mixnet IP   : {mixnet_ip}");

        assert_ne!(
            clearnet_ip, mixnet_ip,
            "IP was not masked: Cloudflare sees {clearnet_ip} on both paths",
        );
    }
}
