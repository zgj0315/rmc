//! 测试专用的 TLS 证书校验器。生产客户端从不用这一套（它核对的是指纹，不是
//! 证书链），这里只是让测试里的 rustls 客户端能跟自签证书握手成功，好去验证
//! 别的性质（比如"服务端只开 TLS 1.3"）。
//!
//! `AcceptAll`：什么证书都信。`AnyHostKey`/`ssh_connect`（Task 4 加）：什么
//! host key 都信的 SSH 客户端处理器，加上「TLS（AcceptAll）+ SSH 握手」的
//! 一步到位帮手——**指纹核对是客户端（rmc-core）的事，在那边测**，这里只
//! 要能连上去，好去验证服务端别的性质（认证方法、通道拒绝、超时……）。

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};

#[derive(Debug)]
pub struct AcceptAll;

impl ServerCertVerifier for AcceptAll {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

/// 测试用 SSH 客户端处理器：什么 host key 都信——指纹核对不是这里的事
/// （客户端侧指纹校验是 rmc-core 的职责，在那边测），这里只要能握手成功。
pub struct AnyHostKey;

impl russh::client::Handler for AnyHostKey {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// 假装成现场客户端：收到 forwarded-tcpip 通道就接受，把收到的字节前面加
/// "echo:" 回写。Task 5 用它验证「工程师连上反向端口 → 字节到达现场客户端」
/// 那条通路真的通了。
pub struct EchoClient;

impl russh::client::Handler for EchoClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _k: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<russh::client::Msg>,
        _connected_address: &str,
        _connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::client::ChannelOpenHandle,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut st = channel.into_stream();
            let mut buf = [0u8; 256];
            while let Ok(n) = st.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                if st.write_all(&[b"echo:", &buf[..n]].concat()).await.is_err() {
                    break;
                }
            }
        });
        Ok(())
    }
}

/// TLS（1.3、`AcceptAll`）+ SSH 握手，返回还没认证的客户端会话。处理器由
/// 调用方给（`ssh_connect`/`ssh_connect_echo` 是两个薄包装）。
pub async fn ssh_connect_with<H: russh::client::Handler + Send + 'static>(
    addr: std::net::SocketAddr,
    handler: H,
) -> russh::client::Handle<H> {
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let tls_cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 该被支持")
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(AcceptAll))
        .with_no_client_auth();
    let sock = tokio::net::TcpStream::connect(addr)
        .await
        .expect("TCP 连接失败");
    let tls = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls_cfg))
        .connect(
            rustls::pki_types::ServerName::try_from(addr.ip().to_string())
                .expect("IP 地址总能当 ServerName"),
            sock,
        )
        .await
        .expect("TLS 握手失败");
    let cfg = std::sync::Arc::new(russh::client::Config {
        inactivity_timeout: None,
        ..Default::default()
    });
    russh::client::connect_stream(cfg, tls, handler)
        .await
        .expect("SSH 握手失败")
}

/// TLS（1.3、`AcceptAll`）+ SSH 握手，返回还没认证的客户端会话。
pub async fn ssh_connect(addr: std::net::SocketAddr) -> russh::client::Handle<AnyHostKey> {
    ssh_connect_with(addr, AnyHostKey).await
}

/// 同上，但客户端处理器是会回显的 `EchoClient`——用来验证反向转发的字节
/// 真的到达了「现场客户端」这一侧。
pub async fn ssh_connect_echo(addr: std::net::SocketAddr) -> russh::client::Handle<EchoClient> {
    ssh_connect_with(addr, EchoClient).await
}
