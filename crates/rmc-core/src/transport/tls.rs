//! TLS 外层。**不做公共 CA 校验**：运维服务器没有域名、证书自签，客户端
//! 核对的是连接码里的指纹——证书里 ed25519 公钥的 SHA-256。有效期、名称、
//! 证书链一概不看：那些是 CA 体系的概念，这里没有 CA。只开 TLS 1.3
//! （`Cargo.toml` 里 rustls/tokio-rustls 都没开 `tls12` feature，见本文件
//! 底部 `tls12_is_not_compiled_in`）。

use crate::addr::HostPort;
use crate::code::ServerFingerprint;
use crate::error::{Error, Result};
use crate::platform::Io;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::sync::Arc;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

/// Ed25519 的 SubjectPublicKeyInfo 是定长的：12 字节前缀 + 32 字节公钥。
/// 与 `rmc-gateway::identity::ED25519_SPKI_PREFIX` 是同一串字节，两侧各自
/// 定义、各自测——这一侧不能依赖 rmc-gateway，见方案的 crate 边界。
pub const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// 只核对服务器公钥指纹，不做任何 CA 校验的 [`ServerCertVerifier`]。
#[derive(Debug)]
struct PinnedServer {
    want: ServerFingerprint,
    algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedServer {
    /// **这是唯一做判断的方法**。rustls 的默认校验链（有效期、名称、
    /// 证书链）整套被绕开——`ParsedCertificate::try_from` 只是借它的 DER
    /// 解析能力取出 SPKI，不调用它任何链式校验的方法。
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let parsed = rustls::server::ParsedCertificate::try_from(end_entity)?;
        let spki = parsed.subject_public_key_info();
        let der: &[u8] = spki.as_ref();
        let mismatch = || {
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            )
        };
        if der.len() != 44 || der[..12] != ED25519_SPKI_PREFIX {
            return Err(mismatch());
        }
        let pk: [u8; 32] = der[12..].try_into().map_err(|_| mismatch())?;
        if ServerFingerprint::of_ed25519_public(&pk) != self.want {
            return Err(mismatch());
        }
        Ok(ServerCertVerified::assertion())
    }

    /// 只开 TLS 1.3（见 `Cargo.toml`），这条永远不会被真正调用——留空实现
    /// 是 trait 要求的形状，明确拒绝而不是悄悄接受，一旦哪天协商真的走到
    /// 1.2（比如谁把 feature 加回来），这里会立刻报错而不是静默通过。
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("只用 TLS 1.3".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algs.supported_schemes()
    }
}

fn connector(pin: &ServerFingerprint) -> Result<TlsConnector> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let algs = provider.signature_verification_algorithms;
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::Config(format!("TLS 配置：{e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServer { want: *pin, algs }))
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(cfg)))
}

/// 在已有字节流上完成 TLS 握手，核对服务器证书里的公钥是否等于 `pin`。
///
/// `server` 只是拨号用的 IP，不承担 SNI 意义：`ServerName::try_from` 对
/// IP 字面量得到的是 `ServerName::IpAddress`，rustls 对这种形态**不发
/// SNI**（RFC 6066 §3 的要求），这正是我们想要的——运维服务器没有域名，
/// 也没有必要让路径上的中间设备从 SNI 里看到一个"看起来像域名"的字符串。
/// 我们自己的 [`PinnedServer`] 本来就不看名字，所以这一点对校验结果没有
/// 任何影响。
pub async fn wrap_tls<S: Io>(
    stream: S,
    server: &HostPort,
    pin: &ServerFingerprint,
) -> Result<TlsStream<S>> {
    let name = ServerName::try_from(server.host().to_string())
        .map_err(|_| Error::Config(format!("运维服务器地址不能用于 TLS：{server}")))?;
    connector(pin)?
        .connect(name, stream)
        .await
        .map_err(classify_tls_error)
}

/// 指纹不符必须是致命的，链路问题按网络类重试。
///
/// R37（Task 6 旧结论，这一轮仍然成立）：`tokio_rustls` 把所有问题都统一
/// 包成 `std::io::Error`，唯一能区分的只有它 `Display` 出来的文本。
/// `PinnedServer::verify_server_cert` 判定失配时恒定返回
/// `rustls::Error::InvalidCertificate(CertificateError::
/// ApplicationVerificationFailure)`——这个变体没有专门的 context 分支，
/// 落的是 `rustls::Error` 自己 `Display` 实现里的通用前缀：
///
/// ```text
/// Self::InvalidCertificate(err) => write!(f, "invalid peer certificate: {err}")
/// ```
///
/// 这一条前缀是唯一稳定、经过源码确认的匹配点，也是这个函数现在唯一会
/// 产出的"证书类"错误——不再需要像旧版（信任公共 CA 时代）那样费心区分
/// 过期/未生效/名字不匹配/未知颁发者，因为我们自己的校验器只会报这一种
/// 失败：公钥跟连接码里的指纹不一致。
fn classify_tls_error(e: std::io::Error) -> Error {
    let msg = e.to_string();
    if msg.contains("invalid peer certificate") {
        Error::TlsPinMismatch(msg)
    } else {
        Error::TlsHandshake(msg)
    }
}

/// 给 `tls.rs`/`preflight.rs` 两处进程内 TLS 测试共用的假服务端——不是
/// docker、不是真实证书，一把随机 ed25519 种子现签一张自签证书，跟
/// `rmc-gateway::identity::Identity` 是同一套做法（PKCS#8 v1 的固定 16
/// 字节前缀 + 32 字节种子），这里独立写一遍：rmc-core 不能依赖
/// rmc-gateway（方案的 crate 边界）。
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// 起一把随机 ed25519 身份，返回只开 TLS 1.3 的服务端配置与它的指纹。
    pub(crate) fn ed25519_server() -> (Arc<rustls::ServerConfig>, ServerFingerprint) {
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        let kp = russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&seed);
        let fp = ServerFingerprint::of_ed25519_public(&kp.public.0);
        let mut pkcs8 = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        pkcs8.extend_from_slice(&seed);
        let key = rcgen::KeyPair::try_from(pkcs8.as_slice()).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["x".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
                pkcs8,
            )),
        )
        .unwrap();
        (Arc::new(cfg), fp)
    }

    /// 起一个只接一条连接的 TLS 服务端，握手成功后发一句 SSH banner——
    /// 只是为了让调用方能确认"读到了点什么"，不是真的在跑 SSH。
    pub(crate) async fn serve_once(cfg: Arc<rustls::ServerConfig>) -> u16 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((s, _)) = l.accept().await {
                let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
                if let Ok(mut t) = acceptor.accept(s).await {
                    use tokio::io::AsyncWriteExt;
                    let _ = t.write_all(b"SSH-2.0-test\r\n").await;
                }
            }
        });
        port
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{ed25519_server, serve_once};
    use super::*;

    /// 一正一反成对：指纹对就该握成，指纹错必须被拒绝且归 Fatal——单独
    /// 一条都抓不住"证书校验被关掉"这类回归（关掉校验时，"指纹对能握成"
    /// 那一条照样绿）。
    ///
    /// **实测过**（brief 原文的预测在这里不对，已订正）：把
    /// `PinnedServer::verify_server_cert` 里
    /// `ServerFingerprint::of_ed25519_public(&pk) != self.want` 的 `!=`
    /// 改成 `==`——**两条都会红**，不是"这条红、下一条变绿"：这条
    /// （指纹对）红是因为合法连接反而被判定失配，`.expect("指纹对就该
    /// 握成")` 直接 panic；下一条（指纹错）**也红**，因为错误的指纹
    /// 反而握成了功，那条测试的 `.unwrap_err()` 在一个 `Ok(TlsStream)`
    /// 上 panic——"握成"这个事实本身没错，但它让**断言**失败，不是让
    /// 测试**通过**。两条同时红，指向同一处：判等条件被翻转。或者把
    /// `ED25519_SPKI_PREFIX` 改掉任意一个字节——这一条红。
    #[tokio::test]
    async fn wrap_tls_accepts_the_server_whose_key_matches_the_pin() {
        use tokio::io::AsyncReadExt;
        let (cfg, fp) = ed25519_server();
        let port = serve_once(cfg).await;
        let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let mut tls = wrap_tls(stream, &HostPort::new("127.0.0.1", port).unwrap(), &fp)
            .await
            .expect("指纹对就该握成");
        let mut buf = [0u8; 16];
        let n = tls.read(&mut buf).await.unwrap();
        assert!(buf[..n].starts_with(b"SSH-2.0-"));
    }

    #[tokio::test]
    async fn wrap_tls_rejects_a_server_whose_key_does_not_match_as_fatal() {
        let (cfg, _fp) = ed25519_server();
        let port = serve_once(cfg).await;
        let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let other = ServerFingerprint::of_ed25519_public(&[1u8; 32]);
        let err = wrap_tls(stream, &HostPort::new("127.0.0.1", port).unwrap(), &other)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::TlsPinMismatch(_)), "{err:?}");
        assert_eq!(err.class(), crate::error::ErrorClass::Fatal);
        assert!(
            !err.to_string().contains("证书链"),
            "文案要说指纹，不说证书链：{err}"
        );
    }

    /// 「只用 TLS 1.3」是构造上的保证：本 crate 的 rustls/tokio-rustls
    /// 不开 `tls12` feature，1.2 的协商路径根本编不出来。这条测试钉住
    /// `Cargo.toml`，别让谁顺手把 feature 加回来。
    ///
    /// 改红：给 `Cargo.toml` 里 rustls 或 tokio-rustls 的 features 加回
    /// `"tls12"`。
    #[test]
    fn tls12_is_not_compiled_in() {
        let manifest = include_str!("../../Cargo.toml");
        for line in manifest.lines().filter(|l| l.contains("rustls")) {
            assert!(!line.contains("tls12"), "rustls 不许开 tls12：{line}");
        }
    }

    /// 链路问题（对端重置、握手中断）必须归 Network——一次抖动不该被判死。
    #[test]
    fn handshake_and_link_errors_classify_as_network() {
        for msg in [
            "peer closed connection without sending TLS close_notify: \
             https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof",
            "connection reset by peer",
            "tls handshake eof",
        ] {
            let err = classify_tls_error(std::io::Error::other(msg));
            assert_eq!(
                err.class(),
                crate::error::ErrorClass::Network,
                "{msg} 应归为 Network，一次链路抖动不该判死"
            );
            assert!(matches!(err, Error::TlsHandshake(_)), "{msg}");
        }
    }

    /// 真实产出的"指纹不符"文本（`rustls::Error::InvalidCertificate` 的
    /// `Display`，不是手写的近似字符串）必须落 Fatal——夹具直接调用钉住
    /// 版本的 rustls 类型产出，不是照着关键词表拼出来的反向验证。
    #[test]
    fn a_real_certificate_mismatch_text_classifies_as_fatal() {
        let msg = rustls::Error::InvalidCertificate(
            rustls::CertificateError::ApplicationVerificationFailure,
        )
        .to_string();
        let err = classify_tls_error(std::io::Error::other(msg.clone()));
        assert_eq!(err.class(), crate::error::ErrorClass::Fatal, "{msg}");
        assert!(matches!(err, Error::TlsPinMismatch(_)), "{msg}");
    }
}
