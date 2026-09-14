//! TLS 外层。根证书内置，不读 Windows 证书库，因此企业注入的审计根不会被接受。

use crate::error::{Error, Result};
use crate::platform::Io;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use std::sync::Arc;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

#[derive(Clone)]
pub struct TlsRoots {
    store: rustls::RootCertStore,
}

impl TlsRoots {
    /// 内置的公共 CA 根，生产环境用这一个。
    pub fn webpki() -> Self {
        let mut store = rustls::RootCertStore::empty();
        store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self { store }
    }

    /// 追加一个 PEM 根，只用于集成测试信任 docker 环境的自签证书。
    ///
    /// R——依赖审计（Task 12）：原来用 `rustls_pemfile::certs`，该 crate
    /// 已被 RUSTSEC-2025-0134 标记为 unmaintained（见 `Cargo.toml` 里
    /// `rustls-pki-types` 依赖上的说明）。`CertificateDer::pem_slice_iter`
    /// 是同一份解析代码在 `rustls-pki-types` 里的原生入口，直接吃
    /// `&[u8]`，不用再手动包一层 `BufReader`。
    pub fn with_extra_pem(&mut self, pem: &[u8]) -> Result<()> {
        let mut added = 0usize;
        for cert in CertificateDer::pem_slice_iter(pem) {
            let cert = cert.map_err(|e| Error::Config(format!("PEM 解析失败：{e}")))?;
            self.store
                .add(cert)
                .map_err(|e| Error::Config(format!("根证书不可用：{e}")))?;
            added += 1;
        }
        if added == 0 {
            return Err(Error::Config("PEM 中没有证书".into()));
        }
        Ok(())
    }

    fn connector(&self) -> TlsConnector {
        let cfg = rustls::ClientConfig::builder()
            .with_root_certificates(self.store.clone())
            .with_no_client_auth();
        TlsConnector::from(Arc::new(cfg))
    }
}

/// 在已有字节流上完成 TLS 握手。`server_name` 同时作为 SNI 与证书校验的名字。
pub async fn wrap_tls<S: Io>(
    stream: S,
    server_name: &str,
    roots: &TlsRoots,
) -> Result<TlsStream<S>> {
    let name = rustls::pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|_| Error::Config(format!("Gateway 主机名不能用于 TLS：{server_name}")))?;
    roots
        .connector()
        .connect(name, stream)
        .await
        .map_err(classify_tls_error)
}

/// 证书链问题是致命的，链路问题按网络类重试。
///
/// R——全局约束：证书错误必须归 `Fatal`（不能被 Supervisor 自动重试，重试一个
/// 坏证书没有意义，只会在同一个错误上死循环）；握手层面的问题（对端重置、
/// 协议不匹配、读写失败）必须归 `Network`（这类问题可能是一次性的抖动，应该
/// 走退避重连）。`tokio_rustls` 把两类问题都统一包成 `std::io::Error`，唯一能
/// 用来区分的只有它 `Display` 出来的文本。
///
/// R37：这里只留一个关键词。对着钉住的 rustls 0.23.44 版本读源码
/// （`rustls::Error` 的 `Display` 实现，`error.rs`）：证书链校验失败时走的
/// 永远是同一条分支——
///
/// ```text
/// Self::InvalidCertificate(err) => write!(f, "invalid peer certificate: {err}")
/// ```
///
/// 不管具体是哪一种 `CertificateError`（过期、未生效、未知颁发者、签名不对、
/// 名字不匹配……），这个前缀恒定存在，是唯一稳定、经过源码确认的匹配点。
/// 上一版这里还列了 `"CertExpired"`、`"CertNotValidYet"` 两个关键词——它们是
/// **另一个 crate**（`rustls-webpki`）内部 `Error` 枚举变体的名字，那个错误
/// 会先被转换成 `rustls::CertificateError::ExpiredContext`/`NotValidYetContext`
/// 才到达这里，转换之后的 `Display` 文本是"certificate expired: verification
/// time ... but certificate is not valid after ..."这种人话句子，从不包含
/// `CertExpired`/`CertNotValidYet` 这两个词——这两条关键词从写下来的第一天
/// 起就没匹配过真实文本，之所以看不出来，是因为下面的测试夹具当年是照着
/// 关键词本身拼出来的字符串，而不是真的从 rustls 产出的文本。`"NotValidForName"`
/// 和 `"InvalidCertificate"` 同理：前者在开了 `std` feature（本项目就是）时
/// 走的是 `NotValidForNameContext` 分支，文本是"certificate not valid for
/// name ..."，同样不包含拼在一起的 `NotValidForName`；后者是外层
/// `rustls::Error` 这个枚举变体自己的名字，从未出现在它自己的 `Display`
/// 输出里（输出的是小写、带空格的 "invalid peer certificate: "，不是
/// PascalCase 的变体名）。`"UnknownIssuer"`/`"BadSignature"`/
/// `"UnknownRevocationStatus"` 三个词本身确实会原样出现（它们是没有专门
/// context 变体的裸枚举值，落到 `{other:?}` 兜底分支），但既然
/// `"invalid peer certificate"` 已经在它们前面出现，留着这三个词不会改变
/// 任何判断结果，纯属摆设。
///
/// 只留一个关键词还有一个好处：这个关键词就是"catch-all"本身，删掉它，
/// `cert_words` 就是空数组，`.any()` 恒为 `false`——不会出现"删掉 catch-all
/// 之后测试还在用某个具体关键词顶着继续走 Fatal 分支，看起来像是没受影响"
/// 这种假阳性。`cert_chain_errors_classify_as_fatal` 下面用真实 rustls
/// `Display` 输出做夹具，就是为了让这件事在测试里立即可见：删掉这一行，
/// 那条测试当场变红。
fn classify_tls_error(e: std::io::Error) -> Error {
    let msg = e.to_string();
    let cert_words = ["invalid peer certificate"];
    if cert_words.iter().any(|w| msg.contains(w)) {
        Error::TlsInvalidCert(msg)
    } else {
        Error::TlsHandshake(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- with_extra_pem：不需要网络，直接跑，默认 `cargo test` 就会执行。---

    #[test]
    fn with_extra_pem_rejects_pem_with_no_certificate() {
        let mut roots = TlsRoots::webpki();
        let err = roots.with_extra_pem(b"not a pem file at all").unwrap_err();
        assert_eq!(err.class(), crate::error::ErrorClass::Fatal);
    }

    #[test]
    fn with_extra_pem_rejects_garbage_that_parses_as_zero_certs() {
        let mut roots = TlsRoots::webpki();
        let pem = b"-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n";
        assert!(roots.with_extra_pem(pem).is_err());
    }

    // --- classify_tls_error：这里钉住的是"证书问题必须落 Fatal、握手/链路
    // 问题必须落 Network"这条全局约束本身,不依赖真实网络就能验证,也不会因为
    // docker harness 不在而跳过。会让这些用例变红的改法：把 classify_tls_error
    // 里 cert_words 命中之后返回的分支从 `Error::TlsInvalidCert` 换成
    // `Error::TlsHandshake`（或者反过来），这两个变体的 `class()` 不同
    // （Fatal vs Network），断言立刻就能看出来。
    //
    // R37：夹具字符串不是手写的近似值，是直接调用钉住版本的
    // `rustls::Error`/`rustls::CertificateError` 的 `Display` 实现产出的——
    // 这就是"pinned rustls 实际产出的文本"本身，不是照着关键词表拼出来的
    // 反向验证。这样一来，`cert_chain_errors_classify_as_fatal` 里任何一条
    // 夹具都只含 "invalid peer certificate" 这一个 catch-all 关键词，不含
    // 任何其他specific 关键词——谁把 classify_tls_error 里的 catch-all
    // 删掉，这条测试当场变红，不会出现"具体关键词顶住、测试看起来没事"的
    // 假阳性。---

    /// 直接用钉住版本的 `rustls::Error::InvalidCertificate` 产出真实文本，
    /// 而不是手写一个"看起来像"的字符串。
    fn real_invalid_certificate_text(err: rustls::CertificateError) -> String {
        rustls::Error::InvalidCertificate(err).to_string()
    }

    #[test]
    fn cert_chain_errors_classify_as_fatal() {
        use rustls::pki_types::UnixTime;
        use rustls::CertificateError;

        let now = UnixTime::now();
        let fixtures = [
            // 没有专门 context 变体的裸枚举值，落 `{other:?}` 兜底分支。
            real_invalid_certificate_text(CertificateError::UnknownIssuer),
            // 有 context 的变体：真实文本是"certificate expired: ..."这种
            // 人话句子，不包含拼在一起的 "CertExpired"——这正是本轮要纠正
            // 的关键词表错误，见 classify_tls_error 上的文档注释。
            real_invalid_certificate_text(CertificateError::ExpiredContext {
                time: now,
                not_after: now,
            }),
            real_invalid_certificate_text(CertificateError::NotValidYetContext {
                time: now,
                not_before: now,
            }),
            real_invalid_certificate_text(CertificateError::NotValidForNameContext {
                expected: rustls::pki_types::ServerName::try_from("gateway.test".to_string())
                    .unwrap(),
                presented: vec!["other.example".to_string()],
            }),
        ];

        for msg in fixtures {
            let err = classify_tls_error(std::io::Error::other(msg.clone()));
            assert_eq!(
                err.class(),
                crate::error::ErrorClass::Fatal,
                "{msg} 应归为 Fatal，不能自动重试一个坏证书"
            );
            assert!(matches!(err, Error::TlsInvalidCert(_)), "{msg}");
        }
    }

    #[test]
    fn handshake_and_link_errors_classify_as_network() {
        for msg in [
            // rustls::ConnectionCommon 里 UNEXPECTED_EOF_MESSAGE 常量的原文
            // （src/conn.rs，0.23.44）。
            "peer closed connection without sending TLS close_notify: \
             https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof",
            "connection reset by peer",
            // tokio-rustls 0.26.5 里 UnexpectedEof 场景下硬编码的原文
            // （src/common/mod.rs）。
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

    // --- Task 10 补的第十一条：未受信证书必须 Fail ---
    //
    // 上一轮复审做过一次实验：把 `TlsRoots::connector()` 换成一个三个方法
    // 全部硬编码返回 `Ok` 的 `ServerCertVerifier`（等价于把证书校验整个
    // 关掉），跑全量 lib 测试，没有任何现有测试变红——本模块上面的用例
    // 全都直接调用 `classify_tls_error`（纯函数，输入是手写的错误文本），
    // 根本不会经过真正的 `connector()`/`wrap_tls`，能揪出"证书校验被
    // 静默关掉"这类回归的只有需要 docker 的 `tests/transport.rs`
    // `#[ignore]` 用例，而本仓没有 CI 会跑它们。
    //
    // 这里在进程内起一个真正的 rustls TLS 服务端（自签证书，跟
    // preflight.rs 里 `gateway_tls_step_passes_when_the_certificate_is_
    // trusted` 用的是同一对固定证书/私钥——两条测试互为正反面：那一条把
    // 证书加进 extra root 断言 Pass，这一条**不**加、断言必须 Fail 且是
    // Fatal 类），证明客户端确实会拒绝一个自己不认识的自签证书。
    //
    // 会让这条测试变红的实现改法：把 `TlsRoots::connector()` 换成一个
    // 总是接受任意证书的 `ServerCertVerifier`（例如三个校验方法全部硬编码
    // 返回 `Ok`），或者把 `classify_tls_error` 里证书错误的分支从
    // `Error::TlsInvalidCert`（Fatal）改判成 `Error::TlsHandshake`
    // （Network，会被当成一次可重试的抖动）。

    const UNTRUSTED_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBODCB36ADAgECAgkAr2yXAE+wDB8wCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJ\n\
bG9jYWxob3N0MCAXDTI2MDkxNDAzNDE1M1oYDzIxMjYwODIxMDM0MTUzWjAUMRIw\n\
EAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ50frL\n\
mLEPSa7z0sqCmmRXJQQxgTfzxlcoJ4CKlST85mlZ9Fl2Un3fPCYFwtRi0eEJ4jAh\n\
5cf6WHGmEM9gZlsVoxgwFjAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0E\n\
AwIDSAAwRQIgAQ1gD0AFOxtEdH0SRv1x7wvGDHHzEXsEqehSXayGKjcCIQCXRetW\n\
I3vKyk+IVraIkoFtpwtyhck6zxYrkM07snH3iw==\n\
-----END CERTIFICATE-----\n";

    const UNTRUSTED_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgqqQ6iAlPo7gj+MbM\n\
Z5JHB/f/r1o7nt406+2/PKx/N1yhRANCAAQ50frLmLEPSa7z0sqCmmRXJQQxgTfz\n\
xlcoJ4CKlST85mlZ9Fl2Un3fPCYFwtRi0eEJ4jAh5cf6WHGmEM9gZlsV\n\
-----END PRIVATE KEY-----\n";

    #[tokio::test]
    async fn untrusted_self_signed_certificate_is_rejected_as_fatal() {
        use tokio::net::TcpListener;

        let certs: Vec<_> = CertificateDer::pem_slice_iter(UNTRUSTED_CERT_PEM.as_bytes())
            .collect::<std::result::Result<_, _>>()
            .expect("测试证书应该能被解析");
        let key = rustls_pki_types::PrivateKeyDer::from_pem_slice(UNTRUSTED_KEY_PEM.as_bytes())
            .expect("测试私钥应该能被解析");
        let server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("测试证书与私钥应该匹配");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((sock, _)) = listener.accept().await {
                // 客户端会在校验证书这一步就失败，握手走不完——服务端这
                // 一侧只需要尝试 accept，不关心结果。
                let _ = acceptor.accept(sock).await;
            }
        });

        // 关键：只用 webpki() 内置公共 CA 根，不调用 with_extra_pem 把这个
        // 自签证书加进信任列表——这正是"未受信"这个场景本身。
        let roots = TlsRoots::webpki();
        let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let err = wrap_tls(stream, "localhost", &roots).await.unwrap_err();

        assert_eq!(
            err.class(),
            crate::error::ErrorClass::Fatal,
            "未受信的自签证书必须归 Fatal，不能被当成一次可重试的网络抖动：{err}"
        );
        assert!(matches!(err, Error::TlsInvalidCert(_)), "{err:?}");
    }
}
