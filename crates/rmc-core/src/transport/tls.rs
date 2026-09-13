//! TLS 外层。根证书内置，不读 Windows 证书库，因此企业注入的审计根不会被接受。

use crate::error::{Error, Result};
use crate::platform::Io;
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
    pub fn with_extra_pem(&mut self, pem: &[u8]) -> Result<()> {
        let mut reader = std::io::BufReader::new(pem);
        let mut added = 0usize;
        for cert in rustls_pemfile::certs(&mut reader) {
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
/// 用来区分的只有它 `Display` 出来的文本——这里按 rustls 对证书类错误固定
/// 使用的关键词匹配，不做正则，图的是可读、可审计。
fn classify_tls_error(e: std::io::Error) -> Error {
    let msg = e.to_string();
    let cert_words = [
        "invalid peer certificate",
        "UnknownIssuer",
        "CertExpired",
        "CertNotValidYet",
        "NotValidForName",
        "BadSignature",
        "UnknownRevocationStatus",
        "InvalidCertificate",
        "certificate",
    ];
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
    // （Fatal vs Network），断言立刻就能看出来。---

    #[test]
    fn cert_chain_errors_classify_as_fatal() {
        for msg in [
            "invalid peer certificate: UnknownIssuer",
            "invalid peer certificate: CertExpired",
            "invalid peer certificate: NotValidForName",
        ] {
            let err = classify_tls_error(std::io::Error::other(msg));
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
            "peer closed connection without sending TLS close_notify",
            "connection reset by peer",
            "unexpected EOF during handshake",
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
}
