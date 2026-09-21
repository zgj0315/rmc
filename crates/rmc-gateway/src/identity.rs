//! 一把 ed25519 身份密钥，两个身份：TLS 自签证书与 SSH host key。指纹 = 公钥的 SHA-256。

use crate::datadir::{write_private_atomic, DataDir};
use crate::{Error, Result};
use base64::Engine;
use rmc_core::code::ServerFingerprint;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use zeroize::Zeroizing;

const FILE_TAG: &str = "rmc-gateway-identity-v1";

/// RFC 8410 的 PKCS#8 v1 前缀，后面直接跟 32 字节种子。
const PKCS8_ED25519_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// Ed25519 的 SubjectPublicKeyInfo 是定长的：12 字节前缀 + 32 字节公钥。
pub const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

pub struct Identity {
    seed: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Identity({})", self.fingerprint())
    }
}

impl Identity {
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut seed = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(&mut *seed);
        Self::from_seed(seed)
    }

    fn from_seed(seed: Zeroizing<[u8; 32]>) -> Self {
        let kp = russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&seed);
        let public = kp.public.0;
        Self { seed, public }
    }

    pub fn create_in(dir: &DataDir) -> Result<Self> {
        let path = dir.identity_key();
        if path.exists() {
            return Err(Error::Identity(format!(
                "{} 已存在，拒绝覆盖——换密钥等于换身份，所有连接码都会作废；确实要换请先手工移走它",
                path.display()
            )));
        }
        let id = Self::generate();
        let line = format!(
            "{FILE_TAG} {}\n",
            base64::engine::general_purpose::STANDARD.encode(*id.seed)
        );
        write_private_atomic(&path, line.as_bytes())?;
        Ok(id)
    }

    pub fn load_from(dir: &DataDir) -> Result<Self> {
        let path = dir.identity_key();
        let text = std::fs::read_to_string(&path)
            .map_err(|e| Error::Identity(format!("读不到 {}：{e}；先运行 init", path.display())))?;
        let rest = text
            .trim()
            .strip_prefix(FILE_TAG)
            .map(str::trim)
            .ok_or_else(|| Error::Identity(format!("{} 不是本程序写的身份文件", path.display())))?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(rest)
            .map_err(|e| Error::Identity(format!("身份文件损坏：{e}")))?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::Identity("身份文件损坏：长度不对".into()))?;
        Ok(Self::from_seed(Zeroizing::new(seed)))
    }

    pub fn fingerprint(&self) -> ServerFingerprint {
        ServerFingerprint::of_ed25519_public(&self.public)
    }

    pub fn ssh_host_key(&self) -> russh::keys::PrivateKey {
        let kp = russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&self.seed);
        russh::keys::PrivateKey::from(kp)
    }

    fn pkcs8(&self) -> Zeroizing<Vec<u8>> {
        let mut der = Zeroizing::new(Vec::with_capacity(48));
        der.extend_from_slice(&PKCS8_ED25519_PREFIX);
        der.extend_from_slice(&*self.seed);
        der
    }

    /// 每次调用现签一张证书——客户端只核对公钥，证书本身不需要稳定。
    pub fn tls_cert_and_key(&self) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
        let pkcs8 = self.pkcs8();
        let key = rcgen::KeyPair::try_from(pkcs8.as_slice())
            .map_err(|e| Error::Tls(format!("身份密钥转 rcgen 失败：{e}")))?;
        let params = rcgen::CertificateParams::new(vec!["rmc-gateway".to_string()])
            .map_err(|e| Error::Tls(format!("证书参数：{e}")))?;
        let cert = params
            .self_signed(&key)
            .map_err(|e| Error::Tls(format!("自签失败：{e}")))?;
        Ok((
            cert.der().clone(),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.to_vec())),
        ))
    }

    pub fn tls_server_config(&self) -> Result<Arc<rustls::ServerConfig>> {
        let (cert, key) = self.tls_cert_and_key()?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| Error::Tls(e.to_string()))?
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .map_err(|e| Error::Tls(e.to_string()))?;
        Ok(Arc::new(cfg))
    }
}

// `PrivatePkcs8KeyDer::from(pkcs8.to_vec())` 把种子复制进了一个不会被 zeroize
// 的 `Vec`——rustls 内部会持有它，这是 TLS 私钥必然的形态，记进文档注释即可。

#[cfg(test)]
mod tests {
    use super::*;

    /// 同一把种子 → SSH host key 与 TLS 证书里的公钥算出同一个指纹。
    ///
    /// 改红：**实测过**——把 `tls_cert_and_key` 里 `let pkcs8 = self.pkcs8();`
    /// 换成 `let pkcs8 = Self::generate().pkcs8();`，第二个 `assert_eq!`（TLS 侧
    /// 指纹）红。brief 原文这里写的是"改 `tls_server_config`"——那是空头支票：
    /// 这条测试只调 `tls_cert_and_key()`（第 150 行），从不经过
    /// `tls_server_config`，改那边这条测试纹丝不动（已用 GLOBAL.md 要求的六步
    /// 流程实测确认：注入、`grep -c` 确认命中一次、跑测试看到绿、还原）。真正
    /// 两侧共用的分支点是 `tls_cert_and_key` 里的 `self.pkcs8()`。
    #[test]
    fn ssh_host_key_and_tls_certificate_share_one_fingerprint() {
        let id = Identity::generate();
        let fp = id.fingerprint();
        // SSH 侧
        let hk = id.ssh_host_key();
        let pk = hk.public_key();
        let ed = pk.key_data().ed25519().expect("ed25519");
        assert_eq!(
            rmc_core::code::ServerFingerprint::of_ed25519_public(&ed.0),
            fp
        );
        // TLS 侧：从证书 DER 里取 SPKI
        let (cert, _) = id.tls_cert_and_key().unwrap();
        let parsed = rustls::server::ParsedCertificate::try_from(&cert).unwrap();
        let spki = parsed.subject_public_key_info();
        let der: &[u8] = spki.as_ref();
        assert_eq!(der.len(), 44);
        assert_eq!(&der[..12], &ED25519_SPKI_PREFIX);
        let pk: [u8; 32] = der[12..].try_into().unwrap();
        assert_eq!(
            rmc_core::code::ServerFingerprint::of_ed25519_public(&pk),
            fp
        );
    }

    #[test]
    fn create_then_load_gives_the_same_identity_and_refuses_overwrite() {
        let tmp = tempfile::tempdir().unwrap();
        let d = crate::datadir::DataDir::at(tmp.path().to_path_buf());
        d.create().unwrap();
        let a = Identity::create_in(&d).unwrap();
        let b = Identity::load_from(&d).unwrap();
        assert_eq!(a.fingerprint(), b.fingerprint());
        let err = Identity::create_in(&d).unwrap_err();
        assert!(matches!(err, crate::Error::Identity(_)), "{err}");
        assert_eq!(
            Identity::load_from(&d).unwrap().fingerprint(),
            a.fingerprint(),
            "拒绝覆盖时不能动原文件"
        );
    }

    /// TLS 配置只开 1.3。改红：`with_protocol_versions` 里加上 `TLS12`。
    #[test]
    fn tls_config_is_13_only() {
        let id = Identity::generate();
        let cfg = id.tls_server_config().unwrap();
        // rustls 的 ServerConfig 没有直接暴露版本列表；用一次握手验：1.2 客户端必须失败。
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
            let client = rustls::ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS12])
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(std::sync::Arc::new(
                    crate::testing_verifier::AcceptAll,
                ))
                .with_no_client_auth();
            let (c, s) = tokio::io::duplex(64 * 1024);
            let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
            let srv = tokio::spawn(async move { acceptor.accept(s).await.map(|_| ()) });
            let r = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client))
                .connect(
                    rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap(),
                    c,
                )
                .await;
            assert!(r.is_err(), "只开 1.3 的服务端不该跟 1.2 客户端握成");
            let _ = srv.await;
        });
    }
}
