//! 一把 ed25519 身份密钥，两个身份：TLS 自签证书与 SSH host key。指纹 = 公钥的 SHA-256。

use crate::datadir::{write_private_atomic_noclobber, DataDir};
use crate::{Error, Result};
use base64::Engine;
use rmc_core::code::ServerFingerprint;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::io;
use std::path::Path;
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
            return Err(Self::already_exists_err(&path));
        }
        let id = Self::generate();
        // R——评审 Critical 1：种子的 base64 形态必须全程只存在于一份
        // `Zeroizing` 里，不能先用普通 `String`/`format!` 拼出来再包一层——
        // 那样中间会留一份不会被清零的裸种子副本。`encode_string` 直接把编码
        // 结果写进已经是 `Zeroizing<String>` 的缓冲区，从未存在过一份普通
        // `String` 装着这把种子。
        let mut line = Zeroizing::new(format!("{FILE_TAG} "));
        base64::engine::general_purpose::STANDARD.encode_string(id.seed.as_slice(), &mut line);
        line.push('\n');
        require_zeroizing_string(&line);
        write_private_atomic_noclobber(&path, line.as_bytes()).map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                Self::already_exists_err(&path)
            } else {
                Error::Io(e)
            }
        })?;
        Ok(id)
    }

    fn already_exists_err(path: &Path) -> Error {
        Error::Identity(format!(
            "{} 已存在，拒绝覆盖——换密钥等于换身份，所有连接码都会作废；确实要换请先手工移走它",
            path.display()
        ))
    }

    pub fn load_from(dir: &DataDir) -> Result<Self> {
        let path = dir.identity_key();
        // R——评审 Critical 1：整份身份文件（含 base64 编码的种子）读进来之后
        // 立刻包进 `Zeroizing`，不留一份裸 `String`。
        let text: Zeroizing<String> =
            Zeroizing::new(std::fs::read_to_string(&path).map_err(|e| {
                Error::Identity(format!("读不到 {}：{e}；先运行 init", path.display()))
            })?);
        let rest = text
            .trim()
            .strip_prefix(FILE_TAG)
            .map(str::trim)
            .ok_or_else(|| Error::Identity(format!("{} 不是本程序写的身份文件", path.display())))?;
        // 解码结果是裸 32 字节种子本身，同样不能落进一个不会清零的 `Vec`：
        // `decode_vec` 直接写进已经是 `Zeroizing<Vec<u8>>` 的缓冲区。
        let mut bytes: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
        base64::engine::general_purpose::STANDARD
            .decode_vec(rest, &mut bytes)
            .map_err(|e| Error::Identity(format!("身份文件损坏：{e}")))?;
        require_zeroizing_bytes(&bytes);
        let seed: [u8; 32] = bytes
            .as_slice()
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
    ///
    /// R——评审 Important 2：这个函数体里，种子至少还有两份不会被清零的裸拷贝，
    /// 都绕不开，如实记录，不要让人以为「副本已经审计完了」：
    ///
    /// 1. `rcgen::KeyPair::try_from(pkcs8.as_slice())`——查过本机缓存的
    ///    `rcgen 0.14.10` 源码，`TryFrom` 实现是
    ///    `serialized_der: key.secret_der().into()`，`KeyPair` 结构体里的
    ///    `serialized_der: Vec<u8>` 字段没有任何 `Drop`/`Zeroize`。`key`
    ///    这个局部变量在本函数返回时超出作用域被释放，它持有的这份种子拷贝
    ///    只是被 `free`，**不会被清零**——在被下一次分配复用之前，堆上那块
    ///    内存原样留着这把身份密钥的种子。`rcgen 0.14` 没有给任何清零钩子，
    ///    这份副本客观上绕不开（除非 fork `rcgen` 或者在 `#![forbid(unsafe_code)]`
    ///    的这个 crate 里做不安全的手工擦写，两者都不在本任务范围内）。
    /// 2. `PrivatePkcs8KeyDer::from(pkcs8.to_vec())`——这一份下面单独有注释：
    ///    它是 `rustls` 内部长期持有的那一份，同样没有 `Zeroize`，但生命周期
    ///    不同（活到 `ServerConfig` 被丢弃为止，不是函数一返回就该消失）。
    ///
    /// 两份性质不同，不要混为一谈：第 2 份是 TLS 私钥必然的形态（`rustls` 自己
    /// 的类型决定的，长期存在是设计如此）；第 1 份是函数内部的临时值，本该
    /// 一函数返回就从内存里消失却没有——这是 `rcgen` 这个版本的 API 限制，
    /// 不是本函数可以绕开的实现选择。
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
// 的 `Vec`——rustls 内部会长期持有它（活到 ServerConfig 被丢弃为止），这是 TLS
// 私钥必然的形态，绕不开。`tls_cert_and_key` 函数体上方的文档注释里记录了
// **另一份**性质不同的裸拷贝（`rcgen::KeyPair` 内部的 `serialized_der`）——
// 那一份是函数内部本该随返回就消失、但因为 rcgen 0.14 没给清零钩子而没有被擦掉
// 的临时值，跟这里说的「TLS 私钥必然的形态」不是同一件事，不要读成只有一份。

/// 编译期钉住：`create_in`/`load_from` 里承载种子（或种子的可逆编码）的绑定必须
/// 是 `Zeroizing<_>`，不能是裸 `String`/`Vec<u8>`。这两个函数只做类型检查，没有
/// 运行时行为——调用点如果把 `line`/`bytes` 的类型换成不带 `Zeroizing` 的裸类型，
/// 这两行调用就对不上参数类型，`cargo build`/`cargo test` 直接编译失败，这就是
/// 「改红」：不是跑起来断言失败，是编不过。
fn require_zeroizing_string(_: &Zeroizing<String>) {}
fn require_zeroizing_bytes(_: &Zeroizing<Vec<u8>>) {}

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

    /// R——评审 Important 3：上面那条测试只验证了「指纹不变」，没有验证「文件
    /// 一字节都没被碰过」——这条补上直接的字节级证据。
    ///
    /// **实测过、如实记录一次失手**：这条测试**不能**证明 `create_in` 已经切到
    /// `write_private_atomic_noclobber`。单独把 `create_in` 里的
    /// `write_private_atomic_noclobber` 换回 `write_private_atomic`（同时保留
    /// 前面 `if path.exists() { return Err(...) }` 那道前置检查），这条测试
    /// 原样通过（绿）——因为第二次调用在走到任何写入之前，就已经被那道前置
    /// `exists()` 检查挡回去了，根本不会碰到 `write_private_atomic*`。这跟
    /// Task 2 那次「改 `tls_server_config`」的空头支票是同一类问题：加了一层
    /// 深层防御（`persist_noclobber`），却写了一条只测得到浅层防御（前置
    /// `exists()`）的「改红」承诺。
    ///
    /// 真正能同时命中 Important 3 那个 TOCTOU 缺口的组合是「去掉前置
    /// `exists()` 检查 **并且** 把 `write_private_atomic_noclobber` 换回
    /// `write_private_atomic`」——两处都改才会红（已实测：`unwrap_err()` 在
    /// `Ok(Identity(..))` 上 panic）。单独去掉前置检查、保留 noclobber 写，
    /// 这条测试仍然绿——这正好证明 `write_private_atomic_noclobber` 本身
    /// 独立提供了保护，不依赖那道前置检查。
    ///
    /// 这条测试真正钉住的是「`create_in` 拒绝覆盖」这个行为的字节级细节
    /// （比它上面那条只比较指纹的测试更严），**不是** race 场景本身——
    /// race 场景（两次调用交错在前置检查与落盘之间）需要真正的并发注入才能
    /// 确定性复现，不在这条测试的覆盖范围内。TOCTOU 缺口本身的回归测试是
    /// `datadir.rs` 里的 `noclobber_write_refuses_an_existing_target_and_leaves_it_untouched`
    /// ——那条测试没有任何前置 `exists()` 检查介入，直接命中
    /// `write_private_atomic_noclobber` 内部的 `persist_noclobber`，已实测
    /// 把它换回 `persist` 会让 `.unwrap_err()` panic（真红）。
    #[test]
    fn create_in_refuses_overwrite_and_leaves_the_file_byte_for_byte_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        let d = crate::datadir::DataDir::at(tmp.path().to_path_buf());
        d.create().unwrap();
        Identity::create_in(&d).unwrap();
        let path = d.identity_key();
        let before = std::fs::read(&path).unwrap();
        let err = Identity::create_in(&d).unwrap_err();
        assert!(matches!(err, crate::Error::Identity(_)), "{err}");
        let after = std::fs::read(&path).unwrap();
        assert_eq!(before, after, "拒绝覆盖必须做到原文件字节不变");
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
