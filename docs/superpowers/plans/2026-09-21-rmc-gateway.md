# rmc-gateway 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把运维服务器做成一个 Rust 二进制（`rmc-gateway`），并把客户端切到「连接码 + 指纹钉死 + 服务端分配端口」，最后用进程内的服务端替掉 docker 集成测试、退役旧的 haproxy + sshd 方案。

**Architecture:** 线上协议不变（TLS 里跑 SSH）。服务端用 russh 的服务端那一半，只实现口令认证与一条反向转发，跑在 rustls 的 TLS 1.3 流上；一把 ed25519 身份密钥同时派生 TLS 自签证书与 SSH host key，整台服务器只有一个指纹。客户端两层各核对一次同一个指纹，申请端口 0 由服务端回填。账号、口令哈希、审计日志都在数据目录里，CLI 与服务进程之间没有 IPC。服务端做成 lib，客户端的集成测试从 docker 换成进程内。

**Tech Stack:** Rust 2021 / MSRV 1.89；russh 0.63（服务端与客户端）；rustls 0.23 + tokio-rustls 0.26（ring）；rcgen 0.14（自签证书）；argon2 0.6（已在锁里）；toml 0.9 + serde；serde_json 1；tokio。

**Spec:** `docs/superpowers/specs/2026-09-21-rmc-gateway-design.md`（第 2 版）。本计划是它的论证；两者冲突以 spec 为准。

## Global Constraints

- **只用 IP，不接受域名**（spec §4.2）；**默认监听 22000，反向端口 22001–22999**（spec §3.3）；**`serve` 是 root 就拒绝启动**，`--allow-root` 放行。
- **只开 TLS 1.3**；客户端 TLS 一侧**只**核对证书公钥并验证握手签名，不校验有效期、名称与链（spec §4.1）。
- **指纹 = ed25519 公钥 32 字节的 SHA-256，base64url 不带填充，43 个字符**。TLS 与 SSH 两层各核对一次同一个指纹。**没有「首次连接自动信任」**，也不留作后备。
- **连接码格式** `rmc1:<账号>@<IP>:<端口>:<指纹>:<校验>`；账号 `[a-z0-9][a-z0-9-]{0,31}`；校验 = 前面全部内容 SHA-256 的前 4 个十六进制字符。
- 服务端**只实现**口令认证与 `tcpip-forward`；`methods` 只登记 password；其余请求一律由 russh 默认拒绝（丢弃 `ChannelOpenHandle` 即 `AdministrativelyProhibited`，已读源码确认）。
- **防爆破数值**（spec §6）：每连接最多 3 次、失败统一延迟 1 秒；同一来源 10 分钟内失败 10 次封 15 分钟；**不做按账号锁定**；未认证连接 20 秒超时、全局最多 64 条、每 IP 最多 8 条；账号不存在或停用时也跑一次等价哈希。
- **心跳 10 秒 × 3**；隧道一断立即释放端口；每条隧道最多 16 条工程师连接；吊销最迟 10 秒内踢掉在线会话。
- 审计日志 JSON Lines、按天一个文件、保留 180 天、**不写口令**。
- 界面用语：一律「运维服务器」，**不出现 Gateway 与「网关」**（rmc-core 与 rmc-app 的源码扫描守着这一条；`code.rs` 里给界面看的错误文案同样受约束）。新增用语「连接码」。
- 口令只用 `Zeroizing<String>` 承载，不进日志、`Debug`、错误文案。
- 新 crate 一律 `#![forbid(unsafe_code)]`；edition 2021；MSRV 1.89（`std::fs::File::lock` 在 1.89 稳定，本计划用它做 CLI 串行化）。
- **依赖新增上限**：`rcgen`（连带 `yasna`）、`toml`（连带 `toml_writer`/`serde_spanned`/`toml_parser`/`winnow`）、`serde_json`（连带 `itoa`/`zmij`）、`serde` 的 derive。`argon2` / `password-hash` 已在锁里。派发前已在探针工程里验过：这批新增过得了仓库的 `cargo deny` 四项。**再多一个包要记裁决。**
- **每个任务结束时八道闸门全绿**：`cargo fmt --all --check`；`cargo clippy --workspace --all-targets -- -D warnings`；`cargo test --workspace`；`cargo zigbuild -p rmc-app --tests --target x86_64-pc-windows-gnu`；`cargo zigbuild -p rmc-gateway --tests --target x86_64-pc-windows-gnu`（**新增**：Windows CI 要用它跑端到端）；`cargo-zigbuild clippy -p rmc-win --all-targets --target x86_64-pc-windows-gnu -- -D warnings`；`cargo deny check advisories bans licenses sources`；`cargo metadata --locked`。
- **变异纪律**：每条关键测试上方写明「改实现的哪一行会让它变红」，**并且真的改一遍**。这台机器没有 `timeout`，用 `perl -e 'alarm shift; exec @ARGV' <秒> <命令>`；**不写 `trap`，绝不 `kill 0`**；注入后 `grep -c` 确认、needle 不带换行、锚点按整行匹配且命中恰为 1；`sed -i.bak` + `mv` 会让 mtime 回退，用会推进 mtime 的写法并在还原后 `touch`。每轮结束清掉自己的 `CARGO_TARGET_DIR`。
- 分支 `feat/rmc-gateway`（已存在，含 spec）。

## 派发前实测过的第三方 API（两个探针，全部一次通过）

计划里的服务端代码不是凭印象写的。两个探针工程在与仓库同一份 `Cargo.lock` 上编译运行过：

1. **一把种子两个身份**：`russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&seed)` → `russh::keys::PrivateKey::from(kp)` 得 host key；PKCS#8 v1 = 固定 16 字节前缀 `30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20` + 种子，`rcgen::KeyPair::try_from(pkcs8)` 自签得证书，同一份 PKCS#8 给 rustls 当私钥。两侧算出的指纹**一字不差**。
2. **客户端按公钥核对**：`rustls::server::ParsedCertificate::try_from(cert)?.subject_public_key_info()` 得 SPKI DER；Ed25519 的 SPKI 定长 44 字节 = 12 字节前缀 `30 2a 30 05 06 03 2b 65 70 03 21 00` + 32 字节公钥。自定义 `ServerCertVerifier`：对的指纹握手成功；错的指纹报 `invalid peer certificate: ApplicationVerificationFailure`——**正好落进 `transport::tls::classify_tls_error` 现有的「invalid peer certificate → TlsInvalidCert → Fatal」分支**。
3. **服务端整条通路**：`rustls::ServerConfig::builder_with_provider(ring).with_protocol_versions(&[&TLS13])` → `tokio_rustls::TlsAcceptor` → `russh::server::run_stream(cfg, tls_stream, handler)`；`Handler::tcpip_forward(&mut self, _, port: &mut u32, session)` 里 `*port = 账号端口` 回填、`session.handle()` 拿 `Handle`；反向监听收到连接后 `handle.channel_open_forwarded_tcpip("127.0.0.1", port, peer_ip, peer_port).await?.into_stream()` 与工程师的 TcpStream `copy_bidirectional`。客户端 `session.tcpip_forward("", 0).await` 返回回填的端口；申请非 0 且不等于账号端口 → 客户端收到 `russh::Error::RequestDenied`（文本 "The request was rejected by the other party"）。
4. **argon2 0.6**：`Argon2::default().hash_password(pw_bytes)` 自动生成盐；解析用 `argon2::password_hash::phc::PasswordHash::new(&phc)`（`password_hash::PasswordHash` 那条路径已弃用，`-D warnings` 下会红）；`verify_password(pw, &parsed)`。
5. `russh::MethodSet::from(&[russh::MethodKind::Password][..])`；`russh::server::Config { methods, max_auth_attempts: 3, inactivity_timeout: None, keepalive_interval: Some(10s), keepalive_max: 3, ..Default::default() }`；`Handle::disconnect(Disconnect, String, String)`。
6. 借用坑：`k.public_key()` 返回**拥有值**，`k.public_key().key_data().ed25519()` 一行写会 E0716，先 `let pk = k.public_key();`。

## 文件结构

```
crates/rmc-core/src/code.rs                 连接码、账号名、服务器指纹（两侧共用的协议类型）——Task 1
crates/rmc-gateway/Cargo.toml               lib + bin；feature "testing"
crates/rmc-gateway/src/lib.rs               模块清单、Error
crates/rmc-gateway/src/datadir.rs           数据目录、原子写、属主/是否 root 判断
crates/rmc-gateway/src/identity.rs          身份密钥 → 指纹 / host key / TLS ServerConfig
crates/rmc-gateway/src/config.rs            config.toml（public_addr、端口区间）
crates/rmc-gateway/src/accounts.rs          accounts.toml、argon2、端口分配、CLI 改写、服务端读取
crates/rmc-gateway/src/cidr.rs              --engineer-allow 的网段匹配
crates/rmc-gateway/src/clock.rs             UTC 日期与 RFC3339（审计文件名与时间戳）
crates/rmc-gateway/src/throttle.rs          认证失败限流与未认证连接限额（纯逻辑，时钟注入）
crates/rmc-gateway/src/audit.rs             JSON Lines 审计日志、按天滚动、180 天清理
crates/rmc-gateway/src/status.rs            status.json 写与读
crates/rmc-gateway/src/server.rs            TLS 监听 + russh 服务端 + 反向转发 + 吊销扫描
crates/rmc-gateway/src/cli.rs               子命令解析与执行（纯函数，收 args 与输出句柄）
crates/rmc-gateway/src/main.rs              薄壳
crates/rmc-gateway/src/testing.rs           TestGateway / FakeAppliance / engineer_exec（feature "testing"）
```

`rmc-gateway` **依赖 `rmc-core`**（用它的 `code::*`、`addr::HostPort`）。决定：不再开第四个 crate 放共用类型——那样只为二百行代码多一个包；rmc-core 本来就是平台中立的协议 + 内核层。代价是 gateway 二进制会编译整个客户端内核（LTO 会剥掉）。

**端到端测试放在 `crates/rmc-gateway/tests/`，不放在 `rmc-core/tests/`。** 理由：如果让 `rmc-core` 反过来 dev-depend `rmc-gateway`，cargo 允许这个经 dev-dependency 的环，但会把 `rmc-core` 编两遍，`rmc_gateway` 交出来的 `rmc_core::code::ConnectionCode` 与测试里的同名类型**对不上**。放在 gateway 一侧则没有环：它本来就正常依赖 rmc-core，测试里的 `rmc_core` 与它链接的是同一份。`rmc-core` 自己的 TLS 单元测试要造服务端证书时用 dev-dependency `rcgen`（本计划已把 rcgen 算进新增依赖）。

---

### Task 1: 连接码、账号名与服务器指纹（rmc-core，纯逻辑，两侧共用）

**Files:**
- Create: `crates/rmc-core/src/code.rs`
- Modify: `crates/rmc-core/src/lib.rs`（加 `pub mod code;` 与 re-export）
- Modify: `crates/rmc-core/src/wording.rs` 的 ALLOWED 表**不动**——`code.rs` 的文案不许含禁用词
- Test: `crates/rmc-core/src/code.rs` 同文件测试模块

**Interfaces:**
- Consumes: `crate::addr::HostPort`（`HostPort::new(host, port)` 接受 IP 字面量）；`sha2`、`base64`（都已是 rmc-core 依赖）
- Produces（后面每个任务都用）:
  - `pub struct ServerFingerprint([u8; 32])`：`of_ed25519_public(&[u8; 32]) -> Self`、`parse(&str) -> Result<Self, CodeError>`、`as_bytes(&self) -> &[u8; 32]`、`Display`（43 字符 base64url 无填充）、`FromStr`、`Clone/PartialEq/Eq/Debug`
  - `pub struct AccountName(String)`：`parse(&str) -> Result<Self, CodeError>`、`as_str`、`Display`
  - `pub struct ConnectionCode { account, ip: IpAddr, port: u16, fingerprint }`（字段私有）：`new(AccountName, IpAddr, u16, ServerFingerprint)`、`parse(&str) -> Result<Self, CodeError>`、`account()`、`ip()`、`port()`、`fingerprint()`、`server() -> HostPort`、`Display`、`FromStr`
  - `pub enum CodeError { Prefix, Shape, Account(String), Address(String), Domain(String), Fingerprint, Checksum }`，`Display` 是给界面看的中文，**不含 Gateway/网关**
  - `pub const CODE_PREFIX: &str = "rmc1"`

- [ ] **Step 1: 写下失败的测试**

创建 `crates/rmc-core/src/code.rs`，先写测试模块：

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn fp() -> ServerFingerprint {
        ServerFingerprint::of_ed25519_public(&[7u8; 32])
    }

    fn sample() -> ConnectionCode {
        ConnectionCode::new(
            AccountName::parse("tunnel-zhang").unwrap(),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            22000,
            fp(),
        )
    }

    /// 指纹就是公钥的 SHA-256，base64url、不带填充、43 个字符。
    /// 改红：`of_ed25519_public` 里把 `Sha256::digest(pk)` 换成 `pk.to_vec()`
    /// 或者把 `URL_SAFE_NO_PAD` 换成 `STANDARD`——第一格或第二格红。
    #[test]
    fn fingerprint_is_url_safe_sha256_of_the_public_key() {
        let s = fp().to_string();
        assert_eq!(s.len(), 43, "{s}");
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'), "{s}");
        // 独立算一遍，别只跟自己比。
        use base64::Engine;
        use sha2::{Digest, Sha256};
        let want = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest([7u8; 32]));
        assert_eq!(s, want);
        assert_eq!(ServerFingerprint::parse(&s).unwrap(), fp());
    }

    #[test]
    fn fingerprint_rejects_wrong_length_and_wrong_alphabet() {
        assert!(matches!(ServerFingerprint::parse("abc"), Err(CodeError::Fingerprint)));
        let s = fp().to_string();
        let bad = format!("{}+", &s[..42]); // 标准 base64 的字符
        assert!(matches!(ServerFingerprint::parse(&bad), Err(CodeError::Fingerprint)));
    }

    /// 连接码往返：格式化再解析得到同一个值。
    /// 改红：`Display` 里漏掉任何一段，或者 `parse` 里把 `rsplitn` 的份数改掉。
    #[test]
    fn connection_code_round_trips() {
        let c = sample();
        let s = c.to_string();
        assert!(s.starts_with("rmc1:tunnel-zhang@203.0.113.10:22000:"), "{s}");
        let back = ConnectionCode::parse(&s).unwrap();
        assert_eq!(back, c);
        assert_eq!(back.server(), HostPort::new("203.0.113.10", 22000).unwrap());
    }

    #[test]
    fn ipv6_is_written_in_brackets_and_parses_back() {
        let c = ConnectionCode::new(
            AccountName::parse("a1").unwrap(),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            22000,
            fp(),
        );
        let s = c.to_string();
        assert!(s.contains("@[::1]:22000:"), "{s}");
        assert_eq!(ConnectionCode::parse(&s).unwrap(), c);
    }

    /// 校验位真的在守：改动中间任何一个字符都红。
    /// 改红：`parse` 里把 `if check != expected` 那句删掉——这条第二格绿了。
    #[test]
    fn checksum_catches_a_flipped_character_and_a_truncated_paste() {
        let s = sample().to_string();
        let mut chars: Vec<char> = s.chars().collect();
        // 翻转账号里的一个字符
        let i = s.find("zhang").unwrap();
        chars[i] = 'x';
        let flipped: String = chars.into_iter().collect();
        assert!(matches!(ConnectionCode::parse(&flipped), Err(CodeError::Checksum)), "{flipped}");
        // 粘贴截断：少了最后两位校验
        let truncated = &s[..s.len() - 2];
        assert!(ConnectionCode::parse(truncated).is_err(), "{truncated}");
    }

    /// 只用 IP：域名写进来直接拒绝，而且错误文案说清楚。
    #[test]
    fn a_domain_name_is_refused_with_a_dedicated_error() {
        let s = sample().to_string().replace("203.0.113.10", "ops.example.com");
        // 校验位跟着变，重算一遍再解析，否则先撞到 Checksum。
        let s = recheck(&s);
        match ConnectionCode::parse(&s) {
            Err(CodeError::Domain(d)) => assert_eq!(d, "ops.example.com"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn account_name_charset_is_enforced() {
        assert!(AccountName::parse("tunnel-zhang").is_ok());
        assert!(AccountName::parse("a").is_ok());
        assert!(AccountName::parse("-a").is_err(), "不能以连字符开头");
        assert!(AccountName::parse("Zhang").is_err(), "不许大写");
        assert!(AccountName::parse("zh ang").is_err());
        assert!(AccountName::parse(&"a".repeat(33)).is_err(), "最多 32");
        assert!(AccountName::parse(&"a".repeat(32)).is_ok());
    }

    #[test]
    fn wrong_prefix_and_wrong_shape_are_distinct_errors() {
        assert!(matches!(ConnectionCode::parse("rmc2:a@1.2.3.4:1:x:y"), Err(CodeError::Prefix)));
        assert!(matches!(ConnectionCode::parse("rmc1:nonsense"), Err(CodeError::Shape)));
        assert!(matches!(ConnectionCode::parse(""), Err(CodeError::Prefix)));
    }

    /// 错误文案要给界面看：不能出现 Gateway / 网关。
    #[test]
    fn error_texts_are_ui_safe() {
        let errs = [
            CodeError::Prefix,
            CodeError::Shape,
            CodeError::Account("x".into()),
            CodeError::Address("x".into()),
            CodeError::Domain("x".into()),
            CodeError::Fingerprint,
            CodeError::Checksum,
        ];
        for e in errs {
            let t = e.to_string();
            assert!(crate::wording::banned_word_in(&t).is_none(), "{t}");
            assert!(!t.is_empty());
        }
    }

    /// 把一个改过正文的连接码的校验位重算，测试专用。
    fn recheck(s: &str) -> String {
        let body = &s[..s.rfind(':').unwrap()];
        format!("{body}:{}", checksum(body))
    }
}
```

- [ ] **Step 2: 运行测试确认失败**

```bash
cargo test -p rmc-core --lib code::
```

预期：编译失败，`cannot find type ServerFingerprint`。

- [ ] **Step 3: 写最小实现**

在测试模块之前写入：

```rust
//! 连接码、账号名与运维服务器指纹——客户端与运维服务器两侧共用的协议类型。
//!
//! 连接码 `rmc1:<账号>@<IP>:<端口>:<指纹>:<校验>` 里**没有秘密**：账号名、
//! 地址、指纹都是公开信息，校验位只防粘贴截断与手误。口令单独发。
//!
//! 只接受 IP，不接受域名——运维服务器没有域名（spec §4.2）。

use crate::addr::HostPort;
use base64::Engine;
use sha2::{Digest, Sha256};
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

pub const CODE_PREFIX: &str = "rmc1";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CodeError {
    #[error("这不是连接码：应当以「rmc1:」开头")]
    Prefix,
    #[error("连接码的格式不对：应当是 rmc1:账号@地址:端口:指纹:校验")]
    Shape,
    #[error("账号名不合法：{0}（只能是小写字母、数字与连字符，1-32 位，不能以连字符开头）")]
    Account(String),
    #[error("地址或端口不合法：{0}")]
    Address(String),
    #[error("连接码里只能是 IP 地址，不能是域名：{0}")]
    Domain(String),
    #[error("指纹不合法：应当是 43 个字符")]
    Fingerprint,
    #[error("连接码的校验不符：可能粘贴时被截断或改动了，请重新复制完整的连接码")]
    Checksum,
}

/// 运维服务器的身份指纹：ed25519 公钥 32 字节的 SHA-256。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ServerFingerprint([u8; 32]);

impl ServerFingerprint {
    pub fn of_ed25519_public(pk: &[u8; 32]) -> Self {
        Self(Sha256::digest(pk).into())
    }

    pub fn parse(s: &str) -> Result<Self, CodeError> {
        if s.len() != 43 {
            return Err(CodeError::Fingerprint);
        }
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|_| CodeError::Fingerprint)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| CodeError::Fingerprint)?;
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for ServerFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.0))
    }
}

impl fmt::Debug for ServerFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ServerFingerprint({self})")
    }
}

impl FromStr for ServerFingerprint {
    type Err = CodeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// 隧道账号名：`[a-z0-9][a-z0-9-]{0,31}`。不再要求 `tunnel-` 前缀——账号
/// 不是系统用户了，那个前缀原本是为了跟系统用户区分。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AccountName(String);

impl AccountName {
    pub fn parse(s: &str) -> Result<Self, CodeError> {
        let ok_len = (1..=32).contains(&s.len());
        let ok_first = s.chars().next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
        let ok_rest = s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if ok_len && ok_first && ok_rest {
            Ok(Self(s.to_string()))
        } else {
            Err(CodeError::Account(s.to_string()))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AccountName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// 校验位：正文（到最后一个 `:` 之前）SHA-256 的前 4 个十六进制字符。
pub(crate) fn checksum(body: &str) -> String {
    let d = Sha256::digest(body.as_bytes());
    format!("{:02x}{:02x}", d[0], d[1])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionCode {
    account: AccountName,
    ip: IpAddr,
    port: u16,
    fingerprint: ServerFingerprint,
}

impl ConnectionCode {
    pub fn new(account: AccountName, ip: IpAddr, port: u16, fingerprint: ServerFingerprint) -> Self {
        Self { account, ip, port, fingerprint }
    }

    pub fn parse(s: &str) -> Result<Self, CodeError> {
        let rest = s.strip_prefix(CODE_PREFIX).and_then(|r| r.strip_prefix(':')).ok_or(CodeError::Prefix)?;
        // 从右往左切：校验、指纹都不含 ':'。
        let mut parts = rest.rsplitn(3, ':');
        let check = parts.next().ok_or(CodeError::Shape)?;
        let fp = parts.next().ok_or(CodeError::Shape)?;
        let head = parts.next().ok_or(CodeError::Shape)?; // 账号@地址:端口
        let body_end = s.len() - check.len() - 1;
        if check != checksum(&s[..body_end]) {
            return Err(CodeError::Checksum);
        }
        let fingerprint = ServerFingerprint::parse(fp)?;
        let (account, addr) = head.rsplit_once('@').ok_or(CodeError::Shape)?;
        let account = AccountName::parse(account)?;
        let (host, port) = split_host_port(addr)?;
        let port: u16 = port.parse().ok().filter(|p| *p != 0).ok_or_else(|| CodeError::Address(addr.to_string()))?;
        let ip: IpAddr = host
            .parse()
            .map_err(|_| if host.chars().any(|c| c.is_ascii_alphabetic()) { CodeError::Domain(host.to_string()) } else { CodeError::Address(addr.to_string()) })?;
        Ok(Self { account, ip, port, fingerprint })
    }

    pub fn account(&self) -> &AccountName { &self.account }
    pub fn ip(&self) -> IpAddr { self.ip }
    pub fn port(&self) -> u16 { self.port }
    pub fn fingerprint(&self) -> &ServerFingerprint { &self.fingerprint }

    /// 客户端拨号用的地址。IP 字面量必定通过 `HostPort` 的校验。
    pub fn server(&self) -> HostPort {
        HostPort::new(&self.ip.to_string(), self.port).expect("IP 字面量必定是合法主机")
    }

    fn body(&self) -> String {
        let host = match self.ip {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => format!("[{v6}]"),
        };
        format!("{CODE_PREFIX}:{}@{host}:{}:{}", self.account, self.port, self.fingerprint)
    }
}

/// `[::1]:22000` 或 `203.0.113.10:22000` → (host, port)。
fn split_host_port(addr: &str) -> Result<(&str, &str), CodeError> {
    if let Some(rest) = addr.strip_prefix('[') {
        let (host, port) = rest.split_once("]:").ok_or_else(|| CodeError::Address(addr.to_string()))?;
        return Ok((host, port));
    }
    addr.rsplit_once(':').ok_or_else(|| CodeError::Address(addr.to_string()))
}

impl fmt::Display for ConnectionCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let body = self.body();
        write!(f, "{body}:{}", checksum(&body))
    }
}

impl FromStr for ConnectionCode {
    type Err = CodeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}
```

`lib.rs` 加 `pub mod code;` 与 `pub use code::{AccountName, CodeError, ConnectionCode, ServerFingerprint};`。

注意 `HostPort::new` 的第一个参数类型以 `addr.rs` 里的实际签名为准（`&str`）；`Domain` 判定用"含字母"是刻意粗糙的：IPv6 也含字母，但它走的是方括号分支、先被 `parse` 成功，走不到这里。

- [ ] **Step 4: 运行测试确认通过**

```bash
cargo test -p rmc-core --lib code::
```

预期：9 passed。然后按注释里的「改红」逐条真的改一遍（至少 4 枪：SHA 换成原样、base64 字母表、校验判断删除、`rsplitn` 份数），每枪注入后 `grep -c` 确认、跑、还原、`touch`。

- [ ] **Step 5: 禁用词与闸门**

```bash
cargo test -p rmc-core --lib wording   # code.rs 现在在扫描范围内
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all --check
```

- [ ] **Step 6: 提交**

```bash
git add crates/rmc-core/src/code.rs crates/rmc-core/src/lib.rs
git commit -m "feat(core): 连接码、账号名与运维服务器指纹（两侧共用的协议类型）"
```

---

### Task 2: rmc-gateway 骨架：数据目录、身份密钥、config.toml、`init` 与 `fingerprint`

**Files:**
- Create: `crates/rmc-gateway/Cargo.toml`、`src/lib.rs`、`src/main.rs`、`src/datadir.rs`、`src/identity.rs`、`src/config.rs`、`src/cli.rs`
- Modify: `Cargo.toml`（workspace members 加 `crates/rmc-gateway`）、`deny.toml`（如有必要加许可证；rcgen/yasna 是 MIT OR Apache-2.0，预计不用动）
- Test: 各文件同文件测试模块

**Interfaces:**
- Consumes: Task 1 的 `rmc_core::code::ServerFingerprint`
- Produces:
  - `rmc_gateway::Error`（thiserror）：`Io(std::io::Error)`、`Config(String)`、`Identity(String)`、`Accounts(String)`、`Tls(String)`、`Listen(String)`
  - `datadir::DataDir`：`default_path() -> PathBuf`、`at(PathBuf)`、`create(&self) -> Result<()>`（0700）、`root()`、`identity_key()`、`config()`、`accounts()`、`accounts_lock()`、`status()`、`audit_dir()`；`write_private_atomic(path, bytes) -> io::Result<()>`；`running_as_root() -> bool`；`DataDir::owned_by_current_user(&self) -> io::Result<bool>`
  - `identity::Identity`：`generate()`、`create_in(&DataDir) -> Result<Self>`（已存在则 `Err(Identity(...))`）、`load_from(&DataDir) -> Result<Self>`、`fingerprint() -> ServerFingerprint`、`ssh_host_key() -> russh::keys::PrivateKey`、`tls_server_config() -> Result<Arc<rustls::ServerConfig>>`
  - `config::GatewayConfig { public_addr: SocketAddr, reverse_ports: RangeInclusive<u16> }`：`Default`（22001..=22999，public_addr 必填所以 `Default` 不实现——用 `new(public_addr)`）、`save(&DataDir)`、`load(&DataDir)`
  - `cli::run(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> i32`，本任务实现 `init --public-addr <ip:port> [--data-dir]` 与 `fingerprint [--data-dir]`；未知子命令打印用法、返回 2

- [ ] **Step 1: crate 骨架**

`crates/rmc-gateway/Cargo.toml`：

```toml
[package]
name = "rmc-gateway"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
publish.workspace = true

[dependencies]
rmc-core.workspace = true
tokio.workspace = true
thiserror.workspace = true
zeroize.workspace = true
tracing.workspace = true
rand.workspace = true
# TLS：与 rmc-core 同一套 provider（ring），只开 1.3
rustls = { version = "0.23", default-features = false, features = ["ring", "std"] }
tokio-rustls = { version = "0.26", default-features = false, features = ["ring"] }
rustls-pki-types = { version = "1", default-features = false, features = ["std"] }
# SSH 服务端那一半；client 那一半 rmc-core 已在用，同一个包
russh = { version = "0.63", default-features = false, features = ["ring"] }
# 自签证书。**新增包**：rcgen + yasna（派发前用仓库的 deny.toml 验过）
rcgen = { version = "0.14", default-features = false, features = ["ring"] }
# 口令哈希。argon2 / password-hash 本来就在锁里（russh 的依赖）
argon2 = "0.6"
sha2 = "0.10"
base64 = "0.22"
# 账号与配置文件。**新增包**：toml 及其解析/写出子包
toml = "0.9"
serde = { version = "1", features = ["derive"] }
# status.json 与审计日志。**新增包**：serde_json（连带 itoa/zmij）
serde_json = "1"
# 原子写与「当前用户是否 root / 是否目录属主」的探针都靠它（本来就在锁里）
tempfile = "3"

[features]
# 端到端测试用的 TestGateway / FakeAppliance（Task 11）；不进发布二进制
testing = []

[dev-dependencies]
tempfile = "3"
tokio = { version = "1", features = ["full", "test-util"] }

[lib]
name = "rmc_gateway"
path = "src/lib.rs"

[[bin]]
name = "rmc-gateway"
path = "src/main.rs"
```

根 `Cargo.toml` 的 `members` 加 `"crates/rmc-gateway"`。`rand` 若不在 `[workspace.dependencies]` 里就按 rmc-core 的写法加（它是 0.8）。

`src/lib.rs`：

```rust
#![forbid(unsafe_code)]
//! 运维服务器：一个二进制，只做口令认证与一条反向转发。设计见
//! `docs/superpowers/specs/2026-09-21-rmc-gateway-design.md`。

pub mod cli;
pub mod config;
pub mod datadir;
pub mod identity;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO 错误：{0}")]
    Io(#[from] std::io::Error),
    #[error("配置错误：{0}")]
    Config(String),
    #[error("身份密钥：{0}")]
    Identity(String),
    #[error("账号库：{0}")]
    Accounts(String),
    #[error("TLS：{0}")]
    Tls(String),
    #[error("监听失败：{0}")]
    Listen(String),
}

pub type Result<T> = std::result::Result<T, Error>;
```

`src/main.rs`：

```rust
#![forbid(unsafe_code)]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = rmc_gateway::cli::run(&args, &mut std::io::stdout(), &mut std::io::stderr());
    std::process::exit(code);
}
```

- [ ] **Step 2: datadir.rs 的失败测试**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_override_beats_the_home_default() {
        // 只测纯函数那一层，不动进程环境变量。
        let p = DataDir::path_from(Some(std::ffi::OsString::from("/x/y")), Some(std::ffi::OsString::from("/home/u")));
        assert_eq!(p, PathBuf::from("/x/y"));
        let p = DataDir::path_from(None, Some(std::ffi::OsString::from("/home/u")));
        assert_eq!(p, PathBuf::from("/home/u/.rmc-gateway"));
    }

    /// 改红：`create` 里把 `0o700` 改成 `0o755`。
    #[cfg(unix)]
    #[test]
    fn the_directory_is_created_private() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let d = DataDir::at(tmp.path().join("data"));
        d.create().unwrap();
        let mode = std::fs::metadata(d.root()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "{mode:o}");
    }

    /// 原子写：写完之后目录里没有临时文件残留，内容对，权限 0600。
    /// 改红：`write_private_atomic` 里把 `rename` 换成直接 `fs::write`——第二格
    /// （权限）红；把 `0o600` 改成 `0o644`——同样红。
    #[test]
    fn private_atomic_write_leaves_no_temp_file_and_is_private() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("f");
        write_private_atomic(&p, b"hello").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"hello");
        let names: Vec<_> = std::fs::read_dir(tmp.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names.len(), 1, "{names:?}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
        // 覆盖写也走同一条路
        write_private_atomic(&p, b"again").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"again");
    }

    #[cfg(unix)]
    #[test]
    fn the_test_process_is_not_root_and_owns_its_tempdir() {
        // CI 与开发机都不以 root 跑测试；这条同时是 `running_as_root` 的反向自证。
        let tmp = tempfile::tempdir().unwrap();
        let d = DataDir::at(tmp.path().to_path_buf());
        assert!(d.owned_by_current_user().unwrap());
        assert!(!running_as_root());
    }
}
```

- [ ] **Step 3: datadir.rs 实现**

```rust
//! 数据目录：身份密钥、配置、账号、状态、审计日志都在这里。目录 0700，文件 0600。

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

pub const ENV_DATA_DIR: &str = "RMC_GATEWAY_DATA";

#[derive(Debug, Clone)]
pub struct DataDir {
    root: PathBuf,
}

impl DataDir {
    /// `$RMC_GATEWAY_DATA`，否则 `~/.rmc-gateway`。
    pub fn default_path() -> PathBuf {
        Self::path_from(
            std::env::var_os(ENV_DATA_DIR),
            std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")),
        )
    }

    pub(crate) fn path_from(env: Option<OsString>, home: Option<OsString>) -> PathBuf {
        if let Some(e) = env.filter(|e| !e.is_empty()) {
            return PathBuf::from(e);
        }
        let home = home.filter(|h| !h.is_empty()).unwrap_or_else(|| OsString::from("."));
        PathBuf::from(home).join(".rmc-gateway")
    }

    pub fn at(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn create(&self) -> io::Result<()> {
        std::fs::create_dir_all(&self.root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.root, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }

    pub fn root(&self) -> &Path { &self.root }
    pub fn identity_key(&self) -> PathBuf { self.root.join("identity.key") }
    pub fn config(&self) -> PathBuf { self.root.join("config.toml") }
    pub fn accounts(&self) -> PathBuf { self.root.join("accounts.toml") }
    pub fn accounts_lock(&self) -> PathBuf { self.root.join("accounts.lock") }
    pub fn status(&self) -> PathBuf { self.root.join("status.json") }
    pub fn audit_dir(&self) -> PathBuf { self.root.join("audit") }

    /// 目录属主是不是当前用户。做法不需要 libc：在目录里建一个临时文件
    /// （它的属主必然是当前 euid），比较两者的 uid。
    #[cfg(unix)]
    pub fn owned_by_current_user(&self) -> io::Result<bool> {
        use std::os::unix::fs::MetadataExt;
        let probe = tempfile::NamedTempFile::new_in(&self.root)?;
        let me = probe.as_file().metadata()?.uid();
        Ok(std::fs::metadata(&self.root)?.uid() == me)
    }

    #[cfg(not(unix))]
    pub fn owned_by_current_user(&self) -> io::Result<bool> {
        Ok(true)
    }
}

/// 写临时文件 → 0600 → rename 覆盖。中途失败不留下半截文件。
pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path.parent().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "路径没有父目录"))?;
    let mut tmp = tempfile::Builder::new().prefix(".tmp-").tempfile_in(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file().set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    use std::io::Write;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

/// 当前进程是不是 root。同样不需要 libc：临时文件的属主 uid 为 0 即 root。
#[cfg(unix)]
pub fn running_as_root() -> bool {
    use std::os::unix::fs::MetadataExt;
    tempfile::NamedTempFile::new()
        .and_then(|f| f.as_file().metadata())
        .map(|m| m.uid() == 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
pub fn running_as_root() -> bool {
    false
}
```

`tempfile` 是正常依赖（原子写与属主探针都靠它），不只在测试里用；它本来就在锁里。

- [ ] **Step 4: identity.rs 的失败测试**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// 同一把种子 → SSH host key 与 TLS 证书里的公钥算出同一个指纹。
    /// 改红：`tls_server_config` 里用 `Identity::generate()` 另造一把——第二格红。
    #[test]
    fn ssh_host_key_and_tls_certificate_share_one_fingerprint() {
        let id = Identity::generate();
        let fp = id.fingerprint();
        // SSH 侧
        let hk = id.ssh_host_key();
        let pk = hk.public_key();
        let ed = pk.key_data().ed25519().expect("ed25519");
        assert_eq!(rmc_core::code::ServerFingerprint::of_ed25519_public(&ed.0), fp);
        // TLS 侧：从证书 DER 里取 SPKI
        let (cert, _) = id.tls_cert_and_key().unwrap();
        let parsed = rustls::server::ParsedCertificate::try_from(&cert).unwrap();
        let spki = parsed.subject_public_key_info();
        let der: &[u8] = spki.as_ref();
        assert_eq!(der.len(), 44);
        assert_eq!(&der[..12], &ED25519_SPKI_PREFIX);
        let pk: [u8; 32] = der[12..].try_into().unwrap();
        assert_eq!(rmc_core::code::ServerFingerprint::of_ed25519_public(&pk), fp);
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
        assert_eq!(Identity::load_from(&d).unwrap().fingerprint(), a.fingerprint(), "拒绝覆盖时不能动原文件");
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
                .with_custom_certificate_verifier(std::sync::Arc::new(crate::testing_verifier::AcceptAll))
                .with_no_client_auth();
            let (c, s) = tokio::io::duplex(64 * 1024);
            let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
            let srv = tokio::spawn(async move { acceptor.accept(s).await.map(|_| ()) });
            let r = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client))
                .connect(rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap(), c)
                .await;
            assert!(r.is_err(), "只开 1.3 的服务端不该跟 1.2 客户端握成");
            let _ = srv.await;
        });
    }
}
```

`AcceptAll` 是一个测试专用的"什么都信"的 `ServerCertVerifier`（`verify_tls13_signature` 直接 `assertion()`），放在 `src/testing_verifier.rs`，`#[cfg(test)] mod testing_verifier;`——Task 3 的测试也用它。

- [ ] **Step 5: identity.rs 实现**

```rust
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
            base64::engine::general_purpose::STANDARD.encode(&*id.seed)
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
```

`PrivatePkcs8KeyDer::from(pkcs8.to_vec())` 把种子复制进了一个不会被 zeroize 的 `Vec`——rustls 内部会持有它，这是 TLS 私钥必然的形态，记进文档注释即可。

- [ ] **Step 6: config.rs**

```rust
//! config.toml：对外地址（只用于打印连接码）与反向端口区间。

use crate::datadir::{write_private_atomic, DataDir};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::ops::RangeInclusive;

pub const DEFAULT_LISTEN_PORT: u16 = 22000;
pub const DEFAULT_REVERSE_PORTS: RangeInclusive<u16> = 22001..=22999;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// 写进连接码、客户端实际拨的地址。**不是**监听地址。
    pub public_addr: SocketAddr,
    pub reverse_port_min: u16,
    pub reverse_port_max: u16,
}

impl GatewayConfig {
    pub fn new(public_addr: SocketAddr) -> Self {
        Self {
            public_addr,
            reverse_port_min: *DEFAULT_REVERSE_PORTS.start(),
            reverse_port_max: *DEFAULT_REVERSE_PORTS.end(),
        }
    }

    pub fn reverse_ports(&self) -> RangeInclusive<u16> {
        self.reverse_port_min..=self.reverse_port_max
    }

    pub fn validate(&self) -> Result<()> {
        if self.reverse_port_min == 0 || self.reverse_port_min > self.reverse_port_max {
            return Err(Error::Config(format!(
                "反向端口区间不合法：{}-{}",
                self.reverse_port_min, self.reverse_port_max
            )));
        }
        if self.public_addr.port() == 0 {
            return Err(Error::Config("public_addr 的端口不能是 0".into()));
        }
        Ok(())
    }

    pub fn save(&self, dir: &DataDir) -> Result<()> {
        self.validate()?;
        let text = toml::to_string(self).map_err(|e| Error::Config(e.to_string()))?;
        let text = format!("# 由 rmc-gateway init 生成。public_addr 是写进连接码的对外地址，改了之后用 account list 重新取连接码。\n{text}");
        write_private_atomic(&dir.config(), text.as_bytes())?;
        Ok(())
    }

    pub fn load(dir: &DataDir) -> Result<Self> {
        let text = std::fs::read_to_string(dir.config())
            .map_err(|e| Error::Config(format!("读不到 {}：{e}；先运行 init", dir.config().display())))?;
        let cfg: Self = toml::from_str(&text).map_err(|e| Error::Config(format!("config.toml 解析失败：{e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_then_load_round_trips_and_validates() {
        let tmp = tempfile::tempdir().unwrap();
        let d = DataDir::at(tmp.path().to_path_buf());
        let c = GatewayConfig::new("203.0.113.10:22000".parse().unwrap());
        c.save(&d).unwrap();
        assert_eq!(GatewayConfig::load(&d).unwrap(), c);
        let mut bad = c.clone();
        bad.reverse_port_min = 30000;
        assert!(bad.save(&d).is_err());
    }
}
```

- [ ] **Step 7: cli.rs（本任务只有 init 与 fingerprint）**

```rust
//! 子命令。`run` 是纯函数：收参数与两个输出句柄，返回退出码。测试直接调它。

use crate::config::GatewayConfig;
use crate::datadir::DataDir;
use crate::identity::Identity;
use std::io::Write;
use std::net::SocketAddr;

pub const USAGE: &str = "\
用法：rmc-gateway <子命令> [选项]

  init --public-addr <IP:端口>   生成身份密钥与 config.toml（对外地址写进连接码）
  fingerprint                    打印本机指纹

通用选项：
  --data-dir <目录>              数据目录（默认 $RMC_GATEWAY_DATA，否则 ~/.rmc-gateway）
";

pub(crate) struct Parsed {
    pub cmd: Vec<String>,
    pub opts: Vec<(String, String)>,
}

/// `--k v` 与 `--k=v` 两种写法；不带 `--` 的按顺序进 cmd。
pub(crate) fn parse(args: &[String]) -> Result<Parsed, String> {
    let mut cmd = Vec::new();
    let mut opts = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(k) = a.strip_prefix("--") {
            if let Some((k, v)) = k.split_once('=') {
                opts.push((k.to_string(), v.to_string()));
            } else {
                let v = args.get(i + 1).ok_or_else(|| format!("--{k} 缺少值"))?;
                opts.push((k.to_string(), v.clone()));
                i += 1;
            }
        } else {
            cmd.push(a.clone());
        }
        i += 1;
    }
    Ok(Parsed { cmd, opts })
}

impl Parsed {
    pub fn opt(&self, k: &str) -> Option<&str> {
        self.opts.iter().rev().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    }
    pub fn data_dir(&self) -> DataDir {
        match self.opt("data-dir") {
            Some(p) => DataDir::at(p.into()),
            None => DataDir::at(DataDir::default_path()),
        }
    }
}

pub fn run(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let p = match parse(args) {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(err, "{e}\n{USAGE}");
            return 2;
        }
    };
    match p.cmd.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["init"] => cmd_init(&p, out, err),
        ["fingerprint"] => cmd_fingerprint(&p, out, err),
        _ => {
            let _ = write!(err, "{USAGE}");
            2
        }
    }
}

fn cmd_init(p: &Parsed, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let addr: SocketAddr = match p.opt("public-addr").map(str::parse) {
        Some(Ok(a)) => a,
        Some(Err(e)) => { let _ = writeln!(err, "--public-addr 不是 IP:端口：{e}"); return 2; }
        None => { let _ = writeln!(err, "init 需要 --public-addr <IP:端口>（写进连接码的对外地址）"); return 2; }
    };
    let dir = p.data_dir();
    if let Err(e) = dir.create() { let _ = writeln!(err, "建不了数据目录 {}：{e}", dir.root().display()); return 1; }
    let id = match Identity::create_in(&dir) { Ok(i) => i, Err(e) => { let _ = writeln!(err, "{e}"); return 1; } };
    if let Err(e) = GatewayConfig::new(addr).save(&dir) { let _ = writeln!(err, "{e}"); return 1; }
    let _ = writeln!(out, "数据目录：{}\n指纹：{}\n对外地址：{addr}\n下一步：rmc-gateway account add <账号>，然后 rmc-gateway serve", dir.root().display(), id.fingerprint());
    0
}

fn cmd_fingerprint(p: &Parsed, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    match Identity::load_from(&p.data_dir()) {
        Ok(id) => { let _ = writeln!(out, "{}", id.fingerprint()); 0 }
        Err(e) => { let _ = writeln!(err, "{e}"); 1 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_in(dir: &std::path::Path, args: &[&str]) -> (i32, String, String) {
        let mut a: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        a.push("--data-dir".into());
        a.push(dir.to_string_lossy().into_owned());
        let (mut o, mut e) = (Vec::new(), Vec::new());
        let code = run(&a, &mut o, &mut e);
        (code, String::from_utf8(o).unwrap(), String::from_utf8(e).unwrap())
    }

    #[test]
    fn init_creates_identity_and_config_and_prints_the_fingerprint() {
        let tmp = tempfile::tempdir().unwrap();
        let (code, out, err) = run_in(tmp.path(), &["init", "--public-addr", "203.0.113.10:22000"]);
        assert_eq!(code, 0, "{err}");
        assert!(tmp.path().join("identity.key").exists());
        assert!(tmp.path().join("config.toml").exists());
        let (code2, fp, _) = run_in(tmp.path(), &["fingerprint"]);
        assert_eq!(code2, 0);
        assert!(out.contains(fp.trim()), "init 打印的指纹要跟 fingerprint 一致：{out} / {fp}");
        assert_eq!(fp.trim().len(), 43);
    }

    #[test]
    fn init_twice_refuses_and_keeps_the_first_identity() {
        let tmp = tempfile::tempdir().unwrap();
        run_in(tmp.path(), &["init", "--public-addr", "203.0.113.10:22000"]);
        let (_, fp1, _) = run_in(tmp.path(), &["fingerprint"]);
        let (code, _, err) = run_in(tmp.path(), &["init", "--public-addr", "203.0.113.11:22000"]);
        assert_eq!(code, 1);
        assert!(err.contains("拒绝覆盖"), "{err}");
        let (_, fp2, _) = run_in(tmp.path(), &["fingerprint"]);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn init_without_public_addr_is_a_usage_error() {
        let tmp = tempfile::tempdir().unwrap();
        let (code, _, err) = run_in(tmp.path(), &["init"]);
        assert_eq!(code, 2);
        assert!(err.contains("public-addr"), "{err}");
    }

    #[test]
    fn unknown_subcommand_prints_usage() {
        let (code, _, err) = run_in(std::path::Path::new("."), &["frobnicate"]);
        assert_eq!(code, 2);
        assert!(err.contains("用法"));
    }
}
```

- [ ] **Step 8: 全部跑绿、八道闸门、提交**

```bash
cargo test -p rmc-gateway
cargo zigbuild -p rmc-gateway --tests --target x86_64-pc-windows-gnu   # lib 必须在 Windows 上也能编（Task 11 要用）
cargo deny check advisories bans licenses sources                        # 新包第一次进锁
git add Cargo.toml Cargo.lock crates/rmc-gateway
git commit -m "feat(gateway): crate 骨架、数据目录、身份密钥、config.toml，init 与 fingerprint"
```

变异至少三枪：`0o700`→`0o755`；`tls_server_config` 另造一把密钥；`with_protocol_versions` 加上 TLS12。

---

### Task 3: 账号库：accounts.toml、argon2、端口分配、`account add|passwd|revoke|list`

**Files:**
- Create: `crates/rmc-gateway/src/accounts.rs`
- Modify: `crates/rmc-gateway/src/lib.rs`（`pub mod accounts;`）、`src/cli.rs`（四个子命令 + USAGE）
- Test: `accounts.rs` 与 `cli.rs` 的测试模块

**Interfaces:**
- Consumes: Task 2 的 `DataDir`、`GatewayConfig`、`Identity`（打印连接码要指纹与 public_addr）；Task 1 的 `AccountName`、`ConnectionCode`
- Produces:
  - `accounts::Account { name: AccountName, port: u16, password_hash: String, enabled: bool, created_at_unix: u64, note: String }`（serde，文件形态 `[[account]]`）
  - `accounts::AccountStore`（CLI 侧，改写）：`open(dir: &DataDir, cfg: &GatewayConfig, listen_port: u16) -> Self`；`add(&self, name: &AccountName, port: Option<u16>, note: &str) -> Result<(Account, Zeroizing<String>)>`；`reset_password(&self, name) -> Result<Zeroizing<String>>`；`revoke(&self, name) -> Result<()>`（`enabled=false`，端口保留）；`list(&self) -> Result<Vec<Account>>`
  - `accounts::AccountReader`（服务端侧，只读、按 mtime 缓存）：`new(dir: &DataDir) -> Self`；`verify(&self, name: &str, password: &str) -> Verify`；`is_active(&self, name: &str) -> bool`；`pub enum Verify { Ok { port: u16 }, Rejected }`
  - `accounts::generate_password() -> Zeroizing<String>`（18 字节随机 → base64，24 字符）
  - `accounts::hash_password(&str) -> String` / `verify_hash(&str, &str) -> bool`（argon2id，PHC 字符串）
  - CLI：`account add <name> [--port N] [--note 文字]`、`account passwd <name>`、`account revoke <name>`、`account list`

- [ ] **Step 1: 失败的测试（accounts.rs）**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GatewayConfig;
    use crate::datadir::DataDir;

    fn store(tmp: &tempfile::TempDir) -> AccountStore {
        let d = DataDir::at(tmp.path().to_path_buf());
        d.create().unwrap();
        let mut cfg = GatewayConfig::new("203.0.113.10:22000".parse().unwrap());
        cfg.reverse_port_min = 22001;
        cfg.reverse_port_max = 22003; // 只留三个号，好测「用完了」
        AccountStore::open(&d, &cfg, 22000)
    }
    fn name(s: &str) -> AccountName { AccountName::parse(s).unwrap() }

    /// 加账号：拿到最小空闲端口与一次性口令；口令只以 argon2id 哈希落盘。
    /// 改红：`add` 里把 `hash_password(&pw)` 换成 `pw.to_string()`——第三格红。
    #[test]
    fn add_allocates_the_lowest_free_port_and_stores_only_a_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp);
        let (a, pw) = s.add(&name("zhang"), None, "张三").unwrap();
        assert_eq!(a.port, 22001);
        assert_eq!(pw.len(), 24);
        let text = std::fs::read_to_string(tmp.path().join("accounts.toml")).unwrap();
        assert!(!text.contains(pw.as_str()), "口令明文进了文件");
        assert!(text.contains("$argon2id$"), "{text}");
        let (b, _) = s.add(&name("li"), None, "").unwrap();
        assert_eq!(b.port, 22002);
    }

    #[test]
    fn explicit_port_must_be_free_in_range_and_not_the_listen_port() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp);
        assert!(s.add(&name("a"), Some(22000), "").is_err(), "监听端口");
        assert!(s.add(&name("a"), Some(22004), "").is_err(), "区间外");
        s.add(&name("a"), Some(22003), "").unwrap();
        assert!(s.add(&name("b"), Some(22003), "").is_err(), "被占");
        assert!(s.add(&name("a"), None, "").is_err(), "重名");
    }

    #[test]
    fn range_exhaustion_is_an_error_not_a_panic() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp);
        for n in ["a", "b", "c"] { s.add(&name(n), None, "").unwrap(); }
        let e = s.add(&name("d"), None, "").unwrap_err();
        assert!(e.to_string().contains("用完"), "{e}");
    }

    /// 服务端读取：对的口令给端口；错的、停用的、不存在的一律 Rejected。
    /// 改红：`verify` 里把 `enabled` 判断删掉——第三格绿。
    #[test]
    fn reader_verifies_password_and_respects_revocation() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp);
        let (_, pw) = s.add(&name("zhang"), None, "").unwrap();
        let r = AccountReader::new(&DataDir::at(tmp.path().to_path_buf()));
        assert_eq!(r.verify("zhang", pw.as_str()), Verify::Ok { port: 22001 });
        assert_eq!(r.verify("zhang", "wrong"), Verify::Rejected);
        assert_eq!(r.verify("nobody", pw.as_str()), Verify::Rejected);
        s.revoke(&name("zhang")).unwrap();
        assert_eq!(r.verify("zhang", pw.as_str()), Verify::Rejected, "吊销后必须拒");
        assert!(!r.is_active("zhang"));
    }

    /// 「账号不存在」与「口令错」在耗时上不可区分：两者都要跑一次 argon2。
    /// 改红：`verify` 里对 `None` 分支直接 `return Verify::Rejected`——第二格红
    /// （不存在的账号快一个数量级）。
    #[test]
    fn unknown_account_costs_the_same_as_a_wrong_password() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp);
        s.add(&name("zhang"), None, "").unwrap();
        let r = AccountReader::new(&DataDir::at(tmp.path().to_path_buf()));
        let t = |f: &dyn Fn()| { let t0 = std::time::Instant::now(); for _ in 0..3 { f(); } t0.elapsed() };
        let wrong = t(&|| { r.verify("zhang", "wrong"); });
        let unknown = t(&|| { r.verify("nobody", "wrong"); });
        // argon2 默认参数一次约 20-60ms；不存在的账号若不跑哈希会是微秒级。
        assert!(unknown.as_secs_f64() > wrong.as_secs_f64() * 0.3, "不存在的账号太快了：{unknown:?} vs {wrong:?}");
    }

    #[test]
    fn reset_password_changes_the_hash_and_revoke_keeps_the_port() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp);
        let (a, pw1) = s.add(&name("zhang"), None, "").unwrap();
        let pw2 = s.reset_password(&name("zhang")).unwrap();
        assert_ne!(pw1.as_str(), pw2.as_str());
        let r = AccountReader::new(&DataDir::at(tmp.path().to_path_buf()));
        assert_eq!(r.verify("zhang", pw1.as_str()), Verify::Rejected);
        assert_eq!(r.verify("zhang", pw2.as_str()), Verify::Ok { port: a.port });
        s.revoke(&name("zhang")).unwrap();
        let listed = s.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert!(!listed[0].enabled);
        assert_eq!(listed[0].port, a.port, "吊销后端口保留，不让别人顶上");
        assert!(s.add(&name("li"), Some(a.port), "").is_err());
    }

    /// 并发改写不丢更新：两个线程各加一个账号，最后两个都在。
    /// 改红：`with_lock` 里把 `file.lock()` 删掉——这条会间歇性红（跑十遍）。
    #[test]
    fn concurrent_adds_do_not_lose_each_other() {
        let tmp = tempfile::tempdir().unwrap();
        let s1 = store(&tmp);
        let d = DataDir::at(tmp.path().to_path_buf());
        let mut cfg = GatewayConfig::new("203.0.113.10:22000".parse().unwrap());
        cfg.reverse_port_max = 22999;
        let s2 = AccountStore::open(&d, &cfg, 22000);
        let h = std::thread::spawn(move || { for i in 0..20 { s2.add(&name(&format!("b{i}")), None, "").unwrap(); } });
        for i in 0..20 { s1.add(&name(&format!("a{i}")), None, "").unwrap(); }
        h.join().unwrap();
        assert_eq!(s1.list().unwrap().len(), 40);
        let ports: std::collections::HashSet<u16> = s1.list().unwrap().iter().map(|a| a.port).collect();
        assert_eq!(ports.len(), 40, "端口撞了");
    }
}
```

- [ ] **Step 2: 实现 accounts.rs**

```rust
//! accounts.toml：账号、端口、口令的 argon2id 哈希、是否启用。
//! CLI 改写它（`AccountStore`，写临时文件 + rename，用 `accounts.lock` 串行化），
//! 服务端只读它（`AccountReader`，按 mtime 缓存）。没有 IPC。

use crate::datadir::{write_private_atomic, DataDir};
use crate::{Error, Result};
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use base64::Engine;
use rmc_core::code::AccountName;
use serde::{Deserialize, Serialize};
use std::ops::RangeInclusive;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::SystemTime;
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    #[serde(with = "account_name_serde")]
    pub name: AccountName,
    pub port: u16,
    pub password_hash: String,
    pub enabled: bool,
    pub created_at_unix: u64,
    #[serde(default)]
    pub note: String,
}

mod account_name_serde {
    use rmc_core::code::AccountName;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(n: &AccountName, s: S) -> Result<S::Ok, S::Error> {
        n.as_str().serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<AccountName, D::Error> {
        let s = String::deserialize(d)?;
        AccountName::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct File {
    #[serde(default, rename = "account")]
    accounts: Vec<Account>,
}

pub fn generate_password() -> Zeroizing<String> {
    use rand::RngCore;
    let mut bytes = Zeroizing::new([0u8; 18]);
    rand::rngs::OsRng.fill_bytes(&mut *bytes);
    Zeroizing::new(base64::engine::general_purpose::STANDARD_NO_PAD.encode(&*bytes))
}

pub fn hash_password(pw: &str) -> String {
    argon2::Argon2::default()
        .hash_password(pw.as_bytes())
        .expect("argon2 默认参数不会失败")
        .to_string()
}

pub fn verify_hash(pw: &str, phc: &str) -> bool {
    let Ok(parsed) = argon2::password_hash::phc::PasswordHash::new(phc) else { return false };
    argon2::Argon2::default().verify_password(pw.as_bytes(), &parsed).is_ok()
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn read_file(path: &PathBuf) -> Result<File> {
    match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text).map_err(|e| Error::Accounts(format!("{} 解析失败：{e}", path.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(File::default()),
        Err(e) => Err(Error::Accounts(format!("读 {} 失败：{e}", path.display()))),
    }
}

// ---------------------------------------------------------------- CLI 侧

pub struct AccountStore {
    dir: DataDir,
    ports: RangeInclusive<u16>,
    listen_port: u16,
}

impl AccountStore {
    pub fn open(dir: &DataDir, cfg: &crate::config::GatewayConfig, listen_port: u16) -> Self {
        Self { dir: dir.clone(), ports: cfg.reverse_ports(), listen_port }
    }

    /// 持锁读-改-写。`std::fs::File::lock` 是 1.89 稳定的 API，进程退出自动释放。
    fn with_lock<T>(&self, f: impl FnOnce(&mut File) -> Result<T>) -> Result<T> {
        let lock = std::fs::File::create(self.dir.accounts_lock())?;
        lock.lock()?;
        let path = self.dir.accounts();
        let mut file = read_file(&path)?;
        let out = f(&mut file)?;
        let text = toml::to_string(&file).map_err(|e| Error::Accounts(e.to_string()))?;
        write_private_atomic(&path, text.as_bytes())?;
        Ok(out)
    }

    pub fn add(&self, name: &AccountName, port: Option<u16>, note: &str) -> Result<(Account, Zeroizing<String>)> {
        let pw = generate_password();
        let hash = hash_password(&pw);
        let ports = self.ports.clone();
        let listen = self.listen_port;
        let acc = self.with_lock(|file| {
            if file.accounts.iter().any(|a| &a.name == name) {
                return Err(Error::Accounts(format!("账号 {name} 已存在（吊销过的账号名不能复用，换一个名字）")));
            }
            let used: std::collections::HashSet<u16> = file.accounts.iter().map(|a| a.port).collect();
            let port = match port {
                Some(p) => {
                    if p == listen { return Err(Error::Accounts(format!("{p} 是监听端口，不能给账号"))); }
                    if !ports.contains(&p) { return Err(Error::Accounts(format!("{p} 不在反向端口区间 {}-{} 内", ports.start(), ports.end()))); }
                    if used.contains(&p) { return Err(Error::Accounts(format!("端口 {p} 已被别的账号占用"))); }
                    p
                }
                None => ports.clone().find(|p| *p != listen && !used.contains(p))
                    .ok_or_else(|| Error::Accounts(format!("反向端口区间 {}-{} 已经用完", ports.start(), ports.end())))?,
            };
            let acc = Account { name: name.clone(), port, password_hash: hash.clone(), enabled: true, created_at_unix: now_unix(), note: note.to_string() };
            file.accounts.push(acc.clone());
            Ok(acc)
        })?;
        Ok((acc, pw))
    }

    pub fn reset_password(&self, name: &AccountName) -> Result<Zeroizing<String>> {
        let pw = generate_password();
        let hash = hash_password(&pw);
        self.with_lock(|file| {
            let a = file.accounts.iter_mut().find(|a| &a.name == name)
                .ok_or_else(|| Error::Accounts(format!("没有账号 {name}")))?;
            a.password_hash = hash.clone();
            Ok(())
        })?;
        Ok(pw)
    }

    pub fn revoke(&self, name: &AccountName) -> Result<()> {
        self.with_lock(|file| {
            let a = file.accounts.iter_mut().find(|a| &a.name == name)
                .ok_or_else(|| Error::Accounts(format!("没有账号 {name}")))?;
            a.enabled = false;
            Ok(())
        })
    }

    pub fn list(&self) -> Result<Vec<Account>> {
        Ok(read_file(&self.dir.accounts())?.accounts)
    }
}

// ---------------------------------------------------------------- 服务端侧

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verify {
    Ok { port: u16 },
    Rejected,
}

pub struct AccountReader {
    path: PathBuf,
    /// (mtime, len) → 上次解析结果
    cache: Mutex<Option<((SystemTime, u64), std::sync::Arc<Vec<Account>>)>>,
    /// 账号不存在时也跑一次同样代价的校验
    dummy_hash: String,
}

impl AccountReader {
    pub fn new(dir: &DataDir) -> Self {
        Self {
            path: dir.accounts(),
            cache: Mutex::new(None),
            dummy_hash: hash_password(&generate_password()),
        }
    }

    fn snapshot(&self) -> std::sync::Arc<Vec<Account>> {
        let stamp = std::fs::metadata(&self.path).ok().and_then(|m| Some((m.modified().ok()?, m.len())));
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let (Some(stamp), Some((old, list))) = (stamp, cache.as_ref()) {
            if *old == stamp { return list.clone(); }
        }
        let list = std::sync::Arc::new(read_file(&self.path).map(|f| f.accounts).unwrap_or_default());
        if let Some(stamp) = stamp { *cache = Some((stamp, list.clone())); }
        list
    }

    pub fn verify(&self, name: &str, password: &str) -> Verify {
        let list = self.snapshot();
        match list.iter().find(|a| a.name.as_str() == name && a.enabled) {
            Some(a) if verify_hash(password, &a.password_hash) => Verify::Ok { port: a.port },
            Some(_) => Verify::Rejected,
            None => {
                // 同样的代价，同样的答案。
                let _ = verify_hash(password, &self.dummy_hash);
                Verify::Rejected
            }
        }
    }

    pub fn is_active(&self, name: &str) -> bool {
        self.snapshot().iter().any(|a| a.name.as_str() == name && a.enabled)
    }
}
```

**mtime 缓存的一个坑**：同一秒内两次改写、文件长度又相同，缓存会漏掉。`(mtime, len)` 已把「长度相同」这一半堵住一半；改口令哈希（同长）在同一秒内两次——只有测试会这么做，测试里用 `reset_password` 后先 `verify` 一次再改。把这条写进 `snapshot` 的注释。

- [ ] **Step 3: CLI 四个子命令**

`cli.rs` 的 `run` 里加：

```rust
        ["account", "add", name] => cmd_account_add(&p, name, out, err),
        ["account", "passwd", name] => cmd_account_passwd(&p, name, out, err),
        ["account", "revoke", name] => cmd_account_revoke(&p, name, out, err),
        ["account", "list"] => cmd_account_list(&p, out, err),
```

公共装载：

```rust
struct Loaded { dir: DataDir, cfg: GatewayConfig, id: Identity }
fn load(p: &Parsed, err: &mut dyn Write) -> Option<Loaded> {
    let dir = p.data_dir();
    let cfg = match GatewayConfig::load(&dir) { Ok(c) => c, Err(e) => { let _ = writeln!(err, "{e}"); return None; } };
    let id = match Identity::load_from(&dir) { Ok(i) => i, Err(e) => { let _ = writeln!(err, "{e}"); return None; } };
    Some(Loaded { dir, cfg, id })
}
fn code_for(l: &Loaded, a: &crate::accounts::Account) -> rmc_core::code::ConnectionCode {
    rmc_core::code::ConnectionCode::new(a.name.clone(), l.cfg.public_addr.ip(), l.cfg.public_addr.port(), l.id.fingerprint())
}
fn listen_port(p: &Parsed) -> u16 {
    p.opt("listen").and_then(|s| s.parse::<std::net::SocketAddr>().ok()).map(|a| a.port()).unwrap_or(crate::config::DEFAULT_LISTEN_PORT)
}
```

`account add` 的输出**照 spec §4.2 的样子**：

```rust
fn cmd_account_add(p: &Parsed, name: &str, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let Some(l) = load(p, err) else { return 1 };
    let name = match rmc_core::code::AccountName::parse(name) { Ok(n) => n, Err(e) => { let _ = writeln!(err, "{e}"); return 2; } };
    let port = match p.opt("port").map(str::parse::<u16>) { Some(Ok(v)) => Some(v), Some(Err(_)) => { let _ = writeln!(err, "--port 不是端口号"); return 2; } None => None };
    let store = crate::accounts::AccountStore::open(&l.dir, &l.cfg, listen_port(p));
    match store.add(&name, port, p.opt("note").unwrap_or("")) {
        Ok((a, pw)) => {
            let _ = writeln!(out, "账号 {} 已开通，端口 {}。", a.name, a.port);
            let _ = writeln!(out, "连接码：  {}", code_for(&l, &a));
            let _ = writeln!(out, "初始口令：{}      （只显示这一次）", pw.as_str());
            let _ = writeln!(out, "远程工程师：ssh -p {} root@{}", a.port, l.cfg.public_addr.ip());
            0
        }
        Err(e) => { let _ = writeln!(err, "{e}"); 1 }
    }
}
```

`passwd` 打印新口令（只显示一次）；`revoke` 打印「已吊销，最迟 10 秒内踢掉在线会话；端口 N 保留」；`list` 每行 `名字  端口  启用/已吊销  备注`，随后每个账号一行连接码。USAGE 同步补全。

CLI 测试（`cli.rs`）：

```rust
    #[test]
    fn account_add_prints_a_parsable_connection_code_and_a_password_once() {
        let tmp = tempfile::tempdir().unwrap();
        run_in(tmp.path(), &["init", "--public-addr", "203.0.113.10:22000"]);
        let (code, out, err) = run_in(tmp.path(), &["account", "add", "zhang", "--note", "张三"]);
        assert_eq!(code, 0, "{err}");
        let line = out.lines().find(|l| l.starts_with("连接码：")).expect("要有连接码");
        let cc = line.trim_start_matches("连接码：").trim();
        let parsed = rmc_core::code::ConnectionCode::parse(cc).expect("连接码要能被客户端解析");
        assert_eq!(parsed.account().as_str(), "zhang");
        assert_eq!(parsed.port(), 22000);
        let (_, fp, _) = run_in(tmp.path(), &["fingerprint"]);
        assert_eq!(parsed.fingerprint().to_string(), fp.trim());
        assert!(out.contains("初始口令："));
        // list 里重取的连接码一字不差
        let (_, listed, _) = run_in(tmp.path(), &["account", "list"]);
        assert!(listed.contains(cc), "{listed}");
        assert!(!listed.contains("初始口令"), "list 不能再打印口令");
    }

    #[test]
    fn account_commands_before_init_fail_with_a_hint() {
        let tmp = tempfile::tempdir().unwrap();
        let (code, _, err) = run_in(tmp.path(), &["account", "add", "zhang"]);
        assert_eq!(code, 1);
        assert!(err.contains("init"), "{err}");
    }
```

- [ ] **Step 4: 跑绿、变异、闸门、提交**

```bash
cargo test -p rmc-gateway
```

变异至少四枪（每条测试注释里那句），外加 `concurrent_adds_do_not_lose_each_other` 去掉 `lock()` 后连跑十遍看是否间歇红。

```bash
git add crates/rmc-gateway
git commit -m "feat(gateway): 账号库——accounts.toml、argon2id、端口分配、account 四个子命令"
```

---

### Task 4: 接入层：TLS 1.3 监听 + russh 服务端 + 只认口令 + 拒绝一切其它请求

**Files:**
- Create: `crates/rmc-gateway/src/server.rs`、`src/testing_verifier.rs`（`#[cfg(test)]`，Task 2 已建则补充）
- Modify: `src/lib.rs`（`pub mod server;`）
- Test: `server.rs` 测试模块（用 russh **客户端**直接打服务端，不经 rmc-core）

**Interfaces:**
- Consumes: Task 2 的 `Identity`（`tls_server_config()`、`ssh_host_key()`、`fingerprint()`）、`DataDir`；Task 3 的 `AccountReader`
- Produces（Task 5/6/7 在同一个文件上加东西）:
  - `server::Timings { keepalive: Duration, keepalive_max: usize, sweep: Duration, handshake: Duration, max_engineers_per_tunnel: usize }`，`Default` = 10s / 3 / 10s / 20s / 16；`Timings::fast()`（测试用：200ms / 3 / 200ms / 500ms / 16）
  - `server::ServerConfig { listen: SocketAddr, data: DataDir, reverse_bind: IpAddr, timings: Timings }`（Task 5 再加 `engineer_allow: Vec<cidr::Cidr>`）
  - `server::Server::bind(cfg: ServerConfig) -> Result<Running>`
  - `server::Running`：`local_addr() -> SocketAddr`、`fingerprint() -> ServerFingerprint`、`shutdown(self)`（async）
  - 内部：`Shared`（identity、TlsAcceptor、`Arc<russh::server::Config>`、`AccountReader`、timings）、`ConnHandler`（每条连接一个）

- [ ] **Step 1: 失败的测试**

`src/testing_verifier.rs`（`#[cfg(test)]`）：

```rust
//! 测试专用：什么证书都信的 TLS 验证器，以及什么 host key 都信的 SSH 处理器。
//! **只在 rmc-gateway 自己的测试里用**——指纹核对是客户端（rmc-core）的事，在那边测。
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

#[derive(Debug)]
pub struct AcceptAll;

impl ServerCertVerifier for AcceptAll {
    fn verify_server_cert(&self, _e: &CertificateDer<'_>, _i: &[CertificateDer<'_>], _n: &ServerName<'_>, _o: &[u8], _t: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _m: &[u8], _c: &CertificateDer<'_>, _d: &rustls::DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("测试客户端不做 1.2".into()))
    }
    fn verify_tls13_signature(&self, _m: &[u8], _c: &CertificateDer<'_>, _d: &rustls::DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

pub struct AnyHostKey;
impl russh::client::Handler for AnyHostKey {
    type Error = russh::Error;
    async fn check_server_key(&mut self, _k: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// TLS（1.3、AcceptAll）+ SSH 握手，返回还没认证的会话。
pub async fn ssh_connect(addr: std::net::SocketAddr) -> russh::client::Handle<AnyHostKey> {
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let tls_cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13]).unwrap()
        .dangerous().with_custom_certificate_verifier(std::sync::Arc::new(AcceptAll)).with_no_client_auth();
    let sock = tokio::net::TcpStream::connect(addr).await.expect("TCP");
    let tls = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls_cfg))
        .connect(rustls::pki_types::ServerName::try_from(addr.ip().to_string()).unwrap(), sock).await.expect("TLS");
    let cfg = std::sync::Arc::new(russh::client::Config { inactivity_timeout: None, ..Default::default() });
    russh::client::connect_stream(cfg, tls, AnyHostKey).await.expect("SSH 握手")
}
```

`server.rs` 的测试模块：

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::AccountStore;
    use crate::config::GatewayConfig;
    use crate::datadir::DataDir;
    use crate::identity::Identity;
    use crate::testing_verifier::ssh_connect;
    use rmc_core::code::AccountName;
    use std::time::Duration;

    /// 一个带一个账号的服务端。返回 (running, 口令, 临时目录)。
    pub(crate) async fn server_with_account(name: &str) -> (Running, zeroize::Zeroizing<String>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let d = DataDir::at(tmp.path().to_path_buf());
        d.create().unwrap();
        Identity::create_in(&d).unwrap();
        let mut cfg = GatewayConfig::new("127.0.0.1:22000".parse().unwrap());
        // 测试里的反向端口由操作系统挑：区间给大，账号加时用 --port 传一个刚探到的空闲号
        cfg.reverse_port_min = 20000;
        cfg.reverse_port_max = 60000;
        cfg.save(&d).unwrap();
        let store = AccountStore::open(&d, &cfg, 22000);
        let free = { let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap(); l.local_addr().unwrap().port() };
        let (_, pw) = store.add(&AccountName::parse(name).unwrap(), Some(free), "").unwrap();
        let running = Server::bind(ServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            data: d,
            reverse_bind: "127.0.0.1".parse().unwrap(),
            timings: Timings::fast(),
        }).await.unwrap();
        (running, pw, tmp)
    }

    async fn within<T>(what: &str, f: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(20), f).await.unwrap_or_else(|_| panic!("{what} 超时"))
    }

    /// 改红：`auth_password` 里不看 `verify` 的结果、一律 `Accept`——第二、三格红。
    #[tokio::test]
    async fn password_auth_accepts_the_live_account_and_rejects_everything_else() {
        let (srv, pw, _tmp) = server_with_account("zhang").await;
        let mut s = within("connect", ssh_connect(srv.local_addr())).await;
        assert!(!s.authenticate_password("zhang", "wrong").await.unwrap().success());
        assert!(!s.authenticate_password("nobody", pw.as_str()).await.unwrap().success());
        assert!(s.authenticate_password("zhang", pw.as_str()).await.unwrap().success());
        srv.shutdown().await;
    }

    /// 服务端只登记 password 一种方法。改红：`methods` 用 `MethodSet::server_supported()`。
    #[tokio::test]
    async fn only_password_is_advertised() {
        let (srv, _pw, _tmp) = server_with_account("zhang").await;
        let mut s = within("connect", ssh_connect(srv.local_addr())).await;
        match s.authenticate_none("zhang").await.unwrap() {
            russh::client::AuthResult::Failure { remaining_methods, .. } => {
                assert_eq!(remaining_methods, russh::MethodSet::from(&[russh::MethodKind::Password][..]));
            }
            other => panic!("none 认证不该成功：{other:?}"),
        }
        srv.shutdown().await;
    }

    /// 认证之后，session 通道与正向转发都被拒——服务端根本没实现它们。
    /// 改红：给 `ConnHandler` 实现 `channel_open_session` 并 `reply.accept()`——第一格红。
    #[tokio::test]
    async fn session_and_direct_tcpip_channels_are_refused_after_auth() {
        let (srv, pw, _tmp) = server_with_account("zhang").await;
        let mut s = within("connect", ssh_connect(srv.local_addr())).await;
        assert!(s.authenticate_password("zhang", pw.as_str()).await.unwrap().success());
        assert!(s.channel_open_session().await.is_err(), "session 通道必须被拒");
        assert!(s.channel_open_direct_tcpip("127.0.0.1", 22, "127.0.0.1", 1).await.is_err(), "正向转发必须被拒");
        // 本任务还没实现反向转发，也必须被拒（Task 5 才开这一条路）
        assert!(s.tcpip_forward("", 0).await.is_err());
        srv.shutdown().await;
    }

    /// 三次口令失败后服务端断开。改红：`max_auth_attempts` 改回默认的 10。
    #[tokio::test]
    async fn three_failures_end_the_connection() {
        let (srv, _pw, _tmp) = server_with_account("zhang").await;
        let mut s = within("connect", ssh_connect(srv.local_addr())).await;
        for _ in 0..3 { let _ = s.authenticate_password("zhang", "wrong").await; }
        let r = within("第四次", s.authenticate_password("zhang", "wrong")).await;
        assert!(r.is_err() || s.is_closed(), "三次之后连接应当被服务端断开：{r:?}");
        srv.shutdown().await;
    }

    /// 只连 TCP、什么都不发：到期被服务端关掉。改红：`handle_connection` 里把
    /// `deadline` 那一支删掉——这条超时红。
    #[tokio::test]
    async fn an_idle_unauthenticated_connection_is_closed_at_the_deadline() {
        use tokio::io::AsyncReadExt;
        let (srv, _pw, _tmp) = server_with_account("zhang").await;
        let mut sock = tokio::net::TcpStream::connect(srv.local_addr()).await.unwrap();
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf)).await.expect("服务端 500ms 内该关掉它").unwrap();
        assert_eq!(n, 0, "应当读到 EOF");
        srv.shutdown().await;
    }

    /// TLS 握手成功但 SSH 认证迟迟不来：同样到期关掉（同一个 deadline 管两段）。
    #[tokio::test]
    async fn tls_ok_but_no_auth_is_also_closed_at_the_deadline() {
        let (srv, _pw, _tmp) = server_with_account("zhang").await;
        let s = within("connect", ssh_connect(srv.local_addr())).await;
        tokio::time::sleep(Duration::from_millis(900)).await;
        assert!(s.is_closed(), "500ms 没认证，服务端该断开");
        srv.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_stops_accepting() {
        let (srv, _pw, _tmp) = server_with_account("zhang").await;
        let addr = srv.local_addr();
        srv.shutdown().await;
        assert!(tokio::net::TcpStream::connect(addr).await.is_err());
    }
}
```

- [ ] **Step 2: 实现**

```rust
//! 接入层：TLS 1.3 → russh 服务端 → 口令认证。只实现口令认证与（Task 5 的）一条反向转发；
//! 其余请求 russh 默认拒绝——`ChannelOpenHandle` 被丢弃即回 AdministrativelyProhibited。

use crate::accounts::{AccountReader, Verify};
use crate::datadir::DataDir;
use crate::identity::Identity;
use crate::{Error, Result};
use rmc_core::code::{AccountName, ServerFingerprint};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinSet;
use zeroize::Zeroizing;

#[derive(Debug, Clone)]
pub struct Timings {
    pub keepalive: Duration,
    pub keepalive_max: usize,
    pub sweep: Duration,
    pub handshake: Duration,
    pub max_engineers_per_tunnel: usize,
}

impl Default for Timings {
    fn default() -> Self {
        Self { keepalive: Duration::from_secs(10), keepalive_max: 3, sweep: Duration::from_secs(10), handshake: Duration::from_secs(20), max_engineers_per_tunnel: 16 }
    }
}

impl Timings {
    /// 测试用：把秒改成几百毫秒，别的不变。
    pub fn fast() -> Self {
        Self { keepalive: Duration::from_millis(200), keepalive_max: 3, sweep: Duration::from_millis(200), handshake: Duration::from_millis(500), max_engineers_per_tunnel: 16 }
    }
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub data: DataDir,
    /// 反向端口绑在哪个地址上：生产 0.0.0.0，测试 127.0.0.1。
    pub reverse_bind: IpAddr,
    pub timings: Timings,
}

pub(crate) struct Shared {
    pub identity: Identity,
    pub tls: tokio_rustls::TlsAcceptor,
    pub ssh: Arc<russh::server::Config>,
    pub accounts: AccountReader,
    pub reverse_bind: IpAddr,
    pub timings: Timings,
}

pub struct Server;

pub struct Running {
    local_addr: SocketAddr,
    fingerprint: ServerFingerprint,
    stop: watch::Sender<bool>,
    accept_task: tokio::task::JoinHandle<()>,
}

impl Running {
    pub fn local_addr(&self) -> SocketAddr { self.local_addr }
    pub fn fingerprint(&self) -> ServerFingerprint { self.fingerprint }
    pub async fn shutdown(self) {
        let _ = self.stop.send(true);
        self.accept_task.abort();
        let _ = self.accept_task.await;
    }
}

impl Server {
    pub async fn bind(cfg: ServerConfig) -> Result<Running> {
        let identity = Identity::load_from(&cfg.data)?;
        let fingerprint = identity.fingerprint();
        let tls = tokio_rustls::TlsAcceptor::from(identity.tls_server_config()?);
        let ssh = Arc::new(russh::server::Config {
            keys: vec![identity.ssh_host_key()],
            methods: russh::MethodSet::from(&[russh::MethodKind::Password][..]),
            max_auth_attempts: 3,
            auth_rejection_time: Duration::from_secs(1),
            inactivity_timeout: None,
            keepalive_interval: Some(cfg.timings.keepalive),
            keepalive_max: cfg.timings.keepalive_max,
            nodelay: true,
            ..Default::default()
        });
        let shared = Arc::new(Shared {
            identity,
            tls,
            ssh,
            accounts: AccountReader::new(&cfg.data),
            reverse_bind: cfg.reverse_bind,
            timings: cfg.timings.clone(),
        });
        let listener = tokio::net::TcpListener::bind(cfg.listen)
            .await
            .map_err(|e| Error::Listen(format!("{}：{e}", cfg.listen)))?;
        let local_addr = listener.local_addr()?;
        let (stop, mut stop_rx) = watch::channel(false);
        let accept_task = tokio::spawn(async move {
            let mut conns = JoinSet::new();
            loop {
                tokio::select! {
                    _ = stop_rx.changed() => break,
                    accepted = listener.accept() => match accepted {
                        Ok((sock, peer)) => { conns.spawn(handle_connection(shared.clone(), sock, peer)); }
                        Err(e) => { tracing::warn!(error = %e, "accept 失败"); tokio::time::sleep(Duration::from_millis(50)).await; }
                    },
                    Some(_) = conns.join_next(), if !conns.is_empty() => {}
                }
            }
            conns.abort_all();
        });
        Ok(Running { local_addr, fingerprint, stop, accept_task })
    }
}

/// 一条连接的全程：TLS 握手 + SSH 认证必须在 `handshake` 内完成，否则直接关掉。
async fn handle_connection(shared: Arc<Shared>, sock: tokio::net::TcpStream, peer: SocketAddr) {
    let started = tokio::time::Instant::now();
    let deadline = tokio::time::sleep_until(started + shared.timings.handshake);
    tokio::pin!(deadline);
    let _ = sock.set_nodelay(true);
    let tls = tokio::select! {
        r = shared.tls.accept(sock) => match r { Ok(t) => t, Err(e) => { tracing::debug!(%peer, error = %e, "TLS 握手失败"); return; } },
        _ = &mut deadline => { tracing::info!(%peer, "TLS 握手超时"); return; }
    };
    let authed = Arc::new(AtomicBool::new(false));
    let handler = ConnHandler { shared: shared.clone(), peer, authed: authed.clone(), account: None };
    let running = tokio::select! {
        r = russh::server::run_stream(shared.ssh.clone(), tls, handler) => match r { Ok(s) => s, Err(e) => { tracing::debug!(%peer, error = %e, "SSH 握手失败"); return; } },
        _ = &mut deadline => { tracing::info!(%peer, "SSH 握手超时"); return; }
    };
    tokio::pin!(running);
    loop {
        tokio::select! {
            r = &mut running => { if let Err(e) = r { tracing::debug!(%peer, error = %e, "会话结束"); } return; }
            _ = &mut deadline, if !authed.load(Ordering::SeqCst) => { tracing::info!(%peer, "认证超时，断开"); return; }
        }
    }
}

pub(crate) struct ConnHandler {
    pub shared: Arc<Shared>,
    pub peer: SocketAddr,
    pub authed: Arc<AtomicBool>,
    pub account: Option<(AccountName, u16)>,
}

impl russh::server::Handler for ConnHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> std::result::Result<russh::server::Auth, Self::Error> {
        // 账号名先按字符集校验：不合法直接拒，不跑哈希（字符集是公开规则，不泄露账号存在性）。
        let Ok(name) = AccountName::parse(user) else { return Ok(russh::server::Auth::reject()) };
        let shared = self.shared.clone();
        let n = name.clone();
        let password = Zeroizing::new(password.to_string());
        // argon2 是几十毫秒的 CPU 活，别在 reactor 线程上做。
        let verdict = tokio::task::spawn_blocking(move || shared.accounts.verify(n.as_str(), &password))
            .await
            .unwrap_or(Verify::Rejected);
        match verdict {
            Verify::Ok { port } => {
                self.authed.store(true, Ordering::SeqCst);
                self.account = Some((name, port));
                Ok(russh::server::Auth::Accept)
            }
            Verify::Rejected => Ok(russh::server::Auth::reject()),
        }
    }
}
```

`Auth::reject()` 让 russh 按 `auth_rejection_time` 延迟应答，不需要自己 sleep。`ConnHandler` **不实现** `tcpip_forward`（Task 5）、`channel_open_session`、`channel_open_direct_tcpip`、`auth_publickey` 等任何别的回调。


- [ ] **Step 3: 跑绿、变异、闸门、提交**

```bash
cargo test -p rmc-gateway server::
```

变异四枪：`Accept` 无条件；`server_supported()`；实现 `channel_open_session` + accept；`max_auth_attempts: 10`；再加一枪删掉 `deadline` 分支。每枪注入确认计数 1。

```bash
git add crates/rmc-gateway
git commit -m "feat(gateway): 接入层——TLS 1.3 + russh 服务端，只认口令，其余一律拒绝"
```

---

### Task 5: 转发层：`tcpip-forward` 回填端口、反向监听、`forwarded-tcpip`、断开即回收、来源白名单

**Files:**
- Create: `crates/rmc-gateway/src/cidr.rs`
- Modify: `src/server.rs`（`ServerConfig.engineer_allow`、`Shared.tunnels`、`ConnHandler.tunnel`、`tcpip_forward`/`cancel_tcpip_forward`、反向监听任务）、`src/lib.rs`（`pub mod cidr;`）、`src/testing_verifier.rs`（加 `EchoClient`）
- Test: `cidr.rs` 与 `server.rs` 测试模块

**Interfaces:**
- Consumes: Task 4 的 `Shared`、`ConnHandler`、`Running`、`Timings`；Task 3 的 `Verify::Ok { port }`
- Produces:
  - `cidr::Cidr`：`parse(&str) -> Result<Self, String>`（`a.b.c.d/n`、`[v6]/n` 或 `v6/n`；不带 `/n` 视为单个地址）、`contains(&self, ip: IpAddr) -> bool`、`Display`
  - `server::ServerConfig` 多一个字段 `engineer_allow: Vec<Cidr>`（空 = 全部放行）
  - `server::Shared.tunnels: Mutex<HashMap<AccountName, TunnelInfo>>`，`pub(crate) struct TunnelInfo { port: u16, peer: SocketAddr, since: SystemTime, engineers: Arc<AtomicUsize>, stop: watch::Sender<bool> }`（Task 6 的吊销扫描与 Task 7 的 status 都读它）
  - `Running::tunnels_snapshot(&self) -> Vec<(AccountName, u16, SocketAddr, usize)>`（测试与 status 用）

- [ ] **Step 1: cidr.rs（先测后写，纯逻辑）**

```rust
//! `--engineer-allow` 的网段匹配。不引新包：v4/v6 各是一次整数掩码比较。

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cidr {
    ip: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let (ip_s, prefix) = match s.rsplit_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let ip_s = ip_s.trim_start_matches('[').trim_end_matches(']');
        let ip: IpAddr = ip_s.parse().map_err(|_| format!("不是 IP 地址：{ip_s}"))?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p.parse::<u8>().ok().filter(|p| *p <= max).ok_or_else(|| format!("前缀长度不合法：{s}"))?,
            None => max,
        };
        Ok(Self { ip, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.ip, ip) {
            (IpAddr::V4(net), IpAddr::V4(a)) => mask4(net, self.prefix) == mask4(a, self.prefix),
            (IpAddr::V6(net), IpAddr::V6(a)) => mask6(net, self.prefix) == mask6(a, self.prefix),
            // v4 映射的 v6（::ffff:a.b.c.d）按 v4 比
            (IpAddr::V4(_), IpAddr::V6(a)) => a.to_ipv4_mapped().is_some_and(|v4| self.contains(IpAddr::V4(v4))),
            _ => false,
        }
    }
}

fn mask4(a: Ipv4Addr, p: u8) -> u32 {
    let bits = u32::from(a);
    if p == 0 { 0 } else { bits & (u32::MAX << (32 - p)) }
}
fn mask6(a: Ipv6Addr, p: u8) -> u128 {
    let bits = u128::from(a);
    if p == 0 { 0 } else { bits & (u128::MAX << (128 - p)) }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.ip, self.prefix)
    }
}

pub fn allowed(list: &[Cidr], ip: IpAddr) -> bool {
    list.is_empty() || list.iter().any(|c| c.contains(ip))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ip(s: &str) -> IpAddr { s.parse().unwrap() }

    /// 改红：`mask4` 里把 `32 - p` 改成 `p`。
    #[test]
    fn v4_prefix_boundaries() {
        let c = Cidr::parse("203.0.113.0/24").unwrap();
        assert!(c.contains(ip("203.0.113.1")));
        assert!(c.contains(ip("203.0.113.255")));
        assert!(!c.contains(ip("203.0.114.0")));
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(ip("8.8.8.8")));
        let single = Cidr::parse("10.1.2.3").unwrap();
        assert!(single.contains(ip("10.1.2.3")));
        assert!(!single.contains(ip("10.1.2.4")));
    }

    #[test]
    fn v6_and_mapped_v4() {
        let c = Cidr::parse("2001:db8::/32").unwrap();
        assert!(c.contains(ip("2001:db8:1::1")));
        assert!(!c.contains(ip("2001:db9::1")));
        let v4 = Cidr::parse("127.0.0.0/8").unwrap();
        assert!(v4.contains(ip("::ffff:127.0.0.1")), "v4 映射地址按 v4 比");
        assert!(!v4.contains(ip("::1")));
    }

    #[test]
    fn empty_list_allows_everyone_and_bad_input_is_an_error() {
        assert!(allowed(&[], ip("8.8.8.8")));
        assert!(!allowed(&[Cidr::parse("10.0.0.0/8").unwrap()], ip("8.8.8.8")));
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("nope").is_err());
    }
}
```

- [ ] **Step 2: 服务端测试（server.rs 测试模块追加）**

`testing_verifier.rs` 加一个会回显的客户端处理器：

```rust
/// 假装成现场客户端：收到 forwarded-tcpip 通道就接受，把收到的字节前面加 "echo:" 回写。
pub struct EchoClient;
impl russh::client::Handler for EchoClient {
    type Error = russh::Error;
    async fn check_server_key(&mut self, _k: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> { Ok(true) }
    async fn server_channel_open_forwarded_tcpip(
        &mut self, channel: russh::Channel<russh::client::Msg>, _a: &str, _p: u32, _oa: &str, _op: u32,
        reply: russh::client::ChannelOpenHandle, _s: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut st = channel.into_stream();
            let mut buf = [0u8; 256];
            while let Ok(n) = st.read(&mut buf).await {
                if n == 0 { break; }
                if st.write_all(&[b"echo:", &buf[..n]].concat()).await.is_err() { break; }
            }
        });
        Ok(())
    }
}
/// `ssh_connect` 泛型化：TLS（1.3、AcceptAll）+ SSH 握手，处理器由调用方给。
pub async fn ssh_connect_with<H: russh::client::Handler + Send + 'static>(addr: std::net::SocketAddr, handler: H) -> russh::client::Handle<H> {
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let tls_cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13]).unwrap()
        .dangerous().with_custom_certificate_verifier(std::sync::Arc::new(AcceptAll)).with_no_client_auth();
    let sock = tokio::net::TcpStream::connect(addr).await.expect("TCP");
    let tls = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls_cfg))
        .connect(rustls::pki_types::ServerName::try_from(addr.ip().to_string()).unwrap(), sock).await.expect("TLS");
    let cfg = std::sync::Arc::new(russh::client::Config { inactivity_timeout: None, ..Default::default() });
    russh::client::connect_stream(cfg, tls, handler).await.expect("SSH 握手")
}
pub async fn ssh_connect(addr: std::net::SocketAddr) -> russh::client::Handle<AnyHostKey> { ssh_connect_with(addr, AnyHostKey).await }
pub async fn ssh_connect_echo(addr: std::net::SocketAddr) -> russh::client::Handle<EchoClient> { ssh_connect_with(addr, EchoClient).await }
```

（Task 4 里那版 `ssh_connect` 的函数体搬进 `ssh_connect_with`，`ssh_connect` 变成一行薄包装。）

测试：

```rust
    async fn engineer_roundtrip(port: u16, msg: &[u8]) -> Vec<u8> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.expect("连反向端口");
        s.write_all(msg).await.unwrap();
        let mut buf = vec![0u8; 256];
        let n = tokio::time::timeout(Duration::from_secs(10), s.read(&mut buf)).await.expect("读超时").unwrap();
        buf.truncate(n);
        buf
    }

    /// 探针 2 的场景：端口 0 → 回填；工程师的字节到客户端再回来。
    /// 改红：`tcpip_forward` 里不写 `*port = account_port`——第一格红；
    /// 反向监听里不开 forwarded-tcpip 通道——第二格红。
    #[tokio::test]
    async fn port_zero_is_filled_with_the_account_port_and_bytes_flow_both_ways() {
        let (srv, pw, _tmp) = server_with_account("zhang").await;
        let mut s = within("connect", ssh_connect_echo(srv.local_addr())).await;
        assert!(s.authenticate_password("zhang", pw.as_str()).await.unwrap().success());
        let got = s.tcpip_forward("", 0).await.expect("tcpip_forward");
        let expected = srv.tunnels_snapshot()[0].1;
        assert_eq!(got as u16, expected);
        assert_eq!(engineer_roundtrip(expected, b"hello").await, b"echo:hello");
        srv.shutdown().await;
    }

    #[tokio::test]
    async fn a_request_for_a_different_port_is_denied() {
        let (srv, pw, _tmp) = server_with_account("zhang").await;
        let mut s = within("connect", ssh_connect_echo(srv.local_addr())).await;
        assert!(s.authenticate_password("zhang", pw.as_str()).await.unwrap().success());
        assert!(s.tcpip_forward("", 9).await.is_err());
        assert!(srv.tunnels_snapshot().is_empty(), "被拒的申请不能留下隧道记录");
        srv.shutdown().await;
    }

    /// 同账号第二条隧道在第一条还活着时被拒（客户端把它映射成「端口占用」）。
    /// 改红：`tcpip_forward` 里把「账号已有隧道」那句判断删掉——第二格绿。
    #[tokio::test]
    async fn a_second_tunnel_for_the_same_account_is_denied_while_the_first_lives() {
        let (srv, pw, _tmp) = server_with_account("zhang").await;
        let mut a = within("a", ssh_connect_echo(srv.local_addr())).await;
        assert!(a.authenticate_password("zhang", pw.as_str()).await.unwrap().success());
        a.tcpip_forward("", 0).await.unwrap();
        let mut b = within("b", ssh_connect_echo(srv.local_addr())).await;
        assert!(b.authenticate_password("zhang", pw.as_str()).await.unwrap().success(), "认证是过的");
        assert!(b.tcpip_forward("", 0).await.is_err(), "第二条必须被拒");
        srv.shutdown().await;
    }

    /// 客户端一断，端口**立即**能被别人绑上，工程师的连接也被断掉。
    /// 改红：`TunnelGuard::drop` 里不发 `stop`——这条在 bind 那一步红（端口还被占着）。
    #[tokio::test]
    async fn disconnecting_frees_the_port_immediately_and_drops_engineers() {
        use tokio::io::AsyncReadExt;
        let (srv, pw, _tmp) = server_with_account("zhang").await;
        let mut s = within("connect", ssh_connect_echo(srv.local_addr())).await;
        assert!(s.authenticate_password("zhang", pw.as_str()).await.unwrap().success());
        let port = s.tcpip_forward("", 0).await.unwrap() as u16;
        let mut eng = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        s.disconnect(russh::Disconnect::ByApplication, "", "").await.unwrap();
        // 立即：给 200ms 的调度余量，不是等心跳
        tokio::time::sleep(Duration::from_millis(200)).await;
        let l = tokio::net::TcpListener::bind(("127.0.0.1", port)).await;
        assert!(l.is_ok(), "端口没有立即释放：{:?}", l.err());
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(2), eng.read(&mut buf)).await.expect("工程师连接应当被断开").unwrap_or(0);
        assert_eq!(n, 0);
        assert!(srv.tunnels_snapshot().is_empty());
        srv.shutdown().await;
    }

    #[tokio::test]
    async fn cancel_tcpip_forward_frees_the_port_without_dropping_the_session() {
        let (srv, pw, _tmp) = server_with_account("zhang").await;
        let mut s = within("connect", ssh_connect_echo(srv.local_addr())).await;
        assert!(s.authenticate_password("zhang", pw.as_str()).await.unwrap().success());
        let port = s.tcpip_forward("", 0).await.unwrap() as u16;
        s.cancel_tcpip_forward("", port as u32).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(tokio::net::TcpListener::bind(("127.0.0.1", port)).await.is_ok());
        assert!(!s.is_closed(), "取消转发不该断会话");
        // 还能再申请一次
        assert_eq!(s.tcpip_forward("", 0).await.unwrap() as u16, port);
        srv.shutdown().await;
    }

    /// 来源白名单：不在名单里的工程师连接被直接关掉，客户端根本收不到通道。
    #[tokio::test]
    async fn engineer_allow_list_filters_sources() {
        use tokio::io::AsyncReadExt;
        let (srv, pw, _tmp) = server_with_account_and_allow("zhang", vec![crate::cidr::Cidr::parse("10.0.0.0/8").unwrap()]).await;
        let mut s = within("connect", ssh_connect_echo(srv.local_addr())).await;
        assert!(s.authenticate_password("zhang", pw.as_str()).await.unwrap().success());
        let port = s.tcpip_forward("", 0).await.unwrap() as u16;
        let mut eng = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(2), eng.read(&mut buf)).await.expect("应当被立刻关掉").unwrap_or(0);
        assert_eq!(n, 0);
        srv.shutdown().await;
    }

    /// 每条隧道最多 N 条工程师连接。改红：`engineers.fetch_add` 那句比较删掉。
    #[tokio::test]
    async fn at_most_n_engineers_per_tunnel() {
        use tokio::io::AsyncReadExt;
        let (srv, pw, _tmp) = server_with_account_and_timings("zhang", Timings { max_engineers_per_tunnel: 2, ..Timings::fast() }).await;
        let mut s = within("connect", ssh_connect_echo(srv.local_addr())).await;
        assert!(s.authenticate_password("zhang", pw.as_str()).await.unwrap().success());
        let port = s.tcpip_forward("", 0).await.unwrap() as u16;
        let _a = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let _b = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut c = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(2), c.read(&mut buf)).await.expect("第三条应当被关掉").unwrap_or(0);
        assert_eq!(n, 0);
        assert_eq!(srv.tunnels_snapshot()[0].3, 2);
        srv.shutdown().await;
    }
```

`server_with_account` 拆成 `server_with_account_and(name, timings, allow)`，三个薄包装调它。

- [ ] **Step 3: 实现**

`ServerConfig` 加 `pub engineer_allow: Vec<crate::cidr::Cidr>`；`Shared` 加 `engineer_allow`、`tunnels: Mutex<HashMap<AccountName, TunnelInfo>>`：

```rust
pub(crate) struct TunnelInfo {
    pub port: u16,
    pub peer: SocketAddr,
    pub since: std::time::SystemTime,
    pub engineers: Arc<std::sync::atomic::AtomicUsize>,
    pub stop: watch::Sender<bool>,
}

/// 挂在 ConnHandler 上；handler 随会话一起被丢弃时，这里把隧道从表里摘掉并停掉监听任务。
struct TunnelGuard {
    shared: Arc<Shared>,
    account: AccountName,
}

impl Drop for TunnelGuard {
    fn drop(&mut self) {
        if let Some(info) = lock(&self.shared.tunnels).remove(&self.account) {
            let _ = info.stop.send(true);
        }
    }
}

fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}
```

`ConnHandler` 加 `tunnel: Option<TunnelGuard>`，并实现：

```rust
    async fn tcpip_forward(&mut self, _address: &str, port: &mut u32, session: &mut russh::server::Session) -> std::result::Result<bool, Self::Error> {
        let Some((account, account_port)) = self.account.clone() else { return Ok(false) };
        if *port != 0 && *port != u32::from(account_port) { return Ok(false); }
        if self.tunnel.is_some() { return Ok(false); }
        // 一个账号同一时刻只有一条隧道
        {
            let mut t = lock(&self.shared.tunnels);
            if t.contains_key(&account) { return Ok(false); }
            // 先占位，再 bind；bind 失败就撤掉占位
            let (stop, _) = watch::channel(false);
            t.insert(account.clone(), TunnelInfo { port: account_port, peer: self.peer, since: std::time::SystemTime::now(), engineers: Arc::new(Default::default()), stop });
        }
        let listener = match tokio::net::TcpListener::bind((self.shared.reverse_bind, account_port)).await {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(%account, account_port, error = %e, "反向端口绑定失败");
                lock(&self.shared.tunnels).remove(&account);
                return Ok(false);
            }
        };
        let (stop_rx, engineers) = {
            let t = lock(&self.shared.tunnels);
            let info = t.get(&account).expect("刚插的");
            (info.stop.subscribe(), info.engineers.clone())
        };
        *port = u32::from(account_port);
        tokio::spawn(reverse_accept_loop(self.shared.clone(), account.clone(), account_port, listener, session.handle(), stop_rx, engineers));
        self.tunnel = Some(TunnelGuard { shared: self.shared.clone(), account });
        Ok(true)
    }

    async fn cancel_tcpip_forward(&mut self, _address: &str, _port: u32, _session: &mut russh::server::Session) -> std::result::Result<bool, Self::Error> {
        // 丢掉 guard 就是全部：摘表、停监听、断工程师。
        Ok(self.tunnel.take().is_some())
    }
```

反向监听任务：

```rust
async fn reverse_accept_loop(
    shared: Arc<Shared>,
    account: AccountName,
    port: u16,
    listener: tokio::net::TcpListener,
    handle: russh::server::Handle,
    mut stop: watch::Receiver<bool>,
    engineers: Arc<std::sync::atomic::AtomicUsize>,
) {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            accepted = listener.accept() => {
                let Ok((mut sock, peer)) = accepted else { continue };
                if !crate::cidr::allowed(&shared.engineer_allow, peer.ip()) {
                    tracing::info!(%account, port, %peer, "工程师来源不在白名单，拒绝");
                    continue; // sock 随作用域关闭
                }
                let prev = engineers.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if prev >= shared.timings.max_engineers_per_tunnel {
                    engineers.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                    tracing::info!(%account, port, %peer, "工程师连接数已达上限，拒绝");
                    continue;
                }
                let handle = handle.clone();
                let engineers = engineers.clone();
                let account = account.clone();
                let _ = sock.set_nodelay(true);
                tasks.spawn(async move {
                    let opened = handle.channel_open_forwarded_tcpip("127.0.0.1", u32::from(port), peer.ip().to_string(), u32::from(peer.port())).await;
                    match opened {
                        Ok(ch) => {
                            let mut st = ch.into_stream();
                            let r = tokio::io::copy_bidirectional(&mut sock, &mut st).await;
                            tracing::debug!(%account, port, %peer, ?r, "工程师连接结束");
                        }
                        Err(e) => tracing::warn!(%account, port, %peer, error = %e, "开 forwarded-tcpip 通道失败"),
                    }
                    engineers.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                });
            }
        }
    }
    // stop 之后：监听随 listener 丢弃而释放，工程师连接全部中止
    tasks.abort_all();
}
```

`Running::tunnels_snapshot`：`Running` 持一份 `Arc<Shared>`（`bind` 里 `shared.clone()` 存进去），读表返回 `(name, port, peer, engineers.load())`。

**一处必须想清楚的竞态**：`TunnelGuard::drop` 在 `ConnHandler` 被丢弃时触发；`ConnHandler` 归 `RunningSession` 所有，`handle_connection` 返回（会话结束、心跳失联、认证超时）就丢。而 `Task 6` 的吊销扫描会从**外面**用 `Handle::disconnect` 断会话——那条路同样走到这里。所以「摘表 + 停监听」只有这一个出口。

- [ ] **Step 4: 跑绿、变异、闸门、提交**

```bash
cargo test -p rmc-gateway
```

变异五枪（每条测试注释里那句）。`disconnecting_frees_the_port_immediately` 那一枪要特别真做：不发 `stop`，看它是不是真的在 bind 那一步红。

```bash
git add crates/rmc-gateway
git commit -m "feat(gateway): 转发层——端口 0 回填、反向监听、forwarded-tcpip、断开即回收、来源白名单"
```

---

### Task 6: 限额与审计：认证失败限流、未认证连接上限、审计日志、吊销 10 秒内踢人

**Files:**
- Create: `crates/rmc-gateway/src/throttle.rs`、`src/clock.rs`、`src/audit.rs`
- Modify: `src/server.rs`（`ServerConfig.limits`、`Shared.throttle/audit`、accept 时的限额、认证成败记账、`TunnelInfo.handle`、吊销扫描任务、审计事件）、`src/lib.rs`
- Test: 三个新文件的测试模块 + `server.rs` 追加四条

**Interfaces:**
- Consumes: Task 4/5 的 `Shared`、`ConnHandler`、`TunnelInfo`、`reverse_accept_loop`
- Produces:
  - `throttle::Limits { per_ip_failures: u32 (10), window: Duration (10min), ban: Duration (15min), max_unauth_global: usize (64), max_unauth_per_ip: usize (8) }`，`Default` 即 spec 数值，`Limits::tiny()`（测试：3 / 2s / 2s / 4 / 2）
  - `throttle::Throttle::new(Limits)`；`admit(&self, ip, now: Instant) -> Admit`，`pub enum Admit { Ok(UnauthSlot), Banned, TooMany }`；`UnauthSlot`（RAII：drop 或 `release()` 都减计数）；`record_failure(&self, ip, now)`；`is_banned(&self, ip, now) -> bool`
  - `clock::civil_from_unix(secs: u64) -> (i64, u8, u8)`、`clock::rfc3339(SystemTime) -> String`、`clock::date_stamp(SystemTime) -> String`（`YYYY-MM-DD`）
  - `audit::AuditEvent`（serde，`#[serde(tag = "event", rename_all = "snake_case")]`）：`ServerStart { listen }`、`AuthOk { account, peer }`、`AuthFail { account, peer }`、`Banned { peer }`、`TunnelUp { account, port, peer }`、`TunnelDown { account, port, reason }`、`EngineerOpen { account, port, peer }`、`EngineerClose { account, port, peer, seconds, to_client, from_client }`、`EngineerRejected { port, peer, reason }`、`AccountChanged { account, action }`
  - `audit::AuditLog::open(dir: &DataDir) -> Result<Self>`（建 `audit/`）、`record(&self, ev: AuditEvent)`（追加一行 `{"ts": "...", ...}`，按天一个文件 `audit-YYYY-MM-DD.log`）、`prune(&self, keep_days: u32)`（按**文件名日期**删，不看 mtime）、`RETENTION_DAYS = 180`
  - `server::ServerConfig.limits: Limits`；`Running::audit_path_today()`（测试读日志用）

- [ ] **Step 1: throttle.rs（纯逻辑，时钟注入）**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::time::{Duration, Instant};
    fn ip(s: &str) -> IpAddr { s.parse().unwrap() }

    /// 改红：`record_failure` 里把 `>= per_ip_failures` 改成 `>`。
    #[test]
    fn n_failures_in_the_window_ban_the_source_and_the_ban_expires() {
        let t = Throttle::new(Limits::tiny()); // 3 次 / 2s 窗口 / 2s 封禁
        let t0 = Instant::now();
        for _ in 0..2 { t.record_failure(ip("1.1.1.1"), t0); }
        assert!(!t.is_banned(ip("1.1.1.1"), t0));
        t.record_failure(ip("1.1.1.1"), t0);
        assert!(t.is_banned(ip("1.1.1.1"), t0 + Duration::from_millis(100)));
        assert!(matches!(t.admit(ip("1.1.1.1"), t0 + Duration::from_millis(100)), Admit::Banned));
        assert!(!t.is_banned(ip("1.1.1.1"), t0 + Duration::from_millis(2100)), "封禁到期");
        assert!(!t.is_banned(ip("2.2.2.2"), t0), "别的来源不受影响");
    }

    #[test]
    fn failures_outside_the_window_do_not_count() {
        let t = Throttle::new(Limits::tiny());
        let t0 = Instant::now();
        t.record_failure(ip("1.1.1.1"), t0);
        t.record_failure(ip("1.1.1.1"), t0 + Duration::from_millis(500));
        // 第三次在窗口外：前两次已经滑出去了
        t.record_failure(ip("1.1.1.1"), t0 + Duration::from_millis(2600));
        assert!(!t.is_banned(ip("1.1.1.1"), t0 + Duration::from_millis(2600)));
    }

    /// 改红：`UnauthSlot::drop` 里不减计数——第三格红。
    #[test]
    fn unauthenticated_slots_are_capped_and_released_on_drop() {
        let t = Throttle::new(Limits::tiny()); // 全局 4，每 IP 2
        let now = Instant::now();
        let a1 = t.admit(ip("1.1.1.1"), now);
        let a2 = t.admit(ip("1.1.1.1"), now);
        assert!(matches!(a1, Admit::Ok(_)) && matches!(a2, Admit::Ok(_)));
        assert!(matches!(t.admit(ip("1.1.1.1"), now), Admit::TooMany), "每 IP 上限");
        drop(a1);
        assert!(matches!(t.admit(ip("1.1.1.1"), now), Admit::Ok(_)), "释放后能再进");
        let b1 = t.admit(ip("2.2.2.2"), now);
        let b2 = t.admit(ip("2.2.2.2"), now);
        assert!(matches!(b1, Admit::Ok(_)) && matches!(b2, Admit::Ok(_)));
        // 此时全局已 4（1.1.1.1 两条 + 2.2.2.2 两条），第三个来源也进不来
        assert!(matches!(t.admit(ip("3.3.3.3"), now), Admit::TooMany), "全局上限");
        // 认证通过后显式 release：不再占未认证名额
        if let Admit::Ok(slot) = b2 { slot.release(); }
        assert!(matches!(t.admit(ip("3.3.3.3"), now), Admit::Ok(_)));
    }
}
```

实现：

```rust
//! 认证失败限流与未认证连接限额。纯逻辑，时间由调用方传入，测试不用真等。

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Limits {
    pub per_ip_failures: u32,
    pub window: Duration,
    pub ban: Duration,
    pub max_unauth_global: usize,
    pub max_unauth_per_ip: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self { per_ip_failures: 10, window: Duration::from_secs(600), ban: Duration::from_secs(900), max_unauth_global: 64, max_unauth_per_ip: 8 }
    }
}

impl Limits {
    pub fn tiny() -> Self {
        Self { per_ip_failures: 3, window: Duration::from_secs(2), ban: Duration::from_secs(2), max_unauth_global: 4, max_unauth_per_ip: 2 }
    }
}

#[derive(Default)]
struct State {
    failures: HashMap<IpAddr, VecDeque<Instant>>,
    banned_until: HashMap<IpAddr, Instant>,
    unauth_global: usize,
    unauth_per_ip: HashMap<IpAddr, usize>,
}

pub struct Throttle {
    limits: Limits,
    state: Arc<Mutex<State>>,
}

pub enum Admit {
    Ok(UnauthSlot),
    Banned,
    TooMany,
}

/// 一个未认证连接占的名额。drop 或 release 都归还。
pub struct UnauthSlot {
    state: Arc<Mutex<State>>,
    ip: IpAddr,
    live: bool,
}

impl UnauthSlot {
    pub fn release(mut self) { self.give_back(); }
    fn give_back(&mut self) {
        if !self.live { return; }
        self.live = false;
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.unauth_global = s.unauth_global.saturating_sub(1);
        if let Some(n) = s.unauth_per_ip.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
            if *n == 0 { s.unauth_per_ip.remove(&self.ip); }
        }
    }
}

impl Drop for UnauthSlot {
    fn drop(&mut self) { self.give_back(); }
}

impl Throttle {
    pub fn new(limits: Limits) -> Self {
        Self { limits, state: Arc::new(Mutex::new(State::default())) }
    }

    pub fn is_banned(&self, ip: IpAddr, now: Instant) -> bool {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match s.banned_until.get(&ip) {
            Some(until) if *until > now => true,
            Some(_) => { s.banned_until.remove(&ip); false }
            None => false,
        }
    }

    pub fn admit(&self, ip: IpAddr, now: Instant) -> Admit {
        if self.is_banned(ip, now) { return Admit::Banned; }
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let per_ip = *s.unauth_per_ip.get(&ip).unwrap_or(&0);
        if s.unauth_global >= self.limits.max_unauth_global || per_ip >= self.limits.max_unauth_per_ip {
            return Admit::TooMany;
        }
        s.unauth_global += 1;
        *s.unauth_per_ip.entry(ip).or_insert(0) += 1;
        Admit::Ok(UnauthSlot { state: self.state.clone(), ip, live: true })
    }

    pub fn record_failure(&self, ip: IpAddr, now: Instant) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let q = s.failures.entry(ip).or_default();
        q.push_back(now);
        while q.front().is_some_and(|t| now.duration_since(*t) > self.limits.window) { q.pop_front(); }
        if q.len() as u32 >= self.limits.per_ip_failures {
            q.clear();
            s.banned_until.insert(ip, now + self.limits.ban);
        }
    }
}
```

**不做按账号锁定**——那等于给攻击者一个锁死合法账号的开关（spec §6）。写进模块文档。

- [ ] **Step 2: clock.rs（日期算法，先测后写）**

```rust
//! UTC 日期与 RFC 3339 时间戳。不引 chrono/time：只要天数↔日历这一个算法（Howard Hinnant 的 civil_from_days）。

use std::time::{SystemTime, UNIX_EPOCH};

pub fn civil_from_days(z: i64) -> (i64, u8, u8) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn civil_from_unix(secs: u64) -> (i64, u8, u8) {
    civil_from_days((secs / 86_400) as i64)
}

pub fn rfc3339(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let (y, m, d) = civil_from_unix(secs);
    let s = secs % 86_400;
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", s / 3600, (s % 3600) / 60, s % 60)
}

pub fn date_stamp(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let (y, m, d) = civil_from_unix(secs);
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// 改红：`civil_from_days` 里任何一个常数。
    #[test]
    fn known_dates() {
        assert_eq!(civil_from_unix(0), (1970, 1, 1));
        assert_eq!(civil_from_unix(951_782_400), (2000, 2, 29), "闰日");
        assert_eq!(civil_from_unix(1_789_948_800), (2026, 9, 21));
        assert_eq!(rfc3339(UNIX_EPOCH + Duration::from_secs(1_789_948_800 + 3661)), "2026-09-21T01:01:01Z");
        assert_eq!(date_stamp(UNIX_EPOCH + Duration::from_secs(1_789_948_800)), "2026-09-21");
    }
}
```

（`1_789_948_800` 是 2026-09-21T00:00:00Z——派发前用 python 核过，连同 `civil_from_days` 对 2000 个随机天数与标准库逐一比对无误；实现者照抄即可，但别信这句话，自己跑一遍 `python3 -c 'import datetime;print(datetime.datetime.fromtimestamp(1789948800, datetime.timezone.utc))'`。第一版计划里这个数写成了 2025 年的，就是这么抓出来的。）

- [ ] **Step 3: audit.rs**

```rust
//! 审计日志：JSON Lines，按天一个文件，保留 180 天。**不写口令**。
//! 这是原方案 §7.1 明确缺的那一块；原方案里 sshd 看到的来源永远是 127.0.0.1，这里是真实地址。

use crate::clock::{date_stamp, rfc3339};
use crate::datadir::DataDir;
use crate::Result;
use serde::Serialize;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::SystemTime;

pub const RETENTION_DAYS: u32 = 180;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEvent {
    ServerStart { listen: String },
    AuthOk { account: String, peer: String },
    AuthFail { account: String, peer: String },
    Banned { peer: String },
    TunnelUp { account: String, port: u16, peer: String },
    TunnelDown { account: String, port: u16, reason: String },
    EngineerOpen { account: String, port: u16, peer: String },
    EngineerClose { account: String, port: u16, peer: String, seconds: u64, to_client: u64, from_client: u64 },
    EngineerRejected { port: u16, peer: String, reason: String },
    AccountChanged { account: String, action: String },
}

#[derive(Serialize)]
struct Line<'a> {
    ts: String,
    #[serde(flatten)]
    ev: &'a AuditEvent,
}

pub struct AuditLog {
    dir: PathBuf,
    // 同一进程内串行写；跨进程（CLI 记 AccountChanged）靠 O_APPEND 一行一写
    write: Mutex<()>,
}

impl AuditLog {
    pub fn open(dir: &DataDir) -> Result<Self> {
        std::fs::create_dir_all(dir.audit_dir())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.audit_dir(), std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self { dir: dir.audit_dir(), write: Mutex::new(()) })
    }

    pub fn path_for(&self, t: SystemTime) -> PathBuf {
        self.dir.join(format!("audit-{}.log", date_stamp(t)))
    }

    pub fn record(&self, ev: AuditEvent) {
        let now = SystemTime::now();
        let line = match serde_json::to_string(&Line { ts: rfc3339(now), ev: &ev }) {
            Ok(l) => l,
            Err(e) => { tracing::error!(error = %e, "审计事件序列化失败"); return; }
        };
        let _g = self.write.lock().unwrap_or_else(|e| e.into_inner());
        let r = std::fs::OpenOptions::new().create(true).append(true).open(self.path_for(now))
            .and_then(|mut f| { #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600)); } writeln!(f, "{line}") });
        if let Err(e) = r { tracing::error!(error = %e, "审计日志写入失败"); }
        tracing::info!(target: "audit", "{line}");
    }

    /// 按文件名里的日期删旧文件（不看 mtime——备份/拷贝会改 mtime）。
    pub fn prune(&self, keep_days: u32) {
        let today = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs() / 86_400).unwrap_or(0) as i64;
        let Ok(rd) = std::fs::read_dir(&self.dir) else { return };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(stamp) = name.strip_prefix("audit-").and_then(|s| s.strip_suffix(".log")) else { continue };
            let Some(days) = days_from_stamp(stamp) else { continue };
            if today - days > i64::from(keep_days) { let _ = std::fs::remove_file(e.path()); }
        }
    }
}

/// `YYYY-MM-DD` → 自 1970-01-01 的天数（Hinnant 的 days_from_civil）。
fn days_from_stamp(s: &str) -> Option<i64> {
    let mut it = s.split('-');
    let y: i64 = it.next()?.parse().ok()?;
    let m: i64 = it.next()?.parse().ok()?;
    let d: i64 = it.next()?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) { return None; }
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 改红：`Line` 上去掉 `#[serde(flatten)]`——第二格红（事件字段被包在 "ev" 里）。
    #[test]
    fn records_one_json_line_per_event_with_a_timestamp() {
        let tmp = tempfile::tempdir().unwrap();
        let d = DataDir::at(tmp.path().to_path_buf());
        let log = AuditLog::open(&d).unwrap();
        log.record(AuditEvent::AuthFail { account: "zhang".into(), peer: "203.0.113.5:4242".into() });
        let text = std::fs::read_to_string(log.path_for(SystemTime::now())).unwrap();
        let v: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(v["event"], "auth_fail");
        assert_eq!(v["account"], "zhang");
        assert!(v["ts"].as_str().unwrap().ends_with('Z'));
        assert_eq!(text.lines().count(), 1);
    }

    #[test]
    fn days_from_stamp_inverts_civil_from_days() {
        for days in [0i64, 10_957, 20_454, 30_000] {
            let (y, m, d) = crate::clock::civil_from_days(days);
            assert_eq!(days_from_stamp(&format!("{y:04}-{m:02}-{d:02}")), Some(days));
        }
    }

    /// 改红：`prune` 里把 `>` 改成 `>=` 之外的任何东西，或者按 mtime 删。
    #[test]
    fn prune_deletes_by_the_date_in_the_file_name() {
        let tmp = tempfile::tempdir().unwrap();
        let d = DataDir::at(tmp.path().to_path_buf());
        let log = AuditLog::open(&d).unwrap();
        std::fs::write(d.audit_dir().join("audit-2020-01-01.log"), "old\n").unwrap();
        std::fs::write(d.audit_dir().join("unrelated.txt"), "keep\n").unwrap();
        log.record(AuditEvent::ServerStart { listen: "x".into() });
        log.prune(RETENTION_DAYS);
        assert!(!d.audit_dir().join("audit-2020-01-01.log").exists());
        assert!(d.audit_dir().join("unrelated.txt").exists());
        assert!(log.path_for(SystemTime::now()).exists());
    }
}
```

- [ ] **Step 4: 接进服务端**

`ServerConfig` 加 `pub limits: Limits`；`Shared` 加 `throttle: Throttle`、`audit: AuditLog`；`TunnelInfo` 加 `handle: russh::server::Handle`；`Running` 加 `audit_path_today()`。

accept 循环里、spawn 之前：

```rust
let now = tokio::time::Instant::now().into_std();
match shared.throttle.admit(peer.ip(), now) {
    Admit::Ok(slot) => { conns.spawn(handle_connection(shared.clone(), sock, peer, slot)); }
    Admit::Banned => { shared.audit.record(AuditEvent::Banned { peer: peer.to_string() }); drop(sock); }
    Admit::TooMany => { tracing::info!(%peer, "未认证连接过多，拒绝"); drop(sock); }
}
```

`handle_connection` 多收 `slot: UnauthSlot`，放进 `ConnHandler.slot: Option<UnauthSlot>`；`auth_password` 成功时 `if let Some(s) = self.slot.take() { s.release(); }` 并记 `AuthOk`；失败时 `throttle.record_failure(peer.ip(), now)` 并记 `AuthFail`。`tcpip_forward` 成功记 `TunnelUp`；`TunnelGuard::drop` 记 `TunnelDown { reason: "会话结束" }`；`reverse_accept_loop` 记 `EngineerOpen` / `EngineerClose`（用 `copy_bidirectional` 返回的 `(a_to_b, b_to_a)` 与开始时刻）/ `EngineerRejected`。**没有一处把口令写进事件**——`AuditEvent` 里根本没有能放它的字段，这是构造上的保证。

吊销扫描（`Server::bind` 里再 spawn 一个任务，随 `stop` 退出）：

```rust
async fn revocation_sweep(shared: Arc<Shared>, mut stop: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(shared.timings.sweep);
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            _ = tick.tick() => {
                let doomed: Vec<(AccountName, russh::server::Handle, u16)> = lock(&shared.tunnels).iter()
                    .filter(|(name, _)| !shared.accounts.is_active(name.as_str()))
                    .map(|(name, info)| (name.clone(), info.handle.clone(), info.port))
                    .collect();
                for (name, handle, port) in doomed {
                    tracing::info!(%name, port, "账号已吊销，断开在线隧道");
                    let _ = handle.disconnect(russh::Disconnect::ByApplication, "账号已吊销".into(), "".into()).await;
                    // 摘表与释放端口由会话结束时的 TunnelGuard::drop 完成，这里不重复做
                }
                shared.audit.prune(crate::audit::RETENTION_DAYS);
            }
        }
    }
}
```

`is_active` 每次 tick 都读一次 `accounts.toml`（按 mtime 缓存，通常不真读）。

- [ ] **Step 5: 服务端测试追加**

```rust
    /// 吊销后最迟一个扫描周期内被踢：测试用 200ms 周期，给 1s。
    /// 改红：`revocation_sweep` 里把 `!is_active` 改成 `is_active`（会踢活人）——
    /// 这条第一格红（吊销前就被踢）；或者干脆不 spawn 扫描——第二格红。
    #[tokio::test]
    async fn a_revoked_account_is_kicked_within_one_sweep() {
        let (srv, pw, tmp) = server_with_account("zhang").await;
        let mut s = within("connect", ssh_connect_echo(srv.local_addr())).await;
        assert!(s.authenticate_password("zhang", pw.as_str()).await.unwrap().success());
        let port = s.tcpip_forward("", 0).await.unwrap() as u16;
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(!s.is_closed(), "没吊销不能踢");
        let d = DataDir::at(tmp.path().to_path_buf());
        let cfg = GatewayConfig::load(&d).unwrap();
        AccountStore::open(&d, &cfg, 22000).revoke(&AccountName::parse("zhang").unwrap()).unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(s.is_closed(), "吊销 1 秒后还在线");
        assert!(tokio::net::TcpListener::bind(("127.0.0.1", port)).await.is_ok(), "端口该释放了");
        srv.shutdown().await;
    }

    /// 同一来源失败 N 次后被封：封禁期内连 TLS 都握不成（TCP 直接被关）。
    #[tokio::test]
    async fn repeated_failures_from_one_source_get_banned() {
        let (srv, _pw, _tmp) = server_with_limits("zhang", Limits::tiny()).await;
        for _ in 0..3 {
            let mut s = within("connect", ssh_connect(srv.local_addr())).await;
            let _ = s.authenticate_password("zhang", "wrong").await;
        }
        let r = tokio::time::timeout(Duration::from_secs(5), async {
            let sock = tokio::net::TcpStream::connect(srv.local_addr()).await.unwrap();
            use tokio::io::AsyncReadExt;
            let mut buf = [0u8; 4];
            sock.readable().await.unwrap();
            let mut sock = sock;
            sock.read(&mut buf).await
        }).await.expect("封禁期内应当被立刻关掉");
        assert_eq!(r.unwrap_or(0), 0, "应当读到 EOF");
        let text = std::fs::read_to_string(srv.audit_path_today()).unwrap();
        assert!(text.contains("\"event\":\"banned\""), "{text}");
        srv.shutdown().await;
    }

    /// 未认证连接上限：多出来的 TCP 连接被立刻关掉，认证过的不占名额。
    #[tokio::test]
    async fn unauthenticated_connections_are_capped_and_authenticated_ones_do_not_count() {
        use tokio::io::AsyncReadExt;
        let (srv, pw, _tmp) = server_with_limits("zhang", Limits::tiny()).await; // 每 IP 2
        let mut a = within("a", ssh_connect(srv.local_addr())).await;
        assert!(a.authenticate_password("zhang", pw.as_str()).await.unwrap().success()); // 认证过：释放名额
        let _b = tokio::net::TcpStream::connect(srv.local_addr()).await.unwrap();       // 未认证 1
        let _c = tokio::net::TcpStream::connect(srv.local_addr()).await.unwrap();       // 未认证 2
        let mut d = tokio::net::TcpStream::connect(srv.local_addr()).await.unwrap();    // 第 3 条：超
        let mut buf = [0u8; 4];
        let n = tokio::time::timeout(Duration::from_secs(2), d.read(&mut buf)).await.expect("应当被关掉").unwrap_or(0);
        assert_eq!(n, 0);
        srv.shutdown().await;
    }

    /// 审计日志里有真实来源、有隧道起落、有工程师起止与字节数——而且**没有口令**。
    #[tokio::test]
    async fn audit_log_records_the_whole_story_without_the_password() {
        let (srv, pw, _tmp) = server_with_account("zhang").await;
        let mut s = within("connect", ssh_connect_echo(srv.local_addr())).await;
        assert!(s.authenticate_password("zhang", pw.as_str()).await.unwrap().success());
        let port = s.tcpip_forward("", 0).await.unwrap() as u16;
        assert_eq!(engineer_roundtrip(port, b"hi").await, b"echo:hi");
        s.disconnect(russh::Disconnect::ByApplication, "", "").await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let text = std::fs::read_to_string(srv.audit_path_today()).unwrap();
        for ev in ["auth_ok", "tunnel_up", "engineer_open", "engineer_close", "tunnel_down"] {
            assert!(text.contains(&format!("\"event\":\"{ev}\"")), "缺 {ev}：{text}");
        }
        assert!(text.contains("\"peer\":\"127.0.0.1:"), "要有真实来源：{text}");
        assert!(!text.contains(pw.as_str()), "口令进了审计日志");
        srv.shutdown().await;
    }
```

- [ ] **Step 6: 跑绿、变异、闸门、提交**

变异至少六枪：throttle 两处、clock 一处、audit 的 flatten、扫描的取反、`UnauthSlot::drop` 不归还。

```bash
git add crates/rmc-gateway
git commit -m "feat(gateway): 限流、连接限额、审计日志、吊销扫描"
```

---

### Task 7: 组装：`serve`、`status.json` 与 `status`、`service print`、拒绝 root

**Files:**
- Create: `crates/rmc-gateway/src/status.rs`
- Modify: `src/server.rs`（在隧道起落与每次扫描时写 status.json）、`src/cli.rs`（`serve`、`status`、`service print`；`account` 子命令记 `AccountChanged` 审计）、`src/lib.rs`、`Cargo.toml`（`tracing-subscriber`，已在锁里）
- Test: `status.rs`、`cli.rs`、`server.rs` 追加

**Interfaces:**
- Consumes: Task 4–6 的一切
- Produces:
  - `status::Status { pid: u32, updated_unix: u64, listen: String, fingerprint: String, tunnels: Vec<TunnelStatus> }`，`TunnelStatus { account, port, peer, since: String, engineers: usize }`；`status::write(&DataDir, &Status)`、`status::read(&DataDir) -> Result<Option<Status>>`、`status::is_live(&Status, now_unix) -> bool`（30 秒内更新过）
  - `server::serve_until(cfg: ServerConfig, stop: impl Future<Output = ()>) -> Result<()>`（`serve` 子命令用 `ctrl_c` 当 stop；测试用 oneshot）
  - `cli::refuse_root(is_root: bool, allow_root: bool) -> Option<String>`（纯函数，返回拒绝理由）
  - CLI：`serve [--listen A:P] [--engineer-allow CIDR]... [--allow-root]`、`status`、`service print [--listen …] [--engineer-allow …]`
  - `USAGE` 完整版（spec §3 的清单）

- [ ] **Step 1: status.rs（先测后写）**

```rust
//! status.json：serve 在隧道起落与每次扫描时原子写出，`status` 子命令只读它。没有 IPC。

use crate::clock::rfc3339;
use crate::datadir::{write_private_atomic, DataDir};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};

/// 服务端至少每个扫描周期（10s）写一次；超过这个时长没更新，就当它没在跑。
pub const STALE_AFTER_SECS: u64 = 30;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelStatus { pub account: String, pub port: u16, pub peer: String, pub since: String, pub engineers: usize }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status { pub pid: u32, pub updated_unix: u64, pub listen: String, pub fingerprint: String, pub tunnels: Vec<TunnelStatus> }

pub fn write(dir: &DataDir, st: &Status) -> Result<()> {
    let text = serde_json::to_string_pretty(st).map_err(|e| Error::Config(e.to_string()))?;
    write_private_atomic(&dir.status(), text.as_bytes())?;
    Ok(())
}

pub fn read(dir: &DataDir) -> Result<Option<Status>> {
    match std::fs::read_to_string(dir.status()) {
        Ok(t) => serde_json::from_str(&t).map(Some).map_err(|e| Error::Config(format!("status.json 解析失败：{e}"))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn is_live(st: &Status, now_unix: u64) -> bool {
    now_unix.saturating_sub(st.updated_unix) <= STALE_AFTER_SECS
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn since_text(t: std::time::SystemTime) -> String { rfc3339(t) }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trip_and_staleness() {
        let tmp = tempfile::tempdir().unwrap();
        let d = DataDir::at(tmp.path().to_path_buf());
        assert_eq!(read(&d).unwrap(), None);
        let st = Status { pid: 1, updated_unix: 1000, listen: "0.0.0.0:22000".into(), fingerprint: "x".into(), tunnels: vec![] };
        write(&d, &st).unwrap();
        assert_eq!(read(&d).unwrap(), Some(st.clone()));
        assert!(is_live(&st, 1030));
        assert!(!is_live(&st, 1031), "改红：把 STALE_AFTER_SECS 改成 31");
    }
}
```

- [ ] **Step 2: 服务端写状态**

`Shared` 加 `data: DataDir`、`listen: SocketAddr`（bind 后的真实地址）；加方法：

```rust
impl Shared {
    pub(crate) fn publish_status(&self) {
        let tunnels = lock(&self.tunnels).iter().map(|(name, info)| crate::status::TunnelStatus {
            account: name.to_string(), port: info.port, peer: info.peer.to_string(),
            since: crate::status::since_text(info.since), engineers: info.engineers.load(std::sync::atomic::Ordering::SeqCst),
        }).collect();
        let st = crate::status::Status { pid: std::process::id(), updated_unix: crate::status::now_unix(), listen: self.listen.to_string(), fingerprint: self.identity.fingerprint().to_string(), tunnels };
        if let Err(e) = crate::status::write(&self.data, &st) { tracing::warn!(error = %e, "写 status.json 失败"); }
    }
}
```

调用点三处：`tcpip_forward` 成功后、`TunnelGuard::drop` 里、`revocation_sweep` 每个 tick。`Server::bind` 成功后立刻写一次（空表）。`serve_until`：

```rust
pub async fn serve_until(cfg: ServerConfig, stop: impl std::future::Future<Output = ()>) -> Result<()> {
    let running = Server::bind(cfg).await?;
    tracing::info!(listen = %running.local_addr(), fingerprint = %running.fingerprint(), "运维服务器已启动");
    stop.await;
    running.shutdown().await;
    Ok(())
}
```

`shutdown` 末尾把 status.json 删掉（`let _ = std::fs::remove_file(...)`）——干净退出后 `status` 直接说没在跑，不用等 30 秒。

服务端测试追加：

```rust
    /// 改红：`tcpip_forward` 成功后不调 `publish_status`——第二格红。
    #[tokio::test]
    async fn status_json_follows_the_tunnel_table() {
        let (srv, pw, tmp) = server_with_account("zhang").await;
        let d = DataDir::at(tmp.path().to_path_buf());
        assert_eq!(crate::status::read(&d).unwrap().unwrap().tunnels.len(), 0);
        let mut s = within("connect", ssh_connect_echo(srv.local_addr())).await;
        assert!(s.authenticate_password("zhang", pw.as_str()).await.unwrap().success());
        let port = s.tcpip_forward("", 0).await.unwrap() as u16;
        let st = crate::status::read(&d).unwrap().unwrap();
        assert_eq!(st.tunnels.len(), 1);
        assert_eq!(st.tunnels[0].port, port);
        assert_eq!(st.tunnels[0].account, "zhang");
        s.disconnect(russh::Disconnect::ByApplication, "", "").await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(crate::status::read(&d).unwrap().unwrap().tunnels.len(), 0);
        srv.shutdown().await;
        assert!(crate::status::read(&d).unwrap().is_none(), "干净退出后不留 status.json");
    }
```

- [ ] **Step 3: CLI**

```rust
pub fn refuse_root(is_root: bool, allow_root: bool) -> Option<String> {
    if is_root && !allow_root {
        Some("拒绝以 root 运行：本程序监听的不是特权端口，没有任何理由当 root。请换一个普通用户（推荐用 `rmc-gateway service print` 生成的单元，它就是这么做的）。容器里只有 root 的话加 --allow-root。".into())
    } else {
        None
    }
}

fn cmd_serve(p: &Parsed, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    if let Some(why) = refuse_root(crate::datadir::running_as_root(), p.opt("allow-root").is_some()) {
        let _ = writeln!(err, "{why}"); return 1;
    }
    let dir = p.data_dir();
    match dir.owned_by_current_user() {
        Ok(true) => {}
        Ok(false) => { let _ = writeln!(err, "数据目录 {} 的属主不是当前用户；serve 与 account 子命令要用同一个用户运行", dir.root().display()); return 1; }
        Err(e) => { let _ = writeln!(err, "检查数据目录失败：{e}"); return 1; }
    }
    let listen: std::net::SocketAddr = match p.opt("listen").unwrap_or("0.0.0.0:22000").parse() { Ok(a) => a, Err(e) => { let _ = writeln!(err, "--listen 不是 IP:端口：{e}"); return 2; } };
    let mut engineer_allow = Vec::new();
    for (k, v) in &p.opts { if k == "engineer-allow" { match crate::cidr::Cidr::parse(v) { Ok(c) => engineer_allow.push(c), Err(e) => { let _ = writeln!(err, "--engineer-allow：{e}"); return 2; } } } }
    let cfg = crate::server::ServerConfig {
        listen, data: dir.clone(), reverse_bind: "0.0.0.0".parse().unwrap(),
        engineer_allow, timings: crate::server::Timings::default(), limits: crate::throttle::Limits::default(),
    };
    let _ = writeln!(out, "数据目录 {}，监听 {listen}", dir.root().display());
    let rt = match tokio::runtime::Runtime::new() { Ok(r) => r, Err(e) => { let _ = writeln!(err, "建不出运行时：{e}"); return 1; } };
    match rt.block_on(crate::server::serve_until(cfg, async { let _ = tokio::signal::ctrl_c().await; })) {
        Ok(()) => 0,
        Err(e) => { let _ = writeln!(err, "{e}"); 1 }
    }
}
```

`--allow-root` 是无值开关：`parse` 里把 `allow-root` 当布尔处理（值为 `"true"`，不吃下一个参数）——在 `parse` 加一张无值开关表 `const FLAGS: &[&str] = &["allow-root"];`。

`serve` 里用 `--engineer-allow` 时把 `reverse_bind` 仍绑 `0.0.0.0`（白名单在 accept 后判断，不改绑定地址）。

`status`：

```rust
fn cmd_status(p: &Parsed, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let dir = p.data_dir();
    match crate::status::read(&dir) {
        Ok(Some(st)) if crate::status::is_live(&st, crate::status::now_unix()) => {
            let _ = writeln!(out, "运行中（pid {}），监听 {}，指纹 {}", st.pid, st.listen, st.fingerprint);
            if st.tunnels.is_empty() { let _ = writeln!(out, "没有在线隧道"); }
            for t in &st.tunnels { let _ = writeln!(out, "{}  端口 {}  来自 {}  自 {}  工程师连接 {}", t.account, t.port, t.peer, t.since, t.engineers); }
            0
        }
        Ok(Some(st)) => { let _ = writeln!(out, "没有在跑（最后一次状态更新 {}，pid {}）", crate::clock::rfc3339(std::time::UNIX_EPOCH + std::time::Duration::from_secs(st.updated_unix)), st.pid); 3 }
        Ok(None) => { let _ = writeln!(out, "没有在跑（数据目录 {} 下没有状态文件）", dir.root().display()); 3 }
        Err(e) => { let _ = writeln!(err, "{e}"); 1 }
    }
}
```

`service print`：

```rust
fn cmd_service_print(p: &Parsed, out: &mut dyn Write, _err: &mut dyn Write) -> i32 {
    let user = std::env::var("USER").or_else(|_| std::env::var("LOGNAME")).unwrap_or_else(|_| "rmc-gateway".into());
    let exe = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "/usr/local/bin/rmc-gateway".into());
    let dir = p.data_dir();
    let mut args = format!("serve --data-dir {}", dir.root().display());
    if let Some(l) = p.opt("listen") { args.push_str(&format!(" --listen {l}")); }
    for (k, v) in &p.opts { if k == "engineer-allow" { args.push_str(&format!(" --engineer-allow {v}")); } }
    let _ = write!(out, "\
# 安装：
#   rmc-gateway service print > rmc-gateway.service
#   sudo install -m 644 rmc-gateway.service /etc/systemd/system/
#   sudo systemctl daemon-reload && sudo systemctl enable --now rmc-gateway
# 本程序自己不做任何需要特权的事；装不装这个单元由管理员决定。
[Unit]
Description=Remote Maintenance Server (rmc-gateway)
After=network-online.target
Wants=network-online.target

[Service]
User={user}
ExecStart={exe} {args}
Restart=on-failure
RestartSec=2
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths={dir}

[Install]
WantedBy=multi-user.target
", dir = dir.root().display());
    0
}
```

`ProtectHome=read-only` 与数据目录默认在 `~/.rmc-gateway` 下：`ReadWritePaths` 会把那一个目录放开（systemd 的 `ReadWritePaths` 优先级高于 `ProtectHome`）。实现者在 Task 12 的部署手册里写一句「在 Debian 12 上实测过这份单元」——**本任务的验收不含真机 systemd**，只验文本。

`account add/passwd/revoke` 各在成功后 `AuditLog::open(&dir)?.record(AccountChanged { account, action: "add"|"passwd"|"revoke" })`。

CLI 测试追加：

```rust
    #[test]
    fn refuse_root_is_a_pure_rule() {
        assert!(refuse_root(true, false).is_some());
        assert!(refuse_root(true, true).is_none());
        assert!(refuse_root(false, false).is_none());
    }

    #[test]
    fn status_before_serve_says_not_running() {
        let tmp = tempfile::tempdir().unwrap();
        let (code, out, _) = run_in(tmp.path(), &["status"]);
        assert_eq!(code, 3);
        assert!(out.contains("没有在跑"), "{out}");
    }

    #[test]
    fn service_print_carries_the_data_dir_listen_and_allow_list() {
        let tmp = tempfile::tempdir().unwrap();
        let (code, out, _) = run_in(tmp.path(), &["service", "print", "--listen", "0.0.0.0:22000", "--engineer-allow", "10.0.0.0/8"]);
        assert_eq!(code, 0);
        for needle in ["[Service]", "User=", "ExecStart=", "serve --data-dir", "--listen 0.0.0.0:22000", "--engineer-allow 10.0.0.0/8", "NoNewPrivileges=yes", "ReadWritePaths="] {
            assert!(out.contains(needle), "缺 {needle}：\n{out}");
        }
        assert!(out.contains(&tmp.path().display().to_string()));
    }

    /// serve 真的把服务端拉起来、写了 status.json、收到 stop 后干净退出。
    #[tokio::test]
    async fn serve_until_runs_and_stops_cleanly() {
        let tmp = tempfile::tempdir().unwrap();
        let mut a = vec!["init".to_string(), "--public-addr".into(), "127.0.0.1:22000".into(), "--data-dir".into(), tmp.path().display().to_string()];
        let (mut o, mut e) = (Vec::new(), Vec::new());
        assert_eq!(run(&a, &mut o, &mut e), 0);
        a.clear();
        let d = crate::datadir::DataDir::at(tmp.path().to_path_buf());
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let cfg = crate::server::ServerConfig { listen: "127.0.0.1:0".parse().unwrap(), data: d.clone(), reverse_bind: "127.0.0.1".parse().unwrap(), engineer_allow: vec![], timings: crate::server::Timings::fast(), limits: crate::throttle::Limits::default() };
        let task = tokio::spawn(crate::server::serve_until(cfg, async { let _ = rx.await; }));
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(crate::status::read(&d).unwrap().is_some(), "serve 起来后要有 status.json");
        tx.send(()).unwrap();
        task.await.unwrap().unwrap();
        assert!(crate::status::read(&d).unwrap().is_none());
    }
```

- [ ] **Step 4: USAGE 定稿、tracing、闸门、提交**

`main.rs` 里在 `run` 之前装 `tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap())).with_writer(std::io::stderr).init()`——审计事件也经 `tracing::info!(target: "audit")` 打到 stderr，systemd 的 journal 里就能直接看。

```bash
cargo test -p rmc-gateway
cargo build --release -p rmc-gateway && ls -la target/release/rmc-gateway
git add crates/rmc-gateway Cargo.lock
git commit -m "feat(gateway): serve、status、service print，拒绝 root"
```

**本任务结束时，一台 Linux 上 `init → account add → serve` 已经能跑。** 用户此时可以先在真机上手工点一遍（用 Task 4 的 `ssh_connect` 那种测试客户端还连不上——要等 Task 8–9 客户端切过来）。

---

### Task 8: 客户端接线：连接码进表单与 `Command::Start`（rmc-core + rmc-app，先接线、不改校验）

这一步只把「连接码」这个值从界面一路送到隧道参数里，**TLS 仍走公共 CA、SSH 仍走 known_hosts、端口仍是 `Config::reverse_port`**——那三样分别在 Task 9、10 换。分成两步是为了每个任务边界都全绿、每次评审只看一件事；中间态在功能上自相矛盾（指纹传进去了却没人核对）是刻意的，只在 feat 分支上存在。

**Files:**
- Modify (rmc-core): `src/state.rs`（`Command::Start`）、`src/tunnel.rs`（`TunnelParams.fingerprint`）、`src/supervisor.rs`（`Credentials`、`begin`、`Command::Start` 分支、`spawn_with_validated_start`、8 处测试夹具）
- Modify (rmc-app): `src/form.rs`、`src/lib.rs`（`dispatch`、`Message::CodeChanged`、夹具）、`src/remember.rs`（`Account` → 按连接码记）、`src/view/maintain.rs`（运维服务器组）、`src/model.rs`（若有引用）、`tests/ui.rs`、`tests/wording.rs`（新增文案「连接码」不含禁用词，扫描自动覆盖）
- Test: 各文件既有测试模块改形 + 新增

**Interfaces:**
- Consumes: Task 1 的 `ConnectionCode`、`ServerFingerprint`、`CodeError`
- Produces:
  - `rmc_core::Command::Start { code: ConnectionCode, password: Zeroizing<String>, appliance: HostPort }`；`Debug` 打印 `code` 的账号与地址、`appliance`、`<redacted>`
  - `rmc_core::tunnel::TunnelParams { username, password, reverse_port, gateway, appliance, fingerprint: ServerFingerprint }`（`reverse_port` Task 10 删）
  - `rmc_app::form::Form { appliance_host, appliance_port, code: String, password, remember, detected_proxy }`；`Field::{ApplianceHost, AppliancePort, Code, Password}`；`Form::validate() -> Result<Validated, Vec<FieldError>>`，`pub struct Validated { pub code: ConnectionCode, pub appliance: HostPort }`；`Form::parsed_code() -> Option<ConnectionCode>`（给界面画只读的地址与账号）
  - `rmc_app::Message::CodeChanged(String)`（替掉 `GatewayHostChanged`/`GatewayPortChanged`/`UsernameChanged`）
  - `rmc_app::remember::Account { code: String }`，`key()` = `账号@IP:端口`（**与今天的键形态一致**，所以「记住密码」的密文定位规则不变），`encode()` = 连接码一行，文件名从 `last-account.txt` 改成 `connection-code.txt`（`AppPaths::connection_code()`）

- [ ] **Step 1: rmc-core——先改类型，让编译器把要改的地方全列出来**

`state.rs`：

```rust
    Start {
        code: ConnectionCode,
        password: Zeroizing<String>,
        appliance: HostPort,
    },
```

`Debug`：`.field("account", &code.account().as_str()).field("server", &code.server()).field("password", &"<redacted>").field("appliance", appliance)`。既有测试 `command_start_debug_never_prints_the_password` 改用 `ConnectionCode::parse(TEST_CODE)`；在 `state.rs` 的测试模块里放一个共用夹具：

```rust
#[cfg(test)]
pub(crate) fn test_code() -> ConnectionCode {
    ConnectionCode::new(
        AccountName::parse("tunnel-zhang").unwrap(),
        "203.0.113.10".parse().unwrap(),
        22000,
        ServerFingerprint::of_ed25519_public(&[9u8; 32]),
    )
}
```

`tunnel.rs`：`TunnelParams` 加 `pub fingerprint: ServerFingerprint`，`Debug` 里打印它（不是秘密）。

`supervisor.rs`：

```rust
struct Credentials {
    code: ConnectionCode,
    password: Zeroizing<String>,
    appliance: HostPort,
}
impl Credentials {
    fn params(&self, reverse_port: u16) -> TunnelParams {
        TunnelParams {
            username: self.code.account().to_string(),
            password: self.password.clone(),
            reverse_port,
            gateway: self.code.server(),
            appliance: self.appliance.clone(),
            fingerprint: *self.code.fingerprint(),
        }
    }
    fn addrs(&self) -> ValidatedAddresses { ... } // 若别处还要 ValidatedAddresses，就在 begin 里算一次存起来
}
```

`Command::Start { code, password, appliance }` 分支：`ValidatedAddresses::validate(code.server(), appliance.clone())` 失败照旧清空 `ctx.creds`（R62）并发 Failed；成功则 `begin(&mut ctx, code, password, appliance)`。`begin` 的审计行不变：「开始连接：账号 {code.account()}，运维服务器 {code.server()}，一体机 {appliance}」。`spawn_with_validated_start` 改收 `(code, password, appliance)`。8 处 `Command::Start {` 夹具与 11 处 `gateway.company.com` 夹具改用 `crate::state::test_code()`（**注意** 现有夹具的运维服务器是域名 `gateway.company.com`，连接码不接受域名，全部换成 `203.0.113.10`；有测试断言审计文案里含域名的，改成含 IP）。

- [ ] **Step 2: rmc-core 全绿**

```bash
cargo test -p rmc-core
```

预期与基线同数（230 lib + 集成用例不变）。这一步没有新测试——它是纯改形，靠既有测试守。

- [ ] **Step 3: rmc-app——form.rs 的失败测试**

```rust
    const GOOD_CODE: &str = "rmc1:tunnel-zhang@203.0.113.10:22000:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:0000";
    // ↑ 实现者用 Task 1 的 ConnectionCode::new(...).to_string() 生成一条真的，
    //   把指纹与校验位填进来；不要手写。测试模块里放 fn good_code() -> String 动态生成更稳。

    /// 连接码格式错，红字指向连接码这一框，而且是 rmc-core 给的那句话。
    /// 改红：`validate` 里把 `CodeError` 的文案换成一句固定的话。
    #[test]
    fn a_bad_code_marks_the_code_field_with_the_parser_message() {
        let mut f = filled();
        f.code = "rmc1:nonsense".into();
        let errs = f.visible_errors();
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].field, Field::Code);
        match &errs[0].reason { Reason::Rejected(msg) => assert!(msg.contains("格式不对"), "{msg}"), r => panic!("{r:?}") }
    }

    #[test]
    fn a_domain_in_the_code_is_refused_with_the_dedicated_text() {
        let mut f = filled();
        f.code = good_code().replace("203.0.113.10", "ops.example.com"); // 校验位随之失效——先撞 Checksum，也是 Rejected
        assert!(f.is_marked(Field::Code));
    }

    #[test]
    fn empty_code_blocks_start_silently_like_the_other_empty_fields() {
        let mut f = filled();
        f.code.clear();
        assert!(!f.can_start());
        assert!(f.visible_errors().is_empty(), "空着不标红");
    }

    /// 一体机地址不能等于运维服务器地址——这条校验以前靠 gateway_host，现在靠连接码里的 IP。
    #[test]
    fn appliance_equal_to_the_server_in_the_code_is_rejected() {
        let mut f = filled();
        f.appliance_host = "203.0.113.10".into();
        f.appliance_port = "22000".into();
        assert!(f.is_marked(Field::ApplianceHost));
    }

    #[test]
    fn parsed_code_exposes_address_and_account_for_the_read_only_line() {
        let f = filled();
        let c = f.parsed_code().expect("好的连接码");
        assert_eq!(c.account().as_str(), "tunnel-zhang");
        assert_eq!(c.server().to_string(), "203.0.113.10:22000");
        let mut bad = f.clone();
        bad.code = "x".into();
        assert!(bad.parsed_code().is_none());
    }
```

`filled()` 夹具：`appliance 192.168.1.1:61001`、`code: good_code()`、`password "pw"`。

- [ ] **Step 4: form.rs 实现**

```rust
#[derive(Clone, Default)]
pub struct Form {
    pub appliance_host: String,
    pub appliance_port: String,
    /// 连接码原文。地址、账号、指纹都从它解析，界面上没有分开的框。
    pub code: String,
    pub password: Zeroizing<String>,
    pub remember: bool,
    pub detected_proxy: Option<String>,
}

pub struct Validated {
    pub code: ConnectionCode,
    pub appliance: HostPort,
}

impl Form {
    pub fn parsed_code(&self) -> Option<ConnectionCode> {
        ConnectionCode::parse(self.code.trim()).ok()
    }

    pub fn validate(&self) -> Result<Validated, Vec<FieldError>> {
        let mut errs = Vec::new();
        let appliance = parse_addr(&self.appliance_host, &self.appliance_port, Field::ApplianceHost, Field::AppliancePort, &mut errs);
        let code = if self.code.trim().is_empty() {
            errs.push(FieldError { field: Field::Code, reason: Reason::Empty });
            None
        } else {
            match ConnectionCode::parse(self.code.trim()) {
                Ok(c) => Some(c),
                Err(e) => { errs.push(FieldError { field: Field::Code, reason: Reason::Rejected(e.to_string()) }); None }
            }
        };
        if self.password.is_empty() {
            errs.push(FieldError { field: Field::Password, reason: Reason::Empty });
        }
        let validated = match (appliance, code) {
            (Some(a), Some(c)) => match ValidatedAddresses::validate(c.server(), a.clone()) {
                Ok(_) => Some(Validated { code: c, appliance: a }),
                Err(e) => { errs.push(FieldError { field: Field::ApplianceHost, reason: Reason::Rejected(e.to_string()) }); None }
            },
            _ => None,
        };
        match validated { Some(v) if errs.is_empty() => Ok(v), _ => Err(errs) }
    }
}
```

`Field` 去掉 `GatewayHost/GatewayPort/Username`，加 `Code`，`label()` 给「连接码」。`Debug for Form` 打印 `code`（不是秘密）。既有的 `Field::Gateway*` 测试删除或改到 `Code`。

- [ ] **Step 5: lib.rs、view/maintain.rs、remember.rs**

`lib.rs`：`Message::CodeChanged(String)`（删三个旧的），`update` 里 `self.form.code = s`；`dispatch(Action::Start)`：

```rust
            Action::Start => match self.form.validate() {
                Ok(v) => self.send(Command::Start { code: v.code, password: self.form.password.clone(), appliance: v.appliance }),
                Err(errors) => tracing::warn!(?errors, "表单还没填对，不发起连接"),
            },
```

既有测试 `pressing_start_sends_the_addresses_the_user_typed` 改成断言 `code.server()` 与 `code.account()` 等于夹具里的；`filled_form()` 夹具改用连接码。

`view/maintain.rs` 运维服务器组：`addr_row("地址", …)` 换成

```rust
        line(row![
            row_label("连接码"),
            input(&form.code, "粘贴运维发来的连接码", form.is_marked(Field::Code), editable, Message::CodeChanged).width(Length::Fill),
        ]),
        parsed_line(form),   // 解析成功：「地址 203.0.113.10:22000 · 账号 tunnel-zhang」（TEXT_SUB 小字）；失败：空行占位
        egress,
```

`parsed_line`：

```rust
fn parsed_line<'a>(form: &Form) -> Element<'a, Message> {
    let t = match form.parsed_code() {
        Some(c) => format!("地址 {} · 账号 {}", c.server(), c.account()),
        None => String::new(),
    };
    line(row![row_label(""), text(t).size(12).color(color::TEXT_SUB)])
}
```

账号那一行（`row_label("账号")` 与 `input(&form.username …)`）**删掉**。密码、记住密码不动。`tests/ui.rs` 里凡是找「账号」输入框、「运维服务器地址」标签的用例改成找「连接码」；新增一条：粘一条好连接码后页面上出现「账号 tunnel-zhang」小字，粘坏的出现红字。

`remember.rs`：

```rust
pub struct Account { pub code: String }
impl Account {
    pub fn from_form(form: &Form) -> Option<Self> {
        let c = form.parsed_code()?;
        Some(Self { code: c.to_string() })
    }
    /// 密文的定位键：账号@IP:端口——与旧版三段式的键**形态一致**。
    pub fn key(&self) -> String {
        let c = ConnectionCode::parse(&self.code).expect("from_form 只造合法的");
        format!("{}@{}:{}", c.account(), c.ip(), c.port())
    }
    pub fn encode(&self) -> String { format!("{}\n", self.code) }
    pub fn decode(text: &str) -> Option<Self> {
        let line = text.lines().next()?.trim();
        ConnectionCode::parse(line).ok()?;
        Some(Self { code: line.to_string() })
    }
}
```

`AppPaths::last_account()` 改名 `connection_code()`，文件名 `connection-code.txt`；`Recall::fill` 把 `form.code = account.code`。remember.rs 的 41 处引用逐一改：凡是构造 `Account { username, host, port }` 的夹具改成 `Account { code: good_code() }`；断言文件「只有三行、没有口令」的改成「只有一行、是一条能解析的连接码、没有口令」。**W202 那两条（换账号时旧密文当场清掉、`secrets\` 下只剩一个 `.sealed`）的语义不变**，键形态一致所以实现不用动、测试只改夹具。

- [ ] **Step 6: 全绿、闸门、提交**

```bash
cargo test -p rmc-app   # 218 lib + 33 ui + 4 wording 附近，数字以实际为准并写进报告
cargo test --workspace
```

变异两枪：`validate` 里 `CodeError` 文案换固定话；`Account::key` 里少拼端口（W202 那两条会抓住吗？——要真的跑一下，答案写进报告）。

```bash
git add crates/rmc-core crates/rmc-app
git commit -m "feat(client): 连接码进表单与 Command::Start（接线，校验下一任务换）"
```

---

### Task 9: 客户端 TLS：指纹核对替掉公共 CA，`Transport` 拆成拨号与 TLS 两段，预检改四步

**Files:**
- Modify (rmc-core): `Cargo.toml`（删 `webpki-roots`；dev-dep 加 `rcgen`）、`src/transport/tls.rs`（重写）、`src/transport/mod.rs`（`new` 少一个参数、`dial`、`connect(gateway, pin)`）、`src/error.rs`（`TlsInvalidCert` → `TlsPinMismatch`）、`src/ssh/mod.rs`（`establish` 传指纹）、`src/preflight.rs`（四步）、`src/supervisor.rs`（预检传指纹）
- Delete (rmc-core): `tests/transport.rs`、`tests/preflight.rs`（都依赖 docker harness 的公共 CA 夹具；等价覆盖在 Task 12 的进程内端到端里回来）
- Modify (rmc-app): `src/wiring.rs`（`Transport::new` 两参）、`src/diag.rs`（处置建议：指纹不符那一条；步骤名常量）、`src/view/diagnostics.rs`（若引用步骤名）、`tests/ui.rs`（若引用步骤名）
- Test: `tls.rs`、`transport/mod.rs`、`preflight.rs`、`diag.rs` 的测试模块

**Interfaces:**
- Consumes: Task 8 的 `TunnelParams.fingerprint`；Task 1 的 `ServerFingerprint`
- Produces:
  - `transport::tls::wrap_tls<S: Io>(stream: S, server: &HostPort, pin: &ServerFingerprint) -> Result<TlsStream<S>>`（只开 1.3；只核对证书公钥与握手签名）
  - `transport::tls::ED25519_SPKI_PREFIX`（与 gateway 一侧同一常量，各自定义、各自测）
  - `Transport::new(resolver, authenticator)`；`Transport::dial(&self, gateway: &HostPort) -> Result<TcpStream>`（TCP + 代理 CONNECT，记录 `last_hop`）；`Transport::connect(&self, gateway, pin) -> Result<Conn>` = `dial` + `wrap_tls`
  - `Error::TlsPinMismatch(String)`：「运维服务器的身份与连接码里的指纹不一致：{0}」，`ErrorClass::Fatal`（不重试）
  - `preflight::{STEP_APPLIANCE_TCP, STEP_APPLIANCE_HOSTKEY, STEP_GATEWAY_REACH = "运维服务器连通", STEP_GATEWAY_TLS = "运维服务器 TLS 与指纹"}`；`preflight::run(transport, gateway, pin, appliance)`；`Preflight::run(&self, gateway, pin, appliance)`
  - rmc-app `diag::advice_for`：TLS 步失败且 detail 含「指纹」→「运维服务器的身份与连接码里的指纹对不上，连接已经拒绝。两种可能：路径上有做中间人的 TLS 审计设备（请客户网管对这个 IP 与端口免做审计），或者连接码已经过期（运维服务器换过密钥，请向运维重新索取连接码）。」；「连通」步失败 → 「连不上运维服务器的这个端口。请确认这台笔记本能出网；客户网络只放行 443 时，请客户网管放行这个 IP 的端口，或由运维把公网 443 映射到运维服务器后重发连接码。」

- [ ] **Step 1: tls.rs 的失败测试（一正一反，成对）**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use rmc_core::code::ServerFingerprint; // 同 crate：crate::code::ServerFingerprint
    use std::sync::Arc;

    /// 用一把随机 ed25519 种子造一个只开 1.3 的 TLS 服务端——与 rmc-gateway 的 Identity 同一套做法，
    /// 这里独立写一遍（rmc-core 不能依赖 rmc-gateway）。
    fn ed25519_server() -> (Arc<rustls::ServerConfig>, ServerFingerprint) {
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        let kp = russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&seed);
        let fp = ServerFingerprint::of_ed25519_public(&kp.public.0);
        let mut pkcs8 = vec![0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
        pkcs8.extend_from_slice(&seed);
        let key = rcgen::KeyPair::try_from(pkcs8.as_slice()).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["x".into()]).unwrap().self_signed(&key).unwrap();
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13]).unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(pkcs8))).unwrap();
        (Arc::new(cfg), fp)
    }

    async fn serve_once(cfg: Arc<rustls::ServerConfig>) -> u16 {
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

    /// 改红：`PinnedServer::verify_server_cert` 里把 `!=` 改成 `==`——这条红、下一条绿；
    /// 把 `ED25519_SPKI_PREFIX` 的任何一个字节改掉——这条红。
    #[tokio::test]
    async fn wrap_tls_accepts_the_server_whose_key_matches_the_pin() {
        use tokio::io::AsyncReadExt;
        let (cfg, fp) = ed25519_server();
        let port = serve_once(cfg).await;
        let stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut tls = wrap_tls(stream, &HostPort::new("127.0.0.1", port).unwrap(), &fp).await.expect("指纹对就该握成");
        let mut buf = [0u8; 16];
        let n = tls.read(&mut buf).await.unwrap();
        assert!(buf[..n].starts_with(b"SSH-2.0-"));
    }

    #[tokio::test]
    async fn wrap_tls_rejects_a_server_whose_key_does_not_match_as_fatal() {
        let (cfg, _fp) = ed25519_server();
        let port = serve_once(cfg).await;
        let stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let other = ServerFingerprint::of_ed25519_public(&[1u8; 32]);
        let err = wrap_tls(stream, &HostPort::new("127.0.0.1", port).unwrap(), &other).await.unwrap_err();
        assert!(matches!(err, Error::TlsPinMismatch(_)), "{err:?}");
        assert_eq!(err.class(), crate::error::ErrorClass::Fatal);
        assert!(!err.to_string().contains("证书链"), "文案要说指纹，不说证书链：{err}");
    }

    /// 「只用 TLS 1.3」是构造上的保证：本 crate 的 rustls 不开 `tls12` feature，1.2 的协商路径
    /// 根本编不出来。这条测试钉住 Cargo.toml，别让谁顺手把 feature 加回来。
    /// 改红：给 rustls 或 tokio-rustls 的 features 加回 "tls12"。
    #[test]
    fn tls12_is_not_compiled_in() {
        let manifest = include_str!("../../Cargo.toml");
        for line in manifest.lines().filter(|l| l.contains("rustls")) {
            assert!(!line.contains("tls12"), "rustls 不许开 tls12：{line}");
        }
    }
}
```


- [ ] **Step 2: tls.rs 实现**

```rust
//! TLS 外层。**不做公共 CA 校验**：运维服务器没有域名、证书自签，客户端核对的是
//! 连接码里的指纹——证书里的 ed25519 公钥的 SHA-256。只开 TLS 1.3。
//! 有效期、名称、证书链一概不看：那些是 CA 体系的概念，这里没有 CA。

use crate::addr::HostPort;
use crate::code::ServerFingerprint;
use crate::error::{Error, Result};
use crate::platform::Io;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::sync::Arc;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

pub const ED25519_SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

#[derive(Debug)]
struct PinnedServer {
    want: ServerFingerprint,
    algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedServer {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, _intermediates: &[CertificateDer<'_>], _server_name: &ServerName<'_>, _ocsp: &[u8], _now: UnixTime) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let parsed = rustls::server::ParsedCertificate::try_from(end_entity)?;
        let spki = parsed.subject_public_key_info();
        let der: &[u8] = spki.as_ref();
        let mismatch = || rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure);
        if der.len() != 44 || der[..12] != ED25519_SPKI_PREFIX { return Err(mismatch()); }
        let pk: [u8; 32] = der[12..].try_into().map_err(|_| mismatch())?;
        if ServerFingerprint::of_ed25519_public(&pk) != self.want { return Err(mismatch()); }
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _m: &[u8], _c: &CertificateDer<'_>, _d: &rustls::DigitallySignedStruct) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("只用 TLS 1.3".into()))
    }
    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &rustls::DigitallySignedStruct) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
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

/// 在已有字节流上完成 TLS 握手，核对服务器公钥的指纹。`server` 只是 IP，没有 SNI 意义。
pub async fn wrap_tls<S: Io>(stream: S, server: &HostPort, pin: &ServerFingerprint) -> Result<TlsStream<S>> {
    let name = ServerName::try_from(server.host().to_string())
        .map_err(|_| Error::Config(format!("运维服务器地址不能用于 TLS：{server}")))?;
    connector(pin)?.connect(name, stream).await.map_err(classify_tls_error)
}

fn classify_tls_error(e: std::io::Error) -> Error {
    let msg = e.to_string();
    if msg.contains("invalid peer certificate") { Error::TlsPinMismatch(msg) } else { Error::TlsHandshake(msg) }
}
```

`Cargo.toml`：rustls 的 features 去掉 `"tls12"`（tokio-rustls 同），删 `webpki-roots`，dev-dependencies 加 `rcgen = { version = "0.14", default-features = false, features = ["ring"] }`。`error.rs`：`TlsInvalidCert` 改名 `TlsPinMismatch`，文案「运维服务器的身份与连接码里的指纹不一致：{0}」，仍归 `Fatal`；`error.rs` 里既有的分类测试改名。

- [ ] **Step 3: Transport 拆两段**

```rust
impl Transport {
    pub fn new(resolver: Arc<dyn ProxyResolver>, authenticator: Arc<dyn ProxyAuthenticator>) -> Self { ... }

    /// TCP 拨号（经代理时含 CONNECT）。不做 TLS。预检的「运维服务器连通」用它。
    pub async fn dial(&self, gateway: &HostPort) -> Result<TcpStream> {
        // 原 connect 的前半段原样搬过来，到 http_connect 成功为止
    }

    pub async fn connect(&self, gateway: &HostPort, pin: &ServerFingerprint) -> Result<Conn> {
        let stream = self.dial(gateway).await?;
        let tls = tls::wrap_tls(stream, gateway, pin).await?;
        Ok(Box::new(tls))
    }
}
```

`transport/mod.rs` 既有测试里 `Transport::new(.., TlsRoots::webpki())` 改成两参；`resolve_dns` 保留（诊断包环境信息可能还用；grep 一下，没人用就删）。`ssh/mod.rs` 的 `establish`：`self.transport.connect(&params.gateway, &params.fingerprint)`。`wiring.rs`：`Transport::new(recorder, authenticator)`。

- [ ] **Step 4: 预检四步**

`preflight.rs` 的 `steps!` 改成：

```rust
steps! {
    STEP_APPLIANCE_TCP = "一体机 TCP";
    STEP_APPLIANCE_HOSTKEY = "一体机 host key 指纹";
    STEP_GATEWAY_REACH = "运维服务器连通";
    STEP_GATEWAY_TLS = "运维服务器 TLS 与指纹";
}
```

`run(transport, gateway, pin, appliance)` 的后两步：

```rust
    let proxy = transport.effective_proxy(gateway).await;
    let via = match &proxy { Some(p) => format!("经代理 {p}"), None => "直连".to_string() };
    let dial = bounded(transport.dial(gateway), || Error::Tcp(format!("连接 {gateway} 超时（含 TCP 拨号与代理 CONNECT）"))).await;
    match dial {
        Ok(stream) => {
            steps.push(PreflightStep { name: STEP_GATEWAY_REACH, outcome: StepOutcome::Pass { detail: format!("{gateway} 可达 · {via}") } });
            let tls = bounded(crate::transport::tls::wrap_tls(stream, gateway, pin), || Error::TlsHandshake(format!("与 {gateway} 的 TLS 握手超时"))).await;
            let outcome = match tls {
                Ok(t) => { drop(t); StepOutcome::Pass { detail: "TLS 1.3 · 指纹与连接码一致".into() } }
                Err(e) => fail(&e),
            };
            steps.push(PreflightStep { name: STEP_GATEWAY_TLS, outcome });
        }
        Err(e) => {
            steps.push(PreflightStep { name: STEP_GATEWAY_REACH, outcome: fail(&e) });
            steps.push(PreflightStep { name: STEP_GATEWAY_TLS, outcome: StepOutcome::Skipped { detail: "运维服务器未连通，未执行".into() } });
        }
    }
```

`Preflight` trait 与 `TransportPreflight` 同步加 `pin` 参数；supervisor 里 `preflight.run(&params.gateway, &params.fingerprint, &params.appliance)`；supervisor 测试里的假 `Preflight` 实现同步改签名。`preflight.rs` 既有单元测试里引用 `STEP_GATEWAY_DNS` 的改到 `STEP_GATEWAY_REACH`，「DNS 失败则 TLS 跳过」那条改成「连通失败则 TLS 跳过」（用一个没人监听的 127.0.0.1 端口即可，不需要 docker）。新增一条单元测试：对着 `tls.rs` 测试里那种 `ed25519_server`（把它提成 `pub(crate)` 的 test_support），指纹对 → 四步全过；指纹错 → 第四步 `Fail` 且 `class == Fatal`，第三步仍 `Pass`。

- [ ] **Step 5: rmc-app 的处置建议**

`diag.rs` `advice_for`：

```rust
        STEP_GATEWAY_REACH => "连不上运维服务器的这个端口。请确认这台笔记本能出网；客户网络只放行 443 时，请客户网管放行这个 IP 的端口，或由运维把公网 443 映射到运维服务器后重发连接码。",
        STEP_GATEWAY_TLS if detail.contains("指纹") => "运维服务器的身份与连接码里的指纹对不上，连接已经拒绝。两种可能：路径上有做中间人的 TLS 审计设备（请客户网管对这个 IP 与端口免做审计），或者连接码已经过期（运维服务器换过密钥，请向运维重新索取连接码）。",
        STEP_GATEWAY_TLS if detail.contains("代理要求认证") => …（不变）,
```

原来「域名解析失败」与「证书不在信任根里」两条**删掉**（连同它们的测试），`STEP_GATEWAY_TLS if detail.contains("host key")` 那条保留到 Task 10 再改。`advice_for` 的测试表按新文案改：`failed("运维服务器的身份与连接码里的指纹不一致：…")` → 含「指纹」「连接码」；`failed("TCP 连接失败：…")` 在 REACH 步 → 含「出网」「443」。

- [ ] **Step 6: 删掉两份 docker 集成测试，全绿，提交**

```bash
git rm crates/rmc-core/tests/transport.rs crates/rmc-core/tests/preflight.rs
cargo test --workspace
cargo deny check advisories bans licenses sources    # webpki-roots 没了，锁文件少一个包
git add -A crates/rmc-core crates/rmc-app Cargo.lock
git commit -m "feat(client): TLS 改为核对连接码里的指纹，Transport 拆成拨号与 TLS，预检改四步"
```

变异三枪：`!=`→`==`；`ED25519_SPKI_PREFIX` 改一个字节；预检里连通失败时不推 Skipped（四步变三步——`report_lists_four_steps_in_fixed_order` 那类测试要红）。

---

### Task 10: 客户端 SSH：host key 比对同一个指纹（删 known_hosts）、申请端口 0、`Config` 瘦身

**Files:**
- Modify (rmc-core): `src/ssh/handler.rs`、`src/ssh/mod.rs`、`src/ssh/test_support.rs`、`src/ssh/pump.rs`（若引用 reverse_port）、`src/tunnel.rs`、`src/state.rs`、`src/config.rs`、`src/error.rs`、`src/supervisor.rs`、`src/knownhosts.rs`（只留指纹工具）、`src/audit.rs`/`src/diagnostic.rs`/`src/addr.rs`（若有 KnownHosts 引用）
- Delete (rmc-core): `tests/ssh_tunnel.rs`、`tests/forwarding.rs`、`tests/common/`、`tests/data/`、`tests/fetch-harness-cert.sh`
- Modify (rmc-app): `src/wiring.rs`、`src/model.rs`、`src/diag.rs`、`src/view/diagnostics.rs`、`src/view/maintain.rs`（若引用）、`tests/ui.rs`
- Test: 各文件测试模块

**Interfaces:**
- Consumes: Task 8 的 `TunnelParams.fingerprint`；Task 9 的 `Transport::connect(gateway, pin)`
- Produces:
  - `TunnelParams { username, password, gateway, appliance, fingerprint }`（**`reverse_port` 删掉**）
  - `TunnelMsg::Authenticated { fingerprint: ServerFingerprint }`（`first_seen` 删掉）；`TunnelMsg::ForwardRegistered { port: u16 }` 不变，但 `port` 现在是**服务端回填的**
  - `TunnelEvent::ServerVerified { fingerprint: String }`（替掉 `HostKey { fingerprint, first_seen }`）；**新增** `TunnelEvent::ForwardPort(u16)`
  - `Error::HostKeyMismatch { expected: String, actual: String }`：「运维服务器的 SSH 身份与连接码里的指纹不一致（连接码 {expected}，本次 {actual}），已拒绝连接。可能路径上有中间人，或连接码已过期（运维服务器换过密钥）」，仍 `Fatal`
  - `Error::ForwardPortBusy`（无字段）：「反向端口被占用：这个账号上一条隧道的监听尚未回收」，仍 `PortBusy`
  - `Error::SshTransport` 新增一种文案：「运维服务器的 host key 不是 ed25519」
  - `Config { gateway, appliance, log_dir }`（`reverse_port`、`known_hosts_path`、`ALLOWED_REVERSE_PORTS`、`validate` 里的端口检查全删）
  - `SshTunnelFactory::new(transport: Arc<Transport>)`（不再收 `KnownHosts`）
  - `knownhosts.rs` 只剩 `fingerprint_sha256`、`fingerprint_of`、`Fingerprint`、`redact_for_error`（给一体机指纹用；`KnownHosts`、`Verdict`、`check`、`open`、文件读写全删）；模块文档改成「OpenSSH 风格的指纹工具，只给一体机 host key 的展示用」
  - rmc-app：`Model.server_fingerprint: Option<String>`、`Model.forward_port: Option<u16>`（替掉 `host_key`）；`AppPaths::known_hosts()` 删；`diag::HOST_KEY_ROW = "运维服务器指纹"`，`HostKeyRecord` → `pub struct ServerVerified { pub fingerprint: String }`，行文案「{fingerprint}（与连接码一致）」

- [ ] **Step 1: handler.rs 的失败测试（`ssh/mod.rs` 测试模块，用 test_support 的进程内假服务端）**

先把 `test_support` 改过来：`GatewayHandler::tcpip_forward` 当 `*port == 0` 时 `*port = self.permitted_port` 并返回 true，非 0 且不等则 false；`test_params()` 去掉 reverse_port；`expected_fingerprint()` 改成返回 `ServerFingerprint`（从 `test_host_key().public_key().key_data().ed25519()` 算）；`tmp_known_hosts` 删掉；`test_params_with_fingerprint(fp)` 新增。**`TEST_HOST_KEY_OPENSSH_PEM` 必须是 ed25519**——它现在就是（`ssh-ed25519`），实现者核一眼。

```rust
    /// 指纹对：认证通过、Authenticated 带指纹、ForwardRegistered 带的是服务端回填的端口。
    /// 改红：`establish_over` 里把 `tcpip_forward("", 0)` 的返回值丢掉、`ForwardRegistered` 填 0——第三格红。
    #[tokio::test]
    async fn pinned_fingerprint_matches_and_the_port_comes_back_from_the_server() {
        let (_reads, _pending, conn) = spawn_gateway(GatewayConfig { permitted_port: 22007, ..Default::default() });
        let (tx, mut rx) = mpsc::channel(32);
        let handle = with_timeout("establish_over", establish_over(conn, test_params(), tx)).await.unwrap();
        match next_msg(&mut rx).await {
            TunnelMsg::Authenticated { fingerprint } => assert_eq!(fingerprint, expected_fingerprint()),
            other => panic!("{other:?}"),
        }
        match next_msg(&mut rx).await {
            TunnelMsg::ForwardRegistered { port } => assert_eq!(port, 22007),
            other => panic!("{other:?}"),
        }
        handle.shutdown().await;
    }

    /// 指纹错：握手阶段就拒绝，Fatal，**不发 Authenticated**，口令根本没送出去。
    /// 改红：`check_server_key` 里把 `!=` 改成 `==`——第一格红（而且上一条也红）。
    #[tokio::test]
    async fn a_wrong_fingerprint_is_fatal_before_any_password_is_sent() {
        let (reads, _pending, conn) = spawn_gateway(GatewayConfig::default());
        let (tx, mut rx) = mpsc::channel(32);
        let wrong = ServerFingerprint::of_ed25519_public(&[3u8; 32]);
        let err = expect_err(with_timeout("establish_over", establish_over(conn, test_params_with_fingerprint(wrong), tx)).await);
        assert!(matches!(err, Error::HostKeyMismatch { .. }), "{err:?}");
        assert_eq!(err.class(), ErrorClass::Fatal);
        assert!(err.to_string().contains("连接码"), "{err}");
        assert!(rx.try_recv().is_err(), "不该有任何隧道消息");
        // 服务端没读到过 USERAUTH：读时间戳只有 KEX 那几拍——实现者按 test_support 的 Sniff 实际能力断言
        let _ = reads;
    }

    /// 服务端拒绝转发（比如同账号已在线）→ PortBusy，不带端口号也说得清。
    #[tokio::test]
    async fn a_denied_forward_is_port_busy_class() {
        let (_r, _p, conn) = spawn_gateway(GatewayConfig { accept_forward: false, ..Default::default() }); // test_support 加这个开关
        let (tx, _rx) = mpsc::channel(32);
        let err = expect_err(with_timeout("establish_over", establish_over(conn, test_params(), tx)).await);
        assert!(matches!(err, Error::ForwardPortBusy), "{err:?}");
        assert_eq!(err.class(), ErrorClass::PortBusy);
    }

```

第四条**不用新写**：`pump.rs` 测试模块里既有的 `forwarded_payload_bytes_never_reach_a_tracing_event`
先开一条 `connected_port = 22002` 的通道（被拒）、再开 22001 的（接受），断言只出现一次
`RemoteSessionOpened`。假服务端回填的就是 22001，所以它现在验的是「按 `registered_port` 过滤」。
改红：`server_channel_open_forwarded_tcpip` 里把与 `registered_port` 的比较删掉——它红。
把这句写进那条测试的文档注释。

- [ ] **Step 2: 实现**

`handler.rs`：

```rust
pub struct ClientHandler {
    pub fingerprint: ServerFingerprint,
    pub appliance: HostPort,
    /// 服务端回填的反向端口；0 = 还没申请。forwarded-tcpip 通道按它过滤。
    pub registered_port: Arc<AtomicU16>,
    pub tx: mpsc::Sender<TunnelMsg>,
    pub next_session_id: Arc<AtomicU64>,
    pub channels: super::pump::SharedChannels,
}

impl russh::client::Handler for ClientHandler {
    type Error = Error;

    async fn check_server_key(&mut self, server_public_key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        // `public_key()` 返回拥有值，先绑定再借（否则 E0716，探针里撞过）。
        let pk = server_public_key.public_key();
        let Some(ed) = pk.key_data().ed25519() else {
            return Err(Error::SshTransport("运维服务器的 host key 不是 ed25519".into()));
        };
        let actual = ServerFingerprint::of_ed25519_public(&ed.0);
        if actual != self.fingerprint {
            return Err(Error::HostKeyMismatch { expected: self.fingerprint.to_string(), actual: actual.to_string() });
        }
        Ok(true)
    }

    async fn server_channel_open_forwarded_tcpip(&mut self, channel, _connected_address, connected_port, _oa, _op, reply, _session) -> Result<(), Self::Error> {
        let want = self.registered_port.load(Ordering::SeqCst);
        if want == 0 || connected_port != u32::from(want) {
            tracing::warn!(connected_port, want, "拒绝未注册端口的 forwarded-tcpip 通道");
            reply.reject(russh::ChannelOpenFailure::AdministrativelyProhibited).await;
            return Ok(());
        }
        reply.accept().await;
        let id = self.alloc_session_id();
        super::pump::spawn(id, channel, self.appliance.clone(), self.tx.clone(), self.channels.clone());
        Ok(())
    }
}
```

`ssh/mod.rs`：

```rust
pub(crate) async fn establish_over(conn: Conn, params: TunnelParams, tx: mpsc::Sender<TunnelMsg>) -> Result<Box<dyn TunnelHandle>> {
    let config = client_config();
    let channels = pump::new_shared_channels();
    let registered_port = Arc::new(AtomicU16::new(0));
    let handler = handler::ClientHandler { fingerprint: params.fingerprint, appliance: params.appliance.clone(), registered_port: registered_port.clone(), tx: tx.clone(), next_session_id: Arc::new(AtomicU64::new(1)), channels: channels.clone() };
    let mut session = russh::client::connect_stream(config, conn, handler).await?;
    let ok = session.authenticate_password(&params.username, params.password.as_str()).await?;
    if !ok.success() { return Err(Error::AuthRejected); }
    let _ = tx.send(TunnelMsg::Authenticated { fingerprint: params.fingerprint }).await;
    // 申请端口 0：端口由运维服务器按账号分配，客户端不知道也不需要知道。
    let port = session.tcpip_forward("", 0).await.map_err(map_tcpip_forward_error)?;
    let port = u16::try_from(port).map_err(|_| Error::SshTransport(format!("运维服务器回填的端口不合法：{port}")))?;
    if port == 0 { return Err(Error::SshTransport("运维服务器没有回填反向端口".into())); }
    registered_port.store(port, Ordering::SeqCst);
    let _ = tx.send(TunnelMsg::ForwardRegistered { port }).await;
    …（后面不变）
}

fn map_tcpip_forward_error(e: russh::Error) -> Error {
    match e {
        russh::Error::RequestDenied => Error::ForwardPortBusy,
        other => Error::SshTransport(format!("注册反向端口失败：{other}")),
    }
}
```

`SshTunnelFactory::new(transport)`；`establish` 调 `self.transport.connect(&params.gateway, &params.fingerprint)`。**`connect_stream` 在 `check_server_key` 返回 `Err` 时把我们的 `Error` 原样带出来吗？** ——`Handler::Error = Error` 且 russh 的 `connect_stream` 返回 `Result<_, H::Error>`，`?` 直接透传；`ssh_tunnel.rs` 里 `recorded_but_changed_host_key_is_fatal` 那条以前就是这么过的。第二条测试守着它。

`supervisor.rs`：`TunnelMsg::Authenticated { fingerprint }` → 审计「运维服务器身份已核对，指纹 {fingerprint}」+ `TunnelEvent::ServerVerified`；`ForwardRegistered { port }` → 审计「反向端口 {port} 已由运维服务器分配」+ `TunnelEvent::ForwardPort(port)`；`creds.params()` 不再收端口；端口占用的预算逻辑（`port_busy_since`）不变。

`config.rs`：删三样；`Default` 只剩 `gateway`、`appliance`、`log_dir`；既有 `reverse_port` 相关测试删除。`knownhosts.rs`：删到只剩指纹工具（约 1250 行 → 200 行以内），其测试模块随之只留指纹的。

rmc-app：`wiring.rs` 里 `SshTunnelFactory::new(egress.transport.clone())`，`AppPaths::known_hosts` 删（`config()` 不再填 `known_hosts_path`；诊断包收集 `known_hosts` 的那一支若有也删）；`model.rs`：

```rust
    pub server_fingerprint: Option<String>,
    pub forward_port: Option<u16>,
    …
            TunnelEvent::ServerVerified { fingerprint } => self.server_fingerprint = Some(fingerprint),
            TunnelEvent::ForwardPort(p) => self.forward_port = Some(p),
```

回到 `Idle`/`Failed` 时 `forward_port = None`（在 `State` 变更那一支里清）。`diag.rs`：`HOST_KEY_ROW = "运维服务器指纹"`，`HostKeyRecord` 换成 `ServerVerified { fingerprint }`，行文案「{fingerprint}（与连接码一致）」；「host key 不一致」的处置建议改成 §7.1 那段（两种可能）。既有测试 `host_key_first_seen_is_recorded_for_the_diagnostics_page` 改成 `server_verified_is_recorded_for_the_diagnostics_page`；诊断页那条「含 host key 的行数」测试改找「指纹」。

- [ ] **Step 3: 删旧集成测试，全绿，提交**

```bash
git rm -r crates/rmc-core/tests/ssh_tunnel.rs crates/rmc-core/tests/forwarding.rs crates/rmc-core/tests/common crates/rmc-core/tests/data crates/rmc-core/tests/fetch-harness-cert.sh
cargo test --workspace
git add -A crates/rmc-core crates/rmc-app
git commit -m "feat(client): SSH host key 比对连接码指纹，申请端口 0 由服务端回填，删 known_hosts"
```

变异四枪（四条新测试各一）。**`ci_workflow.rs` 此时会不会红？** 它钉的是 `core.yml` 的文本，不看测试文件是否存在；`integration` job 还在（Task 12 才删），这里不动它。

---

### Task 11: 界面收尾：「远程工程师请连接 … 端口 …」、连接码随连接成功落盘（与记住密码无关）

**Files:**
- Modify (rmc-app): `src/model.rs`（若需要）、`src/view/maintain.rs`（提示行）、`src/lib.rs`（连接成功时落盘连接码；启动时预填）、`src/remember.rs`（`persist_code` / `recall` 拆开秘密与非秘密；`clear` 不再删连接码）、`tests/ui.rs`
- Test: 各文件测试模块

**Interfaces:**
- Consumes: Task 10 的 `Model.forward_port`、`TunnelEvent::ForwardPort`；Task 8 的 `Form::parsed_code`、`AppPaths::connection_code()`
- Produces:
  - `view::maintain::engineer_hint(code: &ConnectionCode, port: u16) -> String` = 「远程工程师请连接 {ip} 端口 {port}」（IPv6 带方括号）
  - `remember::persist_code(paths: &AppPaths, form: &Form) -> std::io::Result<()>`（写 `connection-code.txt`，不看 `remember`）
  - `remember::recall(paths, store) -> Recall`：`Recall { code: Option<String>, secret: Option<…>, note: Option<String> }`——连接码有就填，口令只在密文存在且解得开时填
  - `remember::clear(...)` 只删 `.sealed`，**不删** `connection-code.txt`（它不是秘密，也不是「记住密码」的一部分）

- [ ] **Step 1: 失败的测试**

`view/maintain.rs`：

```rust
    #[test]
    fn engineer_hint_names_ip_and_port() {
        let c = ConnectionCode::parse(&good_code()).unwrap();
        assert_eq!(engineer_hint(&c, 22003), "远程工程师请连接 203.0.113.10 端口 22003");
        let v6 = ConnectionCode::new(AccountName::parse("a").unwrap(), "::1".parse().unwrap(), 22000, *c.fingerprint());
        assert_eq!(engineer_hint(&v6, 22003), "远程工程师请连接 [::1] 端口 22003");
    }

    /// 已连接且拿到端口才画；未连接或还没拿到端口不画。改红：把 `forward_port` 的判断删掉。
    #[test]
    fn the_hint_line_appears_only_when_connected_with_a_port() {
        let mut m = Model::default();
        let f = filled_form();
        let no = view(&m, &f, ...);   // 按本文件既有 view 测试的调用方式
        assert!(iced_test::simulator(no).find("远程工程师请连接").is_err());
        m.apply(TunnelEvent::State(State::Connected { degraded: false }));
        m.apply(TunnelEvent::ForwardPort(22003));
        let yes = view(&m, &f, ...);
        assert!(iced_test::simulator(yes).find("远程工程师请连接 203.0.113.10 端口 22003").is_ok());
    }
```

`remember.rs`：

```rust
    /// 不勾记住密码，连接成功也要把连接码记下来；下次启动预填。改红：`persist_code` 里加 `if !form.remember { return Ok(()) }`。
    #[test]
    fn the_code_is_persisted_regardless_of_remember() {
        let (paths, _tmp) = tmp_paths();
        let mut f = filled();
        f.remember = false;
        persist_code(&paths, &f).unwrap();
        let text = std::fs::read_to_string(paths.connection_code()).unwrap();
        assert_eq!(text.trim(), f.code.trim());
        assert!(!text.contains("pw"), "连接码文件里不能有口令");
        let r = recall(&paths, &NoStore);
        assert_eq!(r.code.as_deref(), Some(f.code.trim()));
        assert!(r.secret.is_none());
    }

    /// 取消「记住密码」只删密文，连接码留着。改红：`clear` 里把 `remove_file(connection_code)` 加回来。
    #[test]
    fn clearing_the_password_keeps_the_code() { … 复用既有 W202 夹具，末尾断言 connection_code() 仍存在、secrets 目录为空 }
```

`lib.rs`：

```rust
    /// 连接成功那一拍连接码落盘；启动时预填。改红：`update` 里 Connected 那一支不调 `persist_code`。
    #[test]
    fn reaching_connected_persists_the_code_and_a_fresh_app_prefills_it() {
        let dir = tempfile::tempdir().unwrap();
        let (mut app, _cmd, _ev) = app_with_fake_core(dir.path());
        app.form = filled_form();
        app.form.remember = false;
        app.apply_event(TunnelEvent::State(State::Connected { degraded: false }));   // 按本文件既有的事件注入方式
        assert!(paths_for(dir.path()).connection_code().exists());
        let (app2, _, _) = app_with_fake_core(dir.path());
        assert_eq!(app2.form().code.trim(), filled_form().code.trim());
        assert!(app2.form().password.is_empty(), "没勾记住密码，口令不回来");
    }
```

- [ ] **Step 2: 实现**

`view/maintain.rs`：

```rust
pub fn engineer_hint(code: &ConnectionCode, port: u16) -> String {
    let ip = match code.ip() { std::net::IpAddr::V6(v6) => format!("[{v6}]"), v4 => v4.to_string() };
    format!("远程工程师请连接 {ip} 端口 {port}")
}
```

状态卡下面、远程会话上面加一行：`matches!(model.state, State::Connected { .. })` 且 `model.forward_port.is_some()` 且 `form.parsed_code().is_some()` 时画 `text(engineer_hint(&code, port)).size(13)`；否则不画（不是空行——布局高度的测试若有，按实际调）。

`remember.rs`：`persist_code` 写 `Account::from_form(form)?.encode()`（原子写：临时文件 + rename，沿用本文件既有写法）；`recall` 拆成两段：先读连接码（文件在就 `Some`），再按连接码的键找密文；`Recall` 结构与 `fill` 相应改；`clear` 去掉删连接码那一句。既有测试里「取消勾选后 `last-account.txt` 消失」的断言改成「`connection-code.txt` 仍在」。

`lib.rs`：`update` 处理 `TunnelEvent::State(State::Connected { .. })` 时，若 `self.form.parsed_code().is_some()` 就 `remember::persist_code(&paths, &self.form)`（失败只 `tracing::warn!`）；原来「勾了记住密码则保存口令」的逻辑不动，但它现在只管密文。启动装配（`App::with_core`）里 `recall` 的 `code` 有就填进 `form.code`。

- [ ] **Step 3: 全绿、闸门、提交**

```bash
cargo test -p rmc-app
git add crates/rmc-app
git commit -m "feat(app): 已连接时提示远程工程师端口，连接码随连接成功落盘"
```

变异三枪（三条新测试各一）。

---

### Task 12: 进程内端到端测试（替掉 docker），CI 改造

**Files:**
- Create: `crates/rmc-gateway/src/testing.rs`（feature `testing`）、`crates/rmc-gateway/tests/e2e.rs`
- Modify: `crates/rmc-gateway/Cargo.toml`（`[dev-dependencies]` 加 `rmc-gateway = { path = ".", features = ["testing"] }`——crate 自引用开 feature 的标准写法；`tempfile` 已是正常依赖）、`crates/rmc-gateway/src/lib.rs`（`#[cfg(feature = "testing")] pub mod testing;`）
- Modify: `.github/workflows/core.yml`（删 `integration` job；`unit` job 的测试命令改成 `cargo test -p rmc-core -p rmc-gateway`；新增 `gateway-release` job）、`.github/workflows/app.yml`（Windows 测试命令加 `-p rmc-gateway`）、`crates/rmc-core/tests/ci_workflow.rs`、`crates/rmc-core/tests/app_workflow.rs`（钉住新形态）
- Test: `tests/e2e.rs`（至少 12 条）、两份 workflow 钉测试

**Interfaces:**
- Consumes: 全部前序任务
- Produces:
  - `rmc_gateway::testing::TestGateway`：`start() -> Self`（`Timings::fast()`、`Limits::default()`、`reverse_bind 127.0.0.1`、`listen 127.0.0.1:0`）、`start_on(listen: SocketAddr)`（重启到同一地址用）、`start_with(timings, limits, allow)`、`addr()`、`fingerprint()`、`add_account(&self, name) -> (ConnectionCode, Zeroizing<String>)`（自动挑空闲端口；连接码里的地址就是 `addr()`）、`revoke(&self, name)`、`shutdown(self)`
  - `rmc_gateway::testing::FakeAppliance`：`start() -> Self`（russh 服务端：banner 默认；口令 `root`/`"appliance-pw"`；`exec` 回 `ok:<命令>\n` 并 exit 0；其它拒绝）、`addr() -> SocketAddr`、`fingerprint_sha256() -> String`（OpenSSH 风格 `SHA256:…`，与 rmc-core 预检第二步的 detail 比）、`stop(self)`（拆掉监听，用来模拟一体机不可达）
  - `rmc_gateway::testing::engineer_exec(ip: IpAddr, port: u16, password: &str, cmd: &str) -> Result<String, String>`（russh 客户端经反向端口登录假一体机、`exec`、收 `Data` 直到 `ExitStatus`/`Close`）

- [ ] **Step 1: testing.rs**

`TestGateway::start_with`：建 tempdir → `DataDir::create` → `Identity::create_in` → `GatewayConfig::new("127.0.0.1:1".parse())`（先占位）→ `save` → `Server::bind(ServerConfig{listen, …})` → 拿到 `local_addr` 后把内存里的 `cfg.public_addr` 改成它（**不重写文件**，连接码在内存里生成）。`add_account`：`store.add(name, Some(free_port()), "")` 再 `ConnectionCode::new(name, addr.ip(), addr.port(), fingerprint)`。

`FakeAppliance`：

```rust
struct ApplianceHandler;
impl russh::server::Handler for ApplianceHandler {
    type Error = russh::Error;
    async fn auth_password(&mut self, user: &str, pw: &str) -> Result<russh::server::Auth, Self::Error> {
        Ok(if user == "root" && pw == APPLIANCE_PASSWORD { russh::server::Auth::Accept } else { russh::server::Auth::reject() })
    }
    async fn channel_open_session(&mut self, _c: russh::Channel<russh::server::Msg>, reply: russh::server::ChannelOpenHandle, _s: &mut russh::server::Session) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }
    async fn exec_request(&mut self, channel: russh::ChannelId, data: &[u8], session: &mut russh::server::Session) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.data(channel, bytes::Bytes::from(format!("ok:{}\n", String::from_utf8_lossy(data))))?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}
```

（`bytes` 是 russh 的依赖，在锁里；`session.data` 收 `impl Into<bytes::Bytes>`，`Vec<u8>` 也行，不用直接依赖 `bytes`——用 `Vec<u8>`。）host key 用 `russh::keys::PrivateKey::random(&mut rand::rngs::OsRng, russh::keys::Algorithm::Ed25519)`；`fingerprint_sha256()` 用 `rmc_core::knownhosts::fingerprint_of(&key.public_key().public_key_bytes())`（Task 10 留下的工具）。监听 `127.0.0.1:0`，每条连接 `run_stream`。

`engineer_exec`：`russh::client::connect(cfg, (ip, port), AnyHostKey)` → `authenticate_password("root", password)` → `channel_open_session` → `exec(true, cmd)` → 循环 `wait()`：`Data { data }` 追加、`ExitStatus`/`Close`/`Eof` 结束；返回 `String`。

- [ ] **Step 2: e2e.rs**

夹具：

```rust
use rmc_core::ssh::SshTunnelFactory;
use rmc_core::transport::Transport;
use rmc_core::platform::{NoProxy, NoProxyAuth};
use rmc_core::tunnel::{TunnelFactory, TunnelMsg, TunnelParams};
use rmc_gateway::testing::{engineer_exec, FakeAppliance, TestGateway, APPLIANCE_PASSWORD};

fn factory() -> SshTunnelFactory {
    SshTunnelFactory::new(Arc::new(Transport::new(Arc::new(NoProxy), Arc::new(NoProxyAuth))))
}
fn params(code: &ConnectionCode, password: &str, appliance: SocketAddr) -> TunnelParams {
    TunnelParams { username: code.account().to_string(), password: Zeroizing::new(password.into()), gateway: code.server(), appliance: HostPort::new(&appliance.ip().to_string(), appliance.port()).unwrap(), fingerprint: *code.fingerprint() }
}
async fn next_msg(rx) -> TunnelMsg { 20 秒超时 }
```

用例（每条的「改红」指向服务端或客户端具体一行，写在文档注释里）：

1. `establishes_reports_the_verified_fingerprint_and_the_server_assigned_port`：`Authenticated { fingerprint } == gw.fingerprint()`；`ForwardRegistered { port } == 账号端口`。
2. `a_wrong_fingerprint_is_fatal_and_no_password_leaves_the_client`：把连接码换成另一个指纹 → `HostKeyMismatch` 或 `TlsPinMismatch`（TLS 先拦，所以是后者）、`Fatal`；服务端审计日志里**没有** `auth_ok`/`auth_fail`（口令根本没送到）。
3. `a_wrong_password_is_auth_class_and_the_server_logs_auth_fail`。
4. `a_second_tunnel_for_the_same_account_is_port_busy`。
5. `engineer_command_reaches_the_appliance_through_the_reverse_port`：`engineer_exec(gw.addr().ip(), port, APPLIANCE_PASSWORD, "uptime") == "ok:uptime\n"`。
6. `reports_session_open_bytes_and_close`：`RemoteSessionOpened`、`RemoteSessionBytes { to_appliance > 0, from_appliance > 0 }`、`RemoteSessionClosed` 依次出现。
7. `two_concurrent_engineers_get_distinct_ids`。
8. `close_remote_session_drops_only_that_session`。
9. `unreachable_appliance_reports_dial_failure_and_keeps_the_tunnel`：`FakeAppliance::stop` 后工程师连入 → `ApplianceDialFailed`，隧道仍在（再起一个假一体机换端口不行——地址已定；这条用一个没人监听的端口当一体机即可）。
10. `preflight_passes_all_four_steps_against_the_real_server`：`rmc_core::preflight::run(&transport, &code.server(), code.fingerprint(), &appliance)` 四步 `Pass`，第二步 detail 等于 `FakeAppliance::fingerprint_sha256()`，第四步 detail 含「指纹与连接码一致」。
11. `preflight_with_a_wrong_fingerprint_fails_only_the_fourth_step`：第三步 `Pass`、第四步 `Fail` 且 `class == Fatal`。
12. `a_revoked_account_is_disconnected_within_one_sweep`：`gw.revoke("zhang")` 后 1 秒内收到 `TunnelMsg::Disconnected`。
13. `the_supervisor_reconnects_after_the_server_restarts_with_the_credentials_it_kept`：用 `rmc_core::supervisor::Supervisor::spawn` + 真 `Deps`（factory、`TransportPreflight`、默认 jitter；`Deps` 里别的字段按 supervisor.rs 现状构造）；`Command::Start` → 等 `State::Connected`；`gw.shutdown()` → 等 `State::Backoff`；`TestGateway::start_on(同一地址)`（**数据目录要复用**：`start_on` 收 `dir`，身份与账号不变）→ 等再次 `Connected`；全程只发过一次 `Start`。
14. `the_supervisor_stops_cleanly_and_the_server_frees_the_port`：`Command::Stop` → `State::Idle`；服务端 `status.json` 里隧道为空。

- [ ] **Step 3: CI**

`core.yml`：
- `unit` job：「单元与假隧道测试」步骤改成 `cargo test -p rmc-core -p rmc-gateway`（端到端在里面，不再 `#[ignore]`）。
- **删掉整个 `integration` job**（docker compose、等待就绪、harness 证书、`--ignored`、导出日志、清理）。
- 新增 `gateway-release` job（ubuntu-24.04）：`dtolnay/rust-toolchain@1.89` 带 `targets: x86_64-unknown-linux-musl`；`sudo apt-get install -y musl-tools`；`cargo build --release -p rmc-gateway --target x86_64-unknown-linux-musl`；`file target/x86_64-unknown-linux-musl/release/rmc-gateway | grep -q 'statically linked'`；`actions/upload-artifact@v4` 名 `rmc-gateway-linux-x86_64`。
- paths 触发加 `crates/rmc-gateway/**`（若用 paths 过滤）。

`app.yml`：两个 job 的测试命令改成 `cargo test -p rmc-win -p rmc-app -p rmc-gateway --no-fail-fast`——**Windows 上跑端到端**就是这一行。

`ci_workflow.rs`：删掉钉 `integration` job 的断言（包括「等待就绪」「harness 证书」那些），加钉 `gateway-release` 的：job 存在、musl target、`statically linked` 检查、artifact 名；`unit` 的测试命令全等。`app_workflow.rs`：`TEST_COMMAND` 常量改成新命令，注释说明「加 `-p rmc-gateway` 是为了让 Windows 真跑端到端」。

`ci_workflow.rs` 里若有钉 `gateway.yml` 的断言，本任务不动它（Task 13 连文件一起删）。

- [ ] **Step 4: 全绿、闸门、提交**

```bash
cargo test -p rmc-gateway --features testing      # 端到端
cargo test --workspace
cargo zigbuild -p rmc-gateway --tests --features testing --target x86_64-pc-windows-gnu   # 端到端在 Windows 上也得编
git add crates/rmc-gateway .github/workflows crates/rmc-core/tests
git commit -m "test(gateway): 进程内端到端替掉 docker 集成测试；CI 出 musl 静态二进制"
```

变异：至少把 2、4、11、12、13 各打一枪，其中 13 那枪是「服务端重启后换一把身份密钥」（`start_on` 用新目录）——客户端必须 `Failed`（指纹不符）而不是 `Connected`。

---

### Task 13: 文档与退役：新的部署手册、方案设计同步、删旧 `gateway/`

**Files:**
- Delete: `gateway/haproxy.cfg`、`gateway/sshd_tunnel_config`、`gateway/systemd/`、`gateway/registry.toml`、`gateway/scripts/`、`gateway/tests/`、`gateway/test-env/`、`gateway/pytest.ini`、`.github/workflows/gateway.yml`
- Rewrite: `gateway/README.md`（部署手册，目标一页）
- Modify: `docs/方案设计.md`（第 2、3.x、4、6、7、8、9、11、12 章）、`docs/使用手册.md`（§1、§2、§7、§8、§9、§10、§11）、`docs/windows-验收清单.md`（§4 维护页字段、§6 host key、§7 证书、§8 记住密码的文件名、§9）、`docs/交付前还剩什么.md`（第 5、6 条关闭；新增本计划记账的几条）、根 `README.md`、`crates/rmc-core/tests/ci_workflow.rs`（若钉过 gateway.yml）
- Test: `cargo test --workspace` 全绿（`app_workflow`/`ci_workflow` 钉住最终形态）

- [ ] **Step 1: 部署手册 `gateway/README.md`**

按这个骨架写，每一节不超过十行：

```
# 运维服务器（rmc-gateway）

一个二进制。不装软件包，不要域名，不要证书，不需要 root。

## 部署（一台干净的 x86_64 Linux）
1. 建一个普通用户（或用现有的），把 GitHub Actions `core` 工作流的 rmc-gateway-linux-x86_64 产物拷到它的 PATH 里；
2. rmc-gateway init --public-addr <这台机器的公网 IP>:22000
3. 防火墙放行 TCP 22000–22999（22000 给现场客户端，22001–22999 给远程工程师）；
4. rmc-gateway serve   （前台跑通一次；开机自启用 rmc-gateway service print 生成的单元，安装命令印在它头三行）
5. 记下 rmc-gateway fingerprint 的输出并备份 ~/.rmc-gateway/（身份密钥丢了，所有连接码作废）。

## 开通账号 / 重置口令 / 吊销 / 看谁在线     （四条命令各一行，account add 的输出照 spec §4.2）
## 客户网络只放行 443 时                     （spec §3.3 那一段）
## 审计日志                                   （~/.rmc-gateway/audit/，JSON Lines，180 天；来源 IP 是真实的）
## 工程师登录一体机                            （ssh -p <端口> root@<IP>；每次核对一体机指纹——诊断页那一行）
## 常见故障（表）                              （连不上 22000 / 认证失败 / 端口被占 / 吊销没生效 / status 说没在跑）
## 已知限制                                    （单实例；反向端口默认公网可达，--engineer-allow 可收；吊销过的账号名不能复用）
```

**不写**任何 haproxy / sshd / PAM / registry.toml / 脚本的内容。

- [ ] **Step 2: 方案设计同步**

- 第 2 章架构图：haproxy + sshd-tunnel 换成 rmc-gateway，443 换成 22000；
- 3.x 传输：公共 CA → 连接码指纹钉死、TLS 1.3；本地存储：`connection-code.txt`；界面示意图运维服务器一组改成连接码；
- 第 4 章整章重写（按 spec §3–§6 压缩成两页）；
- 第 6 章：账号开通 = `account add`，端口由服务端分配，客户端不知道端口；
- 第 7 章：威胁模型表「钓鱼 / 假 Gateway」一行改成「连接码调包」；「互联网扫描」一行加「按来源限流、来源白名单可选」；7.2 最小权限清单对应改；7.3 后续加固里已做的三条（取消首次信任、来源白名单、审计点）划掉；
- 第 8 章测试策略：docker 换成进程内，Windows CI 也跑端到端；
- 第 9 章交付范围：Gateway 一节换成 rmc-gateway；
- 第 11 章加一行：「haproxy + sshd-tunnel（V1 原方案）｜第一次真要部署时暴露出部署路径从未验证、隧道账号可经系统 sshd 绕过限制、账号端口与客户端对不上三件事；换成自研二进制之后依赖归零、来源可审计、端口由服务端分配。代价见 spec §9」；
- 第 12 章核心原则：「Gateway 与一体机不引入自研服务端」改成「一体机不引入任何东西；运维服务器是一个只做口令认证与一条反向转发的自研二进制，除此之外的请求在代码里构造不出来」。

- [ ] **Step 3: 使用手册、验收清单、交付清单、README**

使用手册：§1 准备的三样改成「连接码 + 初始密码」；§2 第 3 步改成粘连接码；§7 端口从连接码/界面提示取；§8 运维三件事换成部署手册的指引 + 「不要重跑 init」；§9 排查表加「运维服务器连通失败」与「指纹不符」两行；§10 文件表 `known_hosts` 删、`last-account.txt` → `connection-code.txt`；§11 已知限制删「反向端口固定 22000」「地址账号不持久化」两条。

验收清单：§4「运维服务器组里依次是：连接码、出网、密码、记住密码」；§6「改掉运维服务器的 host key 后重连」改成「用另一台服务器的连接码（指纹不同）」；§7 删证书那一条，加「客户网络只放行 443 时的两条出路」；§8 文件名；§9 诊断页四项新名字。

交付清单：第 5、6 条标「已关（本计划）」；把 spec §10 记账的几条（探测旧会话顶掉、口令自助修改、aarch64、吊销名不能复用、`start_on` 之外的多实例）加进 C 档。

根 README 的文档入口表加「部署运维服务器 → gateway/README.md」（已有则改描述）。

- [ ] **Step 4: 删旧目录与工作流，钉测试，提交**

```bash
git rm -r gateway/haproxy.cfg gateway/sshd_tunnel_config gateway/systemd gateway/registry.toml gateway/scripts gateway/tests gateway/test-env gateway/pytest.ini .github/workflows/gateway.yml
cargo test --workspace        # ci_workflow / app_workflow 若钉过 gateway.yml 或 integration 的痕迹，这里会红，修到绿
git add -A
git commit -m "docs: 运维服务器部署手册、方案设计同步；退役 haproxy + sshd 与其测试环境"
```

**本任务结束即整个计划结束。** 交付前用户要做的：push → CI 全绿（五个 job：unit、deny、gateway-release、linux-checks、windows-build）→ 在一台干净 Linux 上照部署手册走一遍 → 一台 Windows 笔记本粘连接码连上 → 工程师 ssh 到反向端口。

---

## 自审（写完计划后对着 spec 过一遍）

**Spec 覆盖**：§2 目标（Task 7 + 13）；§3 形态与 CLI（Task 2、3、7）；§3.1 数据目录（Task 2、3、6、7）；§3.2 无 IPC（Task 3 的 mtime 缓存、Task 6 的扫描、Task 7 的 status.json）；§3.3 普通用户与 `service print`（Task 7）、443 映射（Task 13 手册）；§4.1 一把密钥一个指纹、TLS 1.3（Task 2、9、10）；§4.2 连接码（Task 1、3）；§5.1 只实现两件事（Task 4、5）；§5.2 端口由服务端定（Task 3、5、10）；§5.3 断开即回收（Task 5）；§6 六行表（Task 3、6）；§7.1（Task 8、9、10）；§7.2（Task 8、10、11）；§8 测试与交付（Task 12、13）；§9、§10 记账（Task 13）。

**类型一致性**：`ServerFingerprint`（Task 1）→ `TunnelParams.fingerprint`（Task 8）→ `wrap_tls(…, pin)`（Task 9）→ `ClientHandler.fingerprint`（Task 10）；`ConnectionCode::server() -> HostPort`（Task 1）→ `Credentials.code.server()`（Task 8）；`Verify::Ok { port }`（Task 3）→ `ConnHandler.account: Option<(AccountName, u16)>`（Task 4）→ `tcpip_forward` 回填（Task 5）→ 客户端 `tcpip_forward("", 0) -> u32`（Task 10）；`TunnelInfo.handle`（Task 6）用于扫描；`Timings::fast()`（Task 4）被 Task 5–7、12 的测试复用；`Limits::tiny()`（Task 6）。

**占位扫描**：全文没有 TBD/TODO；Task 4 的 `auth_password` 只有一版；Task 9 第三条测试改成钉 Cargo.toml；Task 10 第四条测试指向 pump.rs 既有用例；Task 12 的 14 条用例给的是名字与断言要点，不是空壳——每条都写明了「等什么消息、比什么值」。

**已知薄弱处（如实记）**：Task 12 第 13 条（服务端重启后重连）依赖 `start_on` 复用数据目录，若 `Running::shutdown` 释放监听有延迟会偶发 bind 失败——用 `SO_REUSEADDR`（tokio 默认开）+ 重试 5 次兜住；Task 6 的 `repeated_failures_from_one_source_get_banned` 依赖「封禁期内 TCP 被立刻关掉」，若 accept 循环的 `admit` 判断放在 TLS 之后就验不出来——放在 spawn 之前。
