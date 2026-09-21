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
        let ok_first = s
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
        let ok_rest = s
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
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
    pub fn new(
        account: AccountName,
        ip: IpAddr,
        port: u16,
        fingerprint: ServerFingerprint,
    ) -> Result<Self, CodeError> {
        if port == 0 {
            return Err(CodeError::Address("端口不能是 0".into()));
        }
        Ok(Self {
            account,
            ip,
            port,
            fingerprint,
        })
    }

    pub fn parse(s: &str) -> Result<Self, CodeError> {
        let rest = s
            .strip_prefix(CODE_PREFIX)
            .and_then(|r| r.strip_prefix(':'))
            .ok_or(CodeError::Prefix)?;
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
        let port: u16 = port
            .parse()
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| CodeError::Address(addr.to_string()))?;
        let ip: IpAddr = host.parse().map_err(|_| {
            if host.chars().any(|c| c.is_ascii_alphabetic()) {
                CodeError::Domain(host.to_string())
            } else {
                CodeError::Address(addr.to_string())
            }
        })?;
        Ok(Self {
            account,
            ip,
            port,
            fingerprint,
        })
    }

    pub fn account(&self) -> &AccountName {
        &self.account
    }
    pub fn ip(&self) -> IpAddr {
        self.ip
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    pub fn fingerprint(&self) -> &ServerFingerprint {
        &self.fingerprint
    }

    /// 客户端拨号用的地址。
    ///
    /// `expect` 在这里够不着：构造 `ConnectionCode` 只有两个口——`new`
    /// 与 `parse`——都已经在构造那一刻排除了 `HostPort::new` 会拒绝的
    /// 两种情况：端口 0（`new` 直接检查；`parse` 靠 `.filter(|p| *p != 0)`）
    /// 与非 IP 主机（`ip` 字段的类型就是 `std::net::IpAddr`，不可能装进
    /// 一个解析失败的字符串）。字段私有挡住了绕开这两个构造口直接拼字面量。
    pub fn server(&self) -> HostPort {
        HostPort::new(&self.ip.to_string(), self.port).expect("IP 字面量必定是合法主机")
    }

    fn body(&self) -> String {
        let host = match self.ip {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => format!("[{v6}]"),
        };
        format!(
            "{CODE_PREFIX}:{}@{host}:{}:{}",
            self.account, self.port, self.fingerprint
        )
    }
}

/// `[::1]:22000` 或 `203.0.113.10:22000` → (host, port)。
fn split_host_port(addr: &str) -> Result<(&str, &str), CodeError> {
    if let Some(rest) = addr.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .ok_or_else(|| CodeError::Address(addr.to_string()))?;
        return Ok((host, port));
    }
    addr.rsplit_once(':')
        .ok_or_else(|| CodeError::Address(addr.to_string()))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

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
        .expect("夹具必须合法")
    }

    /// 指纹就是公钥的 SHA-256，base64url、不带填充、43 个字符。
    /// 改红：`of_ed25519_public` 里把 `Sha256::digest(pk)` 换成 `pk.to_vec()`
    /// 或者把 `URL_SAFE_NO_PAD` 换成 `STANDARD`——第一格或第二格红。
    #[test]
    fn fingerprint_is_url_safe_sha256_of_the_public_key() {
        let s = fp().to_string();
        assert_eq!(s.len(), 43, "{s}");
        assert!(
            s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "{s}"
        );
        // 独立算一遍，别只跟自己比。
        use base64::Engine;
        use sha2::{Digest, Sha256};
        let want =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest([7u8; 32]));
        assert_eq!(s, want);
        assert_eq!(ServerFingerprint::parse(&s).unwrap(), fp());
    }

    #[test]
    fn fingerprint_rejects_wrong_length_and_wrong_alphabet() {
        assert!(matches!(
            ServerFingerprint::parse("abc"),
            Err(CodeError::Fingerprint)
        ));
        let s = fp().to_string();
        let bad = format!("{}+", &s[..42]); // 标准 base64 的字符
        assert!(matches!(
            ServerFingerprint::parse(&bad),
            Err(CodeError::Fingerprint)
        ));
    }

    /// 连接码往返：格式化再解析得到同一个值。
    /// 改红：`Display` 里漏掉任何一段，或者 `parse` 里把 `rsplitn` 的份数改掉。
    #[test]
    fn connection_code_round_trips() {
        let c = sample();
        let s = c.to_string();
        assert!(
            s.starts_with("rmc1:tunnel-zhang@203.0.113.10:22000:"),
            "{s}"
        );
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
        )
        .expect("夹具必须合法");
        let s = c.to_string();
        assert!(s.contains("@[::1]:22000:"), "{s}");
        assert_eq!(ConnectionCode::parse(&s).unwrap(), c);
    }

    /// `server()` 给出的 `HostPort` 必须是 `HostPort` 自己认的——不是靠
    /// `ConnectionCode` 这边碰巧没拼错方括号。IPv6 走的是 `IpAddr::to_string()`
    /// 拿到不带方括号的 `"::1"`，直接喂给 `HostPort::new(host, port)`（两个
    /// 独立参数，不是拼成一条 `"host:port"` 字符串再解析），所以不需要方括号；
    /// 这条测试独立验证这个假设，不满足于 `ipv6_is_written_in_brackets_and_parses_back`
    /// 只验了 `ConnectionCode` 自己的往返。
    #[test]
    fn server_for_ipv6_is_a_hostport_that_parses_back() {
        let c = ConnectionCode::new(
            AccountName::parse("a1").unwrap(),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            22000,
            fp(),
        )
        .expect("夹具必须合法");
        let hp = c.server();
        assert_eq!(hp, HostPort::new("::1", 22000).unwrap());
        // Display 往返也要成立：拼出来的字符串本身能被 HostPort 的
        // FromStr 解析回同一个值（这条要求方括号，跟 new() 不同）。
        let round: HostPort = hp.to_string().parse().unwrap();
        assert_eq!(round, hp);
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
        assert!(
            matches!(ConnectionCode::parse(&flipped), Err(CodeError::Checksum)),
            "{flipped}"
        );
        // 粘贴截断：少了最后两位校验
        let truncated = &s[..s.len() - 2];
        assert!(ConnectionCode::parse(truncated).is_err(), "{truncated}");
    }

    /// 只用 IP：域名写进来直接拒绝，而且错误文案说清楚。
    #[test]
    fn a_domain_name_is_refused_with_a_dedicated_error() {
        let s = sample()
            .to_string()
            .replace("203.0.113.10", "ops.example.com");
        // 校验位跟着变，重算一遍再解析，否则先撞到 Checksum。
        let s = recheck(&s);
        match ConnectionCode::parse(&s) {
            Err(CodeError::Domain(d)) => assert_eq!(d, "ops.example.com"),
            other => panic!("{other:?}"),
        }
    }

    /// `new` 是构造 `ConnectionCode` 的两个口之一，必须自己挡住端口 0——
    /// 不能指望调用方先走一遍 `parse` 那条路径的 `.filter(|p| *p != 0)`。
    /// 少了这道校验，`server()` 会在 `HostPort::new` 里因为「端口不能为
    /// 0」而返回 `Err`，被 `server()` 的 `.expect(...)` 当场 panic。
    ///
    /// 改红：把 `new` 里 `if port == 0 { return Err(...); }` 那两行删掉——
    /// 这条测试立刻红（`new` 返回 `Ok`，`assert!(matches!(.., Err(..)))` 落空）。
    #[test]
    fn new_rejects_port_zero() {
        let err = ConnectionCode::new(
            AccountName::parse("a1").unwrap(),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            0,
            fp(),
        );
        assert!(matches!(err, Err(CodeError::Address(_))), "{err:?}");
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
        assert!(matches!(
            ConnectionCode::parse("rmc2:a@1.2.3.4:1:x:y"),
            Err(CodeError::Prefix)
        ));
        assert!(matches!(
            ConnectionCode::parse("rmc1:nonsense"),
            Err(CodeError::Shape)
        ));
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
