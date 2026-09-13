//! 主机与端口的解析与校验。界面上的 Gateway 与一体机地址都经此类型。

use crate::error::{Error, Result};
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

/// R33：字段私有。公开字段会让结构体字面量绕过 `valid_host()`——
/// Task 4 审查用两个具体例子演示过后果：一个含
/// `]:443 <指纹>\n[gateway.company.com` 的 host 会让一次 known_hosts
/// 写入产出两行，第二行是伪造成另一台 Gateway 的记录；一个含空格的
/// host 会永久性地砸坏文件，此后每次查询全新 Gateway 都会变成 Fatal。
/// 今天树上没有任何结构体字面量构造、也没有生产调用点，改起来成本是
/// 零；Task 5 起 `HostPort` 会被到处使用，届时再收紧就要扫一遍所有
/// 调用点——跟当初趁 `Error::Io` 还没有调用点时去掉 `#[from]` 是
/// 同一个道理。读出口见下面的 `host()`/`port()`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPort {
    host: String,
    port: u16,
}

fn valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
    {
        return false;
    }
    // R18 / RFC 1123 §2.1：真实域名的最后一段从不是纯数字——顶级域名都是
    // 字母。如果整个字符串本身解析不出合法的 IP 字面量，又以纯数字标签
    // 收尾，那就是 "127.1"、"0x7f.1"、"2130706433" 这类历史遗留的数字式
    // IPv4 写法：Rust 的 `IpAddr` 解析器很严格，会直接拒绝这些写法，但
    // 这台客户端最终跑在 Windows 上，其 resolver 接受 inet_aton 风格，会
    // 把它们当成 127.0.0.1 处理——必须在主机名校验这一层就连同整个 host
    // 一起拒绝，不能指望 is_loopback 单独接住这种拼写（is_loopback 只在
    // host 已经被判定合法之后才会被调用）。
    if host.parse::<IpAddr>().is_err() {
        if let Some(last_label) = host.rsplit('.').next() {
            if !last_label.is_empty() && last_label.chars().all(|c| c.is_ascii_digit()) {
                return false;
            }
        }
    }
    true
}

impl HostPort {
    pub fn new(host: &str, port: u16) -> Result<Self> {
        if port == 0 {
            return Err(Error::Config("端口不能为 0".into()));
        }
        if !valid_host(host) {
            return Err(Error::Config(format!("主机名不合法：{host}")));
        }
        Ok(Self {
            host: host.to_string(),
            port,
        })
    }

    /// R33：字段私有，这是唯一的读出口。私有字段逼着调用方只能经
    /// `new`/`FromStr` 拿到一个已经过 `valid_host` 校验的值，堵死了拿
    /// 结构体字面量绕过校验直接拼出 `HostPort` 的口子——见下面 `host`
    /// 字段私有化本身的说明。
    pub fn host(&self) -> &str {
        &self.host
    }

    /// R33：同上，端口的唯一读出口。
    pub fn port(&self) -> u16 {
        self.port
    }

    fn is_ipv6_literal(&self) -> bool {
        self.host.contains(':')
    }

    /// 一体机地址是否指向本机回环。转发目标指向本机毫无意义，且会把
    /// Gateway 的通道接到客户端自己身上，见 config::validate_addresses。
    ///
    /// 用 `std::net::IpAddr` 按数值解析，而不是字符串前缀/相等匹配：
    /// - 前缀匹配 "127." 会被恰好长这样的主机名误伤（假阳性，例如
    ///   "127.0.0.1.example.com" 根本不是回环地址，却会被拒绝）；
    /// - 字符串相等匹配 "::1" 会漏掉同一地址的其他合法书写形式，例如展开
    ///   写法 "0:0:0:0:0:0:0:1"（假阴性，真正的回环地址反而被放行，
    ///   这正是校验要挡住的那类问题）。
    ///
    /// R17：`Ipv6Addr::is_loopback` 只特判字面量 `::1`，不会先把
    /// IPv4-映射地址（`::ffff:127.0.0.1`、压缩写法 `::ffff:7f00:1`）折算
    /// 成 IPv4 再判断——这类地址数值上就是 127.0.0.1，双栈系统上连它会
    /// 落到本机回环接口，必须先用 `to_canonical()` 折算，否则原样漏判。
    ///
    /// R17：这是纯字符串/数值判断，不做 DNS 解析——这是个同步的校验函数，
    /// 不能在这里发起网络 I/O，这是刻意的取舍。因此一个解析后才指向回环、
    /// 但书写形式本身不是回环写法的主机名（例如内部 DNS 把某条自定义记录
    /// 指向了 127.0.0.1）不在这个函数的能力范围内。
    pub fn is_loopback(&self) -> bool {
        if self.host.eq_ignore_ascii_case("localhost")
            || self.host.eq_ignore_ascii_case("localhost.")
        {
            return true;
        }
        self.host
            .parse::<IpAddr>()
            .map(|ip| ip.to_canonical().is_loopback())
            .unwrap_or(false)
    }
}

impl FromStr for HostPort {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let (host, port) = if let Some(rest) = s.strip_prefix('[') {
            let (host, tail) = rest
                .split_once(']')
                .ok_or_else(|| Error::Config(format!("IPv6 地址缺少右方括号：{s}")))?;
            let port = tail
                .strip_prefix(':')
                .ok_or_else(|| Error::Config(format!("地址缺少端口：{s}")))?;
            (host, port)
        } else {
            let (host, port) = s
                .rsplit_once(':')
                .ok_or_else(|| Error::Config(format!("地址缺少端口：{s}")))?;
            // 没加方括号却含多个冒号：多半是漏了方括号的 IPv6 字面量，不是
            // “主机名里恰好有个冒号”。按最后一个冒号硬切会把地址的尾段
            // 悄悄当成端口，解析“成功”但结果是错的，见测试
            // rejects_unbracketed_ipv6_literal。
            if host.contains(':') {
                return Err(Error::Config(format!("IPv6 地址必须加方括号：{s}")));
            }
            (host, port)
        };
        let port: u16 = port
            .parse()
            .map_err(|_| Error::Config(format!("端口不是 0-65535 的整数：{port}")))?;
        Self::new(host, port)
    }
}

impl fmt::Display for HostPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_ipv6_literal() {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hostname_and_port() {
        let hp: HostPort = "gateway.company.com:443".parse().unwrap();
        assert_eq!(hp.host, "gateway.company.com");
        assert_eq!(hp.port, 443);
    }

    #[test]
    fn parses_ipv4() {
        let hp: HostPort = "192.168.100.10:22".parse().unwrap();
        assert_eq!(hp.host, "192.168.100.10");
        assert_eq!(hp.port, 22);
    }

    #[test]
    fn parses_bracketed_ipv6() {
        let hp: HostPort = "[fd00::1]:22".parse().unwrap();
        assert_eq!(hp.host, "fd00::1");
        assert_eq!(hp.port, 22);
    }

    #[test]
    fn display_round_trips() {
        for s in [
            "gateway.company.com:443",
            "192.168.100.10:22",
            "[fd00::1]:22",
        ] {
            let hp: HostPort = s.parse().unwrap();
            assert_eq!(hp.to_string(), s);
        }
    }

    #[test]
    fn rejects_missing_port() {
        assert!("gateway.company.com".parse::<HostPort>().is_err());
    }

    #[test]
    fn rejects_port_zero() {
        assert!("gateway.company.com:0".parse::<HostPort>().is_err());
    }

    #[test]
    fn rejects_port_out_of_range() {
        assert!("gateway.company.com:70000".parse::<HostPort>().is_err());
    }

    #[test]
    fn rejects_empty_host() {
        assert!(":443".parse::<HostPort>().is_err());
    }

    #[test]
    fn rejects_host_with_whitespace_or_scheme() {
        assert!("https://gateway.company.com:443"
            .parse::<HostPort>()
            .is_err());
        assert!("gate way.com:443".parse::<HostPort>().is_err());
    }

    // --- 以下是本任务补的边界用例：brief 给的用例只覆盖了「加了方括号的
    // IPv6」这一种形状,没有覆盖方括号本身写错、或者干脆没写方括号的情况。---

    #[test]
    fn rejects_unbracketed_ipv6_literal() {
        // 不加方括号的多冒号地址是漏了方括号的 IPv6 字面量，不是「主机名
        // 恰好带个冒号」。按最后一个冒号硬切会把地址的尾段悄悄当成端口，
        // 解析「成功」但结果是错的——例如 "fd00::1:22" 会被切成
        // host="fd00::1"、port=22，看起来还挺像那么回事，实际上用户很可能
        // 是想写完整地址 "fd00::1:22" 本身（不带端口），或者漏了方括号。
        // 两种意图都不该被这条 rsplit_once 硬猜中。
        assert!("fd00::1:22".parse::<HostPort>().is_err());
        assert!("2001:db8::1234:22".parse::<HostPort>().is_err());
    }

    #[test]
    fn rejects_ipv6_missing_closing_bracket() {
        assert!("[fd00::1:22".parse::<HostPort>().is_err());
    }

    #[test]
    fn rejects_ipv6_missing_port_after_brackets() {
        assert!("[fd00::1]".parse::<HostPort>().is_err());
    }

    #[test]
    fn rejects_host_name_over_253_chars() {
        let long_host = "a".repeat(254);
        assert!(HostPort::new(&long_host, 443).is_err());
    }

    #[test]
    fn accepts_host_name_at_253_chars() {
        let host = "a".repeat(253);
        assert!(HostPort::new(&host, 443).is_ok());
    }

    #[test]
    fn loopback_detects_ipv4_ipv6_and_localhost_forms() {
        for (host, want) in [
            ("127.0.0.1", true),
            ("127.255.255.255", true),
            ("localhost", true),
            ("LOCALHOST", true),
            ("::1", true),
            // IPv6 回环地址的展开写法：与 "::1" 数值相同、文本不同——按
            // 字符串相等比较会漏判，必须按数值判断。
            ("0:0:0:0:0:0:0:1", true),
            ("10.0.0.1", false),
            ("192.168.100.10", false),
            ("gateway.company.com", false),
        ] {
            let hp = HostPort::new(host, 22).unwrap();
            assert_eq!(hp.is_loopback(), want, "host={host}");
        }
    }

    #[test]
    fn loopback_check_does_not_false_positive_on_coincidental_hostname() {
        // "127." 前缀匹配会被恰好长这样的主机名误伤（假阳性，把合法配置
        // 错误地当成回环拒绝）；必须按数值判断，而不是看字符串前缀。
        let hp = HostPort::new("127.0.0.1.example.com", 22).unwrap();
        assert!(!hp.is_loopback());
    }

    // --- R17：is_loopback 补的两处漏判。---

    #[test]
    fn loopback_detects_ipv4_mapped_ipv6_dotted_form() {
        // ::ffff:127.0.0.1 数值上就是 127.0.0.1；Ipv6Addr::is_loopback
        // 只特判字面量 "::1"，不会先把 IPv4-映射地址折算成 IPv4 再判断，
        // 双栈系统上连它会落到本机回环接口——正是这个校验要挡住的
        // "Gateway 的隧道被接回客户端自己身上"。
        let hp = HostPort::new("::ffff:127.0.0.1", 22).unwrap();
        assert!(hp.is_loopback());
    }

    #[test]
    fn loopback_detects_ipv4_mapped_ipv6_compressed_form() {
        // 同一个地址的压缩写法：::ffff:7f00:1 与 ::ffff:127.0.0.1 数值
        // 相同（0x7f00 0x0001 = 127.0.0.1），只是没写成内嵌点分十进制。
        let hp = HostPort::new("::ffff:7f00:1", 22).unwrap();
        assert!(hp.is_loopback());
    }

    #[test]
    fn loopback_detects_localhost_with_trailing_dot() {
        // "localhost." 是 FQDN 词根写法，解析器按跟 "localhost" 完全
        // 等价处理，不解析成 IP 字面量，字符串比较也不相等，容易漏判。
        let hp = HostPort::new("localhost.", 22).unwrap();
        assert!(hp.is_loopback());
    }

    // --- R18：历史遗留的数字式 IPv4 写法，主机名校验这一层就要拒绝。
    // 每种拼写单独一条测试，便于单独验证哪种拼写被漏掉。---

    #[test]
    fn rejects_legacy_numeric_ipv4_dotted_short_form() {
        // Windows 的 resolver 接受 inet_aton 风格，"127.1" 会被当成
        // 127.0.0.1——不能指望 is_loopback 接住这种拼写，必须在这里连同
        // host 一起拒绝。
        assert!(HostPort::new("127.1", 22).is_err());
    }

    #[test]
    fn rejects_legacy_numeric_ipv4_three_octet_form() {
        assert!(HostPort::new("127.0.1", 22).is_err());
    }

    #[test]
    fn rejects_legacy_numeric_ipv4_hex_octet_form() {
        assert!(HostPort::new("0x7f.1", 22).is_err());
    }

    #[test]
    fn rejects_legacy_numeric_ipv4_decimal_integer_form() {
        assert!(HostPort::new("2130706433", 22).is_err());
    }
}
