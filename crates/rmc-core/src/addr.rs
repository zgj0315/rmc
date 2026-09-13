//! 主机与端口的解析与校验。界面上的 Gateway 与一体机地址都经此类型。

use crate::error::{Error, Result};
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPort {
    pub host: String,
    pub port: u16,
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
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
    /// `IpAddr::is_loopback` 按数值判断，两个方向的问题一起解决。
    pub fn is_loopback(&self) -> bool {
        self.host.eq_ignore_ascii_case("localhost")
            || self
                .host
                .parse::<IpAddr>()
                .map(|ip| ip.is_loopback())
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
}
