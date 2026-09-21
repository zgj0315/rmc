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
            Some(p) => p
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .ok_or_else(|| format!("前缀长度不合法：{s}"))?,
            None => max,
        };
        Ok(Self { ip, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.ip, ip) {
            (IpAddr::V4(net), IpAddr::V4(a)) => mask4(net, self.prefix) == mask4(a, self.prefix),
            (IpAddr::V6(net), IpAddr::V6(a)) => mask6(net, self.prefix) == mask6(a, self.prefix),
            // v4 映射的 v6（::ffff:a.b.c.d）按 v4 比
            (IpAddr::V4(_), IpAddr::V6(a)) => a
                .to_ipv4_mapped()
                .is_some_and(|v4| self.contains(IpAddr::V4(v4))),
            _ => false,
        }
    }
}

fn mask4(a: Ipv4Addr, p: u8) -> u32 {
    let bits = u32::from(a);
    if p == 0 {
        0
    } else {
        bits & (u32::MAX << (32 - p))
    }
}
fn mask6(a: Ipv6Addr, p: u8) -> u128 {
    let bits = u128::from(a);
    if p == 0 {
        0
    } else {
        bits & (u128::MAX << (128 - p))
    }
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
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

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
        assert!(!allowed(
            &[Cidr::parse("10.0.0.0/8").unwrap()],
            ip("8.8.8.8")
        ));
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("nope").is_err());
    }
}
