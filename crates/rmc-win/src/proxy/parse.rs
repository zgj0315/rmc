//! 代理串解析。纯函数，与 Win32 无关，因此跨平台可测。
//! 覆盖两种来源：WinHTTP/IE 的 `http=host:port;https=host:port`，
//! 以及 PAC 求值结果 `PROXY host:port; DIRECT`。

use rmc_core::addr::HostPort;

/// 从代理串里挑出适用于 CONNECT 隧道的代理条目。返回 `None` 表示直连。
///
/// `target_host` 目前不参与挑选，原因不是疏漏，是这两种输入格式本身都
/// 不带「针对哪个目标」的信息。WinHTTP 的手动覆盖串（`http=..;https=..`）
/// 是按协议分的，同一份配置对会话里的每个目标都适用，语法里没有主机名
/// 的位置；PAC 结果串是 `WinHttpGetProxyForUrl` 已经针对某个具体 URL
/// 求值过之后的产物——「对哪个目标适用」这件事在调用 PAC 求值时就已经
/// 用 `target_host` 决定了，传到这里的 `raw` 本身就是那次求值的结果，
/// 这个函数只需要在结果里挑一项，不需要再看一次目标是谁。
///
/// bypass 名单命中与否是另一件事，由 [`host_is_bypassed`] 独立判断，
/// 调用方应当在命中 bypass 时直接跳过这个函数，走直连。保留这个参数
/// （而不是删掉它）是为了让调用方在两处调用点（命中 PAC 之前、命中
/// 静态配置之后）都能保持同一个签名，也给未来万一出现真正按目标区分
/// 的代理格式留好位置；`_` 前缀只是让 clippy 别为「暂时没用上」报警，
/// 不代表这行为没写清楚——见下面的 `target_host_does_not_affect_selection`，
/// 这条测试钉住「暂时没用上」这件事本身，谁不小心让它产生副作用就会
/// 看到测试变红。
pub fn parse_proxy_list(raw: &str, _target_host: &str) -> Option<HostPort> {
    let entries: Vec<&str> = raw
        .split([';', ' ', '\t', '\n'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if entries.is_empty() {
        return None;
    }

    // PAC 结果里 DIRECT 在最前面就是直连。
    if entries[0].eq_ignore_ascii_case("DIRECT") {
        return None;
    }

    let mut https_hit = None;
    let mut first_hit = None;

    let mut i = 0usize;
    while i < entries.len() {
        let entry = entries[i];
        // PAC 形式：PROXY host:port
        if entry.eq_ignore_ascii_case("PROXY") {
            i += 1;
            if let Some(hp) = entries.get(i).and_then(|e| parse_one(e)) {
                first_hit = first_hit.or(Some(hp));
            }
            i += 1;
            continue;
        }
        if entry.eq_ignore_ascii_case("DIRECT") {
            i += 1;
            continue;
        }

        // WinHTTP 形式：可能带 scheme=
        let (scheme, body) = match entry.split_once('=') {
            Some((s, b)) => (Some(s.to_ascii_lowercase()), b),
            None => (None, entry),
        };
        if let Some(hp) = parse_one(body) {
            if scheme.as_deref() == Some("https") {
                https_hit = https_hit.or(Some(hp));
            } else {
                first_hit = first_hit.or(Some(hp));
            }
        }
        i += 1;
    }

    // 建 CONNECT 隧道要用 https 那一项（跟代理之间也走加密），其余情况
    // 退回第一个能解析出来的条目。
    https_hit.or(first_hit)
}

/// `host` 或 `host:port`，端口缺省为 80。
fn parse_one(s: &str) -> Option<HostPort> {
    let s = s.trim().trim_end_matches('/');
    let s = s.strip_prefix("http://").unwrap_or(s);
    let s = s.strip_prefix("https://").unwrap_or(s);
    if s.is_empty() {
        return None;
    }
    match s.rsplit_once(':') {
        Some((host, port)) => {
            let port: u16 = port.parse().ok()?;
            HostPort::new(host, port).ok()
        }
        None => HostPort::new(s, 80).ok(),
    }
}

/// 解析 bypass 名单（分号/空白分隔）成模式列表，交给 [`host_is_bypassed`]
/// 逐条比对。
pub fn parse_bypass_list(raw: &str) -> Vec<String> {
    raw.split([';', ' ', '\t', '\n'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// 命中 bypass 列表时应当直连。`<local>` 只匹配不含点的主机名。
pub fn host_is_bypassed(host: &str, patterns: &[String]) -> bool {
    let host_lower = host.to_ascii_lowercase();
    for p in patterns {
        let p = p.to_ascii_lowercase();
        if p == "<local>" {
            if !host_lower.contains('.') {
                return true;
            }
            continue;
        }
        if let Some(suffix) = p.strip_prefix('*') {
            if host_lower.ends_with(suffix) {
                return true;
            }
            continue;
        }
        if let Some(prefix) = p.strip_suffix('*') {
            if host_lower.starts_with(prefix) {
                return true;
            }
            continue;
        }
        if host_lower == p {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // 下面每条测试的注释都写明「改实现的哪一行会让它变红」，且已经逐条
    // 改过一遍确认——过程记在 task-1-report.md，这里不重复贴 diff。

    #[test]
    fn parses_a_bare_host_port() {
        // 改红：给 parse_one 里 `let port: u16 = port.parse().ok()?;`
        // 之后接一个 `.wrapping_add(1)`，8080 变成 8081，字符串比对失败。
        let hp = parse_proxy_list("proxy.company.com:8080", "gateway.company.com").unwrap();
        assert_eq!(hp.to_string(), "proxy.company.com:8080");
    }

    #[test]
    fn defaults_missing_port_to_80() {
        // 改红：把 `None => HostPort::new(s, 80).ok()` 里的 80 换成别的数。
        // W5：HostPort 字段私有（rmc-core R33），用 .port() 不是 .port。
        let hp = parse_proxy_list("proxy.company.com", "gateway.company.com").unwrap();
        assert_eq!(hp.port(), 80);
    }

    #[test]
    fn strips_the_scheme_prefix() {
        // 改红：删掉 `entry.split_once('=')` 那段 scheme 剥离逻辑，
        // 让 "http=proxy.company.com:8080" 整段被当成主机名去解析。
        let hp = parse_proxy_list("http=proxy.company.com:8080", "gateway.company.com").unwrap();
        assert_eq!(hp.to_string(), "proxy.company.com:8080");
    }

    #[test]
    fn prefers_the_https_entry_when_present() {
        // 我们要建的是 CONNECT 隧道，应当用 https 那一项。
        // 改红：把最后一行 `https_hit.or(first_hit)` 换成
        // `first_hit.or(https_hit)`。
        let raw = "http=p1.company.com:8080;https=p2.company.com:8443";
        let hp = parse_proxy_list(raw, "gateway.company.com").unwrap();
        assert_eq!(hp.to_string(), "p2.company.com:8443");
    }

    #[test]
    fn accepts_semicolon_and_space_separators() {
        // 改红：把 `split([';', ' ', '\t', '\n'])` 里的 ' ' 删掉。
        for raw in [
            "https=p.company.com:8443;http=q:8080",
            "https=p.company.com:8443 http=q:8080",
        ] {
            let hp = parse_proxy_list(raw, "gateway.company.com").unwrap();
            assert_eq!(hp.to_string(), "p.company.com:8443", "{raw}");
        }
    }

    #[test]
    fn returns_none_for_direct() {
        // 改红：删掉 `if entries.is_empty() { return None; }` 或者
        // 删掉 DIRECT 那条判断，任一处都会让某一个 assert 变成
        // panic-on-unwrap 或者断言失败。
        assert!(parse_proxy_list("", "gateway.company.com").is_none());
        assert!(parse_proxy_list("   ", "gateway.company.com").is_none());
        assert!(parse_proxy_list("DIRECT", "gateway.company.com").is_none());
    }

    #[test]
    fn parses_pac_style_proxy_result() {
        // 改红：删掉 `entry.eq_ignore_ascii_case("PROXY")` 这条分支，
        // "PROXY" 会被当成主机名去解析，解析失败整个函数返回 None。
        let hp = parse_proxy_list("PROXY proxy.company.com:8080", "gateway.company.com").unwrap();
        assert_eq!(hp.to_string(), "proxy.company.com:8080");
    }

    #[test]
    fn pac_direct_first_means_direct() {
        // 改红：把 `entries[0].eq_ignore_ascii_case("DIRECT")` 的 `[0]`
        // 换成扫描整个列表（比如用 .any(..)），DIRECT 排第几个都会被
        // 判成直连，这条测试就测不出"只有排第一才算直连"这件事了——
        // 但更直接的改法是干脆删掉这个 if，函数会往下把 PROXY p:8080
        // 解析出来,返回 Some 而不是 None。
        assert!(parse_proxy_list("DIRECT; PROXY p:8080", "gw.company.com").is_none());
    }

    #[test]
    fn ignores_malformed_entries_and_takes_the_next_good_one() {
        // 改红：把 `if let Some(hp) = parse_one(body)` 换成
        // `let hp = parse_one(body).unwrap()`（遇到解析失败直接 panic
        // 而不是跳过）。
        let hp = parse_proxy_list("https=:::;https=p.company.com:8443", "gw.company.com").unwrap();
        assert_eq!(hp.to_string(), "p.company.com:8443");
    }

    #[test]
    fn target_host_does_not_affect_selection() {
        // 钉住 parse_proxy_list 文档上的承诺：target_host 目前不参与挑选
        // （见函数上方注释里的理由）。改红：给 `_target_host` 去掉下划线
        // 前缀，在函数体最前面加一行
        // `if target_host.starts_with('g') { return None; }`——
        // "gateway-a..." 会被强制判成 None，"totally-different..." 走
        // 正常逻辑判成 Some，两次调用结果就分道了。
        let raw = "https=p2.company.com:8443";
        let a = parse_proxy_list(raw, "gateway-a.company.com");
        let b = parse_proxy_list(raw, "totally-different.example.org");
        assert_eq!(a, b);
    }

    #[test]
    fn bypass_list_splits_on_semicolon_and_whitespace() {
        // 改红：parse_bypass_list 的 split 模式去掉 ' '。
        let got = parse_bypass_list("*.local;169.254.*  <local>");
        assert_eq!(got, vec!["*.local", "169.254.*", "<local>"]);
    }

    #[test]
    fn bypass_matches_suffix_wildcard() {
        // 改红：把 `p.strip_prefix('*')` 那支分支删掉，
        // 或者把 `ends_with(suffix)` 换成 `==suffix`。
        let p = parse_bypass_list("*.company.internal");
        assert!(host_is_bypassed("appliance.company.internal", &p));
        assert!(!host_is_bypassed("gateway.company.com", &p));
    }

    #[test]
    fn bypass_local_matches_dotless_hosts_only() {
        // 改红：把 `if !host_lower.contains('.')` 的 `!` 去掉——
        // <local> 就会反过来只匹配带点的主机名。
        let p = parse_bypass_list("<local>");
        assert!(host_is_bypassed("gateway", &p));
        assert!(!host_is_bypassed("gateway.company.com", &p));
    }

    #[test]
    fn bypass_exact_match() {
        // 改红：把 `host_lower == p` 的 `==` 换成 `!=`——
        // "gateway.company.com" 跟自己精确匹配那一条反而判不中了。
        let p = parse_bypass_list("gateway.company.com");
        assert!(host_is_bypassed("gateway.company.com", &p));
        assert!(!host_is_bypassed("other.company.com", &p));
    }

    #[test]
    fn end_to_end_bypass_decision_from_a_raw_pattern_list() {
        // 计划原文这里叫 bypassed_target_resolves_to_direct，注释说
        // 「验证两个函数配合」，实现却只调了 host_is_bypassed 一个函数，
        // 跟上面 bypass_matches_suffix_wildcard 逐字同构、只换了一个
        // pattern——W12 点名的弱测试。改成这样：从一条混合了四种模式
        // 的原始 bypass 串解析出列表（真正用上 parse_bypass_list 的分割
        // 逻辑），再验证 host_is_bypassed 对四种不同命中方式、以及一个
        // 完全不命中的主机分别给出正确答案——这才是「两个函数配合」在
        // 处理一条真实、混合的配置串，而不是四条各自独立的单模式用例。
        //
        // 改红：把 parse_bypass_list 的分隔符去掉 ';'（四个模式会被解析
        // 成一整条粘在一起的字符串，没有一个能再单独匹配上）；或者把
        // host_is_bypassed 循环体里任意一支 continue 换成 return false
        // （后面的模式再也没机会被比对到）。
        let patterns = parse_bypass_list("*.local;169.254.*;<local>;gateway.company.com");
        assert!(host_is_bypassed("printer.local", &patterns)); // 前缀通配
        assert!(host_is_bypassed("169.254.1.1", &patterns)); // 后缀通配
        assert!(host_is_bypassed("appliance", &patterns)); // <local>
        assert!(host_is_bypassed("gateway.company.com", &patterns)); // 精确匹配
        assert!(!host_is_bypassed("other.company.com", &patterns)); // 不命中
    }
}
