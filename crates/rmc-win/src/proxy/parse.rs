//! 代理串解析。纯函数，与 Win32 无关，因此跨平台可测。
//! 覆盖两种来源：WinHTTP/IE 的手工配置 `http=host:port;https=host:port`，
//! 以及 PAC 求值结果——`DIRECT`，或者跟手工配置同样格式的
//! `scheme=host:port[;...]` 列表（这是 `WinHttpGetProxyForUrl` 真正
//! 返回的形状：它已经替调用方从 PAC 脚本的原始返回值里剥掉了
//! `SOCKS`/`SOCKS4`/`SOCKS5` 这些非 HTTP 类型、并在遇到 `DIRECT` 时
//! 截断列表，`WINHTTP_PROXY_INFO.lpszProxy` 的文档格式跟
//! `WINHTTP_CURRENT_USER_IE_PROXY_CONFIG.lpszProxy` 完全一样，见
//! `winhttp.rs` 里 `eval_pac` 的实现与那里引用的文档）。这个函数额外
//! 兼容 `PROXY host:port`/`HTTP host:port`/`HTTPS host:port` 这种空格
//! 分隔的 PAC 原生关键字写法，以及 `SOCKS*` 关键字（识别出来但不当成
//! 可用代理，因为这条隧道全靠 HTTP CONNECT 建立、SOCKS 用不了）——这不
//! 是本函数会从真实 WinHTTP 调用点收到的输入，是为了不让这个"纯函数、
//! 可以被任何调用方喂任何字符串"的公开 API 在收到这类输入时安静地做错
//! 事（把字面量 `SOCKS5`/`HTTPS` 当成主机名去解析）。

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

        // PAC 原生返回值的裸关键字写法（空格分隔，不带 `=`）：
        // `PROXY host:port`、`HTTP host:port`、`HTTPS host:port`。
        // "下一个 token 就是地址"这件事只在下一个 token 本身不是另一个
        // 保留关键字时才成立——`PROXY ;DIRECT` 这种畸形输入按分隔符拆完
        // 之后，"PROXY" 紧跟着的就是字面量 "DIRECT"，不做这层检查会把
        // "DIRECT" 错当成主机名解析出 `DIRECT:80` 这样一个荒谬的代理。
        if entry.eq_ignore_ascii_case("PROXY")
            || entry.eq_ignore_ascii_case("HTTP")
            || entry.eq_ignore_ascii_case("HTTPS")
        {
            let is_https = entry.eq_ignore_ascii_case("HTTPS");
            i += 1;
            if let Some(next) = entries.get(i) {
                if !is_reserved_keyword(next) {
                    if let Some(hp) = parse_one(next) {
                        if is_https {
                            https_hit = https_hit.or(Some(hp));
                        } else {
                            first_hit = first_hit.or(Some(hp));
                        }
                    }
                    i += 1;
                }
            }
            continue;
        }
        // SOCKS/SOCKS4/SOCKS5：PAC 合法的返回值类型，但这条隧道全靠
        // HTTP CONNECT 建立，SOCKS 是完全不同的协议，用不了。把它的
        // 地址当成 HTTP 代理去 CONNECT，只会连上一个不认识 HTTP 的
        // 服务器——比直接跳过更容易在排查时误导人（现场会看到「Gateway
        // TLS 失败」而不是「代理类型不支持」）。跳过整条 `SOCKS* addr`，
        // 让循环继续找列表里后面能用的条目。
        if entry.eq_ignore_ascii_case("SOCKS")
            || entry.eq_ignore_ascii_case("SOCKS4")
            || entry.eq_ignore_ascii_case("SOCKS5")
        {
            i += 1;
            if let Some(next) = entries.get(i) {
                if !is_reserved_keyword(next) {
                    i += 1;
                }
            }
            continue;
        }
        if entry.eq_ignore_ascii_case("DIRECT") {
            i += 1;
            continue;
        }

        // 手工配置形式：可能带 scheme=
        let (scheme, body) = match entry.split_once('=') {
            Some((s, b)) => (Some(s.to_ascii_lowercase()), b),
            None => (None, entry),
        };
        // socks=/socks4=/socks5= 同上，跳过而不是当成 HTTP 代理解析。
        if matches!(
            scheme.as_deref(),
            Some("socks") | Some("socks4") | Some("socks5")
        ) {
            i += 1;
            continue;
        }
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

/// `PROXY`/`HTTP`/`HTTPS`/`SOCKS*` 这些裸关键字词——独立成词时不能被
/// 当成主机名去解析。见 [`parse_proxy_list`] 里对 `PROXY ;DIRECT` 这类
/// 畸形输入的处理。
fn is_reserved_keyword(s: &str) -> bool {
    const KEYWORDS: &[&str] = &[
        "DIRECT", "PROXY", "SOCKS", "SOCKS4", "SOCKS5", "HTTP", "HTTPS",
    ];
    KEYWORDS.iter().any(|k| s.eq_ignore_ascii_case(k))
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
    fn socks_keyword_is_recognized_and_not_treated_as_a_proxy_host() {
        // W18（评审）：改红前，"SOCKS5 p.company.com:1080" 会把字面量
        // "SOCKS5" 当成裸主机名解析成 `SOCKS5:80`，报告成一个自信的
        // 代理——现场表现是客户端去 TCP 拨一台真的叫 "SOCKS5" 的主机，
        // 失败被归因成"Gateway TLS 失败"而不是"代理类型不支持"。
        //
        // 改红：删掉 SOCKS/SOCKS4/SOCKS5 那个分支（连同它的 `continue`），
        // 让 "SOCKS5" 掉进最后的手工配置分支被当成裸主机名解析。
        for raw in ["SOCKS5 p.company.com:1080", "SOCKS p.company.com:1080"] {
            assert!(parse_proxy_list(raw, "gw.company.com").is_none(), "{raw}");
        }
    }

    #[test]
    fn socks_scheme_prefix_form_is_also_skipped() {
        // 手工配置格式里的 `socks=host:port`（真实的 IE"高级"代理设置
        // 允许单独给 SOCKS 填一条）同样不可用——不跟任何其它条目搭配，
        // 单独一条 `socks=` 应该被跳过，跳过之后没有其它候选，结果是
        // `None`。
        //
        // 注意：这条测试原来写成跟一条 `https=` 搭配、断言选中 https
        // 那一项——但 `https_hit.or(first_hit)` 里 https 优先级本来就
        // 高于其它一切，删掉 socks= 的跳过逻辑之后 socks= 会走进
        // `first_hit`，`https_hit.or(first_hit)` 仍然选 https_hit，
        // 测试结果不变、看不出任何差别——这是本任务实现过程中自己
        // 抓到的一次弱测试（改红验证时才发现），已经改成这条更严格的
        // 独立形式，配合下面
        // `socks_scheme_prefix_does_not_shadow_a_later_usable_entry`
        // 一起覆盖"单独出现"与"跟非 https 条目搭配"两种情况。
        //
        // 改红：删掉 `matches!(scheme.as_deref(), Some("socks") | ...)`
        // 这一整段 socks= 跳过逻辑——"socks=socks.company.com:1080" 会
        // 被当成一个普通 scheme 走进 first_hit，返回 Some 而不是 None。
        assert!(parse_proxy_list("socks=socks.company.com:1080", "gw.company.com").is_none());
    }

    #[test]
    fn socks_scheme_prefix_does_not_shadow_a_later_usable_entry() {
        // 混在一条可用的 `http=` 条目旁边（都不是 https，所以走的是
        // `first_hit` 而不是 `https_hit` 的优先级）时，可用的那条应该
        // 照样被选中，而不是被 `socks=` 抢占 `first_hit`。
        //
        // 改红：同上，删掉 socks= 跳过逻辑——socks= 会抢先填满
        // first_hit，后面的 http= 条目因为 `first_hit.or(Some(hp))`
        // 的短路而被忽略，结果变成 socks.company.com:1080 而不是
        // p.company.com:8080。
        let hp = parse_proxy_list(
            "socks=socks.company.com:1080;http=p.company.com:8080",
            "gw.company.com",
        )
        .unwrap();
        assert_eq!(hp.to_string(), "p.company.com:8080");
    }

    #[test]
    fn https_keyword_form_is_recognized_like_the_equals_form() {
        // 部分 PAC 实现会用裸关键字写法而不是手工配置的 `https=` 形式。
        //
        // 改红：把 `entry.eq_ignore_ascii_case("HTTPS")` 那个分支条件
        // 里的 `HTTPS` 删掉（只留 PROXY/HTTP），"HTTPS" 会被当成主机名
        // 解析成 `HTTPS:80` 而不是识别出后面那个地址。
        let hp = parse_proxy_list("HTTPS p.company.com:8443", "gw.company.com").unwrap();
        assert_eq!(hp.to_string(), "p.company.com:8443");
    }

    #[test]
    fn proxy_keyword_followed_by_another_keyword_has_no_usable_address() {
        // W18（评审）：`"PROXY ;DIRECT"` 这种畸形输入按分隔符拆完之后，
        // "PROXY" 后面紧跟的就是字面量 "DIRECT"——改红前这里会被当成
        // 主机名解析出 `DIRECT:80`，报告成一个自信的代理。
        //
        // 改红：把 `if !is_reserved_keyword(next)` 这层判断删掉，
        // 直接对 `next` 调 `parse_one`。
        assert!(parse_proxy_list("PROXY ;DIRECT", "gw.company.com").is_none());
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
