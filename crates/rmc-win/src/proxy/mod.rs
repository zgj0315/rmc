//! 系统代理探测与解析。取原始配置、对 PAC 求值这两件事都经
//! [`ProxySource`] 抽象；"最终该不该走代理、走哪一个"的判断
//! （[`SystemProxyResolver::decide`]）是纯函数——只依赖 trait 给回的
//! 普通 Rust 值，不摸任何 Win32 符号，因此这条判断逻辑本身在这台
//! macOS 上就能用 [`ProxySource`] 的假实现整条路径测到，包括 PAC 求值
//! 成功/失败、bypass 命中、静态代理这几条路径怎么互相让位。真正碰
//! Win32 的部分只在 [`winhttp`]，整块 `#[cfg(windows)]`，职责仅止于
//! "调 API、把结果转成普通 Rust 值"。

pub mod parse;
#[cfg(windows)]
pub mod winhttp;

use parse::{host_is_bypassed, parse_bypass_list, parse_proxy_list};
use rmc_core::addr::HostPort;
use rmc_core::platform::ProxyResolver;

/// 从 WinHTTP/IE 读到的原始系统代理配置。这一层只是数据搬运，不含任何
/// "该不该用"的判断——那部分在 [`SystemProxyResolver::decide`]。
#[derive(Debug, Clone, Default)]
pub struct RawProxyConfig {
    /// 对应 IE"自动检测设置"（WPAD，经 DHCP/DNS 发现，不需要显式地址）。
    /// 这个字段与 `pac_url` 不是互斥选项，见 [`SystemProxyResolver::decide`]
    /// 里 `pac_active` 的判断——只看 `pac_url.is_some()` 会漏掉"只勾了
    /// 自动检测、没填地址"这种很常见的企业配置。
    pub auto_detect: bool,
    /// 对应 IE"使用设置脚本"填的 PAC 文件地址。
    pub pac_url: Option<String>,
    pub proxy: Option<String>,
    pub bypass: Option<String>,
}

/// 取系统代理原始数据、对 PAC 求值——这两件事都要摸 Win32 API，抽成
/// trait 是为了让 [`SystemProxyResolver`] 的判断逻辑不依赖具体实现，
/// 测试时换上假实现即可跑在任何平台。
pub trait ProxySource: Send + Sync {
    fn current(&self) -> RawProxyConfig;

    /// 对 PAC 脚本求值，返回形如 `PROXY host:port; DIRECT` 的结果。
    /// `None` 表示求值本身失败（脚本下不下来、自动检测超时等），**不是**
    /// "脚本说直连"——这两件事必须分开处理，混成同一个结果就是
    /// progress.md W12 点名的那种"测试通过但没验证名字声称的事"。见
    /// [`ProxyDecision`]。
    fn eval_pac(&self, pac_url: &str, target_url: &str) -> Option<String>;
}

/// 一次代理解析的完整结果，比 [`ProxyResolver::resolve`] 需要的
/// `Option<HostPort>` 更细。那个签名是 rmc-core 定的，`None` 天然把
/// "确认不需要代理"与"该走代理但求值失败、又没有静态代理可退"压成了
/// 同一个值——这两件事对现场工程师是完全不同的处置：前者是正常直连，
/// 后者是配置可能有问题、需要人去看。`resolve()` 的文档已经承诺
/// "`None` 就是直连"，这份实现忠实履行这个承诺（除了尝试直连也没有
/// 别的动作可做），但这个类型把两者的区别保留下来，供诊断页（后续
/// 任务，方案 §3.10 的预检结果需要区分"需要代理"这一项）走 `decide()`
/// 而不是 `resolve()`，把这两种情况分开报告。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyDecision {
    /// 命中 bypass 名单（无论是主路径，还是 PAC 求值失败后退回手工
    /// 配置那条路径），判定直连。
    Bypassed,
    /// 没有任何代理机制在起作用（没开自动检测、没填 PAC 地址、也没有
    /// 静态代理），直连。
    NotConfigured,
    /// 没有 PAC 在管，走的是手工配置的静态代理。
    StaticProxy(HostPort),
    /// PAC 求值成功，脚本自己的决定是直连。
    PacDirect,
    /// PAC 求值成功，脚本给出了要走的代理。
    PacProxy(HostPort),
    /// PAC 求值失败（下不了脚本、自动检测超时等），退回到手工配置的
    /// 静态代理。
    PacEvalFailedFellBackToStatic(HostPort),
    /// PAC 求值失败，且没有静态代理可退——这不是"确认不需要代理"，是
    /// "配置可能有问题、被迫尝试直连"。诊断页必须能把这一项跟
    /// `NotConfigured` 区分开报告，否则现场工程师会把"公司网络本来就
    /// 不需要代理"和"WPAD 服务器联系不上"当成同一件事处理。
    PacEvalFailedNoFallback,
}

impl ProxyDecision {
    /// 折成 [`ProxyResolver::resolve`] 需要的形状：只有真的解析出一个
    /// 代理地址时才是 `Some`，其余（包括两种不同原因的"直连"）都是
    /// `None`。
    pub fn into_target(self) -> Option<HostPort> {
        match self {
            ProxyDecision::StaticProxy(hp)
            | ProxyDecision::PacProxy(hp)
            | ProxyDecision::PacEvalFailedFellBackToStatic(hp) => Some(hp),
            ProxyDecision::Bypassed
            | ProxyDecision::NotConfigured
            | ProxyDecision::PacDirect
            | ProxyDecision::PacEvalFailedNoFallback => None,
        }
    }
}

pub struct SystemProxyResolver<S: ProxySource> {
    source: S,
}

impl<S: ProxySource> SystemProxyResolver<S> {
    pub fn new(source: S) -> Self {
        Self { source }
    }

    pub fn source(&self) -> &S {
        &self.source
    }

    /// 判断给定目标该不该走代理、走哪一个，细节见 [`ProxyDecision`]。
    /// 纯函数：只调用 [`ProxySource`] 的两个方法拿数据，不摸任何 Win32
    /// 符号，因此这条判断逻辑本身在任何平台都能用假实现测到。
    ///
    /// **为什么 bypass 名单不对 PAC 生效**：这不是本实现随手定的规则，
    /// 是 Win32 API 本身的形状决定的——`WinHttpGetProxyForUrl` 求值
    /// PAC 时根本不接收 bypass 名单这个参数；`lpszProxyBypass` 只出现
    /// 在 `WINHTTP_CURRENT_USER_IE_PROXY_CONFIG` 里，与同一结构体的
    /// 手工 `lpszProxy` 配对生效，IE/Edge 的真实行为也是如此——PAC
    /// 脚本自己给出的 DIRECT/PROXY 决定就是最终决定。如果颠倒这个
    /// 顺序（bypass 优先于 PAC），一条内部域名同时落在 bypass 名单里、
    /// 又被公司 PAC 策略故意路由去代理（出于审计/过滤要求，这种配置
    /// 并不少见），就会被错误地判成直连，而直连在只允许经代理出网的
    /// 网络里往往就是连不通。bypass 名单只在"没有 PAC 在管"时才检查：
    /// PAC 未启用（`pac_active` 为假），或者 PAC 求值失败、退回手工
    /// 配置这条路径。
    pub fn decide(&self, target: &HostPort) -> ProxyDecision {
        let cfg = self.source.current();

        let pac_active = cfg.auto_detect || cfg.pac_url.is_some();
        if pac_active {
            let pac_url = cfg.pac_url.as_deref().unwrap_or("");
            let url = format!("https://{}:{}/", target.host(), target.port());
            return match self.source.eval_pac(pac_url, &url) {
                Some(result) => match parse_proxy_list(&result, target.host()) {
                    Some(hp) => ProxyDecision::PacProxy(hp),
                    None => ProxyDecision::PacDirect,
                },
                None => manual_decision(target, &cfg, true),
            };
        }

        manual_decision(target, &cfg, false)
    }
}

/// bypass 名单 + 静态代理，手工配置这条路径。纯函数，不碰 `self` 也不
/// 碰 [`ProxySource`]——`decide()` 在两个不同的调用点用到它：没有 PAC
/// 在管时，以及 PAC 求值失败退回手工配置时，`pac_eval_failed` 只影响
/// "有静态代理可退"这一支该标成 [`ProxyDecision`] 的哪个变体，不影响
/// 判断本身。
fn manual_decision(
    target: &HostPort,
    cfg: &RawProxyConfig,
    pac_eval_failed: bool,
) -> ProxyDecision {
    if let Some(bypass) = cfg.bypass.as_deref() {
        if host_is_bypassed(target.host(), &parse_bypass_list(bypass)) {
            return ProxyDecision::Bypassed;
        }
    }
    let proxy = cfg
        .proxy
        .as_deref()
        .and_then(|raw| parse_proxy_list(raw, target.host()));
    match (pac_eval_failed, proxy) {
        (true, Some(hp)) => ProxyDecision::PacEvalFailedFellBackToStatic(hp),
        (true, None) => ProxyDecision::PacEvalFailedNoFallback,
        (false, Some(hp)) => ProxyDecision::StaticProxy(hp),
        (false, None) => ProxyDecision::NotConfigured,
    }
}

#[async_trait::async_trait]
impl<S: ProxySource> ProxyResolver for SystemProxyResolver<S> {
    async fn resolve(&self, target: &HostPort) -> Option<HostPort> {
        self.decide(target).into_target()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // 下面每条测试上方都写明「改实现的哪一行会让它变红」，且已经逐条
    // 改过一遍确认——过程记在 task-2-report.md，这里不重复贴 diff。

    /// 记录每次 `eval_pac` 收到的 `(pac_url, target_url)`，比 brief
    /// 给的样例（只记 target_url）多验证一件事：只开自动检测、没填
    /// 显式地址时，`decide()` 传给 `eval_pac` 的 `pac_url` 到底是什么。
    struct Fake {
        raw: RawProxyConfig,
        pac_result: Option<String>,
        pac_calls: Mutex<Vec<(String, String)>>,
    }

    impl Fake {
        fn new(raw: RawProxyConfig, pac_result: Option<&str>) -> Self {
            Self {
                raw,
                pac_result: pac_result.map(str::to_string),
                pac_calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl ProxySource for Fake {
        fn current(&self) -> RawProxyConfig {
            self.raw.clone()
        }
        fn eval_pac(&self, pac_url: &str, target_url: &str) -> Option<String> {
            self.pac_calls
                .lock()
                .unwrap()
                .push((pac_url.to_string(), target_url.to_string()));
            self.pac_result.clone()
        }
    }

    fn raw() -> RawProxyConfig {
        RawProxyConfig {
            auto_detect: false,
            pac_url: None,
            proxy: None,
            bypass: None,
        }
    }

    fn gw() -> HostPort {
        "gateway.company.com:443".parse().unwrap()
    }

    #[tokio::test]
    async fn no_configuration_means_direct() {
        // 改红：把 manual_decision 里 `(false, None) => NotConfigured`
        // 换成返回一个 `Some(HostPort)` 的变体。
        let r = SystemProxyResolver::new(Fake::new(raw(), None));
        assert!(r.resolve(&gw()).await.is_none());
    }

    #[tokio::test]
    async fn static_proxy_is_used() {
        // 改红：manual_decision 里 `(false, Some(hp)) => StaticProxy(hp)`
        // 换成 `(false, Some(_)) => ProxyDecision::NotConfigured`。
        let mut c = raw();
        c.proxy = Some("https=proxy.company.com:8080".into());
        let r = SystemProxyResolver::new(Fake::new(c, None));
        assert_eq!(
            r.resolve(&gw()).await.unwrap().to_string(),
            "proxy.company.com:8080"
        );
    }

    #[tokio::test]
    async fn bypass_wins_over_static_proxy() {
        // 改红：manual_decision 里删掉 bypass 检查那一整段
        // `if let Some(bypass) = ... { ... }`。
        let mut c = raw();
        c.proxy = Some("proxy.company.com:8080".into());
        c.bypass = Some("*.company.com".into());
        let r = SystemProxyResolver::new(Fake::new(c, None));
        assert!(r.resolve(&gw()).await.is_none(), "命中 bypass 应直连");
    }

    #[tokio::test]
    async fn pac_result_wins_over_static_proxy() {
        // 改红：decide() 里 `if pac_active { ... }` 换成
        // `if false { ... }`（或者干脆删掉这整段），静态代理会被
        // 直接返回而不是 PAC 结果。
        let mut c = raw();
        c.proxy = Some("static.company.com:8080".into());
        c.pac_url = Some("http://wpad.company.com/wpad.dat".into());
        let r = SystemProxyResolver::new(Fake::new(c, Some("PROXY pac.company.com:3128")));
        assert_eq!(
            r.resolve(&gw()).await.unwrap().to_string(),
            "pac.company.com:3128"
        );
    }

    #[tokio::test]
    async fn pac_is_evaluated_against_an_https_url_for_the_gateway() {
        // 改红：把 decide() 里 `format!("https://{}:{}/", ...)` 的
        // scheme 从 "https" 换成 "http"——CONNECT 隧道走的是 TLS，
        // PAC 必须按真实要连接的 scheme 求值，用错 scheme 可能求出
        // 完全不同的路由规则（很多企业 PAC 脚本按 scheme 分流）。
        // 顺带验证 pac_url 参数本身也原样传到了 eval_pac——不是brief
        // 原样例只查 target_url 那种只验证一半的写法。
        let mut c = raw();
        c.pac_url = Some("http://wpad.company.com/wpad.dat".into());
        let fake = Fake::new(c, Some("PROXY p:3128"));
        let r = SystemProxyResolver::new(fake);
        r.resolve(&gw()).await;
        let calls = r.source().pac_calls.lock().unwrap().clone();
        assert_eq!(
            calls,
            vec![(
                "http://wpad.company.com/wpad.dat".to_string(),
                "https://gateway.company.com:443/".to_string()
            )]
        );
    }

    #[tokio::test]
    async fn pac_returning_direct_means_direct() {
        // 改红：decide() 里 PAC 求值成功那一支，把
        // `None => ProxyDecision::PacDirect` 换成
        // `None => ProxyDecision::PacEvalFailedNoFallback`——resolve()
        // 的结果这条测试看不出差别（两者 into_target 都是 None），但
        // 下面 `decide_distinguishes_...` 那条测试会先变红；单独测这
        // 一条时改成让它直接 `.unwrap()` 出一个 HostPort 才会让*这条*
        // 测试变红：把 `None => PacDirect` 换成
        // `None => ProxyDecision::PacProxy(target.clone())`。
        let mut c = raw();
        c.pac_url = Some("http://wpad/wpad.dat".into());
        c.proxy = Some("static.company.com:8080".into());
        let r = SystemProxyResolver::new(Fake::new(c, Some("DIRECT")));
        assert!(r.resolve(&gw()).await.is_none());
    }

    #[tokio::test]
    async fn pac_failure_falls_back_to_the_static_proxy() {
        // 改红：decide() 里 `None => manual_decision(target, &cfg, true)`
        // 换成 `None => ProxyDecision::PacEvalFailedNoFallback`（跳过
        // 退回静态代理这一步）。
        let mut c = raw();
        c.pac_url = Some("http://wpad/wpad.dat".into());
        c.proxy = Some("static.company.com:8080".into());
        let r = SystemProxyResolver::new(Fake::new(c, None));
        assert_eq!(
            r.resolve(&gw()).await.unwrap().to_string(),
            "static.company.com:8080"
        );
    }

    #[test]
    fn decide_distinguishes_pac_failure_without_fallback_from_not_configured() {
        // 这条测试钉住本任务对"resolve() 混平了两件事"这个问题给出的
        // 答案：resolve()（=into_target()）确实把两者都折成 None，但
        // decide() 必须能分开——一个是"确认不需要代理"，一个是"该走
        // 代理但求值失败、又没有静态代理可退、被迫尝试直连"。诊断页
        // （§3.10 的预检结果要区分"需要代理"）该读 decide() 而不是
        // resolve()。
        //
        // 改红：把 manual_decision 里
        // `(true, None) => ProxyDecision::PacEvalFailedNoFallback`
        // 换成 `(true, None) => ProxyDecision::NotConfigured`——两次
        // decide() 调用会返回同一个变体，第一条 assert_ne! 变红。
        let not_configured = SystemProxyResolver::new(Fake::new(raw(), None)).decide(&gw());

        let mut c = raw();
        c.pac_url = Some("http://wpad/wpad.dat".into());
        let pac_failed_no_fallback = SystemProxyResolver::new(Fake::new(c, None)).decide(&gw());

        assert_ne!(not_configured, pac_failed_no_fallback);
        assert_eq!(not_configured, ProxyDecision::NotConfigured);
        assert_eq!(
            pac_failed_no_fallback,
            ProxyDecision::PacEvalFailedNoFallback
        );
        // 但两者折成 resolve() 的形状之后确实都是直连——除了尝试直连，
        // 没有别的动作可做，这是 resolve() 自身文档承诺的行为，不是
        // 这条测试要否定的事。
        assert_eq!(not_configured.into_target(), None);
        assert_eq!(pac_failed_no_fallback.into_target(), None);
    }

    #[test]
    fn bypass_does_not_apply_while_pac_governs_the_decision() {
        // 命中 gateway.company.com 的 bypass 模式，但 PAC 在管，且 PAC
        // 求值成功给出了一个代理——bypass 名单不该覆盖 PAC 的决定
        // （见 decide() 上方注释：WinHttpGetProxyForUrl 根本不接收
        // bypass 名单这个参数，这是 Win32 API 形状决定的规则）。
        //
        // 改红：把 decide() 改成先检查 bypass 再检查 pac_active（比如
        // 在 `let cfg = self.source.current();` 之后立刻插入
        // manual_decision 的 bypass 检查并在命中时直接返回
        // ProxyDecision::Bypassed）——这条测试会从 PacProxy 变成
        // Bypassed，assert_eq! 失败。
        let mut c = raw();
        c.pac_url = Some("http://wpad.company.com/wpad.dat".into());
        c.bypass = Some("*.company.com".into());
        let r = SystemProxyResolver::new(Fake::new(c, Some("PROXY pac.company.com:3128")));
        assert_eq!(
            r.decide(&gw()),
            ProxyDecision::PacProxy("pac.company.com:3128".parse().unwrap())
        );
    }

    #[test]
    fn bypass_reapplies_after_pac_evaluation_fails() {
        // PAC 求值失败之后退回手工配置这条路径，bypass 名单要重新
        // 生效——这时走的已经是手工配置，不再是 PAC 的决定。
        //
        // 改红：把 decide() 里 `None => manual_decision(target, &cfg, true)`
        // 换成 `None => ProxyDecision::PacEvalFailedNoFallback`（彻底
        // 跳过 manual_decision，也就跳过了它里面的 bypass 检查）——这条
        // 测试会从 Bypassed 变成 PacEvalFailedNoFallback。
        let mut c = raw();
        c.pac_url = Some("http://wpad/wpad.dat".into());
        c.bypass = Some("*.company.com".into());
        let r = SystemProxyResolver::new(Fake::new(c, None));
        assert_eq!(r.decide(&gw()), ProxyDecision::Bypassed);
    }

    #[test]
    fn auto_detect_alone_still_triggers_pac_evaluation() {
        // 只勾了"自动检测"、没填 PAC 地址——这是很常见的企业配置
        // （纯 WPAD，经 DHCP/DNS 发现，没有一个"PAC 地址"字符串）。
        // 只看 pac_url.is_some() 会让这种配置直接跳过 PAC 求值。
        //
        // 改红：decide() 里 `cfg.auto_detect || cfg.pac_url.is_some()`
        // 去掉 `cfg.auto_detect ||`，只剩 `cfg.pac_url.is_some()`——
        // eval_pac 再也不会被调用，pac_calls 是空的，两条 assert 都
        // 会失败（第一条在 unwrap 处 panic）。
        let mut c = raw();
        c.auto_detect = true;
        let fake = Fake::new(c, Some("PROXY wpad-found.company.com:3128"));
        let r = SystemProxyResolver::new(fake);
        assert_eq!(
            r.decide(&gw()).into_target().unwrap().to_string(),
            "wpad-found.company.com:3128"
        );
        let calls = r.source().pac_calls.lock().unwrap().clone();
        assert_eq!(
            calls,
            vec![(
                String::new(),
                "https://gateway.company.com:443/".to_string()
            )]
        );
    }

    #[test]
    fn manual_decision_is_pure_and_needs_no_fake_at_all() {
        // manual_decision 是这份实现里唯一一处完全不需要 ProxySource
        // 抽象、连 Fake 都不用的单元——直接测它本身。
        //
        // 改红：把 manual_decision 里 bypass 检查那段的 `return
        // ProxyDecision::Bypassed` 删掉。
        let mut c = raw();
        c.proxy = Some("proxy.company.com:8080".into());
        c.bypass = Some("*.company.com".into());
        assert_eq!(manual_decision(&gw(), &c, false), ProxyDecision::Bypassed);
    }
}
