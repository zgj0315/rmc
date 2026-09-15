//! 系统代理探测与解析。取原始配置、对 PAC 求值这两件事都经
//! [`ProxySource`] 抽象；"最终该不该走代理、走哪一个"的判断
//! （[`SystemProxyResolver::decide`]）是纯函数——只依赖 trait 给回的
//! 普通 Rust 值，不摸任何 Win32 符号，因此这条判断逻辑本身在这台
//! macOS 上就能用 [`ProxySource`] 的假实现整条路径测到，包括 PAC 求值
//! 成功/失败、bypass 命中、静态代理这几条路径怎么互相让位。真正碰
//! Win32 的部分只在 [`winhttp`]，整块 `#[cfg(windows)]`，职责仅止于
//! "调 API、把结果转成普通 Rust 值"。
//!
//! [`autoproxy_flags`] 是这条边界上专门抠出来的第三块纯逻辑：WinHTTP
//! 的自动代理选项要不要打开"自动检测"、要不要打开"配置地址"这两个
//! 标志位，只取决于 `RawProxyConfig` 的两个字段，不需要摸任何 Win32
//! 符号就能算出来——评审第一轮就是把这段计算整个丢在 `winhttp.rs`
//! 里，结果两条真实缺陷（`auto_detect` 从未真正生效、`lpszAutoConfigUrl`
//! 违反 MSDN 的 NULL 前置条件）都藏在这台机器测不到的地方。见下方
//! `autoproxy_flags` 与它的表驱动测试。
//!
//! [`pac_outcome`] 是同一个形状的第四块（W20.1）：`WinHttpGetProxyForUrl`
//! 成功之后 `(dwAccessType, lpszProxy)` 这一对该怎么读，本来整段留在
//! `winhttp.rs` 里、零自动化覆盖——复审实测把那两条 arm 对调，35 条
//! 测试加两条 zigbuild 闸门全绿。搬到这里之后同样表驱动测。

pub mod parse;
#[cfg(windows)]
pub mod winhttp;

use parse::{host_is_bypassed, parse_bypass_list, parse_proxy_list};
use rmc_core::addr::HostPort;
use rmc_core::platform::ProxyResolver;
use std::sync::Arc;

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

/// 与 `windows::Win32::Networking::WinHttp::WINHTTP_AUTOPROXY_AUTO_DETECT`
/// 数值相同（Win32 头文件定义、稳定不变的 ABI 常量）。这里重新声明成
/// 普通 `u32`，不是嫌麻烦少写一次 `use`——是因为 [`autoproxy_flags`]
/// 要在非 Windows 平台上编译、跑表驱动测试，而 `windows` crate 整个
/// 只在 `[target.'cfg(windows)'.dependencies]` 里，非 Windows target
/// 上根本拉不到这个依赖，这几个常量符号在 macOS 上不存在。
/// `winhttp.rs` 里有编译期断言核对这两份数值不会漂移，见那边的
/// `const _: () = assert!(...)`。
/// `pub`（而不是 `pub(crate)`）纯粹是为了不需要 `#[allow(dead_code)]`：
/// 这几个常量与 [`autoproxy_flags`] 只有两处消费者——`winhttp.rs`
/// （`#[cfg(windows)]`）与本文件的测试模块（`#[cfg(test)]`）——在
/// macOS 上跑一次不带 `--cfg test` 的 lib 检查（`cargo clippy
/// --all-targets` 会做这一趟）时两者都不在，私有/`pub(crate)` 会被
/// `dead_code` 判定为"整个 crate 都没人用"，因为死代码分析看的是
/// "是否可能被 crate 外部使用"而不是"今天有没有人用"。
pub const AUTOPROXY_AUTO_DETECT: u32 = 1;
/// 同上，对应 `WINHTTP_AUTOPROXY_CONFIG_URL`。
pub const AUTOPROXY_CONFIG_URL: u32 = 2;
/// 同上，对应 `WINHTTP_AUTO_DETECT_TYPE_DHCP`。
pub const AUTO_DETECT_TYPE_DHCP: u32 = 1;
/// 同上，对应 `WINHTTP_AUTO_DETECT_TYPE_DNS_A`。
pub const AUTO_DETECT_TYPE_DNS_A: u32 = 2;

/// 算出 `WINHTTP_AUTOPROXY_OPTIONS` 要用的 `(dwFlags, dwAutoDetectFlags)`
/// 这一对标志位。纯函数：只依赖 `RawProxyConfig` 的两个字段，不摸
/// 任何 Win32 符号，因此评审指出的两条缺陷都能在这台机器上直接用
/// 表驱动测试钉住：
///
/// - **`auto_detect` 必须真正参与计算**：只看 `pac_url` 会让"只勾自动
///   检测、没填地址"的配置永远打不开 `AUTOPROXY_AUTO_DETECT` 标志——
///   `decide()` 那一层已经会因为 `pac_active` 触发调用 `eval_pac`，
///   但如果这一层不看 `auto_detect`，WinHTTP 侧实际执行的自动检测就
///   完全没打开，等于白调用了一次。
/// - **`lpszAutoConfigUrl` 的 NULL 前置条件**：MSDN 原文——「If
///   **dwFlags** does not include `WINHTTP_AUTOPROXY_CONFIG_URL`, then
///   **lpszAutoConfigUrl** must be **NULL**.」——这个前置条件必须由
///   `dwFlags` 与"要不要传地址"两者保持一致来满足；这个函数只负责算出
///   `dwFlags`，真正决定要不要把 `lpszAutoConfigUrl` 设成 NULL 的地方
///   在 `winhttp.rs`（`pac_url.is_some()` 与 `flags` 里是否含
///   `AUTOPROXY_CONFIG_URL` 由同一个 `pac_url` 决定，天然一致，不会
///   出现"标志开了但没传地址"或者"传了地址但标志没开"的分裂状态）。
///
/// 返回值第二项（`dwAutoDetectFlags`）固定是 DHCP + DNS_A 两个探测
/// 方式都打开——只在 `dwFlags` 真的含 `AUTOPROXY_AUTO_DETECT` 时才会
/// 被 WinHTTP 实际使用，`auto_detect` 为假时这个值被忽略，固定给一个
/// 值不影响正确性，也让签名更简单。
pub fn autoproxy_flags(auto_detect: bool, pac_url: Option<&str>) -> (u32, u32) {
    let mut flags = 0u32;
    if auto_detect {
        flags |= AUTOPROXY_AUTO_DETECT;
    }
    if pac_url.is_some() {
        flags |= AUTOPROXY_CONFIG_URL;
    }
    (flags, AUTO_DETECT_TYPE_DHCP | AUTO_DETECT_TYPE_DNS_A)
}

/// 同上，对应 `WINHTTP_ACCESS_TYPE_NO_PROXY`（Win32 头文件里是 1）。
pub const ACCESS_TYPE_NO_PROXY: u32 = 1;
/// 同上，对应 `WINHTTP_ACCESS_TYPE_NAMED_PROXY`（Win32 头文件里是 3）。
pub const ACCESS_TYPE_NAMED_PROXY: u32 = 3;

/// 一次 PAC 求值**成功**之后的结论。
///
/// W20.1：上一轮把它编码成一个字符串——`"DIRECT"` 这个字面量既当
/// 「PAC 说直连」的信号、又混在真代理列表的语法里，跨层传一个魔法值。
/// 形状上跟 W15 刚消掉的「空串当跨层信号」是同一个毛病，换成枚举之后
/// 那个字面量在跨层接口上就不存在了。
///
/// 注意这个类型只表达「求值成功」的两种结论；「求值失败」是外面那层
/// `Option` 的 `None`，两者不能再混。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacOutcome {
    /// PAC 脚本的决定是直连。
    Direct,
    /// PAC 脚本给出了代理，内容是 `WinHttpGetProxyForUrl` 回填的
    /// `lpszProxy`（格式与手工配置的 `lpszProxy` 相同）。
    Proxies(String),
}

/// `WinHttpGetProxyForUrl` 成功返回之后，`(dwAccessType, lpszProxy)`
/// 这一对该怎么读。纯函数，不摸任何 Win32 符号。
///
/// W20.1：这段映射本来整个在 `winhttp.rs` 里，**零自动化覆盖**——复审
/// 实测把 `NO_PROXY` 与 `NAMED_PROXY` 两条 arm 对调，35 passed 加两条
/// zigbuild 闸门全绿。而它是 Task 2 后果最大的那条行为修复：PAC 说
/// 直连时 `lpszProxy` 通常是 NULL，只看这个字段会把「PAC 成功地说了
/// 直连」读成「PAC 求值失败」，于是任何用 PAC 且对 Gateway 返回
/// DIRECT 的企业网络，客户端都会认定 PAC 坏了、去连一个本不该走的
/// 静态代理。形状与 [`autoproxy_flags`] 一样，搬到这里表驱动测。
///
/// `None` 表示这次结果读不出结论——调用成功了，`dwAccessType` 却既不是
/// 「不用代理」也不是「用这个代理」，或者说了「用这个代理」却没给出
/// 代理是谁。这跟调用本身失败一样，都归到「求值失败」那一档。
pub fn pac_outcome(access_type: u32, proxy_list: Option<String>) -> Option<PacOutcome> {
    match access_type {
        ACCESS_TYPE_NO_PROXY => Some(PacOutcome::Direct),
        // `proxy_list` 为 `None` 时这里也是 `None`：说了「走代理」却
        // 没说走哪个，读不出结论。
        ACCESS_TYPE_NAMED_PROXY => proxy_list.map(PacOutcome::Proxies),
        _ => None,
    }
}

/// 取系统代理原始数据、对 PAC 求值——这两件事都要摸 Win32 API，抽成
/// trait 是为了让 [`SystemProxyResolver`] 的判断逻辑不依赖具体实现，
/// 测试时换上假实现即可跑在任何平台。
pub trait ProxySource: Send + Sync {
    fn current(&self) -> RawProxyConfig;

    /// 对 PAC 脚本求值。`auto_detect`/`pac_url` 原样转发
    /// `RawProxyConfig` 里的对应字段（`pac_url` 为 `None` 就是"只开
    /// 自动检测、没有显式地址"）——不再用空字符串充当跨层信号，那种
    /// 写法本身就是评审抓到的一个缺陷（当时会让 `lpszAutoConfigUrl`
    /// 指向一个非 NULL 的空宽字符串，违反 MSDN 的前置条件）。
    ///
    /// 求值成功时返回 [`PacOutcome`]：要么「脚本说直连」，要么「脚本
    /// 给了这些代理」。代理列表的内容不是本 trait 编出来的格式，是
    /// `WinHttpGetProxyForUrl` 真正的输出形状（它已经替调用方从 PAC
    /// 脚本的原始返回值里剥掉了 `SOCKS` 等非 HTTP 类型、并在遇到
    /// `DIRECT` 时截断列表，`lpszProxy` 的文档格式跟手工配置的
    /// `lpszProxy` 完全一样），实现见 `winhttp.rs`。
    ///
    /// `None` 表示求值本身失败（脚本下不下来、自动检测超时、
    /// `WinHttpGetProxyForUrl` 报错、或者结果读不出结论），**不是**
    /// "脚本说直连"——这两件事必须分开处理，混成同一个结果就是
    /// progress.md W12 点名的那种"测试通过但没验证名字声称的事"。
    /// 见 [`ProxyDecision`] 与 [`pac_outcome`]。
    fn eval_pac(
        &self,
        auto_detect: bool,
        pac_url: Option<&str>,
        target_url: &str,
    ) -> Option<PacOutcome>;
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
    source: Arc<S>,
}

impl<S: ProxySource> SystemProxyResolver<S> {
    pub fn new(source: S) -> Self {
        Self {
            source: Arc::new(source),
        }
    }

    pub fn source(&self) -> &S {
        &self.source
    }
}

impl<S: ProxySource + 'static> SystemProxyResolver<S> {
    /// 判断给定目标该不该走代理、走哪一个，细节见 [`ProxyDecision`]。
    /// 判断逻辑本身（bypass/PAC/静态代理三者的优先级）是纯函数，不摸
    /// 任何 Win32 符号；`ProxySource` 的两个方法则是同步、可能阻塞的
    /// 调用（尤其 `eval_pac` 在自动检测时可能真的发起 DHCP/DNS 网络
    /// I/O，耗时可达数秒），所以这里用 [`tokio::task::spawn_blocking`]
    /// 把它们分派到 tokio 的阻塞线程池，不占用调用方所在的异步执行
    /// 线程——如果调用方是 `current_thread` runtime，或者共享的
    /// runtime 上还跑着 UI 事件循环，直接同步调用会让整个事件循环卡住
    /// 到 Win32 调用返回为止。`+ 'static` 是 `spawn_blocking` 的闭包
    /// 要求，`Arc<S>` 让每次调用只克隆一次引用计数，不复制 `S` 本身。
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
    pub async fn decide(&self, target: &HostPort) -> ProxyDecision {
        let source = Arc::clone(&self.source);
        let cfg = match tokio::task::spawn_blocking(move || source.current()).await {
            Ok(cfg) => cfg,
            Err(e) => {
                tracing::error!("读取系统代理配置的阻塞任务崩溃：{e}");
                RawProxyConfig::default()
            }
        };

        let pac_active = cfg.auto_detect || cfg.pac_url.is_some();
        if pac_active {
            let source = Arc::clone(&self.source);
            let auto_detect = cfg.auto_detect;
            let pac_url = cfg.pac_url.clone();
            let url = format!("https://{}:{}/", target.host(), target.port());
            let pac_result = tokio::task::spawn_blocking(move || {
                source.eval_pac(auto_detect, pac_url.as_deref(), &url)
            })
            .await
            .unwrap_or_else(|e| {
                tracing::error!("PAC 求值的阻塞任务崩溃：{e}");
                None
            });
            return match pac_result {
                Some(PacOutcome::Direct) => ProxyDecision::PacDirect,
                Some(PacOutcome::Proxies(list)) => match parse_proxy_list(&list, target.host()) {
                    Some(hp) => ProxyDecision::PacProxy(hp),
                    // 列表里没有一项能用（例如整条都是 SOCKS，或者
                    // 以 `DIRECT` 收尾）——PAC 的决定仍然是"别走代理"。
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
impl<S: ProxySource + 'static> ProxyResolver for SystemProxyResolver<S> {
    async fn resolve(&self, target: &HostPort) -> Option<HostPort> {
        self.decide(target).await.into_target()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration;

    // 下面每条测试上方都写明「改实现的哪一行会让它变红」，且已经逐条
    // 改过一遍确认——过程记在 task-2-report.md，这里不重复贴 diff。

    #[test]
    fn autoproxy_flags_combines_auto_detect_and_config_url_independently() {
        // W14/W15（评审）：这两个标志位必须能独立开关——`auto_detect`
        // 决定 AUTOPROXY_AUTO_DETECT，`pac_url.is_some()` 决定
        // AUTOPROXY_CONFIG_URL，四种组合表驱动测一遍。
        //
        // 改红：把 `if auto_detect { flags |= AUTOPROXY_AUTO_DETECT; }`
        // 删掉——第 2、4 行（auto_detect=true 的两行）会失败，因为
        // AUTOPROXY_AUTO_DETECT 这一位再也不会被置上。
        let cases = [
            (false, None, 0u32),
            (true, None, AUTOPROXY_AUTO_DETECT),
            (false, Some("http://wpad/wpad.dat"), AUTOPROXY_CONFIG_URL),
            (
                true,
                Some("http://wpad/wpad.dat"),
                AUTOPROXY_AUTO_DETECT | AUTOPROXY_CONFIG_URL,
            ),
        ];
        for (auto_detect, pac_url, expected_flags) in cases {
            let (flags, auto_detect_flags) = autoproxy_flags(auto_detect, pac_url);
            assert_eq!(
                flags, expected_flags,
                "auto_detect={auto_detect} pac_url={pac_url:?}"
            );
            assert_eq!(
                auto_detect_flags,
                AUTO_DETECT_TYPE_DHCP | AUTO_DETECT_TYPE_DNS_A
            );
        }
    }

    #[test]
    fn dw_access_type_decides_direct_versus_named_proxy() {
        // W20.1：这段映射原来整个在 `winhttp.rs`（`#[cfg(windows)]`）
        // 里，一个字节的自动化保护都没有——复审实测把 NO_PROXY 与
        // NAMED_PROXY 两条 arm 对调，35 passed 加两条 zigbuild 闸门
        // **全绿**。对调之后的真实后果：任何用 PAC 且对 Gateway 返回
        // DIRECT 的企业网络，客户端都会认定 PAC 坏了、去连一个本不该
        // 走的静态代理。
        //
        // 改红：把 `pac_outcome` 里 `ACCESS_TYPE_NO_PROXY` 与
        // `ACCESS_TYPE_NAMED_PROXY` 两条 arm 对调——第 1、2、3 行全红。
        let cases = [
            // dwAccessType 说"不用代理"，就是 PAC 说直连。lpszProxy
            // 是不是 NULL 都不改变这个结论——这正是上一轮读错的地方。
            (ACCESS_TYPE_NO_PROXY, None, Some(PacOutcome::Direct)),
            (
                ACCESS_TYPE_NO_PROXY,
                Some("p.company.com:8080"),
                Some(PacOutcome::Direct),
            ),
            (
                ACCESS_TYPE_NAMED_PROXY,
                Some("p.company.com:8080"),
                Some(PacOutcome::Proxies("p.company.com:8080".into())),
            ),
            // 说了"走代理"却没说走哪个：读不出结论，归到求值失败。
            (ACCESS_TYPE_NAMED_PROXY, None, None),
            // WINHTTP_ACCESS_TYPE_DEFAULT_PROXY(0) /
            // AUTOMATIC_PROXY(4)：`WinHttpGetProxyForUrl` 不该回填这两
            // 个值，真回填了也读不出结论。
            (0, Some("p.company.com:8080"), None),
            (4, None, None),
        ];
        for (access_type, proxy_list, expected) in cases {
            assert_eq!(
                pac_outcome(access_type, proxy_list.map(str::to_string)),
                expected,
                "access_type={access_type}"
            );
        }
    }

    /// 记录每次 `eval_pac` 收到的 `(auto_detect, pac_url, target_url)`，
    /// 比 brief 给的样例（只记 target_url）多验证两件事：只开自动检测、
    /// 没填显式地址时 `pac_url` 传的是 `None` 不是魔法空字符串；以及
    /// `auto_detect` 本身有没有原样转发过去（W15）。
    struct Fake {
        raw: RawProxyConfig,
        pac_result: Option<PacOutcome>,
        pac_calls: Mutex<Vec<(bool, Option<String>, String)>>,
    }

    impl Fake {
        fn new(raw: RawProxyConfig, pac_result: Option<PacOutcome>) -> Self {
            Self {
                raw,
                pac_result,
                pac_calls: Mutex::new(Vec::new()),
            }
        }

        /// "PAC 求值成功，给出了这些代理"。
        fn proxies(raw: RawProxyConfig, list: &str) -> Self {
            Self::new(raw, Some(PacOutcome::Proxies(list.to_string())))
        }
    }

    impl ProxySource for Fake {
        fn current(&self) -> RawProxyConfig {
            self.raw.clone()
        }
        fn eval_pac(
            &self,
            auto_detect: bool,
            pac_url: Option<&str>,
            target_url: &str,
        ) -> Option<PacOutcome> {
            self.pac_calls.lock().unwrap().push((
                auto_detect,
                pac_url.map(str::to_string),
                target_url.to_string(),
            ));
            self.pac_result.clone()
        }
    }

    /// 用来证明 `decide()`/`resolve()` 真的把阻塞调用分派出去了、没有
    /// 占住调用方所在的异步执行线程——见
    /// `blocking_proxy_source_calls_do_not_starve_the_async_runtime`。
    struct SlowFake {
        /// `current()` 里睡多久。
        current_sleep: Duration,
        /// `eval_pac()` 里睡多久。W20.1：上一轮只给 `current()` 加了
        /// 睡眠，于是"eval_pac 也走了 spawn_blocking"这件事零覆盖——
        /// 复审实测把 `eval_pac` 那次 `spawn_blocking` 换成同步调用，
        /// 35 passed 全绿。而它才是真正会阻塞数秒的那个（自动检测要跑
        /// DHCP INFORM + DNS wpad，MSDN 明说可能"several seconds"）。
        pac_sleep: Duration,
        /// 触发 PAC 那条路径要靠这个字段（`decide()` 看 `pac_active`）。
        auto_detect: bool,
    }

    impl SlowFake {
        fn slow_current(sleep: Duration) -> Self {
            Self {
                current_sleep: sleep,
                pac_sleep: Duration::ZERO,
                auto_detect: false,
            }
        }
        fn slow_pac(sleep: Duration) -> Self {
            Self {
                current_sleep: Duration::ZERO,
                pac_sleep: sleep,
                auto_detect: true,
            }
        }
    }

    impl ProxySource for SlowFake {
        fn current(&self) -> RawProxyConfig {
            std::thread::sleep(self.current_sleep);
            RawProxyConfig {
                auto_detect: self.auto_detect,
                ..RawProxyConfig::default()
            }
        }
        fn eval_pac(&self, _: bool, _: Option<&str>, _: &str) -> Option<PacOutcome> {
            std::thread::sleep(self.pac_sleep);
            None
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
        //
        // W17（评审）：额外用 decide() 断言精确变体，不只是 resolve()
        // 的字符串——评审实测过 StaticProxy 与
        // PacEvalFailedFellBackToStatic 整体互换、27 条测试全绿，因为
        // 原来没有一条测试直接比较 decide() 在"没有 PAC、走静态代理"
        // 这个场景下的变体身份。
        let mut c = raw();
        c.proxy = Some("https=proxy.company.com:8080".into());
        let r = SystemProxyResolver::new(Fake::new(c, None));
        assert_eq!(
            r.decide(&gw()).await,
            ProxyDecision::StaticProxy("proxy.company.com:8080".parse().unwrap())
        );
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
        let r = SystemProxyResolver::new(Fake::proxies(c, "PROXY pac.company.com:3128"));
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
        // 顺带验证 pac_url/auto_detect 参数本身也原样传到了 eval_pac
        // ——不是 brief 原样例只查 target_url 那种只验证一半的写法。
        let mut c = raw();
        c.pac_url = Some("http://wpad.company.com/wpad.dat".into());
        let fake = Fake::proxies(c, "PROXY p:3128");
        let r = SystemProxyResolver::new(fake);
        r.resolve(&gw()).await;
        let calls = r.source().pac_calls.lock().unwrap().clone();
        assert_eq!(
            calls,
            vec![(
                false,
                Some("http://wpad.company.com/wpad.dat".to_string()),
                "https://gateway.company.com:443/".to_string()
            )]
        );
    }

    #[tokio::test]
    async fn pac_returning_direct_means_direct() {
        // W17（评审）：改红前只断言 `resolve().is_none()`，评审实测
        // 把 `PacDirect` 换成 `NotConfigured` 或 `Bypassed` 都全绿——
        // 三者折成 resolve() 都是 None。这里改成断言 decide() 的精确
        // 变体，结构上就排除了另外两种可能。
        //
        // 改红：decide() 里 PAC 求值成功那一支，把
        // `None => ProxyDecision::PacDirect` 换成
        // `None => ProxyDecision::NotConfigured`（或 `Bypassed`）。
        let mut c = raw();
        c.pac_url = Some("http://wpad/wpad.dat".into());
        c.proxy = Some("static.company.com:8080".into());
        let r = SystemProxyResolver::new(Fake::new(c, Some(PacOutcome::Direct)));
        assert_eq!(r.decide(&gw()).await, ProxyDecision::PacDirect);
        assert!(r.resolve(&gw()).await.is_none());
    }

    #[tokio::test]
    async fn pac_failure_falls_back_to_the_static_proxy() {
        // 改红：decide() 里 `None => manual_decision(target, &cfg, true)`
        // 换成 `None => ProxyDecision::PacEvalFailedNoFallback`（跳过
        // 退回静态代理这一步）。
        //
        // W17（评审）：同上，额外断言 decide() 的精确变体
        // （`PacEvalFailedFellBackToStatic`），不止是折叠之后的地址。
        let mut c = raw();
        c.pac_url = Some("http://wpad/wpad.dat".into());
        c.proxy = Some("static.company.com:8080".into());
        let r = SystemProxyResolver::new(Fake::new(c, None));
        assert_eq!(
            r.decide(&gw()).await,
            ProxyDecision::PacEvalFailedFellBackToStatic(
                "static.company.com:8080".parse().unwrap()
            )
        );
        assert_eq!(
            r.resolve(&gw()).await.unwrap().to_string(),
            "static.company.com:8080"
        );
    }

    #[tokio::test]
    async fn decide_distinguishes_pac_failure_without_fallback_from_not_configured() {
        // 这条测试钉住本任务对"resolve() 混平了两件事"这个问题给出的
        // 答案：resolve() 确实把两者都折成 None，但 decide() 必须能
        // 分开——一个是"确认不需要代理"，一个是"该走代理但求值失败、
        // 又没有静态代理可退、被迫尝试直连"。诊断页（§3.10 的预检结果
        // 要区分"需要代理"）该读 decide() 而不是 resolve()。
        //
        // W17（评审）：原来这里还有两条
        // `assert_eq!(...into_target(), None)`，评审指出这两条在结构上
        // 不可证伪——`NotConfigured`/`PacEvalFailedNoFallback` 都没有
        // 载荷，`into_target()` 对它们的分支根本没有 `HostPort` 可返回，
        // 不管映射表怎么改都只能是 None。删掉，换成下面两条独立、真正
        // 会调用 `resolve()`（走一遍真实的折叠代码路径，而不是直接
        // 摆弄 `ProxyDecision` 值）的测试。
        //
        // 改红：把 manual_decision 里
        // `(true, None) => ProxyDecision::PacEvalFailedNoFallback`
        // 换成 `(true, None) => ProxyDecision::NotConfigured`——两次
        // decide() 调用会返回同一个变体，第一条 assert_ne! 变红。
        let not_configured = SystemProxyResolver::new(Fake::new(raw(), None))
            .decide(&gw())
            .await;

        let mut c = raw();
        c.pac_url = Some("http://wpad/wpad.dat".into());
        let pac_failed_no_fallback = SystemProxyResolver::new(Fake::new(c, None))
            .decide(&gw())
            .await;

        assert_ne!(not_configured, pac_failed_no_fallback);
        assert_eq!(not_configured, ProxyDecision::NotConfigured);
        assert_eq!(
            pac_failed_no_fallback,
            ProxyDecision::PacEvalFailedNoFallback
        );
    }

    #[tokio::test]
    async fn pac_failure_without_fallback_resolves_to_direct() {
        // 上一条测试的"折叠之后确实一样"那一半，用真正的 resolve()
        // 调用证明（而不是直接对 into_target() 断言 None，那样对无
        // 载荷的变体是不可证伪的）——如果 manual_decision 错误地把
        // `(true, None)` 映射成一个带假地址的变体，这里会在 `.unwrap()`
        // 处 panic 或者 `is_none()` 断言失败，是真的会失败的检查。
        let mut c = raw();
        c.pac_url = Some("http://wpad/wpad.dat".into());
        let r = SystemProxyResolver::new(Fake::new(c, None));
        assert!(r.resolve(&gw()).await.is_none());
    }

    #[tokio::test]
    async fn bypass_does_not_apply_while_pac_governs_the_decision() {
        // 命中 gateway.company.com 的 bypass 模式，但 PAC 在管，且 PAC
        // 求值成功给出了一个代理——bypass 名单不该覆盖 PAC 的决定
        // （见 decide() 上方注释：WinHttpGetProxyForUrl 根本不接收
        // bypass 名单这个参数，这是 Win32 API 形状决定的规则）。
        //
        // 改红：把 decide() 改成先检查 bypass 再检查 pac_active（比如
        // 在 `let cfg = ...` 之后立刻插入 manual_decision 的 bypass
        // 检查并在命中时直接返回 ProxyDecision::Bypassed）——这条测试
        // 会从 PacProxy 变成 Bypassed，assert_eq! 失败。
        let mut c = raw();
        c.pac_url = Some("http://wpad.company.com/wpad.dat".into());
        c.bypass = Some("*.company.com".into());
        let r = SystemProxyResolver::new(Fake::proxies(c, "PROXY pac.company.com:3128"));
        assert_eq!(
            r.decide(&gw()).await,
            ProxyDecision::PacProxy("pac.company.com:3128".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn bypass_reapplies_after_pac_evaluation_fails() {
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
        assert_eq!(r.decide(&gw()).await, ProxyDecision::Bypassed);
    }

    #[tokio::test]
    async fn auto_detect_alone_still_triggers_pac_evaluation() {
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
        let fake = Fake::proxies(c, "PROXY wpad-found.company.com:3128");
        let r = SystemProxyResolver::new(fake);
        assert_eq!(
            r.decide(&gw()).await.into_target().unwrap().to_string(),
            "wpad-found.company.com:3128"
        );
        let calls = r.source().pac_calls.lock().unwrap().clone();
        assert_eq!(
            calls,
            vec![(true, None, "https://gateway.company.com:443/".to_string())]
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

    #[tokio::test]
    async fn blocking_proxy_source_calls_do_not_starve_the_async_runtime() {
        // W16（评审给的反例）：`current()` 用 `std::thread::sleep` 模拟
        // 一次真实的、可能耗时数秒的 Win32/网络阻塞调用（WinHTTP 的
        // 自动检测正是这种调用）。如果 decide() 直接同步调用它，这次
        // sleep 会挡住当前 tokio 任务所在的执行线程，`tokio::time::
        // timeout` 自己也需要被调度才能触发，会因为调度不到而"超时"
        // 得比实际慢、或者干脆等 sleep 走完才返回——测不出超时。用
        // `spawn_blocking` 把阻塞调用分派到独立的阻塞线程池之后，当前
        // 异步任务所在的线程仍然空闲，timeout 能在真实预算内触发。
        //
        // 改红：把 decide() 里
        // `tokio::task::spawn_blocking(move || source.current())`
        // 换回直接同步调用 `source.current()`（不经过 spawn_blocking）
        // ——这条测试会从"超时"变成等满 500ms 的 sleep 之后才返回，
        // `outcome.is_err()` 断言失败。
        let r = SystemProxyResolver::new(SlowFake::slow_current(Duration::from_millis(500)));
        let outcome = tokio::time::timeout(Duration::from_millis(50), r.resolve(&gw())).await;
        assert!(outcome.is_err(), "阻塞调用不该占用调用方的异步执行线程");
    }

    #[tokio::test]
    async fn a_blocking_pac_evaluation_does_not_starve_the_async_runtime_either() {
        // W20.1 的第二半：上一条只覆盖了 `current()`。复审实测把
        // `eval_pac` 那次 `spawn_blocking` 换成同步调用，35 passed
        // 全绿——而 `eval_pac` 才是真正会阻塞数秒的那个（自动检测要跑
        // 完 DHCP INFORM + DNS wpad 才轮到 PAC 下载与执行，MSDN 对这
        // 两个函数的原话是 "blocking, synchronous"）。
        //
        // 改红：把 decide() 里包着 `source.eval_pac(...)` 的那次
        // `tokio::task::spawn_blocking` 去掉、直接同步调用——这条会从
        // "超时"变成等满 500ms 才返回，`is_err()` 断言失败。
        // （注意 `current()` 这一路仍然走 spawn_blocking，所以这条测试
        // 单独钉住的就是 eval_pac 那一处。）
        let r = SystemProxyResolver::new(SlowFake::slow_pac(Duration::from_millis(500)));
        let outcome = tokio::time::timeout(Duration::from_millis(50), r.resolve(&gw())).await;
        assert!(outcome.is_err(), "PAC 求值不该占用调用方的异步执行线程");
    }
}
