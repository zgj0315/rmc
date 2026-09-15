//! WinHTTP 取系统代理配置并对 PAC 求值。
//! 本模块含 unsafe，逻辑都很短：判断"该不该用、用哪个"完全不在这里，
//! 都在 [`super::SystemProxyResolver::decide`]（纯函数，跨平台可测）；
//! 这里只做两件事——调 Win32 API、把结果转成 [`super::RawProxyConfig`]
//! / `Option<String>` 这些普通 Rust 值。
#![allow(unsafe_code)]

use super::{ProxySource, RawProxyConfig};
use std::sync::Mutex;
use windows::core::{HRESULT, PCWSTR, PWSTR};
use windows::Win32::Foundation::{GlobalFree, HGLOBAL};
use windows::Win32::Networking::WinHttp::{
    WinHttpCloseHandle, WinHttpGetIEProxyConfigForCurrentUser, WinHttpGetProxyForUrl, WinHttpOpen,
    ERROR_WINHTTP_LOGIN_FAILURE, WINHTTP_ACCESS_TYPE_NAMED_PROXY, WINHTTP_ACCESS_TYPE_NO_PROXY,
    WINHTTP_AUTOPROXY_AUTO_DETECT, WINHTTP_AUTOPROXY_CONFIG_URL, WINHTTP_AUTOPROXY_OPTIONS,
    WINHTTP_AUTO_DETECT_TYPE_DHCP, WINHTTP_AUTO_DETECT_TYPE_DNS_A,
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG, WINHTTP_PROXY_INFO,
};

// 编译期核对：mod.rs 里为了跨平台可测而重新声明的这几个 u32 常量，
// 数值必须跟 windows crate 里的真实定义一致——用 const 断言让 zigbuild
// 在这一点上出现分歧时直接编译失败，而不是留到运行时才发现。这种分歧
// 只会在 Windows 上才现形，这台 macOS 机器的 `cargo test` 一次都测
// 不到，const 断言把它挪到了编译期，跟运行平台无关。
const _: () = assert!(super::AUTOPROXY_AUTO_DETECT == WINHTTP_AUTOPROXY_AUTO_DETECT);
const _: () = assert!(super::AUTOPROXY_CONFIG_URL == WINHTTP_AUTOPROXY_CONFIG_URL);
const _: () = assert!(super::AUTO_DETECT_TYPE_DHCP == WINHTTP_AUTO_DETECT_TYPE_DHCP);
const _: () = assert!(super::AUTO_DETECT_TYPE_DNS_A == WINHTTP_AUTO_DETECT_TYPE_DNS_A);

/// WinHTTP 会话句柄，跨多次 [`WinHttpSource::eval_pac`] 调用复用。
struct AutoProxySession(*mut core::ffi::c_void);

// SAFETY: 这个裸指针只经 `WinHttpSource::session` 里的 `Mutex` 访问，
// 同一时刻只有一个线程能拿到它、发起 Win32 调用——`Send` 只是说"这个
// 指针本身可以被安全地转移到另一个线程持有"，真正的互斥仍然由外层的
// `Mutex<Option<AutoProxySession>>` 保证，不代表绕开了任何同步要求。
unsafe impl Send for AutoProxySession {}

pub struct WinHttpSource {
    // W16（评审）：跨调用复用 session 句柄。MSDN《AutoProxy Issues in
    // WinHTTP》原文：「It is best to use the same session handle for
    // multiple WinHttpGetProxyForUrl calls」，且自动发现的结果缓存
    // 「is discarded when the application closes the session
    // handle」——上一轮实现每次调用都开一个新会话、用完就关，等于永远
    // 缓存不到任何东西，每次都要重新走一遍完整的 DHCP/DNS 发现、下载、
    // 执行 PAC 脚本。
    session: Mutex<Option<AutoProxySession>>,
}

impl WinHttpSource {
    pub fn new() -> Self {
        Self {
            session: Mutex::new(None),
        }
    }
}

impl Default for WinHttpSource {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for WinHttpSource {
    fn drop(&mut self) {
        if let Some(session) = self.session.lock().unwrap().take() {
            // SAFETY: `session.0` 是本模块自己用 `WinHttpOpen` 拿到、
            // 且只有这一处持有所有权的有效句柄；`Drop::drop` 只运行
            // 一次，不会对同一句柄重复调用 `WinHttpCloseHandle`。
            unsafe {
                let _ = WinHttpCloseHandle(session.0);
            }
        }
    }
}

/// 释放 WinHTTP 用 `GlobalAlloc` 分配、要求调用方 `GlobalFree` 归还的
/// 字符串内存。`WinHttpGetIEProxyConfigForCurrentUser` 与
/// `WinHttpGetProxyForUrl` 的输出字符串字段都是这类内存——MSDN 对应
/// 文档都写着"调用方必须用 GlobalFree 释放"，这是本任务在 brief 原始
/// 代码样例之外发现的一个真实缺陷：漏了这一步，每读一次系统代理配置、
/// 每求值一次 PAC 就泄漏几十到上百字节。这两个函数会在 Supervisor 的
/// 重连循环里反复调用（网络切换、断线重连都会触发），日积月累会变成
/// 看得见的问题——不是理论上的洁癖。空指针视为"没有这一项"，不是需要
/// 释放的内存，直接返回。
///
/// # Safety
/// `p` 必须是 `GlobalAlloc`（或等价地，由 WinHTTP 按同样约定分配）
/// 出来的内存，且调用方之后不再使用这个指针——这正是
/// `WinHttpGetIEProxyConfigForCurrentUser`/`WinHttpGetProxyForUrl` 的
/// 输出字段的约定，喂一个不满足这个前提的裸指针进来是未定义行为。
unsafe fn free_pwstr(p: PWSTR) {
    if p.is_null() {
        return;
    }
    // SAFETY: 见函数级别的 Safety 说明，调用方已经保证了这个前提。
    unsafe {
        let _ = GlobalFree(Some(HGLOBAL(p.0.cast())));
    }
}

/// 把 WinHTTP 输出的 `PWSTR` 拷贝成 Rust `String`，并释放底层内存
/// （见 [`free_pwstr`]）。空指针、非法 UTF-16、拷贝出空串，这三种情况
/// 在 `RawProxyConfig` / PAC 结果里都等价于"这一项没配置"，统一映射
/// 成 `None`。
///
/// # Safety
/// 同 [`free_pwstr`]。
unsafe fn take_pwstr(p: PWSTR) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // SAFETY: `p` 非空，且满足调用方的前提（见函数级别 Safety 说明）；
    // `PWSTR::to_string` 要求指针指向一段有效、以 0 结尾的 UTF-16
    // 数据，这正是 WinHTTP 输出字符串的约定形状。
    let s = unsafe { p.to_string() }.ok();
    // SAFETY: 同上，`free_pwstr` 的前提与本函数完全一致。
    unsafe {
        free_pwstr(p);
    }
    s.filter(|s| !s.is_empty())
}

impl ProxySource for WinHttpSource {
    fn current(&self) -> RawProxyConfig {
        let mut ie = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG::default();
        // SAFETY: `ie` 是本函数栈上的局部变量，生命周期覆盖整次调用。
        let ok = unsafe { WinHttpGetIEProxyConfigForCurrentUser(&mut ie) }.is_ok();
        if !ok {
            // 保守起见，失败时不去碰这三个指针字段：MSDN 没有明确保证
            // 失败路径下它们维持 `::default()` 留下的 NULL（不像下面
            // eval_pac 里的 lpszProxy/lpszProxyBypass——那两个 MSDN
            // 原文明确写了"非 NULL 就要释放"，不区分调用成功与否）。
            return RawProxyConfig::default();
        }
        // SAFETY: `ok` 为真，`ie` 的三个指针字段要么是
        // `WinHttpGetIEProxyConfigForCurrentUser` 按文档约定分配、
        // 需要 GlobalFree 释放的内存，要么是 NULL（表示这一项没配置）。
        let (pac_url, proxy, bypass) = unsafe {
            (
                take_pwstr(ie.lpszAutoConfigUrl),
                take_pwstr(ie.lpszProxy),
                take_pwstr(ie.lpszProxyBypass),
            )
        };
        RawProxyConfig {
            auto_detect: ie.fAutoDetect.as_bool(),
            pac_url,
            proxy,
            bypass,
        }
    }

    fn eval_pac(
        &self,
        auto_detect: bool,
        pac_url: Option<&str>,
        target_url: &str,
    ) -> Option<String> {
        let mut guard = self.session.lock().unwrap();
        let session = match guard.as_ref() {
            Some(s) => s.0,
            None => {
                // SAFETY: 参数都是空指针/已知常量，符合 WinHttpOpen 的
                // 调用约定（不带用户代理串、不用手工代理、无额外标志）。
                let handle = unsafe {
                    WinHttpOpen(
                        PCWSTR::null(),
                        WINHTTP_ACCESS_TYPE_NO_PROXY,
                        PCWSTR::null(),
                        PCWSTR::null(),
                        0,
                    )
                };
                // W6：0.62 下 WinHttpOpen 返回裸 *mut c_void，没有
                // is_invalid()，用 is_null()——brief 原文写的是 0.58
                // 的用法，编不过。
                if handle.is_null() {
                    return None;
                }
                *guard = Some(AutoProxySession(handle));
                guard.as_ref().unwrap().0
            }
        };

        let pac_wide: Option<Vec<u16>> =
            pac_url.map(|s| s.encode_utf16().chain(std::iter::once(0)).collect());
        let url_wide: Vec<u16> = target_url
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let url_pcwstr = PCWSTR(url_wide.as_ptr());

        // W14（评审）：lpszAutoConfigUrl 为 NULL 当且仅当 dwFlags 不含
        // AUTOPROXY_CONFIG_URL——MSDN 原文明确要求这一点（「If dwFlags
        // does not include WINHTTP_AUTOPROXY_CONFIG_URL, then
        // lpszAutoConfigUrl must be NULL.」）。这里与 `super::
        // autoproxy_flags` 都由同一个 `pac_url` 决定，天然一致：
        // `pac_url` 是 `None` 时 flags 里没有 CONFIG_URL 这一位、
        // `lpszAutoConfigUrl` 也是 `PCWSTR::null()`；反过来 `pac_url`
        // 是 `Some` 时两者同时成立，不会出现"标志开了但没传地址"或者
        // "传了地址但标志没开"这种上一轮实现踩中的分裂状态（当时
        // `pac_wide` 在空串情形下是 `[0u16]`——一个非 NULL 的、指向空
        // 宽字符串的指针，正是文档禁止的组合）。
        let (flags, auto_detect_flags) = super::autoproxy_flags(auto_detect, pac_url);
        let auto_config_url = match &pac_wide {
            Some(w) => PCWSTR(w.as_ptr()),
            None => PCWSTR::null(),
        };

        // W16（评审）：fAutoLogonIfChallenged 两步法。MSDN 明确说这个
        // 标志为 TRUE 时，进程外的 WinHTTP 自动代理服务不缓存结果；
        // 官方推荐写法是先 FALSE 试一次，只有失败且原因是
        // ERROR_WINHTTP_LOGIN_FAILURE（下载 PAC 脚本的服务器本身要求
        // 认证）才重试一次 TRUE。绝大多数网络根本不需要认证就能下载
        // PAC 脚本，两步法让绝大多数调用都保留缓存。
        let mut options = WINHTTP_AUTOPROXY_OPTIONS {
            dwFlags: flags,
            dwAutoDetectFlags: auto_detect_flags,
            lpszAutoConfigUrl: auto_config_url,
            fAutoLogonIfChallenged: false.into(),
            ..Default::default()
        };
        let mut info = WINHTTP_PROXY_INFO::default();
        // SAFETY: `session` 是当前持有的有效 WinHTTP 会话句柄；
        // `url_pcwstr` 指向 `url_wide`，其生命周期覆盖这次调用；
        // `options`/`info` 都是本次调用独占的栈上可变引用。
        let mut result =
            unsafe { WinHttpGetProxyForUrl(session, url_pcwstr, &mut options, &mut info) };
        if let Err(e) = &result {
            if e.code() == HRESULT::from_win32(ERROR_WINHTTP_LOGIN_FAILURE) {
                options.fAutoLogonIfChallenged = true.into();
                info = WINHTTP_PROXY_INFO::default();
                // SAFETY: 同上，重试只改了 `fAutoLogonIfChallenged`。
                result =
                    unsafe { WinHttpGetProxyForUrl(session, url_pcwstr, &mut options, &mut info) };
            }
        }

        // 不论成功与否都统一拷贝并释放这两个字段：`WinHttpGetProxyForUrl`
        // 的文档原文要求"Free the lpszProxy and lpszProxyBypass strings
        // contained in this structure (if they are non-NULL) using
        // GlobalFree"——两个字段并列写的，不是"多释放一个更安全"的
        // 防御性写法，是文档原本就要求两个都释放，不区分调用成功与否；
        // 失败路径下这两个字段理论上仍是 `::default()` 留下的 NULL，
        // `take_pwstr` 对 NULL 是 no-op，统一处理不会多做什么，只是
        // 不必再靠"调用是否成功"去猜要不要释放。上一轮实现里这两个
        // 字段的释放不对称（lpszProxy 只在成功时释放，lpszProxyBypass
        // 无条件释放），是评审指出的一处真实缺陷。
        // SAFETY: `info` 的两个指针字段要么是 NULL，要么是
        // `WinHttpGetProxyForUrl` 按文档约定分配、需要 GlobalFree
        // 释放的内存。
        let (proxy_string, _bypass) =
            unsafe { (take_pwstr(info.lpszProxy), take_pwstr(info.lpszProxyBypass)) };

        result.ok()?;

        // W16（评审，连带发现）：DIRECT 不是一个字符串关键字，是
        // `info.dwAccessType`——`WinHttpGetProxyForUrl` 已经替调用方把
        // PAC 脚本"要不要用代理"这件事翻译成了这个字段：
        // `WINHTTP_ACCESS_TYPE_NO_PROXY` 就是 PAC 决定直连，
        // `WINHTTP_ACCESS_TYPE_NAMED_PROXY` 才是"lpszProxy 里有要用的
        // 代理"。上一轮实现完全没看这个字段，只要调用成功就直接读
        // `lpszProxy`——而 PAC 说直连时 `lpszProxy` 通常是 NULL，
        // `take_pwstr` 会返回 `None`，被上层 `decide()` 当成"PAC 求值
        // 本身失败"（退回静态代理或报告 `PacEvalFailedNoFallback`），
        // 而不是"PAC 成功地说了直连"——这正是本任务标题要解决的那类
        // 「直连」与「求值失败」混淆，藏在了上一轮测试没能覆盖到
        // 的这一层 Win32 边界上。
        match info.dwAccessType {
            WINHTTP_ACCESS_TYPE_NO_PROXY => Some("DIRECT".to_string()),
            WINHTTP_ACCESS_TYPE_NAMED_PROXY => proxy_string,
            other => {
                tracing::warn!("WinHttpGetProxyForUrl 返回了未预期的 dwAccessType={other:?}");
                None
            }
        }
    }
}
