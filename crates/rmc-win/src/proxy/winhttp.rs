//! WinHTTP 取系统代理配置并对 PAC 求值。
//! 本模块含 unsafe，逻辑都很短：判断"该不该用、用哪个"完全不在这里，
//! 都在 [`super::SystemProxyResolver::decide`]（纯函数，跨平台可测）；
//! 这里只做两件事——调 Win32 API、把结果转成 [`super::RawProxyConfig`]
//! / `Option<String>` 这些普通 Rust 值。
#![allow(unsafe_code)]

use super::{ProxySource, RawProxyConfig};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{GlobalFree, HGLOBAL};
use windows::Win32::Networking::WinHttp::{
    WinHttpCloseHandle, WinHttpGetIEProxyConfigForCurrentUser, WinHttpGetProxyForUrl, WinHttpOpen,
    WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_AUTOPROXY_AUTO_DETECT, WINHTTP_AUTOPROXY_CONFIG_URL,
    WINHTTP_AUTOPROXY_OPTIONS, WINHTTP_AUTO_DETECT_TYPE_DHCP, WINHTTP_AUTO_DETECT_TYPE_DNS_A,
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG, WINHTTP_PROXY_INFO,
};

pub struct WinHttpSource;

/// 释放 WinHTTP 用 `GlobalAlloc` 分配、要求调用方 `GlobalFree` 归还的
/// 字符串内存。`WinHttpGetIEProxyConfigForCurrentUser` 与
/// `WinHttpGetProxyForUrl` 的输出字符串字段都是这类内存——MSDN 对应
/// 文档都写着"调用方必须用 GlobalFree 释放"，这是本任务在 brief 原始
/// 代码样例之外发现的一个真实缺陷：漏了这一步，每读一次系统代理配置、
/// 每求值一次 PAC 就泄漏几十到上百字节。这两个函数会在 Supervisor 的
/// 重连循环里反复调用（网络切换、断线重连都会触发），日积月累会变成
/// 看得见的问题——不是理论上的洁癖。空指针视为"没有这一项"，不是需要
/// 释放的内存，直接返回。
fn free_pwstr(p: PWSTR) {
    if p.is_null() {
        return;
    }
    unsafe {
        let _ = GlobalFree(Some(HGLOBAL(p.0.cast())));
    }
}

/// 把 WinHTTP 输出的 `PWSTR` 拷贝成 Rust `String`，并释放底层内存
/// （见 [`free_pwstr`]）。空指针、非法 UTF-16、拷贝出空串，这三种情况
/// 在 `RawProxyConfig` / PAC 结果里都等价于"这一项没配置"，统一映射
/// 成 `None`。
fn take_pwstr(p: PWSTR) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let s = unsafe { p.to_string() }.ok();
    free_pwstr(p);
    s.filter(|s| !s.is_empty())
}

impl ProxySource for WinHttpSource {
    fn current(&self) -> RawProxyConfig {
        let mut ie = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG::default();
        let ok = unsafe { WinHttpGetIEProxyConfigForCurrentUser(&mut ie) }.is_ok();
        if !ok {
            // 失败时 WinHTTP 没有分配任何东西，没有需要释放的内存。
            return RawProxyConfig::default();
        }
        RawProxyConfig {
            auto_detect: ie.fAutoDetect.as_bool(),
            pac_url: take_pwstr(ie.lpszAutoConfigUrl),
            proxy: take_pwstr(ie.lpszProxy),
            bypass: take_pwstr(ie.lpszProxyBypass),
        }
    }

    fn eval_pac(&self, pac_url: &str, target_url: &str) -> Option<String> {
        let session = unsafe {
            WinHttpOpen(
                PCWSTR::null(),
                WINHTTP_ACCESS_TYPE_NO_PROXY,
                PCWSTR::null(),
                PCWSTR::null(),
                0,
            )
        };
        // W6：0.62 下 WinHttpOpen 返回裸 *mut c_void，没有 is_invalid()，
        // 用 is_null()——brief 原文写的是 0.58 的用法，编不过。
        if session.is_null() {
            return None;
        }

        let pac_wide: Vec<u16> = pac_url.encode_utf16().chain(std::iter::once(0)).collect();
        let url_wide: Vec<u16> = target_url
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        // 自动检测（DHCP/DNS 找 wpad）总是打开；显式 PAC 地址只在配置
        // 了才加进去——`pac_url` 为空串就是调用方（decide()）传来的
        // "只勾了自动检测、没填地址"信号，这时不能把
        // WINHTTP_AUTOPROXY_CONFIG_URL 也打开，否则 WinHttp 会拿一个
        // 空字符串当 PAC 地址去请求，直接失败而不是退到自动检测。
        let mut flags = WINHTTP_AUTOPROXY_AUTO_DETECT;
        if !pac_url.is_empty() {
            flags |= WINHTTP_AUTOPROXY_CONFIG_URL;
        }

        let mut options = WINHTTP_AUTOPROXY_OPTIONS {
            dwFlags: flags,
            dwAutoDetectFlags: WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A,
            lpszAutoConfigUrl: PCWSTR(pac_wide.as_ptr()),
            fAutoLogonIfChallenged: true.into(),
            ..Default::default()
        };
        let mut info = WINHTTP_PROXY_INFO::default();
        let ok = unsafe {
            WinHttpGetProxyForUrl(session, PCWSTR(url_wide.as_ptr()), &mut options, &mut info)
        }
        .is_ok();

        let result = if ok { take_pwstr(info.lpszProxy) } else { None };
        // WinHttpGetProxyForUrl 的文档没有说会填 lpszProxyBypass（PAC
        // 结果本身已经用 DIRECT 表达"不代理"），但结构体形状上这个
        // 字段确实存在——万一某个 Windows 版本真的填了它，防御性释放
        // 一下，总比悄悄泄漏安全，代价只是一次对空指针的判断。
        free_pwstr(info.lpszProxyBypass);

        unsafe {
            let _ = WinHttpCloseHandle(session);
        }
        result
    }
}
