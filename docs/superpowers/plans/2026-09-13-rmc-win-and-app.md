# Windows 平台层与界面 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 补齐 rmc-core 需要的 Windows 能力（系统代理、SSPI 代理认证、电源与网络事件、DPAPI 记住密码、单实例、托盘与通知），并做出与已定版画板一致的 iced 界面。

**Architecture:** rmc-win 把每个 Win32 调用拆成「取原始数据」与「解析原始数据」两半，解析那一半是纯函数、跨平台可测，Win32 那一半靠人工验收清单守。rmc-app 同样分两层：`model.rs` 是从 `TunnelEvent` 推导出的纯视图模型，在 Linux 上单元测试；`view/` 只把模型画成 iced 控件。界面永远只发 `Command`、只读 `TunnelEvent`。

**Tech Stack:** Rust 2021、iced 0.13（`tiny-skia` 软件渲染回落）、windows 0.58、tray-icon 0.19、tokio

**Spec:** `docs/方案设计.md` 第 3.1、3.9、3.10，界面细节以画板为准：`design/body-*.html` 与 `design/canvas.json`

**依赖：** `2026-09-13-rmc-core.md` 与 `2026-09-13-rmc-core-part2.md` 全部完成。

## Global Constraints

- 窗口固定 520×720，不可最大化，不需要管理员权限。
- 顶部三个页签：维护、诊断、日志。导出诊断包是动作，放在诊断页内。
- 表单按两段连接分组：维护目标只放一体机，公司 Gateway 组含地址、出网、账号、密码、记住密码。地址与端口分开输入。
- 出网一行是自动检测结果，带勾号与「自动检测」标注，不是输入项；无代理时显示直连。
- 默认不保存密码；勾选记住密码后用 DPAPI 当前用户范围加密落盘。
- 认证失败回到未开启，口令框清空，不自动重试，不显示剩余尝试次数。
- V1 不做会话时长上限与空闲自动停止，界面只显示已连接时长，不要画倒计时。
- 状态配色取 Windows 11 Fluent 语义色：未开启 `#8a8a8a`、进行中 `#0067c0`、已连接 `#0f7b0f`、一体机不可达 `#b8560f`、重连中 `#9d5d00`、失败 `#c42b1c`。
- 反向端口在界面上一律写全「Gateway 反向端口 127.0.0.1:22001」。
- rmc-win 与 rmc-app 只在 `#[cfg(windows)]` 下编译 Win32 部分，纯逻辑模块必须在 Linux 上可测。

---

### Task 1: rmc-win 骨架、单实例与代理字符串解析

**Files:**
- Create: `crates/rmc-win/Cargo.toml`
- Create: `crates/rmc-win/src/lib.rs`
- Create: `crates/rmc-win/src/single_instance.rs`
- Create: `crates/rmc-win/src/proxy/parse.rs`
- Modify: `Cargo.toml`（workspace members）
- Test: `crates/rmc-win/src/proxy/parse.rs` 同文件测试模块

**Interfaces:**
- Consumes: rmc-core 的 `HostPort`
- Produces:
  - `pub fn parse_proxy_list(raw: &str, target_host: &str) -> Option<HostPort>`：解析 WinHTTP 风格的代理串，挑出适用于目标的第一项
  - `pub fn parse_bypass_list(raw: &str) -> Vec<String>` 与 `pub fn host_is_bypassed(host: &str, patterns: &[String]) -> bool`
  - `#[cfg(windows)] pub struct SingleInstance`，`SingleInstance::acquire(name: &str) -> Option<Self>`

- [ ] **Step 1: 写下失败的测试**

创建 `crates/rmc-win/src/proxy/parse.rs`：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_bare_host_port() {
        let hp = parse_proxy_list("proxy.company.com:8080", "gateway.company.com").unwrap();
        assert_eq!(hp.to_string(), "proxy.company.com:8080");
    }

    #[test]
    fn defaults_missing_port_to_80() {
        let hp = parse_proxy_list("proxy.company.com", "gateway.company.com").unwrap();
        assert_eq!(hp.port, 80);
    }

    #[test]
    fn strips_the_scheme_prefix() {
        let hp = parse_proxy_list("http=proxy.company.com:8080", "gateway.company.com").unwrap();
        assert_eq!(hp.to_string(), "proxy.company.com:8080");
    }

    #[test]
    fn prefers_the_https_entry_when_present() {
        // 我们要建的是 CONNECT 隧道，应当用 https 那一项。
        let raw = "http=p1.company.com:8080;https=p2.company.com:8443";
        let hp = parse_proxy_list(raw, "gateway.company.com").unwrap();
        assert_eq!(hp.to_string(), "p2.company.com:8443");
    }

    #[test]
    fn accepts_semicolon_and_space_separators() {
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
        assert!(parse_proxy_list("", "gateway.company.com").is_none());
        assert!(parse_proxy_list("   ", "gateway.company.com").is_none());
        assert!(parse_proxy_list("DIRECT", "gateway.company.com").is_none());
    }

    #[test]
    fn parses_pac_style_proxy_result() {
        let hp = parse_proxy_list("PROXY proxy.company.com:8080", "gateway.company.com").unwrap();
        assert_eq!(hp.to_string(), "proxy.company.com:8080");
    }

    #[test]
    fn pac_direct_first_means_direct() {
        assert!(parse_proxy_list("DIRECT; PROXY p:8080", "gw.company.com").is_none());
    }

    #[test]
    fn ignores_malformed_entries_and_takes_the_next_good_one() {
        let hp = parse_proxy_list("https=:::;https=p.company.com:8443", "gw.company.com").unwrap();
        assert_eq!(hp.to_string(), "p.company.com:8443");
    }

    #[test]
    fn bypass_list_splits_on_semicolon_and_whitespace() {
        let got = parse_bypass_list("*.local;169.254.*  <local>");
        assert_eq!(got, vec!["*.local", "169.254.*", "<local>"]);
    }

    #[test]
    fn bypass_matches_suffix_wildcard() {
        let p = parse_bypass_list("*.company.internal");
        assert!(host_is_bypassed("appliance.company.internal", &p));
        assert!(!host_is_bypassed("gateway.company.com", &p));
    }

    #[test]
    fn bypass_local_matches_dotless_hosts_only() {
        let p = parse_bypass_list("<local>");
        assert!(host_is_bypassed("gateway", &p));
        assert!(!host_is_bypassed("gateway.company.com", &p));
    }

    #[test]
    fn bypass_exact_match() {
        let p = parse_bypass_list("gateway.company.com");
        assert!(host_is_bypassed("gateway.company.com", &p));
        assert!(!host_is_bypassed("other.company.com", &p));
    }

    #[test]
    fn bypassed_target_resolves_to_direct() {
        // 调用方在命中 bypass 时不应再取代理，这里断言两个函数配合的用法。
        let patterns = parse_bypass_list("*.company.com");
        assert!(host_is_bypassed("gateway.company.com", &patterns));
    }
}
```

- [ ] **Step 2: 运行测试确认失败**

```bash
cargo test -p rmc-win
```

预期：包不存在，`error: package ID specification rmc-win did not match any packages`。

- [ ] **Step 3: 写最小实现**

根 `Cargo.toml` 的 members 改为 `["crates/rmc-core", "crates/rmc-win"]`，并在 `[workspace.dependencies]` 加：

```toml
rmc-core = { path = "crates/rmc-core" }
windows = "0.58"
```

创建 `crates/rmc-win/Cargo.toml`：

```toml
[package]
name = "rmc-win"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[dependencies]
rmc-core.workspace = true
tokio.workspace = true
tracing.workspace = true
async-trait = "0.1"
zeroize = { version = "1", features = ["std"] }

[target.'cfg(windows)'.dependencies]
windows = { workspace = true, features = [
  "Win32_Foundation",
  "Win32_Security",
  "Win32_System_Threading",
  "Win32_Networking_WinHttp",
  "Win32_Security_Cryptography",
  "Win32_Security_Authentication_Identity",
  "Win32_System_Power",
  "Win32_Networking_NetworkListManager",
  "Win32_System_Com",
] }
```

创建 `crates/rmc-win/src/proxy/parse.rs`，在测试模块之前插入：

```rust
//! 代理串解析。纯函数，与 Win32 无关，因此跨平台可测。
//! 覆盖两种来源：WinHTTP/IE 的 `http=host:port;https=host:port`，
//! 以及 PAC 求值结果 `PROXY host:port; DIRECT`。

use rmc_core::addr::HostPort;

/// 从代理串里挑出适用于 CONNECT 的代理。返回 None 表示直连。
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
```

创建 `crates/rmc-win/src/single_instance.rs`：

```rust
//! 单实例互斥量。第二个实例拿不到互斥量就退出并把已有窗口置前。

#[cfg(windows)]
mod imp {
    use windows::core::HSTRING;
    use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, ERROR_ALREADY_EXISTS};
    use windows::Win32::System::Threading::CreateMutexW;

    pub struct SingleInstance(HANDLE);

    impl SingleInstance {
        /// 拿到互斥量返回 Some；已有实例在跑返回 None。
        pub fn acquire(name: &str) -> Option<Self> {
            let wide = HSTRING::from(format!("Local\\{name}"));
            let handle = unsafe { CreateMutexW(None, true, &wide) }.ok()?;
            if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
                unsafe { let _ = CloseHandle(handle) };
                return None;
            }
            Some(Self(handle))
        }
    }

    impl Drop for SingleInstance {
        fn drop(&mut self) {
            unsafe { let _ = CloseHandle(self.0) };
        }
    }
}

#[cfg(windows)]
pub use imp::SingleInstance;
```

创建 `crates/rmc-win/src/lib.rs`：

```rust
#![forbid(unsafe_code)]
//! Windows 平台适配。Win32 调用集中在带 unsafe 的子模块里，
//! 解析逻辑一律放在纯函数模块，跨平台可测。

pub mod proxy;
pub mod single_instance;
```

`proxy/mod.rs` 暂时只写 `pub mod parse;`。注意 `single_instance` 的 Win32 实现需要 `unsafe`，把 `lib.rs` 的 `#![forbid(unsafe_code)]` 改为 `#![deny(unsafe_op_in_unsafe_fn)]`，并在每个用到 unsafe 的模块顶部加 `#![allow(unsafe_code)]` 的说明注释。

- [ ] **Step 4: 运行测试确认通过**

```bash
cargo test -p rmc-win
cargo clippy -p rmc-win --all-targets -- -D warnings
```

预期：14 passed（Linux 上编译时跳过 Win32 模块）。

- [ ] **Step 5: 提交**

```bash
git add Cargo.toml crates/rmc-win
git commit -m "feat(win): rmc-win 骨架、单实例与代理串解析"
```

---

### Task 2: 系统代理解析器

**Files:**
- Create: `crates/rmc-win/src/proxy/mod.rs`（替换占位）
- Create: `crates/rmc-win/src/proxy/winhttp.rs`
- Test: `crates/rmc-win/src/proxy/mod.rs` 同文件测试模块

**Interfaces:**
- Consumes: Task 1 的 `parse_proxy_list`、`parse_bypass_list`、`host_is_bypassed`
- Produces:
  - `pub struct RawProxyConfig { pub auto_detect: bool, pub pac_url: Option<String>, pub proxy: Option<String>, pub bypass: Option<String> }`
  - `pub trait ProxySource: Send + Sync { fn current(&self) -> RawProxyConfig; fn eval_pac(&self, pac_url: &str, target_url: &str) -> Option<String> }`
  - `#[cfg(windows)] pub struct WinHttpSource`，实现 `ProxySource`
  - `pub struct SystemProxyResolver<S: ProxySource>`，实现 rmc-core 的 `ProxyResolver`
  - 解析优先级：bypass 命中 → 直连；PAC 存在 → 求值结果；否则静态代理串

- [ ] **Step 1: 写下失败的测试**

在 `crates/rmc-win/src/proxy/mod.rs` 写测试模块：

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use rmc_core::addr::HostPort;
    use rmc_core::platform::ProxyResolver;
    use std::sync::Mutex;

    struct Fake {
        raw: RawProxyConfig,
        pac_result: Option<String>,
        pac_calls: Mutex<Vec<String>>,
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
        fn eval_pac(&self, _pac_url: &str, target_url: &str) -> Option<String> {
            self.pac_calls.lock().unwrap().push(target_url.to_string());
            self.pac_result.clone()
        }
    }

    fn raw() -> RawProxyConfig {
        RawProxyConfig { auto_detect: false, pac_url: None, proxy: None, bypass: None }
    }

    fn gw() -> HostPort {
        "gateway.company.com:443".parse().unwrap()
    }

    #[tokio::test]
    async fn no_configuration_means_direct() {
        let r = SystemProxyResolver::new(Fake::new(raw(), None));
        assert!(r.resolve(&gw()).await.is_none());
    }

    #[tokio::test]
    async fn static_proxy_is_used() {
        let mut c = raw();
        c.proxy = Some("https=proxy.company.com:8080".into());
        let r = SystemProxyResolver::new(Fake::new(c, None));
        assert_eq!(r.resolve(&gw()).await.unwrap().to_string(), "proxy.company.com:8080");
    }

    #[tokio::test]
    async fn bypass_wins_over_static_proxy() {
        let mut c = raw();
        c.proxy = Some("proxy.company.com:8080".into());
        c.bypass = Some("*.company.com".into());
        let r = SystemProxyResolver::new(Fake::new(c, None));
        assert!(r.resolve(&gw()).await.is_none(), "命中 bypass 应直连");
    }

    #[tokio::test]
    async fn pac_result_wins_over_static_proxy() {
        let mut c = raw();
        c.proxy = Some("static.company.com:8080".into());
        c.pac_url = Some("http://wpad.company.com/wpad.dat".into());
        let r = SystemProxyResolver::new(Fake::new(c, Some("PROXY pac.company.com:3128")));
        assert_eq!(r.resolve(&gw()).await.unwrap().to_string(), "pac.company.com:3128");
    }

    #[tokio::test]
    async fn pac_is_evaluated_against_an_https_url_for_the_gateway() {
        let mut c = raw();
        c.pac_url = Some("http://wpad.company.com/wpad.dat".into());
        let fake = Fake::new(c, Some("PROXY p:3128"));
        let r = SystemProxyResolver::new(fake);
        r.resolve(&gw()).await;
        let calls = r.source().pac_calls.lock().unwrap().clone();
        assert_eq!(calls, vec!["https://gateway.company.com:443/".to_string()]);
    }

    #[tokio::test]
    async fn pac_returning_direct_means_direct() {
        let mut c = raw();
        c.pac_url = Some("http://wpad/wpad.dat".into());
        c.proxy = Some("static.company.com:8080".into());
        let r = SystemProxyResolver::new(Fake::new(c, Some("DIRECT")));
        assert!(r.resolve(&gw()).await.is_none());
    }

    #[tokio::test]
    async fn pac_failure_falls_back_to_the_static_proxy() {
        let mut c = raw();
        c.pac_url = Some("http://wpad/wpad.dat".into());
        c.proxy = Some("static.company.com:8080".into());
        let r = SystemProxyResolver::new(Fake::new(c, None));
        assert_eq!(r.resolve(&gw()).await.unwrap().to_string(), "static.company.com:8080");
    }
}
```

- [ ] **Step 2: 运行测试确认失败**

```bash
cargo test -p rmc-win proxy
```

预期：编译失败，`cannot find type RawProxyConfig`。

- [ ] **Step 3: 写最小实现**

替换 `crates/rmc-win/src/proxy/mod.rs`，在测试模块之前插入：

```rust
//! 系统代理解析。取值与求值经 ProxySource 抽象，便于不依赖 Win32 测试。

pub mod parse;
#[cfg(windows)]
pub mod winhttp;

use parse::{host_is_bypassed, parse_bypass_list, parse_proxy_list};
use rmc_core::addr::HostPort;
use rmc_core::platform::ProxyResolver;

#[derive(Debug, Clone, Default)]
pub struct RawProxyConfig {
    pub auto_detect: bool,
    pub pac_url: Option<String>,
    pub proxy: Option<String>,
    pub bypass: Option<String>,
}

pub trait ProxySource: Send + Sync {
    fn current(&self) -> RawProxyConfig;
    /// 对 PAC 脚本求值，返回形如 `PROXY host:port; DIRECT` 的结果。
    fn eval_pac(&self, pac_url: &str, target_url: &str) -> Option<String>;
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
}

#[async_trait::async_trait]
impl<S: ProxySource> ProxyResolver for SystemProxyResolver<S> {
    async fn resolve(&self, target: &HostPort) -> Option<HostPort> {
        let cfg = self.source.current();

        // bypass 最高优先，命中即直连。
        if let Some(bypass) = cfg.bypass.as_deref() {
            if host_is_bypassed(&target.host, &parse_bypass_list(bypass)) {
                return None;
            }
        }

        // PAC 次之。求值失败时退回静态配置，而不是判定直连。
        if let Some(pac) = cfg.pac_url.as_deref() {
            let url = format!("https://{}:{}/", target.host, target.port);
            if let Some(result) = self.source.eval_pac(pac, &url) {
                return parse_proxy_list(&result, &target.host);
            }
        }

        cfg.proxy
            .as_deref()
            .and_then(|raw| parse_proxy_list(raw, &target.host))
    }
}
```

创建 `crates/rmc-win/src/proxy/winhttp.rs`：

```rust
//! WinHTTP 取系统代理配置并对 PAC 求值。
//! 本模块含 unsafe，逻辑都很短，解析全部委托给 parse.rs。
#![allow(unsafe_code)]

use super::{ProxySource, RawProxyConfig};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Networking::WinHttp::{
    WinHttpCloseHandle, WinHttpGetIEProxyConfigForCurrentUser, WinHttpGetProxyForUrl, WinHttpOpen,
    WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_AUTOPROXY_CONFIG_URL, WINHTTP_AUTOPROXY_OPTIONS,
    WINHTTP_AUTO_DETECT_TYPE_DHCP, WINHTTP_AUTO_DETECT_TYPE_DNS_A, WINHTTP_AUTOPROXY_AUTO_DETECT,
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG, WINHTTP_PROXY_INFO,
};

pub struct WinHttpSource;

fn pwstr_to_string(p: PWSTR) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let s = unsafe { p.to_string() }.ok()?;
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

impl ProxySource for WinHttpSource {
    fn current(&self) -> RawProxyConfig {
        let mut ie = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG::default();
        let ok = unsafe { WinHttpGetIEProxyConfigForCurrentUser(&mut ie) }.is_ok();
        if !ok {
            return RawProxyConfig::default();
        }
        RawProxyConfig {
            auto_detect: ie.fAutoDetect.as_bool(),
            pac_url: pwstr_to_string(ie.lpszAutoConfigUrl),
            proxy: pwstr_to_string(ie.lpszProxy),
            bypass: pwstr_to_string(ie.lpszProxyBypass),
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
        if session.is_invalid() {
            return None;
        }

        let pac_wide: Vec<u16> = pac_url.encode_utf16().chain(std::iter::once(0)).collect();
        let url_wide: Vec<u16> = target_url.encode_utf16().chain(std::iter::once(0)).collect();

        let mut options = WINHTTP_AUTOPROXY_OPTIONS {
            dwFlags: WINHTTP_AUTOPROXY_CONFIG_URL | WINHTTP_AUTOPROXY_AUTO_DETECT,
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
        let result = if ok { pwstr_to_string(info.lpszProxy) } else { None };
        unsafe { let _ = WinHttpCloseHandle(session) };
        result
    }
}
```

- [ ] **Step 4: 运行测试确认通过**

```bash
cargo test -p rmc-win
cargo clippy -p rmc-win --all-targets -- -D warnings
```

预期：21 passed。Windows 上另跑一次 `cargo build -p rmc-win --target x86_64-pc-windows-msvc` 确认 Win32 模块编译通过。

- [ ] **Step 5: 提交**

```bash
git add crates/rmc-win/src/proxy
git commit -m "feat(win): 系统代理解析，支持 PAC 与 bypass"
```

---

### Task 3: SSPI 代理认证

**Files:**
- Create: `crates/rmc-win/src/sspi.rs`
- Modify: `crates/rmc-win/src/lib.rs`
- Test: `crates/rmc-win/src/sspi.rs` 同文件测试模块（状态推进的纯逻辑部分）

**Interfaces:**
- Consumes: rmc-core 的 `ProxyAuthenticator`
- Produces:
  - `pub trait SspiContext: Send { fn step(&mut self, input: Option<&[u8]>) -> Option<Vec<u8>> }`
  - `#[cfg(windows)] pub struct NegotiateContext`，实现 `SspiContext`
  - `pub struct SspiProxyAuthenticator<F>`，`F: Fn(&str) -> Option<Box<dyn SspiContext>>`，实现 `ProxyAuthenticator`
  - 只接受 `Negotiate` 与 `NTLM` 两个 scheme，其他返回 None

- [ ] **Step 1: 写下失败的测试**

创建 `crates/rmc-win/src/sspi.rs`，先写测试模块：

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use rmc_core::platform::ProxyAuthenticator;
    use std::sync::{Arc, Mutex};

    /// 两轮协商的假上下文，记录每轮收到的输入。
    struct TwoLeg {
        seen: Arc<Mutex<Vec<Option<Vec<u8>>>>>,
        round: usize,
    }

    impl SspiContext for TwoLeg {
        fn step(&mut self, input: Option<&[u8]>) -> Option<Vec<u8>> {
            self.seen.lock().unwrap().push(input.map(|b| b.to_vec()));
            self.round += 1;
            match self.round {
                1 => Some(b"leg-one".to_vec()),
                2 => Some(b"leg-two".to_vec()),
                _ => None,
            }
        }
    }

    fn authenticator(seen: Arc<Mutex<Vec<Option<Vec<u8>>>>>) -> impl ProxyAuthenticator {
        SspiProxyAuthenticator::new(move |scheme: &str| {
            assert!(matches!(scheme, "Negotiate" | "NTLM"));
            Some(Box::new(TwoLeg { seen: seen.clone(), round: 0 }) as Box<dyn SspiContext>)
        })
    }

    #[tokio::test]
    async fn first_round_gets_no_challenge_and_returns_base64() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let a = authenticator(seen.clone());
        let token = a.next_token("Negotiate", None).await.unwrap();
        assert_eq!(token, "bGVnLW9uZQ==");
        assert_eq!(seen.lock().unwrap().clone(), vec![None]);
    }

    #[tokio::test]
    async fn second_round_passes_the_decoded_challenge() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let a = authenticator(seen.clone());
        a.next_token("Negotiate", None).await.unwrap();
        let token = a.next_token("Negotiate", Some("Y2hhbGxlbmdl")).await.unwrap();
        assert_eq!(token, "bGVnLXR3bw==");
        let got = seen.lock().unwrap().clone();
        assert_eq!(got[1], Some(b"challenge".to_vec()));
    }

    #[tokio::test]
    async fn context_is_reused_across_rounds_of_one_connection() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let a = authenticator(seen.clone());
        a.next_token("Negotiate", None).await.unwrap();
        a.next_token("Negotiate", Some("Y2hhbGxlbmdl")).await.unwrap();
        // 第三轮上下文已用尽，必须返回 None 而不是重开一个新的。
        assert!(a.next_token("Negotiate", Some("Y2hhbGxlbmdl")).await.is_none());
    }

    #[tokio::test]
    async fn unsupported_scheme_returns_none() {
        let a = SspiProxyAuthenticator::new(|_: &str| {
            panic!("不支持的 scheme 不该创建上下文");
        });
        assert!(a.next_token("Basic", None).await.is_none());
        assert!(a.next_token("Digest", None).await.is_none());
    }

    #[tokio::test]
    async fn malformed_challenge_base64_returns_none() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let a = authenticator(seen);
        a.next_token("Negotiate", None).await.unwrap();
        assert!(a.next_token("Negotiate", Some("!!not-base64!!")).await.is_none());
    }

    #[tokio::test]
    async fn context_factory_returning_none_yields_none() {
        let a = SspiProxyAuthenticator::new(|_: &str| None);
        assert!(a.next_token("Negotiate", None).await.is_none());
    }
}
```

- [ ] **Step 2: 运行测试确认失败**

```bash
cargo test -p rmc-win sspi
```

预期：编译失败，`cannot find trait SspiContext`。

- [ ] **Step 3: 写最小实现**

在 `crates/rmc-win/Cargo.toml` 加 `base64 = "0.22"`。

在 `crates/rmc-win/src/sspi.rs` 测试模块之前插入：

```rust
//! 代理认证的 SSPI 协商。多轮 token 在同一条 TCP 连接上完成，
//! 因此上下文要跨轮保留，由本类型持有。

use base64::Engine;
use rmc_core::platform::ProxyAuthenticator;
use std::sync::Mutex;

/// 一次协商的安全上下文。每调用一次 step 推进一轮。
pub trait SspiContext: Send {
    /// 输入是服务端 challenge 的原始字节，首轮为 None。
    /// 返回下一个要发出的 token，None 表示协商结束或失败。
    fn step(&mut self, input: Option<&[u8]>) -> Option<Vec<u8>>;
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

pub struct SspiProxyAuthenticator<F> {
    factory: F,
    /// None 表示还没开始；Some(None) 表示上下文已用尽。
    context: Mutex<Option<Option<Box<dyn SspiContext>>>>,
}

impl<F> SspiProxyAuthenticator<F>
where
    F: Fn(&str) -> Option<Box<dyn SspiContext>> + Send + Sync,
{
    pub fn new(factory: F) -> Self {
        Self { factory, context: Mutex::new(None) }
    }
}

#[async_trait::async_trait]
impl<F> ProxyAuthenticator for SspiProxyAuthenticator<F>
where
    F: Fn(&str) -> Option<Box<dyn SspiContext>> + Send + Sync,
{
    async fn next_token(&self, scheme: &str, challenge: Option<&str>) -> Option<String> {
        // 只有这两个 scheme 能用当前登录用户的身份，Basic 需要明文口令，不做。
        if !matches!(scheme, "Negotiate" | "NTLM") {
            return None;
        }

        let decoded = match challenge {
            Some(c) => match b64().decode(c) {
                Ok(bytes) => Some(bytes),
                Err(_) => return None,
            },
            None => None,
        };

        let mut guard = self.context.lock().ok()?;
        if guard.is_none() {
            *guard = Some((self.factory)(scheme));
        }
        let slot = guard.as_mut()?;
        let ctx = slot.as_mut()?;
        let out = ctx.step(decoded.as_deref());
        if out.is_none() {
            // 协商结束或失败，丢掉上下文，后续轮次一律返回 None。
            *slot = None;
            return None;
        }
        Some(b64().encode(out?))
    }
}

#[cfg(windows)]
mod win {
    #![allow(unsafe_code)]
    //! Negotiate 上下文。用 InitializeSecurityContextW 逐轮推进。
    //! 凭据用 SEC_WINNT_AUTH_IDENTITY 的默认值，即当前登录用户。

    use super::SspiContext;
    use windows::core::w;
    use windows::Win32::Security::Authentication::Identity::{
        AcquireCredentialsHandleW, DeleteSecurityContext, FreeCredentialsHandle,
        InitializeSecurityContextW, ISC_REQ_CONFIDENTIALITY, ISC_REQ_CONNECTION,
        SECBUFFER_TOKEN, SECBUFFER_VERSION, SECPKG_CRED_OUTBOUND, SecBuffer, SecBufferDesc,
        SECURITY_NATIVE_DREP,
    };
    use windows::Win32::Security::Credentials::SecHandle;

    pub struct NegotiateContext {
        cred: SecHandle,
        ctx: Option<SecHandle>,
        target: Vec<u16>,
        done: bool,
    }

    impl NegotiateContext {
        /// `target_spn` 形如 `HTTP/proxy.company.com`。
        pub fn new(target_spn: &str) -> Option<Self> {
            let mut cred = SecHandle::default();
            let mut expiry = Default::default();
            let ok = unsafe {
                AcquireCredentialsHandleW(
                    None,
                    w!("Negotiate"),
                    SECPKG_CRED_OUTBOUND,
                    None,
                    None,
                    None,
                    None,
                    &mut cred,
                    Some(&mut expiry),
                )
            }
            .is_ok();
            if !ok {
                return None;
            }
            Some(Self {
                cred,
                ctx: None,
                target: target_spn.encode_utf16().chain(std::iter::once(0)).collect(),
                done: false,
            })
        }
    }

    impl SspiContext for NegotiateContext {
        fn step(&mut self, input: Option<&[u8]>) -> Option<Vec<u8>> {
            if self.done {
                return None;
            }
            let mut out_buf = vec![0u8; 16 * 1024];
            let mut out = SecBuffer {
                cbBuffer: out_buf.len() as u32,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: out_buf.as_mut_ptr().cast(),
            };
            let mut out_desc = SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: 1,
                pBuffers: &mut out,
            };

            let mut in_storage = input.map(|b| b.to_vec());
            let mut in_desc_storage;
            let in_desc = match in_storage.as_mut() {
                Some(bytes) => {
                    let mut buf = SecBuffer {
                        cbBuffer: bytes.len() as u32,
                        BufferType: SECBUFFER_TOKEN,
                        pvBuffer: bytes.as_mut_ptr().cast(),
                    };
                    in_desc_storage = SecBufferDesc {
                        ulVersion: SECBUFFER_VERSION,
                        cBuffers: 1,
                        pBuffers: &mut buf,
                    };
                    Some(&mut in_desc_storage as *mut SecBufferDesc)
                }
                None => None,
            };

            let mut new_ctx = SecHandle::default();
            let mut attrs = 0u32;
            let mut expiry = Default::default();
            let status = unsafe {
                InitializeSecurityContextW(
                    Some(&self.cred),
                    self.ctx.as_ref().map(|c| c as *const SecHandle),
                    windows::core::PCWSTR(self.target.as_ptr()),
                    ISC_REQ_CONNECTION | ISC_REQ_CONFIDENTIALITY,
                    0,
                    SECURITY_NATIVE_DREP,
                    in_desc,
                    0,
                    Some(&mut new_ctx),
                    Some(&mut out_desc),
                    &mut attrs,
                    Some(&mut expiry),
                )
            };
            if status.is_err() {
                self.done = true;
                return None;
            }
            self.ctx = Some(new_ctx);
            let n = out.cbBuffer as usize;
            if n == 0 {
                self.done = true;
                return None;
            }
            out_buf.truncate(n);
            Some(out_buf)
        }
    }

    impl Drop for NegotiateContext {
        fn drop(&mut self) {
            if let Some(ctx) = self.ctx.take() {
                unsafe { let _ = DeleteSecurityContext(&ctx) };
            }
            unsafe { let _ = FreeCredentialsHandle(&self.cred) };
        }
    }
}

#[cfg(windows)]
pub use win::NegotiateContext;
```

在 `lib.rs` 加 `pub mod sspi;`。

- [ ] **Step 4: 运行测试确认通过**

```bash
cargo test -p rmc-win sspi
```

预期：6 passed。

Windows 上的人工验收：在一台域内机器上，把系统代理指向一台要求 Negotiate 的代理，运行 Task 10 完成后的客户端，确认诊断页的「代理认证（SSPI Negotiate）」一行为通过，且没有任何要求输入代理口令的提示。若协商失败，诊断页必须显示「代理要求认证，协商失败」而不是连接超时。

- [ ] **Step 5: 提交**

```bash
git add crates/rmc-win/src/sspi.rs crates/rmc-win/src/lib.rs crates/rmc-win/Cargo.toml
git commit -m "feat(win): SSPI 代理认证，Negotiate 与 NTLM"
```

---

本计划余下任务接续在 `2026-09-13-rmc-win-and-app-part2.md`：

| 任务 | 内容 |
|---|---|
| 4 | DPAPI 记住密码，实现凭据存储 |
| 5 | 电源与网络事件，实现 `SystemEvents` |
| 6 | rmc-app 骨架：iced 窗口、软件渲染回落、三个页签、Fluent 主题常量 |
| 7 | 视图模型 `model.rs`：从 `TunnelEvent` 推导，纯函数，Linux 可测 |
| 8 | 维护页：未开启表单两分组与六个状态渲染 |
| 9 | 诊断页与诊断包导出 |
| 10 | 日志页与 app 到 Supervisor 的接线 |
| 11 | 托盘图标与系统通知 |
| 12 | 便携包、Authenticode 签名、CI 产物与 Windows 人工验收清单 |
