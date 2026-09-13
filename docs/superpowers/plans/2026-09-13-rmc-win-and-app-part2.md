# Windows 平台层与界面 实施计划（续）

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 接着 `2026-09-13-rmc-win-and-app.md` 的 Task 3，完成 DPAPI、系统事件、iced 界面三页、托盘通知与打包。

**Architecture:** 界面分两层。`model.rs` 是从 `TunnelEvent` 推导的纯视图模型，含配色、文案、可用按钮，在 Linux 上单元测试；`view/` 只负责把模型画成 iced 控件。

**Spec:** `docs/方案设计.md` 第 3.9、3.10，界面以画板为准：`design/body-*.html`、`design/canvas.json`

**Global Constraints:** 与 `2026-09-13-rmc-win-and-app.md` 的同名小节完全一致，每个任务都隐含包含它。

---

### Task 4: DPAPI 记住密码

**Files:**
- Create: `crates/rmc-win/src/secret.rs`
- Modify: `crates/rmc-win/src/lib.rs`
- Test: `crates/rmc-win/src/secret.rs` 同文件测试模块

**Interfaces:**
- Consumes: 无
- Produces:
  - `pub trait SecretStore: Send + Sync { fn save(&self, key: &str, secret: &str) -> std::io::Result<()>; fn load(&self, key: &str) -> Option<Zeroizing<String>>; fn clear(&self, key: &str) -> std::io::Result<()> }`
  - `pub trait Sealer: Send + Sync { fn seal(&self, plain: &[u8]) -> Option<Vec<u8>>; fn unseal(&self, sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> }`
  - `#[cfg(windows)] pub struct DpapiSealer`，实现 `Sealer`（`CryptProtectData` 当前用户范围）
  - `pub struct FileSecretStore<S: Sealer>`，`FileSecretStore::new(dir: PathBuf, sealer: S)`，实现 `SecretStore`

- [ ] **Step 1: 写下失败的测试**

创建 `crates/rmc-win/src/secret.rs`，先写测试模块：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// 可逆的假密封器，只做字节取反，用来验证存储层逻辑。
    struct FlipSealer;

    impl Sealer for FlipSealer {
        fn seal(&self, plain: &[u8]) -> Option<Vec<u8>> {
            Some(plain.iter().map(|b| !b).collect())
        }
        fn unseal(&self, sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
            Some(Zeroizing::new(sealed.iter().map(|b| !b).collect()))
        }
    }

    struct FailingSealer;

    impl Sealer for FailingSealer {
        fn seal(&self, _plain: &[u8]) -> Option<Vec<u8>> {
            None
        }
        fn unseal(&self, _sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
            None
        }
    }

    fn tmpdir() -> std::path::PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let n = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let d = std::env::temp_dir().join(format!("rmc-secret-{n}"));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn round_trips_a_secret() {
        let s = FileSecretStore::new(tmpdir(), FlipSealer);
        s.save("tunnel-zhang@gateway.company.com:443", "pw-123").unwrap();
        let got = s.load("tunnel-zhang@gateway.company.com:443").unwrap();
        assert_eq!(got.as_str(), "pw-123");
    }

    #[test]
    fn plaintext_never_hits_the_disk() {
        let dir = tmpdir();
        let s = FileSecretStore::new(dir.clone(), FlipSealer);
        s.save("k", "PLAINTEXT-9f2a").unwrap();
        for entry in std::fs::read_dir(&dir).unwrap() {
            let bytes = std::fs::read(entry.unwrap().path()).unwrap();
            let text = String::from_utf8_lossy(&bytes);
            assert!(!text.contains("PLAINTEXT-9f2a"), "明文落盘了：{text}");
        }
    }

    #[test]
    fn missing_key_loads_none() {
        let s = FileSecretStore::new(tmpdir(), FlipSealer);
        assert!(s.load("nope").is_none());
    }

    #[test]
    fn clear_removes_the_secret() {
        let s = FileSecretStore::new(tmpdir(), FlipSealer);
        s.save("k", "pw").unwrap();
        s.clear("k").unwrap();
        assert!(s.load("k").is_none());
    }

    #[test]
    fn clear_on_missing_key_is_not_an_error() {
        let s = FileSecretStore::new(tmpdir(), FlipSealer);
        assert!(s.clear("never-existed").is_ok());
    }

    #[test]
    fn unseal_failure_loads_none_rather_than_panicking() {
        let dir = tmpdir();
        FileSecretStore::new(dir.clone(), FlipSealer).save("k", "pw").unwrap();
        // 换一个解不开的密封器，模拟换了 Windows 账号
        let s = FileSecretStore::new(dir, FailingSealer);
        assert!(s.load("k").is_none());
    }

    #[test]
    fn seal_failure_is_an_error_not_a_silent_plaintext_write() {
        let dir = tmpdir();
        let s = FileSecretStore::new(dir.clone(), FailingSealer);
        assert!(s.save("k", "pw").is_err());
        assert!(std::fs::read_dir(&dir).unwrap().next().is_none(), "失败时不该留文件");
    }

    #[test]
    fn keys_with_slashes_and_colons_are_usable() {
        let s = FileSecretStore::new(tmpdir(), FlipSealer);
        let key = "tunnel-zhang@gateway.company.com:443";
        s.save(key, "pw").unwrap();
        assert_eq!(s.load(key).unwrap().as_str(), "pw");
    }

    #[test]
    fn different_keys_do_not_collide() {
        let s = FileSecretStore::new(tmpdir(), FlipSealer);
        s.save("a@gw:443", "pw-a").unwrap();
        s.save("b@gw:443", "pw-b").unwrap();
        assert_eq!(s.load("a@gw:443").unwrap().as_str(), "pw-a");
        assert_eq!(s.load("b@gw:443").unwrap().as_str(), "pw-b");
    }

    #[test]
    fn overwrite_replaces_the_previous_secret() {
        let s = FileSecretStore::new(tmpdir(), FlipSealer);
        s.save("k", "old").unwrap();
        s.save("k", "new").unwrap();
        assert_eq!(s.load("k").unwrap().as_str(), "new");
    }
}
```

- [ ] **Step 2: 运行测试确认失败**

```bash
cargo test -p rmc-win secret
```

预期：编译失败，`cannot find trait Sealer`。

- [ ] **Step 3: 写最小实现**

在 `crates/rmc-win/Cargo.toml` 加 `sha2 = "0.10"`。

在 `crates/rmc-win/src/secret.rs` 测试模块之前插入：

```rust
//! 记住密码。密封交给 Sealer，Windows 上是 DPAPI 当前用户范围。
//! 默认不保存，只有用户勾选时调用方才会写入。

use std::io;
use std::path::PathBuf;
use zeroize::Zeroizing;

pub trait Sealer: Send + Sync {
    fn seal(&self, plain: &[u8]) -> Option<Vec<u8>>;
    fn unseal(&self, sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>>;
}

pub trait SecretStore: Send + Sync {
    fn save(&self, key: &str, secret: &str) -> io::Result<()>;
    fn load(&self, key: &str) -> Option<Zeroizing<String>>;
    fn clear(&self, key: &str) -> io::Result<()>;
}

pub struct FileSecretStore<S: Sealer> {
    dir: PathBuf,
    sealer: S,
}

impl<S: Sealer> FileSecretStore<S> {
    pub fn new(dir: PathBuf, sealer: S) -> Self {
        Self { dir, sealer }
    }

    /// key 可能含冒号与 @，取其哈希做文件名，避免非法字符。
    fn path_for(&self, key: &str) -> PathBuf {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(key.as_bytes());
        let hex: String = digest.iter().take(16).map(|b| format!("{b:02x}")).collect();
        self.dir.join(format!("{hex}.sealed"))
    }
}

impl<S: Sealer> SecretStore for FileSecretStore<S> {
    fn save(&self, key: &str, secret: &str) -> io::Result<()> {
        let sealed = self
            .sealer
            .seal(secret.as_bytes())
            .ok_or_else(|| io::Error::other("密封失败，未写入任何文件"))?;
        std::fs::create_dir_all(&self.dir)?;
        let path = self.path_for(key);
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &sealed)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    fn load(&self, key: &str) -> Option<Zeroizing<String>> {
        let sealed = std::fs::read(self.path_for(key)).ok()?;
        let plain = self.sealer.unseal(&sealed)?;
        let text = String::from_utf8(plain.to_vec()).ok()?;
        Some(Zeroizing::new(text))
    }

    fn clear(&self, key: &str) -> io::Result<()> {
        match std::fs::remove_file(self.path_for(key)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(windows)]
mod win {
    #![allow(unsafe_code)]
    //! DPAPI。CRYPTPROTECT_LOCAL_MACHINE 不设置，因此密文绑定当前 Windows 账号，
    //! 换账号或换机器都解不开。

    use super::Sealer;
    use windows::Win32::Foundation::LocalFree;
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB,
    };
    use zeroize::Zeroizing;

    pub struct DpapiSealer;

    fn take_blob(blob: &CRYPT_INTEGER_BLOB) -> Vec<u8> {
        let out =
            unsafe { std::slice::from_raw_parts(blob.pbData, blob.cbData as usize) }.to_vec();
        unsafe {
            let _ = LocalFree(Some(windows::Win32::Foundation::HLOCAL(blob.pbData.cast())));
        }
        out
    }

    impl Sealer for DpapiSealer {
        fn seal(&self, plain: &[u8]) -> Option<Vec<u8>> {
            let mut input = CRYPT_INTEGER_BLOB {
                cbData: plain.len() as u32,
                pbData: plain.as_ptr() as *mut u8,
            };
            let mut out = CRYPT_INTEGER_BLOB::default();
            let ok = unsafe {
                CryptProtectData(&mut input, None, None, None, None, 0, &mut out)
            }
            .is_ok();
            if !ok {
                return None;
            }
            Some(take_blob(&out))
        }

        fn unseal(&self, sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
            let mut input = CRYPT_INTEGER_BLOB {
                cbData: sealed.len() as u32,
                pbData: sealed.as_ptr() as *mut u8,
            };
            let mut out = CRYPT_INTEGER_BLOB::default();
            let ok = unsafe {
                CryptUnprotectData(&mut input, None, None, None, None, 0, &mut out)
            }
            .is_ok();
            if !ok {
                return None;
            }
            Some(Zeroizing::new(take_blob(&out)))
        }
    }
}

#[cfg(windows)]
pub use win::DpapiSealer;
```

在 `lib.rs` 加 `pub mod secret;`。

- [ ] **Step 4: 运行测试确认通过**

```bash
cargo test -p rmc-win secret
```

预期：10 passed。

Windows 人工验收：勾选记住密码连接一次，退出后重开，密码框应自动填上；再用另一个 Windows 账号登录同一台机器打开客户端，密码框必须为空且不报错。

- [ ] **Step 5: 提交**

```bash
git add crates/rmc-win/src/secret.rs crates/rmc-win/src/lib.rs crates/rmc-win/Cargo.toml
git commit -m "feat(win): DPAPI 记住密码"
```

---

### Task 5: 电源与网络事件

**Files:**
- Create: `crates/rmc-win/src/events.rs`
- Modify: `crates/rmc-win/src/lib.rs`
- Test: `crates/rmc-win/src/events.rs` 同文件测试模块

**Interfaces:**
- Consumes: rmc-core 的 `SystemEvents`、`SystemEvent`
- Produces:
  - `pub struct EventHub`，`EventHub::new() -> Self`，实现 `SystemEvents`
  - `EventHub::emit(&self, e: SystemEvent)`：供 Win32 回调与测试注入
  - `pub fn debounce_ms() -> u64`（常量 800，网络状态抖动时合并事件）
  - `#[cfg(windows)] pub fn spawn_win32_listeners(hub: Arc<EventHub>)`：注册休眠恢复与网络连通性变化通知

- [ ] **Step 1: 写下失败的测试**

创建 `crates/rmc-win/src/events.rs`，先写测试模块：

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use rmc_core::platform::{SystemEvent, SystemEvents};
    use std::sync::Arc;

    #[tokio::test]
    async fn subscriber_receives_an_emitted_event() {
        let hub = Arc::new(EventHub::new());
        let mut rx = hub.subscribe();
        hub.emit(SystemEvent::NetworkChanged);
        assert_eq!(rx.recv().await.unwrap(), SystemEvent::NetworkChanged);
    }

    #[tokio::test]
    async fn two_subscribers_both_receive() {
        let hub = Arc::new(EventHub::new());
        let mut a = hub.subscribe();
        let mut b = hub.subscribe();
        hub.emit(SystemEvent::ResumedFromSleep);
        assert_eq!(a.recv().await.unwrap(), SystemEvent::ResumedFromSleep);
        assert_eq!(b.recv().await.unwrap(), SystemEvent::ResumedFromSleep);
    }

    #[tokio::test]
    async fn emitting_with_no_subscriber_does_not_panic() {
        let hub = EventHub::new();
        hub.emit(SystemEvent::NetworkChanged);
    }

    #[tokio::test]
    async fn late_subscriber_does_not_see_earlier_events() {
        // 事件是瞬时信号，迟到的订阅者不该收到历史事件而触发多余重连。
        let hub = Arc::new(EventHub::new());
        hub.emit(SystemEvent::NetworkChanged);
        let mut rx = hub.subscribe();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
                .await
                .is_err()
        );
    }

    #[test]
    fn debounce_is_under_one_second() {
        // 太长会拖慢现场恢复，太短会在网卡切换时连发多次。
        assert!((300..=1000).contains(&debounce_ms()));
    }
}
```

- [ ] **Step 2: 运行测试确认失败**

```bash
cargo test -p rmc-win events
```

预期：编译失败，`cannot find type EventHub`。

- [ ] **Step 3: 写最小实现**

在 `crates/rmc-win/src/events.rs` 测试模块之前插入：

```rust
//! 电源与网络事件。事件是瞬时信号，用 broadcast 发布，不做缓存。

use rmc_core::platform::{SystemEvent, SystemEvents};
use tokio::sync::broadcast;

/// 网络状态抖动时的合并窗口，毫秒。
pub fn debounce_ms() -> u64 {
    800
}

pub struct EventHub {
    tx: broadcast::Sender<SystemEvent>,
}

impl EventHub {
    pub fn new() -> Self {
        Self { tx: broadcast::channel(16).0 }
    }

    /// 供 Win32 回调与测试注入。无人订阅时静默丢弃。
    pub fn emit(&self, e: SystemEvent) {
        let _ = self.tx.send(e);
    }
}

impl Default for EventHub {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemEvents for EventHub {
    fn subscribe(&self) -> broadcast::Receiver<SystemEvent> {
        self.tx.subscribe()
    }
}

#[cfg(windows)]
mod win {
    #![allow(unsafe_code)]
    //! 休眠恢复用 PowerRegisterSuspendResumeNotification，
    //! 网络变化用 NLM 的 INetworkListManagerEvents。两者都在后台线程注册。

    use super::{debounce_ms, EventHub};
    use rmc_core::platform::SystemEvent;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// 合并窗口内的重复事件只发一次。
    struct Debouncer {
        last: std::sync::Mutex<Option<Instant>>,
    }

    impl Debouncer {
        fn new() -> Self {
            Self { last: std::sync::Mutex::new(None) }
        }
        fn allow(&self) -> bool {
            let mut guard = self.last.lock().unwrap();
            let now = Instant::now();
            match *guard {
                Some(t) if now.duration_since(t) < Duration::from_millis(debounce_ms()) => false,
                _ => {
                    *guard = Some(now);
                    true
                }
            }
        }
    }

    /// 注册两类通知。失败只记日志，不影响其余功能：
    /// 没有事件时客户端仍会按退避序列重连，只是恢复慢一些。
    pub fn spawn_win32_listeners(hub: Arc<EventHub>) {
        let power_hub = hub.clone();
        std::thread::spawn(move || {
            if let Err(e) = register_power(power_hub) {
                tracing::warn!(error = %e, "注册休眠恢复通知失败，恢复后将依赖退避重连");
            }
        });
        std::thread::spawn(move || {
            if let Err(e) = register_network(hub) {
                tracing::warn!(error = %e, "注册网络变化通知失败，切网后将依赖退避重连");
            }
        });
    }

    fn register_power(hub: Arc<EventHub>) -> windows::core::Result<()> {
        use windows::Win32::System::Power::{
            PowerRegisterSuspendResumeNotification, DEVICE_NOTIFY_CALLBACK,
            DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS,
        };
        use windows::Win32::System::SystemServices::PBT_APMRESUMEAUTOMATIC;

        static DEBOUNCE: std::sync::OnceLock<Debouncer> = std::sync::OnceLock::new();
        static HUB: std::sync::OnceLock<Arc<EventHub>> = std::sync::OnceLock::new();
        let _ = HUB.set(hub);
        let _ = DEBOUNCE.set(Debouncer::new());

        unsafe extern "system" fn callback(
            _context: *const std::ffi::c_void,
            event_type: u32,
            _setting: *const std::ffi::c_void,
        ) -> u32 {
            if event_type == PBT_APMRESUMEAUTOMATIC {
                if let (Some(hub), Some(d)) = (HUB.get(), DEBOUNCE.get()) {
                    if d.allow() {
                        hub.emit(SystemEvent::ResumedFromSleep);
                    }
                }
            }
            0
        }

        let params = DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS {
            Callback: Some(callback),
            Context: std::ptr::null_mut(),
        };
        let mut handle = Default::default();
        unsafe {
            PowerRegisterSuspendResumeNotification(
                DEVICE_NOTIFY_CALLBACK,
                &params as *const _ as *const _,
                &mut handle,
            )
        }
        .ok()?;
        // 句柄随进程存活，故意不注销。
        std::mem::forget(handle);
        loop {
            std::thread::park();
        }
    }

    fn register_network(hub: Arc<EventHub>) -> windows::core::Result<()> {
        // NLM 的 COM 事件接收需要一个 STA 消息循环。为了把 unsafe 面积压到最小，
        // 这里用轮询代替：每 2 秒读一次连通性，变化时发事件。
        use windows::Win32::Networking::NetworkListManager::{
            INetworkListManager, NetworkListManager, NLM_CONNECTIVITY,
        };
        use windows::Win32::System::Com::{
            CoCreateInstance, CoInitializeEx, CLSCTX_ALL, COINIT_APARTMENTTHREADED,
        };

        unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }.ok()?;
        let nlm: INetworkListManager =
            unsafe { CoCreateInstance(&NetworkListManager, None, CLSCTX_ALL) }?;

        let debounce = Debouncer::new();
        let mut previous: Option<NLM_CONNECTIVITY> = None;
        loop {
            if let Ok(current) = unsafe { nlm.GetConnectivity() } {
                if previous.map(|p| p.0 != current.0).unwrap_or(false) && debounce.allow() {
                    hub.emit(SystemEvent::NetworkChanged);
                }
                previous = Some(current);
            }
            std::thread::sleep(Duration::from_secs(2));
        }
    }
}

#[cfg(windows)]
pub use win::spawn_win32_listeners;
```

在 `lib.rs` 加 `pub mod events;`。

- [ ] **Step 4: 运行测试确认通过**

```bash
cargo test -p rmc-win events
```

预期：5 passed。

Windows 人工验收：连接成功后合盖休眠再唤醒，客户端应在几秒内从重连中回到已连接，日志里有一条休眠恢复记录；拔掉网线切到 Wi-Fi，同样应立即重连而不是等满退避。

- [ ] **Step 5: 提交**

```bash
git add crates/rmc-win/src/events.rs crates/rmc-win/src/lib.rs
git commit -m "feat(win): 休眠恢复与网络变化事件"
```

---

### Task 6: rmc-app 骨架与主题

**Files:**
- Create: `crates/rmc-app/Cargo.toml`
- Create: `crates/rmc-app/src/main.rs`
- Create: `crates/rmc-app/src/theme.rs`
- Create: `crates/rmc-app/src/view/mod.rs`
- Create: `crates/rmc-app/src/view/chrome.rs`
- Modify: `Cargo.toml`（workspace members）
- Test: `crates/rmc-app/src/theme.rs` 同文件测试模块

**Interfaces:**
- Consumes: 无
- Produces:
  - `pub const WINDOW_SIZE: (f32, f32) = (520.0, 720.0)`
  - `pub mod color`：`IDLE`、`PROGRESS`、`CONNECTED`、`DEGRADED`、`BACKOFF`、`FAILED`、`TEXT`、`TEXT_SUB`、`CARD`、`BORDER`、`WINDOW`、`ACCENT` 共 12 个 `iced::Color` 常量
  - `pub fn tint(base: iced::Color) -> iced::Color`：状态卡背景的浅色版本
  - `pub enum Tab { Maintain, Diagnostics, Logs }`，`Tab::label(&self) -> &'static str`
  - `view::chrome::title_bar()`、`view::chrome::tabs(active: Tab)`

- [ ] **Step 1: 写下失败的测试**

创建 `crates/rmc-app/src/theme.rs`，先写测试模块：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn to_hex(c: iced::Color) -> String {
        format!(
            "#{:02x}{:02x}{:02x}",
            (c.r * 255.0).round() as u8,
            (c.g * 255.0).round() as u8,
            (c.b * 255.0).round() as u8
        )
    }

    #[test]
    fn window_is_fixed_at_the_agreed_size() {
        assert_eq!(WINDOW_SIZE, (520.0, 720.0));
    }

    #[test]
    fn state_colors_match_the_approved_palette() {
        assert_eq!(to_hex(color::IDLE), "#8a8a8a");
        assert_eq!(to_hex(color::PROGRESS), "#0067c0");
        assert_eq!(to_hex(color::CONNECTED), "#0f7b0f");
        assert_eq!(to_hex(color::DEGRADED), "#b8560f");
        assert_eq!(to_hex(color::BACKOFF), "#9d5d00");
        assert_eq!(to_hex(color::FAILED), "#c42b1c");
    }

    #[test]
    fn accent_is_the_fluent_blue() {
        assert_eq!(to_hex(color::ACCENT), "#0067c0");
    }

    #[test]
    fn tint_is_lighter_than_its_base_and_keeps_the_hue_direction() {
        for base in [color::CONNECTED, color::DEGRADED, color::BACKOFF, color::FAILED] {
            let t = tint(base);
            assert!(t.r >= base.r && t.g >= base.g && t.b >= base.b, "{:?}", base);
            assert!(t.r > 0.9 && t.g > 0.9 && t.b > 0.88, "底色应当很浅：{t:?}");
        }
    }

    #[test]
    fn tab_labels_are_the_three_agreed_pages() {
        let labels: Vec<&str> = [Tab::Maintain, Tab::Diagnostics, Tab::Logs]
            .iter()
            .map(|t| t.label())
            .collect();
        assert_eq!(labels, vec!["维护", "诊断", "日志"]);
    }
}
```

- [ ] **Step 2: 运行测试确认失败**

```bash
cargo test -p rmc-app
```

预期：包不存在。

- [ ] **Step 3: 写最小实现**

根 `Cargo.toml` 的 members 加 `"crates/rmc-app"`。

创建 `crates/rmc-app/Cargo.toml`：

```toml
[package]
name = "rmc-app"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[dependencies]
rmc-core.workspace = true
tokio.workspace = true
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
iced = { version = "0.13", default-features = false, features = ["wgpu", "tiny-skia", "tokio", "advanced"] }
zeroize = { version = "1", features = ["std"] }

[target.'cfg(windows)'.dependencies]
rmc-win = { path = "../rmc-win" }
tray-icon = "0.19"

[[bin]]
name = "rmc"
path = "src/main.rs"
```

`tiny-skia` 与 `wgpu` 同时开启时，iced 在 wgpu 初始化失败时自动回落到软件渲染，这是 RDP 与虚拟机里能起来的关键。

创建 `crates/rmc-app/src/theme.rs`，在测试模块之前插入：

```rust
//! 配色与尺寸常量。取值来自已定版画板，改动前先改画板。

use iced::Color;

/// 固定窗口尺寸，不可最大化。
pub const WINDOW_SIZE: (f32, f32) = (520.0, 720.0);

const fn rgb(r: u8, g: u8, b: u8) -> Color {
    Color {
        r: r as f32 / 255.0,
        g: g as f32 / 255.0,
        b: b as f32 / 255.0,
        a: 1.0,
    }
}

pub mod color {
    use super::rgb;
    use iced::Color;

    pub const IDLE: Color = rgb(0x8a, 0x8a, 0x8a);
    pub const PROGRESS: Color = rgb(0x00, 0x67, 0xc0);
    pub const CONNECTED: Color = rgb(0x0f, 0x7b, 0x0f);
    pub const DEGRADED: Color = rgb(0xb8, 0x56, 0x0f);
    pub const BACKOFF: Color = rgb(0x9d, 0x5d, 0x00);
    pub const FAILED: Color = rgb(0xc4, 0x2b, 0x1c);

    pub const ACCENT: Color = rgb(0x00, 0x67, 0xc0);
    pub const TEXT: Color = rgb(0x1c, 0x1c, 0x1c);
    pub const TEXT_SUB: Color = rgb(0x6b, 0x6b, 0x6b);
    pub const CARD: Color = rgb(0xff, 0xff, 0xff);
    pub const BORDER: Color = rgb(0xe8, 0xe8, 0xe8);
    pub const WINDOW: Color = rgb(0xf3, 0xf3, 0xf3);
}

/// 状态卡的浅色底，把状态色按 8% 混到白底上。
pub fn tint(base: Color) -> Color {
    const K: f32 = 0.08;
    Color {
        r: 1.0 - (1.0 - base.r) * K,
        g: 1.0 - (1.0 - base.g) * K,
        b: 1.0 - (1.0 - base.b) * K,
        a: 1.0,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Maintain,
    Diagnostics,
    Logs,
}

impl Tab {
    pub fn label(&self) -> &'static str {
        match self {
            Tab::Maintain => "维护",
            Tab::Diagnostics => "诊断",
            Tab::Logs => "日志",
        }
    }

    pub const ALL: [Tab; 3] = [Tab::Maintain, Tab::Diagnostics, Tab::Logs];
}
```

创建 `crates/rmc-app/src/view/chrome.rs`：

```rust
//! 标题栏与页签。窗口用系统装饰，标题栏这里只画应用名。

use crate::theme::{color, Tab};
use crate::Message;
use iced::widget::{button, container, row, text, Space};
use iced::{Alignment, Element, Length};

pub fn title_bar<'a>() -> Element<'a, Message> {
    container(
        row![
            text("Remote Maintenance").size(12).color(color::TEXT_SUB),
            Space::with_width(Length::Fill),
        ]
        .align_y(Alignment::Center)
        .padding([0, 14]),
    )
    .height(40)
    .into()
}

pub fn tabs<'a>(active: Tab) -> Element<'a, Message> {
    let mut r = row![].spacing(4).padding([0, 14]);
    for t in Tab::ALL {
        let is_active = t == active;
        let label = text(t.label())
            .size(13)
            .color(if is_active { color::TEXT } else { color::TEXT_SUB });
        r = r.push(
            button(label)
                .on_press(Message::TabSelected(t))
                .padding([8, 10])
                .style(move |_, _| button::Style {
                    background: None,
                    text_color: if is_active { color::TEXT } else { color::TEXT_SUB },
                    border: iced::Border {
                        color: if is_active { color::ACCENT } else { iced::Color::TRANSPARENT },
                        width: 2.0,
                        radius: 0.0.into(),
                    },
                    ..Default::default()
                }),
        );
    }
    container(r.align_y(Alignment::Center)).height(40).into()
}
```

创建 `crates/rmc-app/src/view/mod.rs`：

```rust
pub mod chrome;
```

创建 `crates/rmc-app/src/main.rs`：

```rust
#![cfg_attr(windows, windows_subsystem = "windows")]
//! 远程维护客户端界面。只发 Command、只读 TunnelEvent。

mod theme;
mod view;

use theme::{Tab, WINDOW_SIZE};

#[derive(Debug, Clone)]
pub enum Message {
    TabSelected(Tab),
}

struct App {
    tab: Tab,
}

impl Default for App {
    fn default() -> Self {
        Self { tab: Tab::Maintain }
    }
}

impl App {
    fn update(&mut self, message: Message) {
        match message {
            Message::TabSelected(t) => self.tab = t,
        }
    }

    fn view(&self) -> iced::Element<'_, Message> {
        use iced::widget::column;
        column![view::chrome::title_bar(), view::chrome::tabs(self.tab)].into()
    }
}

fn main() -> iced::Result {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("RMC_LOG")
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    #[cfg(windows)]
    let _instance = match rmc_win::single_instance::SingleInstance::acquire("rmc-client") {
        Some(i) => i,
        None => {
            tracing::info!("已有实例在运行，退出");
            return Ok(());
        }
    };

    iced::application("Remote Maintenance", App::update, App::view)
        .window(iced::window::Settings {
            size: iced::Size::new(WINDOW_SIZE.0, WINDOW_SIZE.1),
            resizable: false,
            ..Default::default()
        })
        .run()
}
```

- [ ] **Step 4: 运行测试确认通过**

```bash
cargo test -p rmc-app
cargo build -p rmc-app
```

预期：5 passed，且 `cargo build` 成功。若 iced 0.13 的 `application` 签名不同，以 `cargo doc -p iced --open` 为准调整，保持 `Message`、`update`、`view` 三者形状不变。

- [ ] **Step 5: 提交**

```bash
git add Cargo.toml crates/rmc-app
git commit -m "feat(app): iced 骨架、Fluent 主题常量与三页签"
```

---

### Task 7: 视图模型

界面里所有的判断都收到这里，成为跨平台可测的纯函数。`view/` 之后只做绘制。

**Files:**
- Create: `crates/rmc-app/src/model.rs`
- Modify: `crates/rmc-app/src/main.rs`
- Test: `crates/rmc-app/src/model.rs` 同文件测试模块

**Interfaces:**
- Consumes: rmc-core 的 `State`、`TunnelEvent`、`RemoteSessionInfo`、`PreflightReport`、`ErrorClass`
- Produces:
  - `pub struct StatusCard { pub dot: iced::Color, pub background: iced::Color, pub title: String, pub subtitle: String }`
  - `pub struct Buttons { pub primary: Option<(&'static str, Action)>, pub secondary: Option<(&'static str, Action)> }`
  - `pub enum Action { Start, Cancel, Stop, RetryNow }`
  - `pub struct Model { pub state: State, pub sessions: Vec<RemoteSessionInfo>, pub preflight: Option<PreflightReport>, pub host_key: Option<(String, bool)>, pub connected_since: Option<SystemTime>, pub credentials_visible: bool, pub addresses_editable: bool }`
  - `Model::apply(&mut self, e: TunnelEvent)`
  - `Model::status_card(&self) -> StatusCard`
  - `Model::buttons(&self) -> Buttons`
  - `Model::elapsed(&self, now: SystemTime) -> Option<String>`（`HH:MM:SS`）

- [ ] **Step 1: 写下失败的测试**

创建 `crates/rmc-app/src/model.rs`，先写测试模块：

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use rmc_core::error::ErrorClass;
    use rmc_core::state::{RemoteSessionInfo, State, TunnelEvent};
    use std::time::{Duration, SystemTime};

    fn model_in(state: State) -> Model {
        let mut m = Model::default();
        m.apply(TunnelEvent::State(state));
        m
    }

    #[test]
    fn idle_shows_credentials_and_editable_addresses() {
        let m = model_in(State::Idle);
        assert!(m.credentials_visible);
        assert!(m.addresses_editable);
        assert_eq!(m.status_card().title, "未开启");
    }

    #[test]
    fn connected_hides_credentials_and_locks_addresses() {
        let m = model_in(State::Connected { degraded: false });
        assert!(!m.credentials_visible, "已连接后凭据区必须隐藏");
        assert!(!m.addresses_editable, "已连接后地址必须锁定");
    }

    #[test]
    fn status_colors_follow_the_state() {
        use crate::theme::color;
        let cases = [
            (State::Idle, color::IDLE),
            (State::Preflight, color::PROGRESS),
            (State::Connecting, color::PROGRESS),
            (State::Connected { degraded: false }, color::CONNECTED),
            (State::Connected { degraded: true }, color::DEGRADED),
            (State::Backoff { attempt: 1, delay: Duration::from_secs(1) }, color::BACKOFF),
            (State::Failed { class: ErrorClass::Fatal, message: "x".into() }, color::FAILED),
        ];
        for (state, want) in cases {
            assert_eq!(model_in(state.clone()).status_card().dot, want, "{state:?}");
        }
    }

    #[test]
    fn degraded_title_says_tunnel_is_fine_but_appliance_is_not() {
        let c = model_in(State::Connected { degraded: true }).status_card();
        assert_eq!(c.title, "一体机不可达");
        assert!(c.subtitle.contains("隧道正常"), "{}", c.subtitle);
    }

    #[test]
    fn backoff_subtitle_names_the_attempt_and_the_delay() {
        let c = model_in(State::Backoff { attempt: 3, delay: Duration::from_secs(5) }).status_card();
        assert!(c.title.contains("第 3 次"), "{}", c.title);
        assert!(c.subtitle.contains('5'), "{}", c.subtitle);
    }

    #[test]
    fn auth_failure_lands_on_idle_with_a_retype_hint() {
        // core 在认证失败时把状态推回 Idle，界面据此提示重新输入。
        let mut m = Model::default();
        m.apply(TunnelEvent::State(State::Connecting));
        m.apply(TunnelEvent::State(State::Idle));
        assert!(m.credentials_visible);
    }

    #[test]
    fn failed_state_shows_the_message_as_subtitle() {
        let c = model_in(State::Failed {
            class: ErrorClass::Fatal,
            message: "Gateway host key 与已记录的不一致".into(),
        })
        .status_card();
        assert!(c.subtitle.contains("host key"), "{}", c.subtitle);
    }

    #[test]
    fn buttons_per_state() {
        assert_eq!(model_in(State::Idle).buttons().primary.unwrap().0, "开启远程维护");
        assert_eq!(model_in(State::Preflight).buttons().primary.unwrap().0, "取消");
        assert_eq!(
            model_in(State::Connected { degraded: false }).buttons().primary.unwrap().0,
            "停止远程维护"
        );
        let b = model_in(State::Backoff { attempt: 1, delay: Duration::from_secs(1) }).buttons();
        assert_eq!(b.primary.unwrap().0, "立即重试");
        assert_eq!(b.secondary.unwrap().0, "停止远程维护");
        assert_eq!(
            model_in(State::Failed { class: ErrorClass::Fatal, message: "x".into() })
                .buttons()
                .primary
                .unwrap()
                .0,
            "重试"
        );
    }

    #[test]
    fn no_countdown_anywhere_in_v1() {
        // 会话上限不在 V1，任何状态都不得出现“剩余”。
        for state in [
            State::Connected { degraded: false },
            State::Connected { degraded: true },
            State::Backoff { attempt: 1, delay: Duration::from_secs(1) },
        ] {
            let c = model_in(state.clone()).status_card();
            assert!(!c.subtitle.contains("剩余"), "{state:?} 出现了倒计时");
            assert!(!c.title.contains("剩余"), "{state:?} 出现了倒计时");
        }
    }

    #[test]
    fn sessions_are_replaced_wholesale_by_each_event() {
        let mut m = Model::default();
        let s = |id| RemoteSessionInfo {
            id,
            opened_at: SystemTime::UNIX_EPOCH,
            to_appliance: 0,
            from_appliance: 0,
        };
        m.apply(TunnelEvent::RemoteSessions(vec![s(1), s(2)]));
        assert_eq!(m.sessions.len(), 2);
        m.apply(TunnelEvent::RemoteSessions(vec![s(2)]));
        assert_eq!(m.sessions.len(), 1);
        m.apply(TunnelEvent::RemoteSessions(vec![]));
        assert!(m.sessions.is_empty());
    }

    #[test]
    fn elapsed_formats_as_hms() {
        let mut m = Model::default();
        let start = SystemTime::UNIX_EPOCH;
        m.apply(TunnelEvent::ConnectedSince(start));
        let now = start + Duration::from_secs(3600 + 34 * 60 + 14);
        assert_eq!(m.elapsed(now).unwrap(), "01:34:14");
    }

    #[test]
    fn elapsed_is_none_before_connecting() {
        assert!(Model::default().elapsed(SystemTime::now()).is_none());
    }

    #[test]
    fn host_key_first_seen_is_recorded_for_the_diagnostics_page() {
        let mut m = Model::default();
        m.apply(TunnelEvent::HostKey {
            fingerprint: "SHA256:aaa".into(),
            first_seen: true,
        });
        assert_eq!(m.host_key, Some(("SHA256:aaa".to_string(), true)));
    }

    #[test]
    fn stopping_clears_sessions_and_elapsed() {
        let mut m = Model::default();
        m.apply(TunnelEvent::ConnectedSince(SystemTime::UNIX_EPOCH));
        m.apply(TunnelEvent::RemoteSessions(vec![RemoteSessionInfo {
            id: 1,
            opened_at: SystemTime::UNIX_EPOCH,
            to_appliance: 0,
            from_appliance: 0,
        }]));
        m.apply(TunnelEvent::State(State::Idle));
        assert!(m.sessions.is_empty());
        assert!(m.elapsed(SystemTime::now()).is_none());
    }
}
```

- [ ] **Step 2: 运行测试确认失败**

```bash
cargo test -p rmc-app model
```

预期：编译失败，`cannot find type Model`。

- [ ] **Step 3: 写最小实现**

创建 `crates/rmc-app/src/model.rs`，在测试模块之前插入：

```rust
//! 视图模型。界面的全部判断都在这里，纯函数，跨平台可测。

use crate::theme::{color, tint};
use rmc_core::preflight::PreflightReport;
use rmc_core::state::{RemoteSessionInfo, State, TunnelEvent};
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Start,
    Cancel,
    Stop,
    RetryNow,
}

#[derive(Debug, Clone)]
pub struct StatusCard {
    pub dot: iced::Color,
    pub background: iced::Color,
    pub title: String,
    pub subtitle: String,
}

#[derive(Debug, Clone, Default)]
pub struct Buttons {
    pub primary: Option<(&'static str, Action)>,
    pub secondary: Option<(&'static str, Action)>,
}

#[derive(Debug, Clone)]
pub struct Model {
    pub state: State,
    pub sessions: Vec<RemoteSessionInfo>,
    pub preflight: Option<PreflightReport>,
    pub host_key: Option<(String, bool)>,
    pub connected_since: Option<SystemTime>,
    pub credentials_visible: bool,
    pub addresses_editable: bool,
}

impl Default for Model {
    fn default() -> Self {
        Self {
            state: State::Idle,
            sessions: Vec::new(),
            preflight: None,
            host_key: None,
            connected_since: None,
            credentials_visible: true,
            addresses_editable: true,
        }
    }
}

impl Model {
    pub fn apply(&mut self, e: TunnelEvent) {
        match e {
            TunnelEvent::State(s) => {
                // 只有未开启与失败两种状态允许编辑，其余一律锁定。
                let editable = matches!(s, State::Idle | State::Failed { .. });
                self.credentials_visible = editable;
                self.addresses_editable = editable;
                if matches!(s, State::Idle) {
                    self.sessions.clear();
                    self.connected_since = None;
                }
                self.state = s;
            }
            TunnelEvent::Preflight(r) => self.preflight = Some(r),
            TunnelEvent::RemoteSessions(list) => self.sessions = list,
            TunnelEvent::HostKey { fingerprint, first_seen } => {
                self.host_key = Some((fingerprint, first_seen));
            }
            TunnelEvent::ConnectedSince(t) => self.connected_since = Some(t),
        }
    }

    pub fn status_card(&self) -> StatusCard {
        let (dot, title, subtitle) = match &self.state {
            State::Idle => (
                color::IDLE,
                "未开启".to_string(),
                "远程维护默认关闭，由现场人员确认后开启".to_string(),
            ),
            State::Preflight => (
                color::PROGRESS,
                "预检中".to_string(),
                "正在检查网络可达性".to_string(),
            ),
            State::Connecting => (
                color::PROGRESS,
                "正在连接".to_string(),
                "口令认证与反向端口注册".to_string(),
            ),
            State::Connected { degraded: false } => (
                color::CONNECTED,
                "已连接".to_string(),
                "Gateway 反向端口 127.0.0.1:22001".to_string(),
            ),
            State::Connected { degraded: true } => (
                color::DEGRADED,
                "一体机不可达".to_string(),
                "隧道正常，每 30 秒重试一体机，恢复后自动转回".to_string(),
            ),
            State::Backoff { attempt, delay } => (
                color::BACKOFF,
                format!("正在重连 · 第 {attempt} 次"),
                format!("{} 秒后重试，口令已保留", delay.as_secs()),
            ),
            State::Stopping => (
                color::IDLE,
                "正在停止".to_string(),
                "正在关闭隧道与全部远程会话".to_string(),
            ),
            State::Failed { message, .. } => {
                (color::FAILED, "连接失败".to_string(), message.clone())
            }
        };
        let background = if matches!(self.state, State::Idle) {
            color::CARD
        } else {
            tint(dot)
        };
        StatusCard { dot, background, title, subtitle }
    }

    pub fn buttons(&self) -> Buttons {
        match &self.state {
            State::Idle => Buttons {
                primary: Some(("开启远程维护", Action::Start)),
                secondary: None,
            },
            State::Preflight | State::Connecting => Buttons {
                primary: Some(("取消", Action::Cancel)),
                secondary: None,
            },
            State::Connected { .. } => Buttons {
                primary: Some(("停止远程维护", Action::Stop)),
                secondary: None,
            },
            State::Backoff { .. } => Buttons {
                primary: Some(("立即重试", Action::RetryNow)),
                secondary: Some(("停止远程维护", Action::Stop)),
            },
            State::Stopping => Buttons::default(),
            State::Failed { .. } => Buttons {
                primary: Some(("重试", Action::RetryNow)),
                secondary: None,
            },
        }
    }

    /// 已连接时长，形如 01:34:14。未连接返回 None。
    pub fn elapsed(&self, now: SystemTime) -> Option<String> {
        let since = self.connected_since?;
        let secs = now.duration_since(since).ok()?.as_secs();
        Some(format!(
            "{:02}:{:02}:{:02}",
            secs / 3600,
            (secs % 3600) / 60,
            secs % 60
        ))
    }
}
```

在 `main.rs` 加 `mod model;`。

- [ ] **Step 4: 运行测试确认通过**

```bash
cargo test -p rmc-app model
```

预期：14 passed。

- [ ] **Step 5: 提交**

```bash
git add crates/rmc-app/src/model.rs crates/rmc-app/src/main.rs
git commit -m "feat(app): 视图模型与状态到界面的映射"
```

---

### Task 8: 维护页

**Files:**
- Create: `crates/rmc-app/src/form.rs`
- Create: `crates/rmc-app/src/view/maintain.rs`
- Modify: `crates/rmc-app/src/view/mod.rs`、`crates/rmc-app/src/main.rs`
- Test: `crates/rmc-app/src/form.rs` 同文件测试模块

**Interfaces:**
- Consumes: Task 7 的 `Model`
- Produces:
  - `pub struct Form { pub appliance_host: String, pub appliance_port: String, pub gateway_host: String, pub gateway_port: String, pub username: String, pub password: Zeroizing<String>, pub remember: bool, pub detected_proxy: Option<String> }`
  - `Form::validate(&self) -> Result<(HostPort, HostPort), Vec<&'static str>>`：返回 (一体机, Gateway) 或字段错误列表
  - `Form::can_start(&self) -> bool`
  - `Form::clear_password(&mut self)`
  - `Form::egress_label(&self) -> String`：有代理时 `经系统代理 host:port`，否则 `直连`
  - `view::maintain::view(model: &Model, form: &Form) -> Element<Message>`

- [ ] **Step 1: 写下失败的测试**

创建 `crates/rmc-app/src/form.rs`，先写测试模块：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn good() -> Form {
        Form {
            appliance_host: "192.168.100.10".into(),
            appliance_port: "22".into(),
            gateway_host: "gateway.company.com".into(),
            gateway_port: "443".into(),
            username: "tunnel-zhang".into(),
            password: Zeroizing::new("pw".into()),
            remember: false,
            detected_proxy: None,
        }
    }

    #[test]
    fn valid_form_yields_both_addresses() {
        let (appliance, gateway) = good().validate().unwrap();
        assert_eq!(appliance.to_string(), "192.168.100.10:22");
        assert_eq!(gateway.to_string(), "gateway.company.com:443");
    }

    #[test]
    fn empty_username_blocks_start() {
        let mut f = good();
        f.username.clear();
        assert!(!f.can_start());
        assert!(f.validate().unwrap_err().iter().any(|e| e.contains("账号")));
    }

    #[test]
    fn empty_password_blocks_start() {
        let mut f = good();
        f.password = Zeroizing::new(String::new());
        assert!(!f.can_start());
    }

    #[test]
    fn bad_appliance_port_is_reported_on_that_field() {
        let mut f = good();
        f.appliance_port = "abc".into();
        let errs = f.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("一体机端口")), "{errs:?}");
    }

    #[test]
    fn bad_gateway_host_is_reported() {
        let mut f = good();
        f.gateway_host = "gate way".into();
        let errs = f.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("Gateway 地址")), "{errs:?}");
    }

    #[test]
    fn loopback_appliance_is_rejected() {
        let mut f = good();
        f.appliance_host = "127.0.0.1".into();
        assert!(f.validate().is_err());
    }

    #[test]
    fn all_errors_are_reported_at_once() {
        let mut f = good();
        f.username.clear();
        f.appliance_port = "0".into();
        f.gateway_host = "bad host".into();
        assert!(f.validate().unwrap_err().len() >= 3);
    }

    #[test]
    fn clear_password_empties_it_and_keeps_everything_else() {
        let mut f = good();
        f.clear_password();
        assert!(f.password.is_empty());
        assert_eq!(f.username, "tunnel-zhang");
        assert_eq!(f.appliance_host, "192.168.100.10");
    }

    #[test]
    fn egress_label_names_the_proxy_when_detected() {
        let mut f = good();
        f.detected_proxy = Some("proxy.company.com:8080".into());
        assert_eq!(f.egress_label(), "经系统代理 proxy.company.com:8080");
    }

    #[test]
    fn egress_label_says_direct_when_no_proxy() {
        assert_eq!(good().egress_label(), "直连");
    }

    #[test]
    fn debug_output_redacts_the_password() {
        let f = good();
        assert!(!format!("{f:?}").contains("pw"), "{f:?}");
    }
}
```

- [ ] **Step 2: 运行测试确认失败**

```bash
cargo test -p rmc-app form
```

预期：编译失败，`cannot find type Form`。

- [ ] **Step 3: 写最小实现**

创建 `crates/rmc-app/src/form.rs`，在测试模块之前插入：

```rust
//! 未开启页的表单状态与校验。按两段连接分组：
//! 维护目标只放一体机，公司 Gateway 组含地址、出网、账号、口令。

use rmc_core::addr::HostPort;
use zeroize::Zeroizing;

#[derive(Clone, Default)]
pub struct Form {
    pub appliance_host: String,
    pub appliance_port: String,
    pub gateway_host: String,
    pub gateway_port: String,
    pub username: String,
    pub password: Zeroizing<String>,
    pub remember: bool,
    /// 自动检测的出网代理，None 表示直连。不是输入项。
    pub detected_proxy: Option<String>,
}

impl std::fmt::Debug for Form {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Form")
            .field("appliance_host", &self.appliance_host)
            .field("appliance_port", &self.appliance_port)
            .field("gateway_host", &self.gateway_host)
            .field("gateway_port", &self.gateway_port)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("remember", &self.remember)
            .field("detected_proxy", &self.detected_proxy)
            .finish()
    }
}

impl Form {
    pub fn validate(&self) -> Result<(HostPort, HostPort), Vec<&'static str>> {
        let mut errs = Vec::new();

        if self.username.trim().is_empty() {
            errs.push("请填写 Gateway 账号");
        }
        if self.password.is_empty() {
            errs.push("请填写密码");
        }

        let appliance = match self.appliance_port.parse::<u16>() {
            Ok(p) => HostPort::new(self.appliance_host.trim(), p).ok(),
            Err(_) => {
                errs.push("一体机端口必须是 1-65535 的整数");
                None
            }
        };
        if appliance.is_none() && !errs.iter().any(|e| e.contains("一体机端口")) {
            errs.push("一体机地址不合法");
        }

        let gateway = match self.gateway_port.parse::<u16>() {
            Ok(p) => HostPort::new(self.gateway_host.trim(), p).ok(),
            Err(_) => {
                errs.push("Gateway 端口必须是 1-65535 的整数");
                None
            }
        };
        if gateway.is_none() && !errs.iter().any(|e| e.contains("Gateway 端口")) {
            errs.push("Gateway 地址不合法");
        }

        if let Some(a) = appliance.as_ref() {
            if a.is_loopback() {
                errs.push("一体机地址不能指向本机");
            }
        }

        match (appliance, gateway) {
            (Some(a), Some(g)) if errs.is_empty() => Ok((a, g)),
            _ => Err(errs),
        }
    }

    pub fn can_start(&self) -> bool {
        self.validate().is_ok()
    }

    /// 认证失败后调用，只清口令，其余已填内容保留。
    pub fn clear_password(&mut self) {
        self.password = Zeroizing::new(String::new());
    }

    pub fn egress_label(&self) -> String {
        match self.detected_proxy.as_deref() {
            Some(p) => format!("经系统代理 {p}"),
            None => "直连".to_string(),
        }
    }
}
```

创建 `crates/rmc-app/src/view/maintain.rs`。结构严格照画板 `design/body-Main.html` 与 `design/body-Connected.html`：

```rust
//! 维护页。未开启时显示两个分组的表单，连接后换成链路与远程会话。

use crate::form::Form;
use crate::model::Model;
use crate::theme::color;
use crate::Message;
use iced::widget::{button, checkbox, column, container, row, text, text_input, Space};
use iced::{Alignment, Element, Length};

fn section<'a>(label: &'a str) -> Element<'a, Message> {
    text(label).size(12).color(color::TEXT_SUB).into()
}

fn card<'a>(content: Element<'a, Message>) -> Element<'a, Message> {
    container(content)
        .style(|_| container::Style {
            background: Some(color::CARD.into()),
            border: iced::Border {
                color: color::BORDER,
                width: 1.0,
                radius: 6.0.into(),
            },
            ..Default::default()
        })
        .width(Length::Fill)
        .into()
}

fn addr_row<'a>(
    label: &'a str,
    host: &'a str,
    port: &'a str,
    editable: bool,
    on_host: fn(String) -> Message,
    on_port: fn(String) -> Message,
) -> Element<'a, Message> {
    let host_input = text_input("", host).width(Length::Fill);
    let port_input = text_input("", port).width(54);
    let (host_input, port_input) = if editable {
        (host_input.on_input(on_host), port_input.on_input(on_port))
    } else {
        (host_input, port_input)
    };
    row![
        text(label).size(13).width(66),
        host_input,
        text(":").size(12).color(color::TEXT_SUB),
        port_input,
    ]
    .spacing(10)
    .align_y(Alignment::Center)
    .padding([9, 12])
    .into()
}

fn status_card<'a>(model: &Model, elapsed: Option<String>) -> Element<'a, Message> {
    let c = model.status_card();
    let mut r = row![
        container(Space::new(10, 10)).style(move |_| container::Style {
            background: Some(c.dot.into()),
            border: iced::Border { radius: 5.0.into(), ..Default::default() },
            ..Default::default()
        }),
        column![
            text(c.title.clone()).size(15),
            text(c.subtitle.clone()).size(12).color(color::TEXT_SUB),
        ]
        .spacing(1)
        .width(Length::Fill),
    ]
    .spacing(11)
    .align_y(Alignment::Center);

    if let Some(e) = elapsed {
        r = r.push(
            column![
                text(e).size(17),
                text("已连接").size(12).color(color::TEXT_SUB),
            ]
            .spacing(1)
            .align_x(Alignment::End),
        );
    }

    container(r)
        .padding([13, 14])
        .style(move |_| container::Style {
            background: Some(c.background.into()),
            border: iced::Border {
                color: color::BORDER,
                width: 1.0,
                radius: 6.0.into(),
            },
            ..Default::default()
        })
        .width(Length::Fill)
        .into()
}

fn credential_groups<'a>(form: &'a Form, editable: bool) -> Element<'a, Message> {
    let egress = row![
        text("出网").size(13).width(66),
        text(form.egress_label()).size(13),
        Space::with_width(Length::Fill),
        text("自动检测").size(12).color(color::TEXT_SUB),
    ]
    .spacing(10)
    .align_y(Alignment::Center)
    .padding([9, 12]);

    let user = text_input("", &form.username).width(Length::Fill);
    let pw = text_input("", &form.password).secure(true).width(Length::Fill);
    let (user, pw) = if editable {
        (user.on_input(Message::UsernameChanged), pw.on_input(Message::PasswordChanged))
    } else {
        (user, pw)
    };

    column![
        section("维护目标"),
        card(
            addr_row(
                "一体机",
                &form.appliance_host,
                &form.appliance_port,
                editable,
                Message::ApplianceHostChanged,
                Message::AppliancePortChanged,
            )
        ),
        section("公司 Gateway"),
        card(
            column![
                addr_row(
                    "地址",
                    &form.gateway_host,
                    &form.gateway_port,
                    editable,
                    Message::GatewayHostChanged,
                    Message::GatewayPortChanged,
                ),
                egress.into(),
                row![text("账号").size(13).width(66), user]
                    .spacing(10)
                    .align_y(Alignment::Center)
                    .padding([9, 12])
                    .into(),
                row![text("密码").size(13).width(66), pw]
                    .spacing(10)
                    .align_y(Alignment::Center)
                    .padding([9, 12])
                    .into(),
                row![
                    Space::with_width(66),
                    checkbox("记住密码", form.remember).on_toggle(Message::RememberToggled),
                    text("默认不保存，勾选后加密落盘").size(12).color(color::TEXT_SUB),
                ]
                .spacing(10)
                .align_y(Alignment::Center)
                .padding([9, 12])
                .into(),
            ]
            .into()
        ),
    ]
    .spacing(12)
    .into()
}

fn sessions<'a>(model: &Model) -> Element<'a, Message> {
    let header = row![
        text("远程会话").size(12).color(color::TEXT_SUB),
        text(format!("{} 个进行中", model.sessions.len()))
            .size(12)
            .color(color::TEXT_SUB),
    ]
    .spacing(8);

    let mut body = column![].spacing(0);
    if model.sessions.is_empty() {
        body = body.push(
            container(text("暂无远程会话").size(12).color(color::TEXT_SUB))
                .padding([13, 12])
                .center_x(Length::Fill),
        );
    } else {
        for s in &model.sessions {
            body = body.push(
                row![
                    text(format!("#{}", s.id)).size(12).color(color::TEXT_SUB).width(20),
                    column![
                        text(format!(
                            "发往一体机 {} · 来自一体机 {}",
                            human_bytes(s.to_appliance),
                            human_bytes(s.from_appliance)
                        ))
                        .size(12)
                        .color(color::TEXT_SUB),
                    ]
                    .width(Length::Fill),
                    button(text("断开").size(12))
                        .on_press(Message::DisconnectSession(s.id))
                        .padding([4, 11]),
                ]
                .spacing(10)
                .align_y(Alignment::Center)
                .padding([9, 12]),
            );
        }
    }

    column![header, card(body.into())].spacing(12).into()
}

fn human_bytes(n: u64) -> String {
    if n >= 1024 * 1024 {
        format!("{:.1} MB", n as f64 / (1024.0 * 1024.0))
    } else if n >= 1024 {
        format!("{} KB", n / 1024)
    } else {
        format!("{n} B")
    }
}

pub fn view<'a>(model: &'a Model, form: &'a Form, elapsed: Option<String>) -> Element<'a, Message> {
    let mut body = column![status_card(model, elapsed)].spacing(12).padding(14);

    if model.credentials_visible {
        body = body.push(credential_groups(form, model.addresses_editable));
    } else {
        body = body.push(sessions(model));
    }

    body = body.push(Space::with_height(Length::Fill));

    let buttons = model.buttons();
    if let Some((label, action)) = buttons.primary {
        let enabled = !matches!(action, crate::model::Action::Start) || form.can_start();
        let mut b = button(text(label).size(13)).width(Length::Fill).padding([9, 0]);
        if enabled {
            b = b.on_press(Message::ActionPressed(action));
        }
        body = body.push(b);
    }
    if let Some((label, action)) = buttons.secondary {
        body = body.push(
            button(text(label).size(13))
                .width(Length::Fill)
                .padding([9, 0])
                .on_press(Message::ActionPressed(action)),
        );
    }

    body.into()
}
```

在 `view/mod.rs` 加 `pub mod maintain;`，在 `main.rs` 加 `mod form;`，并把 `Message` 扩成：

```rust
#[derive(Debug, Clone)]
pub enum Message {
    TabSelected(Tab),
    ApplianceHostChanged(String),
    AppliancePortChanged(String),
    GatewayHostChanged(String),
    GatewayPortChanged(String),
    UsernameChanged(String),
    PasswordChanged(String),
    RememberToggled(bool),
    ActionPressed(model::Action),
    DisconnectSession(u64),
    Tick,
}
```

- [ ] **Step 4: 运行测试确认通过**

```bash
cargo test -p rmc-app
cargo build -p rmc-app
```

预期：25 passed（theme 5 + model 14 + form 11 中扣去重名，按实际数字为准），`cargo build` 成功。

- [ ] **Step 5: 提交**

```bash
git add crates/rmc-app/src/form.rs crates/rmc-app/src/view crates/rmc-app/src/main.rs
git commit -m "feat(app): 维护页表单两分组与状态渲染"
```

---

### Task 9: 诊断页与诊断包导出

**Files:**
- Create: `crates/rmc-app/src/diag.rs`
- Create: `crates/rmc-app/src/view/diagnostics.rs`
- Modify: `crates/rmc-app/src/view/mod.rs`、`crates/rmc-app/Cargo.toml`
- Test: `crates/rmc-app/src/diag.rs` 同文件测试模块

**Interfaces:**
- Consumes: rmc-core 的 `PreflightReport`、`StepOutcome`
- Produces:
  - `pub struct DiagRow { pub name: String, pub ok: Option<bool>, pub detail: String, pub highlight: bool }`
  - `pub fn rows(report: &PreflightReport, proxy: Option<&str>, host_key: Option<&(String, bool)>) -> Vec<DiagRow>`
  - `pub fn advice_for(report: &PreflightReport) -> Option<(String, String)>`：失败项的标题与处置建议
  - `pub fn bundle(dir: &Path, report: Option<&PreflightReport>, env: &str) -> std::io::Result<PathBuf>`：生成 zip，含脱敏日志与预检结果

- [ ] **Step 1: 写下失败的测试**

创建 `crates/rmc-app/src/diag.rs`，先写测试模块：

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use rmc_core::error::ErrorClass;
    use rmc_core::preflight::{PreflightReport, PreflightStep, StepOutcome, STEP_APPLIANCE_TCP, STEP_GATEWAY_TLS};

    fn report(tls: StepOutcome) -> PreflightReport {
        PreflightReport {
            steps: vec![
                PreflightStep {
                    name: STEP_APPLIANCE_TCP,
                    outcome: StepOutcome::Pass { detail: "可达 6 ms".into() },
                },
                PreflightStep { name: STEP_GATEWAY_TLS, outcome: tls },
            ],
        }
    }

    #[test]
    fn passing_steps_render_as_ok() {
        let rows = rows(&report(StepOutcome::Pass { detail: "握手成功".into() }), None, None);
        assert!(rows.iter().all(|r| r.ok == Some(true)));
        assert!(rows.iter().all(|r| !r.highlight));
    }

    #[test]
    fn failing_step_is_highlighted() {
        let rows = rows(
            &report(StepOutcome::Fail {
                detail: "证书链不受信任".into(),
                class: ErrorClass::Fatal,
            }),
            None,
            None,
        );
        let tls = rows.iter().find(|r| r.name.contains("TLS")).unwrap();
        assert_eq!(tls.ok, Some(false));
        assert!(tls.highlight);
    }

    #[test]
    fn skipped_step_has_no_verdict() {
        let rows = rows(
            &report(StepOutcome::Skipped { detail: "未执行".into() }),
            None,
            None,
        );
        let tls = rows.iter().find(|r| r.name.contains("TLS")).unwrap();
        assert_eq!(tls.ok, None);
    }

    #[test]
    fn proxy_row_is_appended_when_a_proxy_was_detected() {
        let rows = rows(
            &report(StepOutcome::Pass { detail: "握手成功".into() }),
            Some("proxy.company.com:8080"),
            None,
        );
        assert!(
            rows.iter().any(|r| r.detail.contains("proxy.company.com:8080")),
            "{rows:#?}"
        );
    }

    #[test]
    fn host_key_row_marks_first_seen() {
        let hk = ("SHA256:aaa".to_string(), true);
        let rows = rows(
            &report(StepOutcome::Pass { detail: "握手成功".into() }),
            None,
            Some(&hk),
        );
        let row = rows.iter().find(|r| r.name.contains("host key")).unwrap();
        assert!(row.detail.contains("首次记录"), "{}", row.detail);
    }

    #[test]
    fn tls_cert_failure_advice_mentions_the_audit_device() {
        let a = advice_for(&report(StepOutcome::Fail {
            detail: "Gateway TLS 证书链无效：UnknownIssuer".into(),
            class: ErrorClass::Fatal,
        }))
        .unwrap();
        assert!(a.1.contains("审计"), "{}", a.1);
        assert!(a.1.contains("放行"), "{}", a.1);
    }

    #[test]
    fn proxy_auth_failure_advice_mentions_sspi() {
        let a = advice_for(&report(StepOutcome::Fail {
            detail: "代理要求认证，协商失败：代理要求 Basic".into(),
            class: ErrorClass::Fatal,
        }))
        .unwrap();
        assert!(a.1.contains("SSPI") || a.1.contains("协商"), "{}", a.1);
    }

    #[test]
    fn no_advice_when_everything_passes() {
        assert!(advice_for(&report(StepOutcome::Pass { detail: "ok".into() })).is_none());
    }

    #[test]
    fn bundle_creates_a_zip_containing_the_report() {
        let dir = std::env::temp_dir().join(format!(
            "rmc-diag-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("rmc-2026-09-13.log"), "INFO 状态 Idle → Preflight\n").unwrap();

        let zip = bundle(
            &dir,
            Some(&report(StepOutcome::Pass { detail: "ok".into() })),
            "客户端 0.1.0",
        )
        .unwrap();
        assert!(zip.exists());
        assert!(zip.extension().unwrap() == "zip");
        assert!(std::fs::metadata(&zip).unwrap().len() > 0);
    }
}
```

- [ ] **Step 2: 运行测试确认失败**

```bash
cargo test -p rmc-app diag
```

预期：编译失败，`cannot find function rows`。

- [ ] **Step 3: 写最小实现**

在 `crates/rmc-app/Cargo.toml` 加 `zip = { version = "2", default-features = false, features = ["deflate"] }`。

创建 `crates/rmc-app/src/diag.rs`，在测试模块之前插入：

```rust
//! 诊断页的数据整理与诊断包导出。失败项单独给处置建议，
//! 现场最常见的两类问题是 TLS 审计设备拦截与代理要求认证。

use rmc_core::preflight::{PreflightReport, StepOutcome};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct DiagRow {
    pub name: String,
    /// Some(true) 通过，Some(false) 失败，None 未执行。
    pub ok: Option<bool>,
    pub detail: String,
    pub highlight: bool,
}

pub fn rows(
    report: &PreflightReport,
    proxy: Option<&str>,
    host_key: Option<&(String, bool)>,
) -> Vec<DiagRow> {
    let mut out: Vec<DiagRow> = report
        .steps
        .iter()
        .map(|s| match &s.outcome {
            StepOutcome::Pass { detail } => DiagRow {
                name: s.name.to_string(),
                ok: Some(true),
                detail: detail.clone(),
                highlight: false,
            },
            StepOutcome::Fail { detail, .. } => DiagRow {
                name: s.name.to_string(),
                ok: Some(false),
                detail: detail.clone(),
                highlight: true,
            },
            StepOutcome::Skipped { detail } => DiagRow {
                name: s.name.to_string(),
                ok: None,
                detail: detail.clone(),
                highlight: false,
            },
        })
        .collect();

    if let Some(p) = proxy {
        out.push(DiagRow {
            name: "系统代理".to_string(),
            ok: Some(true),
            detail: format!("经 {p}，代理认证走 SSPI 协商"),
            highlight: false,
        });
    }

    if let Some((fp, first_seen)) = host_key {
        out.push(DiagRow {
            name: "Gateway host key".to_string(),
            ok: Some(true),
            detail: if *first_seen {
                format!("{fp}（首次记录）")
            } else {
                format!("{fp}（与记录一致）")
            },
            highlight: false,
        });
    }

    out
}

/// 失败项对应的处置建议。返回 (标题, 正文)。
pub fn advice_for(report: &PreflightReport) -> Option<(String, String)> {
    let failure = report.first_failure()?;
    let detail = match &failure.outcome {
        StepOutcome::Fail { detail, .. } => detail.clone(),
        _ => return None,
    };

    let body = if detail.contains("证书") {
        "服务器证书不在客户端信任根中，说明客户网络存在 TLS 审计设备，流量被解密后重新签名。\
         客户端不接受企业注入的根证书，因此连接中止。请联系客户网络管理员，把 Gateway 的 \
         443 端口加入审计设备的放行名单。"
    } else if detail.contains("代理要求认证") {
        "代理要求认证且 SSPI 协商未通过。请确认这台笔记本已加入域且当前用户有出网权限；\
         若代理只支持 Basic 认证，本版本无法自动通过，需要网络管理员为 Gateway 的地址放行。"
    } else if detail.contains("host key") {
        "Gateway 的 host key 与本机记录不一致，连接已拒绝。若 Gateway 确实更换过主机密钥，\
         请联系运维确认指纹后再删除本机的 known_hosts 记录；否则本次连接可能指向了假 Gateway。"
    } else if detail.contains("一体机") {
        "一体机不可达。请确认设备已开机、sshd 在运行，以及这台笔记本仍在一体机所在网段。"
    } else if detail.contains("解析") {
        "Gateway 域名解析失败。请确认笔记本能正常出网，以及 Gateway 地址填写无误。"
    } else {
        "请把诊断包导出后交给远程工程师。"
    };

    Some((failure.name.to_string(), body.to_string()))
}

/// 打包脱敏日志与预检结果。日志本身不含口令，原样收入。
pub fn bundle(dir: &Path, report: Option<&PreflightReport>, env: &str) -> std::io::Result<PathBuf> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let out_path = dir.join(format!("rmc-diagnostics-{stamp}.zip"));
    let file = std::fs::File::create(&out_path)?;
    let mut zip = zip::ZipWriter::new(file);
    let opts: zip::write::FileOptions<'_, ()> =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    zip.start_file("environment.txt", opts)?;
    zip.write_all(env.as_bytes())?;

    if let Some(r) = report {
        zip.start_file("preflight.txt", opts)?;
        for s in &r.steps {
            let line = match &s.outcome {
                StepOutcome::Pass { detail } => format!("[通过] {} — {detail}\n", s.name),
                StepOutcome::Fail { detail, class } => {
                    format!("[失败/{class:?}] {} — {detail}\n", s.name)
                }
                StepOutcome::Skipped { detail } => format!("[未执行] {} — {detail}\n", s.name),
            };
            zip.write_all(line.as_bytes())?;
        }
    }

    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
        if !(name.starts_with("rmc-") && name.ends_with(".log")) {
            continue;
        }
        zip.start_file(format!("logs/{name}"), opts)?;
        zip.write_all(&std::fs::read(&path)?)?;
    }

    zip.finish()?;
    Ok(out_path)
}
```

创建 `crates/rmc-app/src/view/diagnostics.rs`，照画板 `design/body-Diagnostics.html` 画：状态行逐条列出 `DiagRow`，失败行底色 `#fdf2f1`、文字 `#a4262c`；下方一个处置建议卡；底部两个按钮，左为强调色的「导出诊断包」，右为「复制检查结果」；再往下一行环境信息。控件用法与 `maintain.rs` 中的 `card`、`section` 完全一致，把这两个辅助函数提到 `view/mod.rs` 供两页共用。

- [ ] **Step 4: 运行测试确认通过**

```bash
cargo test -p rmc-app diag
cargo build -p rmc-app
```

预期：9 passed。

- [ ] **Step 5: 提交**

```bash
git add crates/rmc-app/src/diag.rs crates/rmc-app/src/view crates/rmc-app/Cargo.toml
git commit -m "feat(app): 诊断页与诊断包导出"
```

---

### Task 10: 日志页与接线

**Files:**
- Create: `crates/rmc-app/src/logs.rs`
- Create: `crates/rmc-app/src/view/logs.rs`
- Create: `crates/rmc-app/src/wiring.rs`
- Modify: `crates/rmc-app/src/main.rs`
- Test: `crates/rmc-app/src/logs.rs` 同文件测试模块

**Interfaces:**
- Consumes: rmc-core 的 `Supervisor`、`Command`、`TunnelEvent`；rmc-win 的四个实现
- Produces:
  - `pub enum LogFilter { All, Info, Warn, Error }`
  - `pub struct LogLine { pub time: String, pub level: LogFilter, pub message: String }`
  - `pub fn parse_line(raw: &str) -> Option<LogLine>`
  - `pub fn tail(path: &Path, limit: usize) -> Vec<LogLine>`（限 200 条）
  - `pub fn counts(lines: &[LogLine]) -> [usize; 4]`（全部、信息、警告、错误）
  - `pub fn filter(lines: &[LogLine], f: LogFilter, query: &str) -> Vec<&LogLine>`
  - `wiring::spawn_core(cfg) -> (Sender<Command>, Receiver<TunnelEvent>)`：组装 rmc-win 的四个实现并启动 Supervisor

- [ ] **Step 1: 写下失败的测试**

创建 `crates/rmc-app/src/logs.rs`，先写测试模块：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
2026-09-13T11:12:44 INFO 预检通过，开始连接 Gateway
2026-09-13T11:12:45 INFO TLS 1.3 握手完成
2026-09-13T11:14:02 WARN 一体机首包延迟 480 ms
2026-09-13T11:52:31 ERROR Gateway 连接被重置
2026-09-13T11:52:33 WARN 反向端口 22001 仍被占用
";

    fn lines() -> Vec<LogLine> {
        SAMPLE.lines().filter_map(parse_line).collect()
    }

    #[test]
    fn parses_time_level_and_message() {
        let l = parse_line("2026-09-13T11:12:44 INFO 预检通过").unwrap();
        assert_eq!(l.time, "11:12:44");
        assert_eq!(l.level, LogFilter::Info);
        assert_eq!(l.message, "预检通过");
    }

    #[test]
    fn parses_all_three_levels() {
        assert_eq!(parse_line("2026-09-13T1:1:1 WARN x").unwrap().level, LogFilter::Warn);
        assert_eq!(parse_line("2026-09-13T1:1:1 ERROR x").unwrap().level, LogFilter::Error);
    }

    #[test]
    fn rejects_malformed_lines() {
        assert!(parse_line("").is_none());
        assert!(parse_line("no timestamp here").is_none());
        assert!(parse_line("2026-09-13T11:12:44").is_none());
    }

    #[test]
    fn counts_cover_all_four_chips() {
        let c = counts(&lines());
        assert_eq!(c, [5, 2, 2, 1], "全部/信息/警告/错误");
    }

    #[test]
    fn filter_all_returns_everything() {
        let l = lines();
        assert_eq!(filter(&l, LogFilter::All, "").len(), 5);
    }

    #[test]
    fn filter_by_level() {
        let l = lines();
        assert_eq!(filter(&l, LogFilter::Warn, "").len(), 2);
        assert_eq!(filter(&l, LogFilter::Error, "").len(), 1);
    }

    #[test]
    fn filter_by_query_is_case_insensitive_substring() {
        let l = lines();
        assert_eq!(filter(&l, LogFilter::All, "tls").len(), 1);
        assert_eq!(filter(&l, LogFilter::All, "端口").len(), 1);
    }

    #[test]
    fn filter_combines_level_and_query() {
        let l = lines();
        assert_eq!(filter(&l, LogFilter::Warn, "端口").len(), 1);
        assert_eq!(filter(&l, LogFilter::Info, "端口").len(), 0);
    }

    #[test]
    fn tail_returns_the_last_lines_in_order_and_caps_at_the_limit() {
        let dir = std::env::temp_dir().join(format!(
            "rmc-logs-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rmc-2026-09-13.log");
        let many: String = (0..500)
            .map(|i| format!("2026-09-13T11:00:00 INFO 第 {i} 行\n"))
            .collect();
        std::fs::write(&path, many).unwrap();

        let got = tail(&path, 200);
        assert_eq!(got.len(), 200);
        assert!(got.first().unwrap().message.contains("第 300 行"));
        assert!(got.last().unwrap().message.contains("第 499 行"));
    }

    #[test]
    fn tail_on_missing_file_is_empty() {
        assert!(tail(std::path::Path::new("/nonexistent/rmc.log"), 200).is_empty());
    }
}
```

- [ ] **Step 2: 运行测试确认失败**

```bash
cargo test -p rmc-app logs
```

预期：编译失败，`cannot find type LogLine`。

- [ ] **Step 3: 写最小实现**

创建 `crates/rmc-app/src/logs.rs`，在测试模块之前插入：

```rust
//! 日志页的数据。默认显示最近 200 条，四个筛选标签都带计数。

use std::path::Path;

pub const TAIL_LIMIT: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFilter {
    All,
    Info,
    Warn,
    Error,
}

impl LogFilter {
    pub fn label(&self) -> &'static str {
        match self {
            LogFilter::All => "全部",
            LogFilter::Info => "信息",
            LogFilter::Warn => "警告",
            LogFilter::Error => "错误",
        }
    }

    pub const ALL: [LogFilter; 4] =
        [LogFilter::All, LogFilter::Info, LogFilter::Warn, LogFilter::Error];
}

#[derive(Debug, Clone)]
pub struct LogLine {
    pub time: String,
    pub level: LogFilter,
    pub message: String,
}

/// 解析 audit.rs 写出的一行：`2026-09-13T11:12:44 INFO 消息`。
pub fn parse_line(raw: &str) -> Option<LogLine> {
    let mut parts = raw.splitn(3, ' ');
    let stamp = parts.next()?;
    let level_str = parts.next()?;
    let message = parts.next()?.trim();
    if message.is_empty() {
        return None;
    }
    let time = stamp.split_once('T')?.1.to_string();
    if time.is_empty() {
        return None;
    }
    let level = match level_str {
        "INFO" => LogFilter::Info,
        "WARN" => LogFilter::Warn,
        "ERROR" => LogFilter::Error,
        _ => return None,
    };
    Some(LogLine { time, level, message: message.to_string() })
}

/// 读取文件末尾若干行。文件缺失或不可读时返回空。
pub fn tail(path: &Path, limit: usize) -> Vec<LogLine> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let all: Vec<LogLine> = text.lines().filter_map(parse_line).collect();
    let start = all.len().saturating_sub(limit);
    all[start..].to_vec()
}

/// 返回 [全部, 信息, 警告, 错误]。
pub fn counts(lines: &[LogLine]) -> [usize; 4] {
    let mut c = [lines.len(), 0, 0, 0];
    for l in lines {
        match l.level {
            LogFilter::Info => c[1] += 1,
            LogFilter::Warn => c[2] += 1,
            LogFilter::Error => c[3] += 1,
            LogFilter::All => {}
        }
    }
    c
}

pub fn filter<'a>(lines: &'a [LogLine], f: LogFilter, query: &str) -> Vec<&'a LogLine> {
    let q = query.trim().to_lowercase();
    lines
        .iter()
        .filter(|l| f == LogFilter::All || l.level == f)
        .filter(|l| q.is_empty() || l.message.to_lowercase().contains(&q))
        .collect()
}
```

创建 `crates/rmc-app/src/view/logs.rs`，照画板 `design/body-Logs.html` 画：顶部四个带计数的胶囊标签加一个搜索框，中间等宽字体的日志列表（警告行底色 `#fdf9ea`、错误行 `#fdf2f1`），底部一行「最近 200 条 · 文件名 · 保留 30 天」与「打开日志目录」按钮。

创建 `crates/rmc-app/src/wiring.rs`：

```rust
//! 把 rmc-win 的平台实现装进 rmc-core 的 Supervisor。
//! 非 Windows 上用 core 自带的空实现，便于在 Linux 跑界面。

use rmc_core::config::Config;
use rmc_core::knownhosts::KnownHosts;
use rmc_core::ssh::SshTunnelFactory;
use rmc_core::state::{Command, TunnelEvent};
use rmc_core::supervisor::{Deps, Supervisor};
use rmc_core::transport::tls::TlsRoots;
use rmc_core::transport::Transport;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};

pub fn spawn_core(cfg: Config) -> (mpsc::Sender<Command>, broadcast::Receiver<TunnelEvent>) {
    #[cfg(windows)]
    let (resolver, authenticator, events) = {
        use rmc_win::events::{spawn_win32_listeners, EventHub};
        use rmc_win::proxy::{winhttp::WinHttpSource, SystemProxyResolver};
        use rmc_win::sspi::{NegotiateContext, SspiProxyAuthenticator};

        let hub = Arc::new(EventHub::new());
        spawn_win32_listeners(hub.clone());
        let auth = SspiProxyAuthenticator::new(|scheme: &str| {
            // SPN 用代理主机名，由 Windows 自行解析当前用户凭据。
            NegotiateContext::new(&format!("HTTP/{scheme}"))
                .map(|c| Box::new(c) as Box<dyn rmc_win::sspi::SspiContext>)
        });
        (
            Arc::new(SystemProxyResolver::new(WinHttpSource)) as Arc<_>,
            Arc::new(auth) as Arc<_>,
            hub as Arc<_>,
        )
    };

    #[cfg(not(windows))]
    let (resolver, authenticator, events) = {
        use rmc_core::platform::{NoProxy, NoProxyAuth, NoSystemEvents};
        (
            Arc::new(NoProxy) as Arc<_>,
            Arc::new(NoProxyAuth) as Arc<_>,
            Arc::new(NoSystemEvents::default()) as Arc<_>,
        )
    };

    let transport = Arc::new(Transport::new(resolver, authenticator, TlsRoots::webpki()));
    let known_hosts = Arc::new(KnownHosts::open(cfg.known_hosts_path.clone()));
    let factory = Arc::new(SshTunnelFactory::new(
        transport.clone(),
        known_hosts,
        cfg.gateway.clone(),
    ));

    Supervisor::spawn(
        cfg,
        Deps {
            factory,
            transport,
            events,
            jitter: || Box::new(rmc_core::backoff::RandJitter),
        },
    )
}
```

在 `main.rs` 里把 `App` 扩成持有 `Model`、`Form`、当前页签、日志缓存与 `Sender<Command>`，`update` 按 `Message` 分发：地址与账号输入写回 `Form`；`ActionPressed(Action::Start)` 校验表单后发 `Command::Start`；`Action::Stop`/`Cancel`/`RetryNow` 各发对应命令；`DisconnectSession(id)` 发 `Command::DisconnectRemoteSession`；`Tick` 每秒刷新已连接时长并重读日志尾部。用 `iced::Subscription` 把 `broadcast::Receiver<TunnelEvent>` 与每秒的 `Tick` 合并成消息流。认证失败时 core 会把状态推回 `Idle`，此时调用 `form.clear_password()`。

- [ ] **Step 4: 运行测试确认通过**

```bash
cargo test -p rmc-app
cargo build -p rmc-app
```

预期：全部通过，`cargo build` 成功；在 Linux 上 `cargo run -p rmc-app` 能起窗口（平台能力为空实现）。

- [ ] **Step 5: 提交**

```bash
git add crates/rmc-app/src
git commit -m "feat(app): 日志页与界面到内核的接线"
```

---

### Task 11: 托盘与通知

**Files:**
- Create: `crates/rmc-app/src/tray.rs`
- Modify: `crates/rmc-app/src/main.rs`
- Test: `crates/rmc-app/src/tray.rs` 同文件测试模块

**Interfaces:**
- Consumes: Task 7 的 `Model::status_card`
- Produces:
  - `pub fn tooltip(model: &Model) -> String`
  - `pub fn icon_color(model: &Model) -> iced::Color`
  - `pub fn notification_for(prev: &State, next: &State, sessions_delta: i64) -> Option<(String, String)>`
  - `#[cfg(windows)] pub struct Tray`，`Tray::new() -> Option<Self>`，`Tray::update(&self, model: &Model)`

- [ ] **Step 1: 写下失败的测试**

创建 `crates/rmc-app/src/tray.rs`，先写测试模块：

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme::color;
    use rmc_core::error::ErrorClass;
    use rmc_core::state::State;
    use std::time::Duration;

    fn model_in(s: State) -> Model {
        let mut m = Model::default();
        m.apply(rmc_core::state::TunnelEvent::State(s));
        m
    }

    #[test]
    fn tooltip_names_the_state() {
        assert!(tooltip(&model_in(State::Idle)).contains("未开启"));
        assert!(tooltip(&model_in(State::Connected { degraded: false })).contains("已连接"));
    }

    #[test]
    fn icon_color_tracks_the_state() {
        assert_eq!(icon_color(&model_in(State::Idle)), color::IDLE);
        assert_eq!(
            icon_color(&model_in(State::Connected { degraded: true })),
            color::DEGRADED
        );
    }

    #[test]
    fn session_opened_triggers_a_notification() {
        let n = notification_for(
            &State::Connected { degraded: false },
            &State::Connected { degraded: false },
            1,
        )
        .unwrap();
        assert!(n.1.contains("远程会话"), "{}", n.1);
    }

    #[test]
    fn session_closed_triggers_a_notification() {
        let n = notification_for(
            &State::Connected { degraded: false },
            &State::Connected { degraded: false },
            -1,
        )
        .unwrap();
        assert!(n.1.contains("结束") || n.1.contains("关闭"), "{}", n.1);
    }

    #[test]
    fn entering_degraded_notifies() {
        let n = notification_for(
            &State::Connected { degraded: false },
            &State::Connected { degraded: true },
            0,
        )
        .unwrap();
        assert!(n.0.contains("一体机"), "{}", n.0);
    }

    #[test]
    fn entering_failed_notifies() {
        let n = notification_for(
            &State::Connecting,
            &State::Failed { class: ErrorClass::Fatal, message: "host key 不一致".into() },
            0,
        )
        .unwrap();
        assert!(n.1.contains("host key"), "{}", n.1);
    }

    #[test]
    fn backoff_does_not_notify() {
        // 网络抖动很常见，弹通知会骚扰现场人员。
        assert!(notification_for(
            &State::Connected { degraded: false },
            &State::Backoff { attempt: 1, delay: Duration::from_secs(1) },
            0,
        )
        .is_none());
    }

    #[test]
    fn unchanged_state_without_session_change_does_not_notify() {
        assert!(notification_for(&State::Idle, &State::Idle, 0).is_none());
    }
}
```

- [ ] **Step 2: 运行测试确认失败**

```bash
cargo test -p rmc-app tray
```

预期：编译失败，`cannot find function tooltip`。

- [ ] **Step 3: 写最小实现**

创建 `crates/rmc-app/src/tray.rs`，在测试模块之前插入：

```rust
//! 托盘提示与系统通知。只在真正需要现场人员知道时弹通知：
//! 远程会话起止、一体机不可达、连接失败。重连不弹。

use crate::model::Model;
use rmc_core::state::State;

pub fn tooltip(model: &Model) -> String {
    let c = model.status_card();
    format!("Remote Maintenance — {}", c.title)
}

pub fn icon_color(model: &Model) -> iced::Color {
    model.status_card().dot
}

/// 返回 (标题, 正文)。无需通知时返回 None。
pub fn notification_for(
    prev: &State,
    next: &State,
    sessions_delta: i64,
) -> Option<(String, String)> {
    if sessions_delta > 0 {
        return Some((
            "远程维护".to_string(),
            format!("有 {sessions_delta} 个远程会话已连入一体机"),
        ));
    }
    if sessions_delta < 0 {
        return Some((
            "远程维护".to_string(),
            format!("{} 个远程会话已结束", -sessions_delta),
        ));
    }

    match (prev, next) {
        (State::Connected { degraded: false }, State::Connected { degraded: true }) => Some((
            "一体机不可达".to_string(),
            "隧道正常，但连不上一体机，请检查设备与网段".to_string(),
        )),
        (State::Connected { degraded: true }, State::Connected { degraded: false }) => {
            Some(("一体机已恢复".to_string(), "一体机重新可达".to_string()))
        }
        (p, State::Failed { message, .. }) if !matches!(p, State::Failed { .. }) => {
            Some(("远程维护失败".to_string(), message.clone()))
        }
        _ => None,
    }
}

#[cfg(windows)]
mod win {
    //! tray-icon 的托盘实现。图标用纯色圆点，按状态换色。

    use super::{icon_color, tooltip};
    use crate::model::Model;
    use tray_icon::{TrayIcon, TrayIconBuilder};

    pub struct Tray(TrayIcon);

    fn dot_icon(c: iced::Color) -> Option<tray_icon::Icon> {
        const N: u32 = 16;
        let mut rgba = Vec::with_capacity((N * N * 4) as usize);
        let cx = (N as f32 - 1.0) / 2.0;
        for y in 0..N {
            for x in 0..N {
                let dx = x as f32 - cx;
                let dy = y as f32 - cx;
                let inside = dx * dx + dy * dy <= (cx - 1.0) * (cx - 1.0);
                if inside {
                    rgba.extend_from_slice(&[
                        (c.r * 255.0) as u8,
                        (c.g * 255.0) as u8,
                        (c.b * 255.0) as u8,
                        255,
                    ]);
                } else {
                    rgba.extend_from_slice(&[0, 0, 0, 0]);
                }
            }
        }
        tray_icon::Icon::from_rgba(rgba, N, N).ok()
    }

    impl Tray {
        pub fn new() -> Option<Self> {
            let icon = dot_icon(crate::theme::color::IDLE)?;
            TrayIconBuilder::new()
                .with_tooltip("Remote Maintenance — 未开启")
                .with_icon(icon)
                .build()
                .ok()
                .map(Tray)
        }

        pub fn update(&self, model: &Model) {
            if let Some(icon) = dot_icon(icon_color(model)) {
                let _ = self.0.set_icon(Some(icon));
            }
            let _ = self.0.set_tooltip(Some(tooltip(model)));
        }
    }
}

#[cfg(windows)]
pub use win::Tray;
```

在 `main.rs` 里持有 `Option<Tray>`，每次 `Model` 变化后调用 `update`；把上一次的 `State` 与会话数存起来，调用 `notification_for` 并在 Windows 上用 tray-icon 的通知能力弹出。

- [ ] **Step 4: 运行测试确认通过**

```bash
cargo test -p rmc-app tray
```

预期：8 passed。

Windows 人工验收：连接成功后让远程工程师连入，托盘应变绿并弹出会话连入通知；停掉一体机 sshd，托盘变橙并弹出一体机不可达；拔网线，托盘变黄但不应弹通知。

- [ ] **Step 5: 提交**

```bash
git add crates/rmc-app/src/tray.rs crates/rmc-app/src/main.rs
git commit -m "feat(app): 托盘状态色与系统通知"
```

---

### Task 12: 打包、签名与 CI

**Files:**
- Create: `.github/workflows/app.yml`
- Create: `crates/rmc-app/build.rs`
- Create: `crates/rmc-app/rmc.manifest`
- Create: `docs/windows-验收清单.md`
- Modify: `crates/rmc-app/Cargo.toml`、根 `Cargo.toml`

**Interfaces:**
- Consumes: 前十一个任务
- Produces: CI 工作流 `app`，产出 `rmc.exe` 便携包

- [ ] **Step 1: 写下清单与构建脚本**

创建 `crates/rmc-app/rmc.manifest`：

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <!-- 明确声明不需要管理员权限，避免 UAC 提权提示 -->
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
      <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
    </windowsSettings>
  </application>
</assembly>
```

创建 `crates/rmc-app/build.rs`：

```rust
fn main() {
    #[cfg(windows)]
    {
        // 嵌入清单，声明 asInvoker 与 PerMonitorV2 DPI。
        println!("cargo:rerun-if-changed=rmc.manifest");
        let mut res = winres::WindowsResource::new();
        res.set_manifest_file("rmc.manifest");
        res.set("FileDescription", "Remote Maintenance Client");
        res.set("ProductName", "Remote Maintenance Client");
        if let Err(e) = res.compile() {
            println!("cargo:warning=嵌入清单失败：{e}");
        }
    }
}
```

在 `crates/rmc-app/Cargo.toml` 加：

```toml
[target.'cfg(windows)'.build-dependencies]
winres = "0.1"
```

根 `Cargo.toml` 加发布配置：

```toml
[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
panic = "abort"
strip = true
```

创建 `.github/workflows/app.yml`：

```yaml
name: app

on:
  push:
    paths: ["crates/**", "Cargo.*", ".github/workflows/app.yml"]
  pull_request:
    paths: ["crates/**", "Cargo.*", ".github/workflows/app.yml"]

jobs:
  linux-checks:
    runs-on: ubuntu-24.04
    timeout-minutes: 25
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@1.82
        with:
          components: rustfmt, clippy
      - uses: Swatinem/rust-cache@v2
      - name: 安装 iced 的系统依赖
        run: |
          sudo apt-get update
          sudo apt-get install -y libxkbcommon-dev libwayland-dev pkg-config
      - run: cargo fmt --all -- --check
      - run: cargo clippy -p rmc-win -p rmc-app --all-targets -- -D warnings
      - run: cargo test -p rmc-win -p rmc-app

  windows-build:
    runs-on: windows-2022
    timeout-minutes: 35
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@1.82
        with:
          components: clippy
      - uses: Swatinem/rust-cache@v2
      - run: cargo clippy -p rmc-win -p rmc-app --all-targets -- -D warnings
      - run: cargo test -p rmc-win -p rmc-app
      - run: cargo build --release -p rmc-app

      - name: 确认不需要管理员权限
        shell: pwsh
        run: |
          $exe = "target/release/rmc.exe"
          if (-not (Test-Path $exe)) { throw "没有产出 $exe" }
          $size = (Get-Item $exe).Length
          Write-Host "rmc.exe 大小 $([math]::Round($size/1MB,1)) MB"
          # 清单里必须是 asInvoker
          $text = Get-Content $exe -Raw -Encoding Byte | ForEach-Object { [char]$_ }
          if (-not ($text -join '' ).Contains('asInvoker')) { throw "清单未嵌入 asInvoker" }

      - uses: actions/upload-artifact@v4
        with:
          name: rmc-portable
          path: target/release/rmc.exe
```

签名不在 CI 做，证书不进仓库。发布流程：从 CI 下载 `rmc-portable`，在持有代码签名证书的机器上执行

```
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a rmc.exe
signtool verify /pa /v rmc.exe
```

- [ ] **Step 2: 本地跑一遍 CI 的命令**

```bash
cargo fmt --all -- --check
cargo clippy -p rmc-win -p rmc-app --all-targets -- -D warnings
cargo test -p rmc-win -p rmc-app
```

预期：全部通过。

- [ ] **Step 3: 写 Windows 人工验收清单**

创建 `docs/windows-验收清单.md`：

```markdown
# Windows 人工验收清单

自动化测试覆盖不到的部分，每次发版在真实 Windows 机器上逐项走一遍。
每项记录机型、Windows 版本与结果。

## 环境与外观

- [ ] 双击 `rmc.exe` 直接启动，没有 UAC 提权提示。
- [ ] 窗口为 520×720，不能拖动改变大小，没有最大化按钮。
- [ ] 在 125% 与 150% 缩放下文字不模糊、不截断。
- [ ] 在 RDP 会话中启动成功（wgpu 不可用时应回落到软件渲染）。
- [ ] 在没有独立显卡驱动的虚拟机中启动成功。
- [ ] 重复启动第二个实例时，已有窗口被置前，不出现两个窗口。

## 未开启页

- [ ] 两个分组顺序为：维护目标、公司 Gateway。
- [ ] 维护目标里只有一体机，地址与端口是两个输入框。
- [ ] 公司 Gateway 里依次是地址加端口、出网、账号、密码、记住密码。
- [ ] 出网一行带勾号与「自动检测」，不可编辑；无代理时显示直连。
- [ ] 账号或密码为空时「开启远程维护」按钮不可点。
- [ ] 页面上没有任何会话时长上限或倒计时。

## 连接流程

- [ ] 预检四项逐项变绿，状态卡为蓝色。
- [ ] 连接成功后凭据区隐藏，地址锁定，状态卡变绿。
- [ ] 已连接时长每秒递增，旁边没有「剩余」字样。
- [ ] 远程工程师连入后，列表出现一条会话并显示双向流量。
- [ ] 点某条会话的「断开」，只有那一条断开，隧道与其他会话不受影响。
- [ ] 点「停止远程维护」后回到未开启，Gateway 上的端口立即释放。

## 异常路径

- [ ] 密码填错：回到未开启，密码框清空，其余已填内容保留，不自动重试。
- [ ] 停掉一体机 sshd：状态卡变橙，文案为一体机不可达，隧道保持。
- [ ] 恢复一体机 sshd：橙色自动回到绿色。
- [ ] 拔网线：状态卡变黄显示第 n 次重连，不弹通知。
- [ ] 插回网线：立即重连而不是等满退避。
- [ ] 合盖休眠再唤醒：几秒内恢复已连接，日志有休眠恢复记录。
- [ ] 改掉 Gateway host key 后重连：状态卡变红，文案指出 host key 不一致，不重试。
- [ ] 任务管理器强杀进程：Gateway 上约 30 秒内回收端口，无残留连接。

## 企业网络

- [ ] 系统代理为静态代理：出网一行显示该代理，连接成功。
- [ ] 系统代理为 PAC：出网一行显示 PAC 求值出的代理，连接成功。
- [ ] 代理要求 Negotiate 认证：无需输入任何代理凭据即连接成功，诊断页「代理认证（SSPI Negotiate）」为通过。
- [ ] 代理只支持 Basic 认证：诊断页明确显示代理要求认证且协商失败，不是连接超时。
- [ ] 客户网络有 TLS 审计设备：诊断页显示证书链不受信任，并给出放行名单的处置建议。

## 凭据与日志

- [ ] 不勾记住密码：重开客户端后密码框为空。
- [ ] 勾记住密码：重开客户端后密码框自动填上。
- [ ] 换另一个 Windows 账号登录同机打开：密码框为空且不报错。
- [ ] 日志页四个标签都带计数，搜索能过滤。
- [ ] 在日志文件里搜索刚用过的密码，必须搜不到。
- [ ] 导出诊断包：zip 能打开，含 environment.txt、preflight.txt 与 logs 目录。

## 托盘

- [ ] 托盘图标颜色与状态卡一致。
- [ ] 远程会话连入与结束各弹一次通知。
- [ ] 一体机不可达弹通知，重连中不弹。
```

- [ ] **Step 4: 推分支验证 CI**

```bash
git push -u origin HEAD
gh run watch
```

预期：`app` 的两个 job 全绿，产物里有 `rmc.exe`。

- [ ] **Step 5: 提交**

```bash
git add .github/workflows/app.yml crates/rmc-app/build.rs crates/rmc-app/rmc.manifest \
        crates/rmc-app/Cargo.toml Cargo.toml docs/windows-验收清单.md
git commit -m "ci(app): Windows 构建产物、清单与人工验收清单"
```

---

## 自检

**规格覆盖**

| 方案条目 | 对应任务 |
|---|---|
| 3.1 iced 与软件渲染回落 | Task 6 |
| 3.1 托盘 | Task 11 |
| 3.2 rmc-win 与 rmc-app 划分 | Task 1、6 |
| 3.9 单实例 | Task 1 |
| 3.9 电源与网络事件 | Task 5 |
| 3.9 系统代理与 PAC | Task 2 |
| 3.9 SSPI 代理认证 | Task 3 |
| 3.9 不需要管理员权限 | Task 12 的清单与 CI 断言 |
| 3.9 Authenticode 签名 | Task 12 |
| 3.8 记住密码用 DPAPI | Task 4 |
| 3.10 三页签与两分组表单 | Task 6、8 |
| 3.10 六个状态渲染 | Task 7、8 |
| 3.10 诊断页与导出诊断包 | Task 9 |
| 3.10 日志页 | Task 10 |
| 画板中的出网一行 | Task 8 的 `egress_label` 与验收清单 |

**刻意留给人工验收的部分**

Win32 调用本身无法在 CI 里断言，因此 `winhttp.rs`、`sspi.rs` 的 `NegotiateContext`、`events.rs` 的两个监听器、`secret.rs` 的 `DpapiSealer`、`tray.rs` 的 `Tray` 都只有解析与推进逻辑被单元测试覆盖，OS 交互靠 `docs/windows-验收清单.md` 守。评审时应确认每个 Win32 模块都在清单里有对应条目。
