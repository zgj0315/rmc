//! 电源与网络事件。笔记本从休眠唤醒、或者从网线切到 Wi-Fi 之后，
//! rmc-core 的 Supervisor 收到一条事件就清零退避计时并立刻重连
//! （`supervisor.rs` 里 `Ok(event) = sys.recv()` 那一支），而不是傻等
//! 上一次失败算出的退避时间走完。
//!
//! 事件是**瞬时信号**：用 `tokio::sync::broadcast` 发布，不做缓存、
//! 不做重放。收不到订阅者就静默丢弃——没人等着这条事件时，它本来
//! 也不该改变任何人的行为。
//!
//! # 两层划分（本 crate 的约定，见 `lib.rs` 的模块文档）
//!
//! `lib.rs` 的模块文档里点名的反例字面就是这个模块会犯的那个错：
//! 「不要把纯逻辑（例如**某个防抖计时器该不该触发**、某个图标该画哪个
//! 像素）也关进 `#[cfg(windows)]` 里」。本任务的初版设计恰恰把
//! [`Debouncer`] 整个建在 `#[cfg(windows)] mod win` 里面，于是它在这台
//! macOS 上一行都不编译、一条测试都跑不到（W73）。这是同一个坑在这个
//! crate 里的第四次：Task 2 栽了两轮（`autoproxy_flags`、
//! `dwAccessType`），Task 3 是 `imp.rs` 的状态分类块，Task 5 是它。
//!
//! 所以这个文件里：
//!
//! - **纯逻辑**（不带 `#[cfg(windows)]`，macOS 上原生可测）：
//!   [`EventHub`]、[`Debouncer`]、[`ConnectivityWatcher`]、
//!   [`PowerGate`]、[`PowerCallbackState`]、[`install`]、
//!   [`register_once`]、[`is_resume_event`]、[`debounce_ms`]。
//!   「窗口内第二次事件该不该发」「一次连通性读数算不算变化」「哪个
//!   `PBT_*` 码才算唤醒」「注册与占格子谁先谁后」这四条判断**全部**在
//!   这一层，下面的测试模块就是在这台机器上跑的。
//! - **Win32**：只有 `win` 子模块整块 `#[cfg(windows)]`，职责只到
//!   「注册通知 / 轮询读数 / 把结果转成普通 Rust 值再交给上面那几条
//!   判断」为止，自己不做任何判断。
//!
//! 修复轮 1 的 W84 是这个约定在**本模块内部**的第二次栽跟头：上一轮
//! 网络那一路做对了（[`ConnectivityWatcher::observe`]），电源那一路的
//! 同构判断（`is_resume_event(..) && debounce.allow_at(..)`）却整个留在
//! `win` 的回调体里，六道闸门对它的两个反向变异一个字都没说。现在它是
//! [`PowerGate::on_event`]。
//!
//! # 时刻是参数，不是 `Instant::now()`（W74）
//!
//! [`Debouncer::allow_at`] 与 [`ConnectivityWatcher::observe`] 都把
//! 「现在几点」当参数收进来，而不是自己去调 `Instant::now()`。理由是
//! 上移之后还得测得动：`#[tokio::test(start_paused = true)]` 控制的是
//! `tokio::time::Instant`，**管不着 `std::time::Instant`**——rmc-core
//! 的 R92 在 `SystemTime` 上学过同一课，当时的解法就是「把时刻显式喂
//! 进去」。真正的 `Instant::now()` 只出现在 `win` 子模块的两个调用点，
//! 各一行。
//!
//! # 关于轮询线程没有停止方式（W83，本任务不处理）
//!
//! `win::poll_network` 用「每 2 秒读一次 NLM 连通性」代替 COM 事件接收
//! （`INetworkListManagerEvents` 要一个 STA 消息循环和一个
//! `#[implement]` 的 COM 对象，unsafe 面积大出一个量级）。这个取舍本身
//! 是合算的，但代价要写明白：**那个线程没有任何停止方式**，进程活多久
//! 它就每 2 秒醒一次多久，笔记本上这是一个永不停歇的定时唤醒。Task 10
//! 接线时再评估要不要给它一个关闭通道（以及要不要在已连接状态下降低
//! 频率）——现在不为此加复杂度，只把账记在这里。

use rmc_core::platform::{SystemEvent, SystemEvents};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

/// 网络状态抖动时的合并窗口，毫秒。
///
/// 800ms 是两头挤出来的：太长会拖慢现场恢复（工程师盯着界面等重连），
/// 太短会在网卡切换时连发多次——插拔网线、Wi-Fi 重新关联的过程里
/// NLM 的连通性读数会在几百毫秒内翻几次，每一次都触发一次立即重连的
/// 话，Supervisor 那边就是连着几次「清零退避、马上重连」。
pub fn debounce_ms() -> u64 {
    800
}

/// `win::poll_network` 的轮询间隔。放在纯逻辑层只是为了让上面那段
/// W83 的说明和实际数值待在一起，不会一个改了另一个没改。
pub const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// [`EventHub`] 内部 `broadcast` 通道的容量（W88）。
///
/// 抽成常量的理由跟 [`POLL_INTERVAL`] 一样：让「这个数是多少」可以被
/// 测试钉住。上一轮这个 16 是写死在 `broadcast::channel(16)` 里的字面
/// 量，改成 1 六道闸门全绿。
///
/// **改小的后果不是丢一条事件，而是一次静默的降级**：`broadcast` 在
/// 接收端落后于发送端时返回 `RecvError::Lagged`，而 Supervisor 那边
/// （`supervisor.rs` 的 `Ok(event) = sys.recv()`）把 `Err` 整支丢掉、
/// 一个字都不记（W94，与 W82 同一笔账，Task 10 一起处理）。也就是说
/// 容量不够时，现场表现是「唤醒之后偶尔不重连」，而日志里什么都没有。
///
/// 16 的来历：同时在飞的事件最多是「唤醒 + 网络变化」两条，16 是给
/// 「订阅者被别的任务挡住一会儿」留的余量，不是一个精算出来的数。
pub const EVENT_CHANNEL_CAPACITY: usize = 16;

// 区间守在编译期而不是写成一条 `#[test]`（同 Task 4 `MAX_SCHEME_CHARS`
// 的先例：钉的是「有界且不小」这条性质，具体数值是可调产品参数）。
//
// 写成 `assert!(EVENT_CHANNEL_CAPACITY >= 8)` 放进测试模块是行不通的，
// 实测被 clippy 的 `assertions_on_constants` 拦下：条件整个可以常量折叠，
// 那条断言会被编译器优化掉，是一条**假的**测试。换成 `const _: () =`
// 之后语义更强——数被改小连编译都过不去，闸门 1 就是红的。
const _: () = assert!(
    EVENT_CHANNEL_CAPACITY >= 8,
    "容量被改小的表现是 Lagged，而 Supervisor 那边对 Err 零日志（W94）"
);

// =====================================================================
// 事件总线
// =====================================================================

/// 系统事件的发布端。实现 rmc-core 的
/// [`SystemEvents`](rmc_core::platform::SystemEvents)，`subscribe` 每次
/// 给一个独立的接收端。
pub struct EventHub {
    tx: broadcast::Sender<SystemEvent>,
}

impl EventHub {
    pub fn new() -> Self {
        Self {
            tx: broadcast::channel(EVENT_CHANNEL_CAPACITY).0,
        }
    }

    /// 发一条事件。供 Win32 回调与测试注入。
    ///
    /// **无人订阅时静默丢弃**：`broadcast::Sender::send` 在没有接收端时
    /// 返回 `Err`，这里故意吞掉。客户端在 Supervisor 起来之前、或者在
    /// 用户主动断开之后，本来就没有人等这条事件；那种时候一条
    /// 「唤醒了」既没有收件人，也不该让发送方（一个 `extern "system"`
    /// 的电源回调）看见任何错误——见 `win::on_power_event` 上关于
    /// panic 不能跨 FFI 边界的那段。
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

// =====================================================================
// 防抖（纯逻辑）
// =====================================================================

/// 中毒了也把里面的值拿出来接着用。
///
/// W20.2 的形状第三次出现（`winhttp.rs`、`sspi.rs` 各一处）。**这里比
/// 那两处更重**：这把锁是在 `extern "system"` 的电源回调里取的。
/// `lock().unwrap()` 在一次中毒之后会让**此后每一次**唤醒回调 panic，
/// 而 panic 跨过 FFI 边界不是「这次事件丢了」——`extern "system"` 没有
/// `-unwind` 后缀，Rust（1.81 起）把穿过它的展开变成一次 abort，也就是
/// 整个客户端进程当场死掉。现场表现是「合盖再打开，托盘图标没了」。
///
/// `win::on_power_event` 外面还包了一层 `catch_unwind`，所以就算真写成
/// `unwrap()`，默认配置下也未必立刻死进程——但那只是把后果换成「此后
/// 每一次唤醒都被吞掉」，一个不报错的哑巴。两处都要对，这里是根治的
/// 那一处。
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// 合并窗口内的重复事件只发一次。
///
/// 语义有一条容易写反、也确实值得单独钉住的：**窗口从「上一次放行」
/// 算起，不是从「上一次尝试」算起**。被挡掉的那一次不更新时间戳——
/// 否则一串间隔 700ms 的抖动会让时间戳一直往前挪，第一条之后**再也
/// 没有**事件能出去，网卡持续抖动时客户端就彻底聋了。见
/// `the_window_runs_from_the_last_allowed_event_not_the_last_attempt`。
pub struct Debouncer {
    last: Mutex<Option<Instant>>,
    window: Duration,
}

impl Debouncer {
    /// 用 [`debounce_ms`] 的窗口。
    pub fn new() -> Self {
        Self::with_window(Duration::from_millis(debounce_ms()))
    }

    /// 自定义窗口。测试用，也让「窗口多长」这件事在类型上是一个值、
    /// 不是一个藏在函数体里的常量。
    pub fn with_window(window: Duration) -> Self {
        Self {
            last: Mutex::new(None),
            window,
        }
    }

    /// 这一刻的事件该不该放行。
    ///
    /// `now` 是参数不是 `Instant::now()`，理由见模块文档的 W74 一节。
    ///
    /// 整个函数体是 panic-free 的，这是它被电源回调调用的前提条件：
    /// - 取锁用上面那个容忍中毒的 [`lock`]；
    /// - 时间差用 `saturating_duration_since` 而不是 `duration_since`
    ///   ——后者在 `now < t` 时的行为随标准库版本变过（早期 panic，
    ///   1.60 起饱和到零），而这里的 `now` 来自调用方，模块自己不该
    ///   依赖一个「看版本」的语义。
    pub fn allow_at(&self, now: Instant) -> bool {
        let mut last = lock(&self.last);
        match *last {
            Some(t) if now.saturating_duration_since(t) < self.window => false,
            _ => {
                *last = Some(now);
                true
            }
        }
    }

    /// 把这把锁弄成中毒状态，只给测试用。
    ///
    /// 在**当前线程**里持锁 panic，再用 `catch_unwind` 接住：`MutexGuard`
    /// 的 `Drop` 在展开途中看到 `thread::panicking()` 为真就会置中毒位，
    /// 所以不需要另起线程。
    #[cfg(test)]
    fn poison_for_test(&self) {
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = self.last.lock().expect("测试开始时这把锁还没中毒");
            panic!("故意 panic，把这把锁弄中毒");
        }));
        std::panic::set_hook(hook);
        assert!(r.is_err(), "这个辅助函数本身必须真的 panic 过一次");
        assert!(self.last.is_poisoned(), "panic 之后这把锁应该已经中毒");
    }
}

impl Default for Debouncer {
    fn default() -> Self {
        Self::new()
    }
}

// =====================================================================
// 连通性变化（纯逻辑）
// =====================================================================

/// 一次连通性读数算不算「变了」。
///
/// **首次观测永远不算**（W79）：第一次读到一个连通性值只说明「程序刚
/// 起来，现在是这个状态」，不说明网络刚刚发生过什么。把它算成变化，
/// 客户端每次启动都会在轮询线程转第二圈时白发一条 `NetworkChanged`。
fn is_change(previous: Option<i32>, current: i32) -> bool {
    matches!(previous, Some(p) if p != current)
}

/// 把「上一次读数是多少 + 这次算不算变化 + 防抖放不放行」三件事合在
/// 一起，让 Win32 那边的轮询循环退化成「读一个数 → 问一句 → 要么发要么
/// 不发」。
pub struct ConnectivityWatcher {
    previous: Option<i32>,
    debounce: Debouncer,
}

impl ConnectivityWatcher {
    pub fn new() -> Self {
        Self {
            previous: None,
            debounce: Debouncer::new(),
        }
    }

    /// 读到一个连通性值，回答「该不该发 `NetworkChanged`」。
    ///
    /// `current` 是 `NLM_CONNECTIVITY` 的裸 `i32`：这一层不需要知道
    /// 那些位的含义，只需要知道「跟上次比变没变」。
    ///
    /// 两个门是**串联**的，而且顺序有意义：先问变没变，变了才去问防抖。
    /// 反过来（先记防抖、再看变化）会让一串「没变」的读数把防抖的时间戳
    /// 一直刷新，真的变化来了反而被自己挡掉。
    ///
    /// `previous` 无论放不放行都要更新——放行与否是给外面看的结论，
    /// 「上次读到什么」是事实。
    pub fn observe(&mut self, current: i32, now: Instant) -> bool {
        let changed = is_change(self.previous, current);
        self.previous = Some(current);
        changed && self.debounce.allow_at(now)
    }
}

impl Default for ConnectivityWatcher {
    fn default() -> Self {
        Self::new()
    }
}

// =====================================================================
// 电源事件码（纯逻辑）
// =====================================================================

/// 与 `windows::Win32::UI::WindowsAndMessaging::PBT_APMRESUMEAUTOMATIC`
/// 数值相同。
///
/// 重新声明成普通 `u32` 的理由跟 `proxy::AUTOPROXY_AUTO_DETECT` 一样：
/// [`is_resume_event`] 要在非 Windows 平台上编译、跑表驱动测试，而
/// `windows` crate 整个只在 `[target.'cfg(windows)'.dependencies]` 里，
/// macOS 上这个符号根本不存在。`win` 子模块里有 `const _: () =
/// assert!(...)` 核对两份数值不会漂移。
pub const PBT_RESUME_AUTOMATIC: u32 = 18;
/// 同上，对应 `PBT_APMRESUMESUSPEND`。**不**算唤醒信号，见
/// [`is_resume_event`]。
pub const PBT_RESUME_SUSPEND: u32 = 7;
/// 同上，对应 `PBT_APMSUSPEND`（要睡了，不是醒了）。
pub const PBT_SUSPEND: u32 = 4;

/// 这个 `PBT_*` 码算不算「刚从休眠里醒过来」。
///
/// 只认 `PBT_APMRESUMEAUTOMATIC`。`PowerRegisterSuspendResumeNotification`
/// 注册的回调会收到 `PBT_APMSUSPEND`（要睡了）、
/// `PBT_APMRESUMESUSPEND`（醒了，而且是用户操作唤醒的）、
/// `PBT_APMRESUMEAUTOMATIC`（醒了，任何原因）三种。三者里只有
/// `PBT_APMRESUMEAUTOMATIC` 是**每次**唤醒都发的——
/// `PBT_APMRESUMESUSPEND` 只在「用户按键唤醒」时跟着发一条，合盖打开
/// 之外的唤醒（定时任务、网卡唤醒）根本没有它。所以认它一个就够，多认
/// 一个只会在用户手动唤醒时多来一条，白白挤掉防抖窗口。
///
/// `PBT_APMSUSPEND` 尤其不能认：那是「即将进入休眠」，此刻去重连只会
/// 在网络已经开始塌的时候多打一次徒劳的连接。
pub fn is_resume_event(event_type: u32) -> bool {
    event_type == PBT_RESUME_AUTOMATIC
}

/// 把「这个码算不算唤醒 + 防抖放不放行」两件事合在一起，让电源回调
/// 退化成「问一句 → 要么发要么不发」。
///
/// # 为什么它必须在这一层（W84）
///
/// 上一轮网络那一路做对了（[`ConnectivityWatcher::observe`]），电源这
/// 一路的同构判断却整个留在了 `#[cfg(windows)] mod win` 的回调体里，
/// 于是它在这台 macOS 上一行都编译不到。评审两枪实测、六道闸门全绿：
///
/// - 把 `if !is_resume_event(..)` 的 `!` 去掉——**真唤醒（18）时什么都
///   不发，而「即将休眠」（4）和 `PBT_POWERSETTINGCHANGE`（32787）反而
///   各发一条 `ResumedFromSleep`**，正好是本任务需求的反面；
/// - 把防抖门的结果丢掉改成 `if true`——窗口内连发。
///
/// 这是 `lib.rs` 模块文档点名禁止的那件事在这个 crate 里的**第四次**，
/// 也是本模块内部的第二次。现在它跟 `observe` 是同一个形状。
pub struct PowerGate {
    debounce: Debouncer,
}

impl PowerGate {
    /// 用 [`debounce_ms`] 的窗口。
    pub fn new() -> Self {
        Self {
            debounce: Debouncer::new(),
        }
    }

    /// 自定义窗口，测试用。
    pub fn with_window(window: Duration) -> Self {
        Self {
            debounce: Debouncer::with_window(window),
        }
    }

    /// 收到一个 `PBT_*` 码，回答「该不该发 `ResumedFromSleep`」。
    ///
    /// 两个门是**串联**的，而且顺序跟 [`ConnectivityWatcher::observe`]
    /// 里一样有意义：先问算不算唤醒，算了才去问防抖。反过来的话，
    /// 「即将休眠」「电源方案变了」这些跟唤醒无关的码会一路刷新防抖
    /// 时间戳——合盖前系统会连发好几条 `PBT_*`，紧接着的那次真唤醒就
    /// 被自己挡掉了。
    ///
    /// `now` 是参数不是 `Instant::now()`，理由见模块文档的 W74 一节。
    /// 整个函数体是 panic-free 的，这是它被 `extern "system"` 回调调用
    /// 的前提条件（见 `win::on_power_event` 的 W75 一段）。
    pub fn on_event(&self, event_type: u32, now: Instant) -> bool {
        is_resume_event(event_type) && self.debounce.allow_at(now)
    }
}

impl Default for PowerGate {
    fn default() -> Self {
        Self::new()
    }
}

// =====================================================================
// 电源回调的进程级状态（纯逻辑，W85/W86）
// =====================================================================

/// 电源回调要用的两样东西**合成一个**（W76）。
///
/// 原先是 `HUB` 与 `DEBOUNCE` 两个独立的 `OnceLock`，回调里写
/// `if let (Some(hub), Some(d)) = (HUB.get(), DEBOUNCE.get())` 去兜
/// 「一个设了另一个没设」这种半截状态。合成一个之后那种状态在类型上
/// 就不可表达了，回调里也只剩一次 `get()`。
///
/// 它住在纯逻辑层而不是 `win` 里（W85）：两个字段都是纯类型，
/// [`install`] 又把格子本身**当参数收**——这正是 W74 对 `Instant` 用过
/// 的同一招。上一轮的取舍是「`OnceLock` 是进程级 static，为它造抽象是
/// 过度设计」，代价是 W76 那条修复零覆盖，而评审实测把 `.is_err()` 改成
/// `.is_ok()`（语义翻成「第一次注册跳过、第二次才注册」，休眠恢复整个
/// 不工作）六道闸门全绿。
pub struct PowerCallbackState {
    hub: std::sync::Arc<EventHub>,
    gate: PowerGate,
}

impl PowerCallbackState {
    /// 回调唯一要做的事：问一句闸，放行就发。
    ///
    /// 放在这里而不是让调用方写 `if state.gate.on_event(..) {
    /// state.hub.emit(..) }`，是因为两个字段都是私有的；顺带让
    /// `win` 那边的回调体里一条判断都不剩。
    ///
    /// 返回值只给测试看，产品代码忽略它。
    pub fn on_power_event(&self, event_type: u32, now: Instant) -> bool {
        let allow = self.gate.on_event(event_type, now);
        if allow {
            self.hub.emit(SystemEvent::ResumedFromSleep);
        }
        allow
    }
}

/// 把回调要用的状态装进格子，返回「本次是不是真的装进去了」。
///
/// `false` 表示格子已经被占住——此前已经注册过一次，第二个 `hub` 在
/// 这里被丢弃，事件仍然发往首次注册的那个总线。调用方必须**看**这个
/// 返回值并记一条日志：静默丢弃的后果是界面上「唤醒后没反应」而日志
/// 里一个字都没有。
///
/// 格子当参数传，所以测试可以 `new` 一个本地 `OnceLock` 真跑两遍，
/// 不需要任何 mock，也不需要在 macOS 上编译 Win32。
pub(crate) fn install(
    cell: &std::sync::OnceLock<PowerCallbackState>,
    hub: std::sync::Arc<EventHub>,
) -> bool {
    cell.set(PowerCallbackState {
        hub,
        gate: PowerGate::new(),
    })
    .is_ok()
}

/// 「还没注册过就注册一次，注册成功了才占格子」——把这个**顺序**也放进
/// 纯逻辑层（W86）。
///
/// 返回 `Ok(true)` 表示本次真的注册并装好了，`Ok(false)` 表示此前已经
/// 注册过、`register` 一次都没被调用，`Err` 表示注册失败——**失败时格子
/// 保持空**，所以将来任何一条重试路径还能再试一次。
///
/// # 为什么这个顺序值得单独抽出来
///
/// 上一轮的写法是先 `POWER.set(..)` 再做 Win32 注册，于是 `.ok()?` 提前
/// 返回时格子**已经被占住**：将来的重试会在「已经注册过吗」那一步直接
/// 跳过并返回 `Ok(())`——休眠恢复功能永久关闭，而调用方拿到的是成功。
/// 这正好是 W76 想堵的那个形状的镜像，也正好是 `lib.rs` 模块文档禁止的
/// 那件事（把一条判断关进 `#[cfg(windows)]`）的又一次：写在 `win` 里的
/// 顺序，在这台机器上一行都测不到。
///
/// `register` 当参数收进来（同 W74 对 `Instant`、W85 对格子的那一招），
/// 测试于是可以喂一个「第一次失败、第二次成功」的闭包，在 macOS 上真跑
/// 完整的重试序列，不需要任何 Win32。
///
/// # 一个明知的、小的代价
///
/// 注册已经生效、格子还空着，中间有几微秒。此刻真有一次唤醒打进来的
/// 话，回调里 `OnceLock::get()` 返回 `None`，这一条事件被丢。后果是
/// 「这一次唤醒不立刻重连，退避序列兜底」；而上面那个半截状态的后果是
/// 「此后永远不重连」。两害相权，取这一头。
///
/// **这个窗口是可以彻底消掉的，只是不值得现在返工。**
/// `DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS` 有一个 `Context: *mut c_void`
/// 字段，系统会把它原样回传给回调的第一个参数（现在那个参数叫
/// `_context`，被直接扔掉）。把状态 `Box::leak` 成 `'static` 塞进
/// `Context`，状态就在注册**之前**已经存在，系统只可能在注册成功
/// **之后**用那个指针调回调——没有格子、没有顺序、也就没有窗口。
/// 纯逻辑层一个字不用改。代价是丢掉 `OnceLock` 兼职的「重复注册探测」，
/// 得另配一个 `AtomicBool`。Task 10 接线时再定。
pub fn register_once<E>(
    cell: &std::sync::OnceLock<PowerCallbackState>,
    hub: std::sync::Arc<EventHub>,
    register: impl FnOnce() -> Result<(), E>,
) -> Result<bool, E> {
    if cell.get().is_some() {
        return Ok(false);
    }
    register()?;
    Ok(install(cell, hub))
}

// =====================================================================
// Win32
// =====================================================================

#[cfg(windows)]
mod win {
    //! 休眠恢复用 `PowerRegisterSuspendResumeNotification`（回调式，
    //! 不需要窗口、不需要消息循环）；网络变化用 NLM 的连通性轮询。
    //!
    //! 这个模块在本机（macOS）上整块被 `#[cfg(windows)]` 切掉，一行
    //! 测试都跑不到；两条闸门是 `cargo zigbuild --target
    //! x86_64-pc-windows-gnu` 与同目标的 clippy。它里面**没有任何判断**
    //! ——「算不算唤醒」「算不算变化」「防抖放不放行」三条全在
    //! [`super`] 的纯逻辑层，在这台机器上被测到。
    #![allow(unsafe_code)]

    use super::{ConnectivityWatcher, EventHub, PowerCallbackState};
    use rmc_core::platform::SystemEvent;
    use std::sync::{Arc, OnceLock};
    use std::time::Instant;
    use windows::Win32::UI::WindowsAndMessaging::{
        PBT_APMRESUMEAUTOMATIC, PBT_APMRESUMESUSPEND, PBT_APMSUSPEND,
    };

    // 三个数值在纯逻辑层重新声明了一份（`is_resume_event` 要在 macOS 上
    // 跑表驱动测试），这里用编译期断言守住两份不漂移——形状同
    // `proxy/winhttp.rs` 里那几条。
    const _: () = assert!(super::PBT_RESUME_AUTOMATIC == PBT_APMRESUMEAUTOMATIC);
    const _: () = assert!(super::PBT_RESUME_SUSPEND == PBT_APMRESUMESUSPEND);
    const _: () = assert!(super::PBT_SUSPEND == PBT_APMSUSPEND);

    /// 电源回调的进程级状态。类型与 [`super::install`] 都在纯逻辑层，
    /// 这里只剩这一个格子（W85）。
    static POWER: OnceLock<PowerCallbackState> = OnceLock::new();

    /// 注册两类通知。失败只记日志，不影响其余功能：没有事件时客户端仍
    /// 会按退避序列重连，只是恢复慢一些。
    pub fn spawn_win32_listeners(hub: Arc<EventHub>) {
        let power_hub = Arc::clone(&hub);
        std::thread::spawn(move || {
            if let Err(e) = register_power(power_hub) {
                tracing::warn!(error = %e, "注册休眠恢复通知失败，恢复后将依赖退避重连");
            }
        });
        std::thread::spawn(move || {
            if let Err(e) = poll_network(hub) {
                tracing::warn!(error = %e, "网络连通性轮询启动失败，切网后将依赖退避重连");
            }
        });
    }

    /// 系统在任意一个线程池线程上调用它。
    ///
    /// # panic 与 FFI 边界（W75）
    ///
    /// 这个函数体里的 panic **不是**「丢一次事件」，而是整个客户端进程
    /// 当场 abort：`extern "system"` 没有 `-unwind` 后缀，Rust 不允许
    /// 展开穿过它。两道防线一起上，理由如下：
    ///
    /// 1. **函数体本身 panic-free**，这是真正的保证：
    ///    [`super::PowerGate::on_event`] 里的 [`super::Debouncer`] 容忍锁
    ///    中毒、用饱和减法，[`EventHub::emit`] 吞掉「没有订阅者」，
    ///    比较、`OnceLock::get` 都不会 panic。
    /// 2. **外面再包一层 `catch_unwind`**，这是保险不是保证：
    ///    - 它挡不住 `panic = "abort"`（Task 10 的 app crate 如果那样
    ///      配置，这一层就是装饰品）；
    ///    - 但在默认的 unwind 配置下，它把「将来某次改动在这个回调里
    ///      写进一个 `unwrap()`」的代价从「客户端进程死掉」降到「丢一次
    ///      唤醒事件，下一次退避重连兜底」。
    ///    - 而且这个回调体里确实有**两段代码不归本模块管**（W89）：
    ///      1. `tracing::info!` ——展开成一次 `Subscriber` 分发，而
    ///         subscriber 是**用户在 `main` 里装的**（Task 10 的 app
    ///         crate，以及任何嵌入本 crate 的人）。这是这个回调里最现实
    ///         的外部 panic 源：自定义 layer、文件 appender 写盘失败、
    ///         格式化实现里的一个 `unwrap()` 都会从这一行 panic 出来。
    ///         Task 3 的 W56 在托盘回调上刚刚认定过同一件事。
    ///      2. `emit` 最终会去唤醒订阅者注册的 waker，那是 tokio 与上层
    ///         任务的代码。（`broadcast` 自己的内部锁是容忍中毒的，
    ///         这一点查过。）
    ///
    ///    这两段都不在本模块的 panic-free 保证范围内，**正因如此第二道
    ///    防线是对的**，不是冗余。
    ///
    /// 返回 0（`ERROR_SUCCESS`）——这个回调的返回值文档要求成功时返回它。
    unsafe extern "system" fn on_power_event(
        _context: *const std::ffi::c_void,
        event_type: u32,
        _setting: *const std::ffi::c_void,
    ) -> u32 {
        // 闭包只捕获 `event_type: u32`（`Copy`，天然 `UnwindSafe`），
        // `POWER` 是 static、不算捕获，所以不需要 `AssertUnwindSafe`。
        //
        // W84：这里**一条判断都没有**——「算不算唤醒」「防抖放不放行」
        // 全在 `PowerCallbackState::on_power_event` 里，在 macOS 上被测。
        let _ = std::panic::catch_unwind(|| {
            if let Some(state) = POWER.get() {
                if state.on_power_event(event_type, Instant::now()) {
                    tracing::info!("检测到休眠恢复，立即重连");
                }
            }
        });
        0
    }

    /// 注册休眠恢复回调。
    ///
    /// # 这个线程注册完就退出（W78）
    ///
    /// `DEVICE_NOTIFY_CALLBACK` 方式注册的回调**由系统线程调用**，不走
    /// 窗口消息，因此不需要消息循环；回调要用的东西又都在 `POWER` 这个
    /// static 里，跟哪个线程注册的没有关系。原先这里挂一句
    /// `loop { std::thread::park(); }` 让线程永远活着——那是一个没有任何
    /// 用途的常驻线程（一个 stack、一个内核线程对象），纯泄漏。注册完
    /// 返回，线程就地退出。
    fn register_power(hub: Arc<EventHub>) -> windows::core::Result<()> {
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::Power::{
            PowerRegisterSuspendResumeNotification, DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS,
        };
        use windows::Win32::UI::WindowsAndMessaging::DEVICE_NOTIFY_CALLBACK;

        // 整个「还没注册过就注册一次、注册成功了才占格子」的顺序在
        // `super::register_once` 里（W86），这里只负责那一次 Win32 调用
        // 本身——本模块不做任何判断，见模块头。
        //
        // W76：`OnceLock::set` 在已经设过时返回 `Err`，原先被 `let _` 吞
        // 掉。真被调用两次的话（Task 10 接线、或者将来加一条「重新注册」
        // 的路径），第二个 hub 会被**静默丢弃**，事件全发给第一个 hub，
        // 界面上表现为「唤醒后没反应」而日志里一个字都没有。
        //
        // 这里既不静默、也不接着往下注册第二个 Win32 通知：注册两次的
        // 后果是每次唤醒回调被叫两遍，而两遍用的是同一个防抖器，第二遍
        // 必然被挡——也就是说第二次注册除了多占一个内核对象什么也不做。
        let installed = super::register_once(&POWER, hub, || {
            // 参数结构体 `Box::leak` 成 `'static`，不是图省事：MSDN 没有
            // 承诺 `PowerRegisterSuspendResumeNotification` 会在返回前把
            // 这个结构体拷走。放在栈上、函数一返回就失效，是在赌一个没人
            // 写下来的实现细节；而这个函数现在**确实会返回**（见上面 W78
            // 那段），赌输的表现是系统拿着一个悬垂指针去取回调地址。
            // 一次、16 字节的泄漏，换掉这个赌局，划算。
            //
            // 泄漏发生在闭包里，也就是**只在真的要注册时**才发生：已经
            // 注册过而跳过的那条路径一个字节都不漏。
            let params: &'static DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS =
                Box::leak(Box::new(DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS {
                    Callback: Some(on_power_event),
                    Context: std::ptr::null_mut(),
                }));

            let mut registration: *mut std::ffi::c_void = std::ptr::null_mut();
            // SAFETY: `DEVICE_NOTIFY_CALLBACK` 这个 flag 要求 `recipient`
            // 指向一个 `DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS`，`params` 正是
            // 它、而且是 `'static` 的；`registration` 是本闭包的局部变量，
            // `&mut` 借用在调用期间有效，API 只往里写一个句柄。
            unsafe {
                PowerRegisterSuspendResumeNotification(
                    DEVICE_NOTIFY_CALLBACK,
                    HANDLE(
                        params as *const DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS
                            as *mut std::ffi::c_void,
                    ),
                    &mut registration,
                )
            }
            .ok()?;

            // W77：原先这里是 `std::mem::forget(registration)`，配一句注释
            // 「句柄随进程存活，故意不注销」。查过 `windows` 0.62.2 之后：
            //
            // - 这个函数的出参在 0.62.2 里根本不是 `HPOWERNOTIFY`，而是裸
            //   的 `*mut c_void`（签名：`registrationhandle: *mut *mut c_void`）；
            // - 就算是 `HPOWERNOTIFY`，那也是
            //   `#[repr(transparent)] struct HPOWERNOTIFY(pub isize)` + `derive(Copy)`，
            //   **没有 `Drop` 实现**。它只实现 `windows_core::Free`，而
            //   `Free` 只有经过 `windows_core::Owned<T>` 包装才会在 `Drop`
            //   里被调用。（而且 `HPOWERNOTIFY::free` 调的是
            //   `UnregisterPowerSettingNotification`，跟 suspend/resume
            //   订阅根本不是一回事——将来想用 `Owned<HPOWERNOTIFY>` 来
            //   「正确地」管这个句柄也是错的。）
            //
            // 两条合起来：`mem::forget` 在这里是彻底的空操作，那句注释在
            // 骗下一个读代码的人——它让人以为「不 forget 就会注销」。
            // （`Copy` 类型上的 `mem::forget` 还会触发 rustc 的
            // `forgetting_copy_types` 警告，在 `-D warnings` 的 clippy 闸门
            // 下直接是编译失败。）
            //
            // 真正为真的事实只有一条，写在这里：**我们故意永不调用
            // `PowerUnregisterSuspendResumeNotification`**。订阅要活到进程
            // 结束，没有「取消订阅」的产品路径；句柄随进程一起消失。
            let _ = registration;
            // 错误类型显式写出来：闭包体里只有 `.ok()?` 一个来源，而
            // `windows::core::Error` 两头都有一堆 `From` 实现，编译器在
            // 这里推不出 `E`（E0282/E0283，闸门 5 实测）。
            Ok::<(), windows::core::Error>(())
        })?;

        if !installed {
            tracing::warn!("休眠恢复通知已经注册过，本次跳过；事件仍然发往首次注册的事件总线");
        }
        Ok(())
    }

    /// 每 [`super::POLL_INTERVAL`] 读一次 NLM 连通性，变化时发事件。
    ///
    /// 这个循环没有出口，线程活到进程结束——见模块文档的 W83 一节，
    /// Task 10 接线时再评估要不要给它关闭通道。
    fn poll_network(hub: Arc<EventHub>) -> windows::core::Result<()> {
        // NLM 的 COM 事件接收（`INetworkListManagerEvents`）需要一个 STA
        // 消息循环和一个 `#[implement]` 的 COM 对象。为了把 unsafe 面积
        // 压到最小，这里用轮询代替。
        use windows::Win32::Networking::NetworkListManager::{
            INetworkListManager, NetworkListManager,
        };
        use windows::Win32::System::Com::{
            CoCreateInstance, CoInitializeEx, CLSCTX_ALL, COINIT_APARTMENTTHREADED,
        };

        // SAFETY: 本线程自己的 COM 初始化，之后本线程只在这里用 COM。
        // 返回 `S_FALSE`（本线程已初始化过）也算成功，`ok()` 认这一点。
        unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }.ok()?;
        // SAFETY: CLSID 取自 `windows` crate 的常量，不聚合（`None`）。
        let nlm: INetworkListManager =
            unsafe { CoCreateInstance(&NetworkListManager, None, CLSCTX_ALL) }?;

        let mut watcher = ConnectivityWatcher::new();
        loop {
            // SAFETY: `nlm` 是上面成功创建、本线程独占的接口指针。
            // 读失败（网络栈正在重启之类）这一轮就跳过，`watcher` 的
            // `previous` 保持不动——下一轮读到的值仍然跟**变化之前**那个
            // 值比较，不会因为中间漏了一拍就把一次真实变化吞掉。
            if let Ok(current) = unsafe { nlm.GetConnectivity() } {
                if watcher.observe(current.0, Instant::now()) {
                    tracing::info!("检测到网络连通性变化，立即重连");
                    hub.emit(SystemEvent::NetworkChanged);
                }
            }
            std::thread::sleep(super::POLL_INTERVAL);
        }
    }
}

#[cfg(windows)]
pub use win::spawn_win32_listeners;

#[cfg(test)]
mod tests {
    use super::*;
    use rmc_core::platform::{SystemEvent, SystemEvents};
    use std::sync::{Arc, OnceLock};
    use tokio::sync::broadcast::error::TryRecvError;

    // -----------------------------------------------------------------
    // 事件总线
    //
    // 诚实分类（见 task-5-report.md「哪些测试钉的是我的代码」一节）：
    // 这一组里 `two_subscribers_both_receive` 与
    // `late_subscriber_does_not_see_earlier_events` 钉的主要是
    // `tokio::sync::broadcast` 的语义（扇出、从当前 tail 开始收），换成
    // 任何一个基于 broadcast 的实现都会绿。留着它们是因为它们钉住了
    // **选型**：哪天有人把 `broadcast` 换成 `watch` 或 `mpsc`，这两条会
    // 立刻变红。
    // -----------------------------------------------------------------

    /// 在**被唤醒的等待者**身上取一条事件，而且失败时是红不是挂。
    ///
    /// 变异实测出来的一条纪律：直接写 `rx.recv().await`，一旦实现退化
    /// 成「`emit` 什么也不发」，这条测试不会变红，它会**永远挂住**——
    /// 发送端还活着，`recv()` 就没有理由返回。挂住的测试在 CI 上是一个
    /// 超时，不是一条「哪里错了」。
    ///
    /// 包一层 `timeout` 就变成红的。**这个超时不花任何真实时间**，跟
    /// W81 改掉的那个 200ms 不是一回事：那一个是在断言「没有事件」，
    /// 超时是它的**成功路径**，每跑一次都要烧满；这一个是在断言「有
    /// 事件」，超时是它的**失败路径**，实现正确时 `recv()` 立刻就绪。
    ///
    /// 用真实的 `recv().await` 而不是 `try_recv()`，是为了仍然走到产品
    /// 里那条路径：Supervisor 是在 `select!` 里 await `sys.recv()` 的，
    /// 「等待者会被唤醒」跟「值确实进了通道」不是同一件事。
    async fn recv_soon(rx: &mut broadcast::Receiver<SystemEvent>) -> SystemEvent {
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("事件应当已经发出，等待者应当被唤醒")
            .expect("事件总线不该在这里关闭")
    }

    #[tokio::test]
    async fn subscriber_receives_an_emitted_event() {
        let hub = Arc::new(EventHub::new());
        let mut rx = hub.subscribe();
        hub.emit(SystemEvent::NetworkChanged);
        assert_eq!(recv_soon(&mut rx).await, SystemEvent::NetworkChanged);
    }

    #[tokio::test]
    async fn two_subscribers_both_receive() {
        let hub = Arc::new(EventHub::new());
        let mut a = hub.subscribe();
        let mut b = hub.subscribe();
        hub.emit(SystemEvent::ResumedFromSleep);
        assert_eq!(recv_soon(&mut a).await, SystemEvent::ResumedFromSleep);
        assert_eq!(recv_soon(&mut b).await, SystemEvent::ResumedFromSleep);
    }

    #[tokio::test]
    async fn emitting_once_delivers_exactly_one_event() {
        // W87：上一轮「`emit` 发且**只**发一条」没有任何测试——评审的
        // 探针（`emit` 里把 `send` 写两遍）20 passed 全绿。多发一条在
        // 产品里就是 Supervisor 多清一次退避、多打一次连接。
        let hub = Arc::new(EventHub::new());
        let mut rx = hub.subscribe();
        hub.emit(SystemEvent::NetworkChanged);
        assert_eq!(recv_soon(&mut rx).await, SystemEvent::NetworkChanged);
        assert_eq!(
            rx.try_recv(),
            Err(TryRecvError::Empty),
            "一次 emit 只该在通道里留下一条"
        );
    }

    #[tokio::test]
    async fn a_channel_full_of_events_reaches_a_subscriber_that_has_not_polled_yet() {
        // 上一条钉常量本身，这一条钉 `EventHub` 真的用了它——把
        // `broadcast::channel(EVENT_CHANNEL_CAPACITY)` 换回
        // `channel(1)`，这条变红（第一次 `recv` 就是 `Lagged`）。
        let hub = Arc::new(EventHub::new());
        let mut rx = hub.subscribe();
        for _ in 0..EVENT_CHANNEL_CAPACITY {
            hub.emit(SystemEvent::NetworkChanged);
        }
        for i in 0..EVENT_CHANNEL_CAPACITY {
            assert_eq!(
                recv_soon(&mut rx).await,
                SystemEvent::NetworkChanged,
                "第 {i} 条应当还在通道里，没有被挤掉"
            );
        }
    }

    #[tokio::test]
    async fn emitting_with_no_subscriber_does_not_panic() {
        // 这一条钉的是 `emit` 里那个 `let _ =`：电源回调在 Supervisor
        // 起来之前就可能开火，那时没有任何订阅者。把 `let _ =` 换成
        // `.unwrap()`，这条立刻变红——而在产品里那一下就是进程 abort。
        let hub = EventHub::new();
        hub.emit(SystemEvent::NetworkChanged);
    }

    #[tokio::test]
    async fn late_subscriber_does_not_see_earlier_events() {
        // 事件是瞬时信号，迟到的订阅者不该收到历史事件而触发多余重连。
        //
        // W81：原先这里烧 200ms 真实时间等一个 `timeout` 超时。
        // `try_recv()` 立刻返回 `Empty`，既快又严格——「超时」只能证明
        // 200ms 内没来，`Empty` 证明的是此刻通道里确实什么都没有。
        let hub = Arc::new(EventHub::new());
        hub.emit(SystemEvent::NetworkChanged);
        let mut rx = hub.subscribe();
        assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
    }

    #[test]
    fn debounce_is_under_one_second() {
        // 太长会拖慢现场恢复，太短会在网卡切换时连发多次。
        assert!((300..=1000).contains(&debounce_ms()));
    }

    // -----------------------------------------------------------------
    // 防抖（W73/W74/W80：这一组钉的全是本模块自己的代码）
    //
    // 时刻一律显式构造：`#[tokio::test(start_paused = true)]` 控制的是
    // `tokio::time::Instant`，管不着这里用的 `std::time::Instant`
    // （rmc-core 的 R92 在 `SystemTime` 上踩过这个坑）。
    // -----------------------------------------------------------------

    /// 一个固定的起点，加上偏移用。
    fn t0() -> Instant {
        Instant::now()
    }

    #[test]
    fn the_first_event_is_always_allowed() {
        let d = Debouncer::with_window(Duration::from_millis(800));
        assert!(d.allow_at(t0()));
    }

    #[test]
    fn a_second_event_inside_the_window_is_suppressed() {
        // 这就是 W80 说的那件「以前零覆盖」的事：窗口内两次事件只发
        // 一次。把 `allow_at` 改成恒返回 `true`，这条变红。
        let base = t0();
        let d = Debouncer::with_window(Duration::from_millis(800));
        assert!(d.allow_at(base), "第一条应当放行");
        assert!(
            !d.allow_at(base + Duration::from_millis(799)),
            "窗口内的第二条应当被挡掉"
        );
    }

    #[test]
    fn an_event_after_the_window_is_allowed_again() {
        // 反向：防抖不能变成「一辈子只发一条」。把 `allow_at` 改成恒
        // 返回 `false`，这条变红。
        let base = t0();
        let d = Debouncer::with_window(Duration::from_millis(800));
        assert!(d.allow_at(base));
        assert!(d.allow_at(base + Duration::from_millis(801)));
    }

    #[test]
    fn an_event_exactly_at_the_window_boundary_is_allowed() {
        // 钉住 `<` 而不是 `<=`：窗口是「这么久之内」，到点即出。
        // 把 `<` 改成 `<=`，这条变红。
        let base = t0();
        let d = Debouncer::with_window(Duration::from_millis(800));
        assert!(d.allow_at(base));
        assert!(d.allow_at(base + Duration::from_millis(800)));
    }

    #[test]
    fn the_window_runs_from_the_last_allowed_event_not_the_last_attempt() {
        // 被挡掉的那一次**不能**更新时间戳。否则一串间隔 700ms 的抖动
        // 会把时间戳一路往前推，第一条之后再也没有事件出得去——网卡
        // 持续抖动时客户端就彻底聋了。
        //
        // 把 `allow_at` 的 `false` 分支也改成写 `*last = Some(now)`，
        // 这条变红（第 1600ms 那次会被挡）。
        let base = t0();
        let d = Debouncer::with_window(Duration::from_millis(800));
        assert!(d.allow_at(base), "0ms：放行");
        assert!(
            !d.allow_at(base + Duration::from_millis(700)),
            "700ms：挡掉"
        );
        assert!(
            !d.allow_at(base + Duration::from_millis(790)),
            "790ms：仍在第一次放行的窗口内，挡掉"
        );
        assert!(
            d.allow_at(base + Duration::from_millis(801)),
            "801ms：距离**上一次放行**已经超过窗口，放行"
        );
    }

    #[test]
    fn a_poisoned_debouncer_still_lets_later_events_through() {
        // W75：这把锁是在 `extern "system"` 回调里取的，一次中毒用
        // `lock().unwrap()` 就是此后每次唤醒都 abort 掉整个客户端。
        // 把 `lock()` 里的 `unwrap_or_else(|e| e.into_inner())` 换回
        // `unwrap()`，这条变红（而且是 panic，不是断言失败）。
        let d = Debouncer::with_window(Duration::from_millis(800));
        d.poison_for_test();
        assert!(d.allow_at(t0()), "中毒之后仍然要能放行");
    }

    #[test]
    fn a_debouncer_built_from_the_product_constant_uses_that_window() {
        // `Debouncer::new()` 真的用了 `debounce_ms()`，不是另一个写死的
        // 数。把 `new()` 改成 `with_window(Duration::from_millis(1))`，
        // 这条变红。
        let d = Debouncer::new();
        let base = t0();
        assert!(d.allow_at(base));
        assert!(!d.allow_at(base + Duration::from_millis(debounce_ms() - 1)));
        assert!(d.allow_at(base + Duration::from_millis(debounce_ms())));
    }

    // -----------------------------------------------------------------
    // 连通性变化（W79）
    // -----------------------------------------------------------------

    #[test]
    fn a_connectivity_reading_counts_as_a_change_only_against_a_previous_one() {
        // 表驱动。第一行是 W79 的正题：首次观测不算变化。
        let cases: &[(Option<i32>, i32, bool, &str)] = &[
            (None, 0, false, "首次观测：没有「之前」可比，不算变化"),
            (None, 64, false, "首次观测，哪怕读到的是「已联网」，也不算"),
            (Some(0), 0, false, "读数没变"),
            (Some(64), 64, false, "读数没变（已联网）"),
            (Some(0), 64, true, "断网 → 联网"),
            (Some(64), 0, true, "联网 → 断网"),
            (Some(64), 66, true, "同为联网，但位变了（IPv4/IPv6 切换）"),
        ];
        for (previous, current, want, why) in cases {
            assert_eq!(
                is_change(*previous, *current),
                *want,
                "previous={previous:?} current={current}：{why}"
            );
        }
    }

    #[test]
    fn the_first_observation_never_emits_even_when_the_debouncer_would_allow_it() {
        // 两个门是串联的。把 `is_change` 的 `matches!` 换成
        // `previous != Some(current)`（也就是让 `None` 算成变化），
        // 这条变红。
        let mut w = ConnectivityWatcher::new();
        assert!(!w.observe(64, t0()));
    }

    #[test]
    fn an_unchanged_reading_never_emits_however_long_you_wait() {
        // 反过来：防抖窗口过去了也不能凭空发。把 `observe` 里的
        // `changed &&` 去掉，这条变红。
        let base = t0();
        let mut w = ConnectivityWatcher::new();
        assert!(!w.observe(64, base));
        assert!(!w.observe(64, base + Duration::from_secs(10)));
        assert!(!w.observe(64, base + Duration::from_secs(20)));
    }

    #[test]
    fn a_flap_inside_the_debounce_window_emits_once() {
        // 拔网线切 Wi-Fi 的真实形状：几百毫秒内连通性翻好几次。
        // 只应该发一条。把 `observe` 里的 `&& self.debounce.allow_at(now)`
        // 去掉，这条变红。
        let base = t0();
        let mut w = ConnectivityWatcher::new();
        assert!(!w.observe(64, base), "首次观测");
        let mut emitted = 0;
        for ms in [100u64, 250, 400, 550, 700] {
            // 0 与 64 交替，每一步都是「变化」
            let value = if ms / 100 % 2 == 0 { 64 } else { 0 };
            if w.observe(value, base + Duration::from_millis(ms)) {
                emitted += 1;
            }
        }
        assert_eq!(emitted, 1, "整段抖动只该合并成一条事件");
    }

    #[test]
    fn a_change_after_the_window_emits_again() {
        // 防抖不能把「稍后真的又切了一次网」永久吞掉。
        let base = t0();
        let mut w = ConnectivityWatcher::new();
        assert!(!w.observe(64, base));
        assert!(
            w.observe(0, base + Duration::from_millis(100)),
            "第一次变化"
        );
        assert!(
            !w.observe(64, base + Duration::from_millis(200)),
            "窗口内的第二次变化被合并"
        );
        assert!(
            w.observe(0, base + Duration::from_millis(1200)),
            "窗口之外的变化要能再发一条"
        );
    }

    // -----------------------------------------------------------------
    // 电源事件码
    // -----------------------------------------------------------------

    #[test]
    fn only_the_automatic_resume_notification_counts_as_a_wake_up() {
        // 把 `is_resume_event` 的比较对象换成 `PBT_RESUME_SUSPEND`
        // （或者改成 `!=`），这条变红。
        let cases: &[(u32, bool, &str)] = &[
            (PBT_RESUME_AUTOMATIC, true, "每次唤醒都发的那一条"),
            (
                PBT_RESUME_SUSPEND,
                false,
                "只在用户按键唤醒时附带，认它只会白挤防抖窗口",
            ),
            (PBT_SUSPEND, false, "即将休眠，此刻重连是徒劳的"),
            (0, false, "PBT_APMQUERYSUSPEND，跟唤醒无关"),
            (32787, false, "PBT_POWERSETTINGCHANGE，跟唤醒无关"),
        ];
        for (code, want, why) in cases {
            assert_eq!(is_resume_event(*code), *want, "code={code}：{why}");
        }
    }

    #[test]
    fn the_power_event_codes_match_the_win32_numbering() {
        // 这三个常量在 `win` 子模块里有 `const _: () = assert!(...)` 跟
        // `windows` crate 的定义核对；那条断言在 macOS 上编译不到，所以
        // 这里把数值本身也钉一道——两边一起改才改得动。
        assert_eq!(PBT_RESUME_AUTOMATIC, 18);
        assert_eq!(PBT_RESUME_SUSPEND, 7);
        assert_eq!(PBT_SUSPEND, 4);
    }

    // -----------------------------------------------------------------
    // 电源闸（W84）
    //
    // 上一轮这两个门整个留在 `#[cfg(windows)]` 的回调体里，这台机器上
    // 一行都编译不到；评审的两枪（PW1 把 `!` 去掉、PW2b 把防抖门换成
    // `if true`）六道闸门全绿。下面四条就是补上的那道检测。
    // -----------------------------------------------------------------

    #[test]
    fn only_a_wake_up_code_opens_the_power_gate() {
        // PW1：把 `on_event` 里的 `is_resume_event(..)` 改成
        // `!is_resume_event(..)`，这条变红——而产品里那一下的表现是
        // **真唤醒时什么都不发，「即将休眠」反而触发重连**。
        let base = t0();
        let g = PowerGate::with_window(Duration::from_millis(800));
        assert!(!g.on_event(PBT_SUSPEND, base), "即将休眠，此刻重连是徒劳的");
        assert!(
            !g.on_event(PBT_RESUME_SUSPEND, base),
            "只在用户按键唤醒时附带，认它只会白挤防抖窗口"
        );
        assert!(
            !g.on_event(32787, base),
            "PBT_POWERSETTINGCHANGE，跟唤醒无关"
        );
        assert!(!g.on_event(0, base), "PBT_APMQUERYSUSPEND，跟唤醒无关");
        assert!(
            g.on_event(PBT_RESUME_AUTOMATIC, base),
            "每次唤醒都发的那一条，必须放行"
        );
    }

    #[test]
    fn a_second_wake_up_inside_the_window_is_suppressed() {
        // PW2b：把 `on_event` 里的 `&& self.debounce.allow_at(now)` 换成
        // `&& true`（或直接去掉），这条变红。
        let base = t0();
        let g = PowerGate::with_window(Duration::from_millis(800));
        assert!(g.on_event(PBT_RESUME_AUTOMATIC, base), "第一条放行");
        assert!(
            !g.on_event(PBT_RESUME_AUTOMATIC, base + Duration::from_millis(799)),
            "窗口内的第二条挡掉"
        );
        assert!(
            g.on_event(PBT_RESUME_AUTOMATIC, base + Duration::from_millis(800)),
            "窗口之外要能再发"
        );
    }

    #[test]
    fn codes_that_are_not_wake_ups_do_not_consume_the_debounce_window() {
        // 两个门串联的**顺序**：先问算不算唤醒，算了才去问防抖。
        // 把 `on_event` 写成 `self.debounce.allow_at(now) &&
        // is_resume_event(event_type)`，这条变红——合盖前系统会连发
        // 好几条 `PBT_*`，紧接着的那次真唤醒就被自己挡掉了。
        let base = t0();
        let g = PowerGate::with_window(Duration::from_millis(800));
        for offset in [0u64, 10, 20, 30] {
            assert!(!g.on_event(PBT_SUSPEND, base + Duration::from_millis(offset)));
        }
        assert!(
            g.on_event(PBT_RESUME_AUTOMATIC, base + Duration::from_millis(40)),
            "前面那一串跟唤醒无关的码不该占掉防抖窗口"
        );
    }

    #[test]
    fn a_power_gate_built_from_the_product_constant_uses_that_window() {
        // `PowerGate::new()` 真的用了 `debounce_ms()`，不是另一个写死的
        // 数。把 `new()` 改成 `with_window(Duration::from_millis(1))`，
        // 这条变红。
        let g = PowerGate::new();
        let base = t0();
        assert!(g.on_event(PBT_RESUME_AUTOMATIC, base));
        assert!(!g.on_event(
            PBT_RESUME_AUTOMATIC,
            base + Duration::from_millis(debounce_ms() - 1)
        ));
        assert!(g.on_event(
            PBT_RESUME_AUTOMATIC,
            base + Duration::from_millis(debounce_ms())
        ));
    }

    // -----------------------------------------------------------------
    // 电源回调的进程级状态（W85/W86）
    //
    // 格子当参数传（同 W74 对 `Instant` 的那一招），所以这两条在 macOS
    // 上真跑，不需要任何 mock。上一轮这里零覆盖，评审的 PW3
    // （`.is_err()` → `.is_ok()`）六道闸门全绿。
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn the_power_callback_emits_a_resume_event_only_for_a_wake_up() {
        let base = t0();
        let cell = OnceLock::new();
        let hub = Arc::new(EventHub::new());
        let mut rx = hub.subscribe();
        assert!(install(&cell, Arc::clone(&hub)));
        let state = cell.get().expect("刚刚装进去的");

        assert!(!state.on_power_event(PBT_SUSPEND, base));
        assert_eq!(
            rx.try_recv(),
            Err(TryRecvError::Empty),
            "「即将休眠」不该发出任何事件"
        );

        assert!(state.on_power_event(PBT_RESUME_AUTOMATIC, base));
        assert_eq!(
            recv_soon(&mut rx).await,
            SystemEvent::ResumedFromSleep,
            "发的必须是唤醒事件，不是 NetworkChanged"
        );
    }

    #[tokio::test]
    async fn installing_a_second_time_is_refused_and_keeps_the_first_hub() {
        // PW3：把 `install` 里的 `.is_ok()` 改成 `.is_err()`，语义正好
        // 翻成「第一次注册跳过、第二次才注册」，休眠恢复整个不工作。
        // 这条的两个 `assert!` 同时变红。
        let base = t0();
        let cell = OnceLock::new();
        let first = Arc::new(EventHub::new());
        let second = Arc::new(EventHub::new());
        let mut rx_first = first.subscribe();
        let mut rx_second = second.subscribe();

        assert!(install(&cell, Arc::clone(&first)), "第一次装得进去");
        assert!(!install(&cell, Arc::clone(&second)), "第二次必须被拒");

        // 格子里仍然是第一个 hub：事件发到 `first`，`second` 上什么都没有。
        assert!(cell
            .get()
            .expect("装过了")
            .on_power_event(PBT_RESUME_AUTOMATIC, base));
        assert_eq!(
            recv_soon(&mut rx_first).await,
            SystemEvent::ResumedFromSleep
        );
        assert_eq!(
            rx_second.try_recv(),
            Err(TryRecvError::Empty),
            "第二个 hub 被丢弃了，不该收到任何事件"
        );
    }

    // -----------------------------------------------------------------
    // 注册顺序（W86）
    //
    // 「还没注册过就注册一次、注册成功了才占格子」这个顺序上一轮整个
    // 写在 `win::register_power` 里，在这台机器上一行都测不到。现在
    // `register` 当参数收进来，于是下面三条在 macOS 上真跑。
    // -----------------------------------------------------------------

    /// 测试用的注册失败，代替 `windows::core::Error`。
    #[derive(Debug, PartialEq, Eq)]
    struct FakeRegisterError;

    #[test]
    fn a_failed_registration_leaves_the_cell_empty_so_a_retry_can_still_work() {
        // 这就是 W86 那条半截状态：上一轮 `POWER.set(..)` 排在 Win32
        // 注册**之前**，`.ok()?` 提前返回时格子已经被占住，将来任何重试
        // 都会走进「已经注册过，本次跳过」并返回 `Ok(())`——功能永久
        // 关闭却报成功。
        //
        // 把 `register_once` 里的 `register()?;` 挪到 `install(..)` 之后
        // （也就是还原上一轮的顺序），这条的最后两个断言变红。
        let cell = OnceLock::new();
        let hub = Arc::new(EventHub::new());

        assert_eq!(
            register_once(&cell, Arc::clone(&hub), || Err(FakeRegisterError)),
            Err(FakeRegisterError),
            "注册失败要如实往上报"
        );
        assert!(cell.get().is_none(), "注册失败之后格子必须还是空的");

        // 重试：这一次注册成功，功能必须真的起来。
        assert_eq!(
            register_once(&cell, Arc::clone(&hub), || Ok::<(), FakeRegisterError>(())),
            Ok(true),
            "重试必须能真的装上，而不是「已经注册过，跳过」"
        );
        assert!(cell.get().is_some());
    }

    #[test]
    fn registering_a_second_time_does_not_touch_win32_at_all() {
        // 已经注册过就连 `register` 都不调用——注册两次的唯一后果是多占
        // 一个内核对象加一次 `Box::leak`，第二遍的回调必然被同一个防抖器
        // 挡掉。把 `register_once` 开头那个 `if cell.get().is_some()` 去掉，
        // 这条变红。
        let cell = OnceLock::new();
        let hub = Arc::new(EventHub::new());
        let calls = std::cell::Cell::new(0u32);

        assert_eq!(
            register_once(&cell, Arc::clone(&hub), || {
                calls.set(calls.get() + 1);
                Ok::<(), FakeRegisterError>(())
            }),
            Ok(true)
        );
        assert_eq!(
            register_once(&cell, Arc::clone(&hub), || {
                calls.set(calls.get() + 1);
                Ok::<(), FakeRegisterError>(())
            }),
            Ok(false),
            "第二次要报「跳过」，不是「装上了」"
        );
        assert_eq!(calls.get(), 1, "第二次不该再碰一次 Win32");
    }

    #[tokio::test]
    async fn a_successful_registration_wires_the_callback_to_that_hub() {
        // 端到端一条：注册成功 → 格子装上 → 回调收到唤醒码 → 这个 hub
        // 的订阅者收到 `ResumedFromSleep`。
        let cell = OnceLock::new();
        let hub = Arc::new(EventHub::new());
        let mut rx = hub.subscribe();

        assert_eq!(
            register_once(&cell, Arc::clone(&hub), || Ok::<(), FakeRegisterError>(())),
            Ok(true)
        );
        assert!(cell
            .get()
            .expect("注册成功之后格子必须装上了")
            .on_power_event(PBT_RESUME_AUTOMATIC, t0()));
        assert_eq!(recv_soon(&mut rx).await, SystemEvent::ResumedFromSleep);
    }

    #[test]
    fn the_network_poll_interval_is_sane() {
        // W83 记在模块文档里的那笔账：这个间隔直接决定笔记本上的定时
        // 唤醒频率。太密费电，太疏让「切网后立刻重连」名不副实。
        assert!(POLL_INTERVAL >= Duration::from_secs(1));
        assert!(POLL_INTERVAL <= Duration::from_secs(5));
    }
}
