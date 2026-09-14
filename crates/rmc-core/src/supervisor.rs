//! 状态机。唯一改变 [`crate::state::State`] 的地方，界面只读事件、只发命令。
//!
//! 见方案 3.5/3.6。行为规约（何时重连、何时退避、何时判 Fatal）几乎全部
//! 落在这个文件里，是整个内核裁决密度最高的一块。
//!
//! # 与 brief 不同的几处，逐条写明理由
//!
//! 1. **不依赖 `crate::audit`**——那个模块和 `Ctx::audit` 字段都是 Task 11
//!    才会创建的东西，Task 10 的实现不引用它，也不调用任何
//!    `audit.record(...)`。
//! 2. **全程用 `tokio::time::Instant`，不用 `std::time::Instant`**——
//!    `retry_at`/`probe_at`/`port_busy_since` 都要喂给
//!    `tokio::time::sleep_until`，测试跑在 `#[tokio::test(start_paused =
//!    true)]` 的虚拟时钟上；如果这几个字段是 `std::time::Instant`，
//!    `std::time::Instant::now()` 拿到的是真实挂钟时间，虚拟时钟推进
//!    之后 `now() + delay` 算出来的截止点会变成一个已经过去的时刻，
//!    `sleep_until` 立刻返回；`PortBusy` 分支里的 `since.elapsed()`
//!    同理，量的是真实时间，虚拟时间里恒为 0，120 秒预算永远到不了。
//!    两者叠加的后果不是测试失败，是**挂死**。
//! 3. **`port_busy_since` 在任何非 `PortBusy` 错误发生时都会被清空**——
//!    不止在 `attempt()` 成功和 `Command::Start` 时清。否则"端口占用→
//!    网络错误→五分钟后全新的端口占用"这个序列会在第三步被误判成
//!    "预算已经用完"，一次重试都不给就直接 `Failed`。
//! 4. **`ErrorClass::ApplianceUnreachable` 不与 `Network` 共用退避分支**
//!    ——方案 §3.6 要的是"隧道保持、转 degraded、每 30 秒探测"，跟
//!    `Network` 类"整条隧道拆了重建、指数退避"是两种完全不同的处置。
//!    这条路径目前没有任何生产调用点会走到（见 [`schedule_retry`] 上的
//!    说明），但 `schedule_retry` 是按 `Error::class()` 泛化处理的，
//!    错误的默认值一旦以后被某个新增调用点撞上，后果是把"探测一体机"
//!    误判成"网络抖动"，所以照样单独给一条分支、并且有一条直接调用
//!    `schedule_retry` 的单元测试钉住它。
//! 5. **`Backoff { attempt }` 在 `PortBusy` 路径上不再恒为 0**——原
//!    brief 那条路从不调用 `backoff.next_delay()`/推进 `Backoff` 的
//!    计数，导致界面在整整 120 秒里一直显示"第 0 次重连"。这里单独
//!    维护一个只在 `PortBusy` 序列里递增的计数，供 `State::Backoff`
//!    上报，不与网络类的指数退避计数混用（两者的语义不同：一个是
//!    "第几次固定 5 秒重试"，一个是"退避表走到第几项"）。
//! 6. **预检经 Task 9 交付的 [`crate::preflight::Preflight`] trait 注入**
//!    ——不直接调用 `preflight::run` 自由函数。`Deps::preflight` 是
//!    生产用 `TransportPreflight`，测试用一个立即返回全 `Pass`（或按
//!    需要脚本化）的假实现，`Scripted` 假隧道工厂才有机会被真正调用到。
//! 7. **公开的 `Command::Start` 一定会先校验地址关系**——处理该命令时
//!    先调用 `config::ValidatedAddresses::validate(gateway, appliance)`，
//!    校验通过才会继续（跑预检、建隧道）；校验失败直接进
//!    `State::Failed { class: Fatal, .. }`，`Deps::factory` 一次都不会
//!    被调用。需要 loopback 一体机地址的测试（`degraded_probe_recovers_
//!    when_the_appliance_comes_back` 一类）不走这条公开入口，改用
//!    `Supervisor::spawn_with_validated_start`——见该函数上的说明，
//!    这是唯一的另一条路，`#[cfg(test)] pub(crate)`，生产构建里根本
//!    不存在这个符号；`pub enum Command` 的任何变体字段在 Rust 里都无法
//!    单独收紧可见性（试过给字段标 `pub(crate)`，编译器报 `E0449`：
//!    "enum variants and their fields always share the visibility of the
//!    enum they are in"），所以这条内部入口不是 `Command` 的又一个
//!    变体，而是一个独立的、`#[cfg(test)]` 门控的构造函数。

use crate::backoff::{Backoff, Jitter};
use crate::config::{Config, ValidatedAddresses};
use crate::error::{Error, ErrorClass};
use crate::platform::{SystemEvent, SystemEvents};
use crate::preflight::{self, Preflight};
use crate::state::{Command, RemoteSessionInfo, State, TunnelEvent};
use crate::transport::Transport;
use crate::tunnel::{TunnelFactory, TunnelHandle, TunnelMsg, TunnelParams};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::{broadcast, mpsc};
use tokio::time::{Duration, Instant};
use zeroize::Zeroizing;

pub const PORT_BUSY_RETRY: Duration = Duration::from_secs(5);
pub const PORT_BUSY_BUDGET: Duration = Duration::from_secs(120);
pub const APPLIANCE_PROBE: Duration = Duration::from_secs(30);

const EVENT_CAPACITY: usize = 256;
const MSG_CAPACITY: usize = 256;

pub struct Deps {
    pub factory: Arc<dyn TunnelFactory>,
    pub transport: Arc<Transport>,
    pub preflight: Arc<dyn Preflight>,
    pub events: Arc<dyn SystemEvents>,
    pub jitter: fn() -> Box<dyn Jitter>,
}

/// 一次 Start 之后持有的凭据，断线重连时复用，不需要界面再问一遍口令。
/// R——第九条：`Credentials` 只在本文件内部构造与消费（唯一的构造点在
/// `begin_start`，唯一的输入是一份 `ValidatedAddresses`），换成直接持有
/// `ValidatedAddresses` 而不是拆开的 `gateway`/`appliance: HostPort`
/// 在这里是"免费"的——不像 `tunnel::TunnelParams`/`ssh::SshTunnelFactory`
/// 那样有外部集成测试（`tests/ssh_tunnel.rs`，用 127.0.0.1 一体机地址）
/// 依赖着裸 `HostPort` 的字段类型，改了会让那个外部 crate 编译不过（见
/// `tunnel.rs` 顶部 R20/R48 的详细权衡）。这里没有类似的外部依赖，直接
/// 把"这对地址已经校验过"这件事在类型上多留一层证据。
struct Credentials {
    username: String,
    password: Zeroizing<String>,
    addrs: ValidatedAddresses,
}

impl Credentials {
    fn params(&self, reverse_port: u16) -> TunnelParams {
        TunnelParams {
            username: self.username.clone(),
            password: self.password.clone(),
            reverse_port,
            appliance: self.addrs.appliance().clone(),
        }
    }
}

pub struct Supervisor;

impl Supervisor {
    pub fn spawn(
        cfg: Config,
        deps: Deps,
    ) -> (mpsc::Sender<Command>, broadcast::Receiver<TunnelEvent>) {
        let (cmd_tx, cmd_rx) = mpsc::channel(32);
        let (ev_tx, ev_rx) = broadcast::channel(EVENT_CAPACITY);
        tokio::spawn(run(cfg, deps, cmd_rx, ev_tx, None));
        (cmd_tx, ev_rx)
    }

    /// 仅供本 crate 内部测试：跳过 `Command::Start` 对地址关系的校验，
    /// 直接携带一份已经用 `config::ValidatedAddresses::for_test`
    /// 构造好的地址对，在 Supervisor 启动后立即当作第一个「开启」动作
    /// 处理——等价于把 `Command::Start` 换成一个跳过校验的版本，见模块
    /// 顶部第 7 条对"为什么不是给 Command 加一个变体"的说明。
    ///
    /// 用途：需要一体机地址是 `127.0.0.1:{port}` 的测试（探测恢复、探测
    /// 持续失败两类场景）——这类地址会被公开的 `Command::Start` 拒绝
    /// （一体机不能是本机回环），必须绕过公开入口，但又不能削弱公开
    /// 入口本身的校验。
    #[cfg(test)]
    pub(crate) fn spawn_with_validated_start(
        cfg: Config,
        deps: Deps,
        username: String,
        password: Zeroizing<String>,
        addrs: ValidatedAddresses,
    ) -> (mpsc::Sender<Command>, broadcast::Receiver<TunnelEvent>) {
        let (cmd_tx, cmd_rx) = mpsc::channel(32);
        let (ev_tx, ev_rx) = broadcast::channel(EVENT_CAPACITY);
        let initial = Some((username, password, addrs));
        tokio::spawn(run(cfg, deps, cmd_rx, ev_tx, initial));
        (cmd_tx, ev_rx)
    }
}

struct Ctx {
    cfg: Config,
    deps: Deps,
    ev: broadcast::Sender<TunnelEvent>,
    state: State,
    creds: Option<Credentials>,
    handle: Option<Box<dyn TunnelHandle>>,
    sessions: BTreeMap<u64, RemoteSessionInfo>,
    /// 网络类错误的指数退避序列状态。
    backoff: Backoff,
    /// 端口占用固定节奏下"第几次重试"，只用于上报 `State::Backoff`，与
    /// `backoff`（指数退避序列）各自独立计数——见模块顶部第 5 条。
    port_busy_attempt: u32,
    /// 端口占用重试预算的起点。`None` 表示当前不在一段连续的端口占用
    /// 序列里；任何非 `PortBusy` 的结果（成功、其他类别的错误、一次新
    /// 的 `Start`）都会清空它，见模块顶部第 3 条。
    port_busy_since: Option<Instant>,
}

impl Ctx {
    fn set_state(&mut self, s: State) {
        self.state = s.clone();
        let _ = self.ev.send(TunnelEvent::State(s));
    }

    fn publish_sessions(&self) {
        let list = self.sessions.values().cloned().collect();
        let _ = self.ev.send(TunnelEvent::RemoteSessions(list));
    }

    async fn teardown(&mut self) {
        if let Some(h) = self.handle.take() {
            h.shutdown().await;
        }
        if !self.sessions.is_empty() {
            self.sessions.clear();
            self.publish_sessions();
        }
    }
}

async fn run(
    cfg: Config,
    deps: Deps,
    mut cmd_rx: mpsc::Receiver<Command>,
    ev: broadcast::Sender<TunnelEvent>,
    initial: Option<(String, Zeroizing<String>, ValidatedAddresses)>,
) {
    let mut sys = deps.events.subscribe();
    let jitter = deps.jitter;
    let mut ctx = Ctx {
        cfg,
        deps,
        ev,
        state: State::Idle,
        creds: None,
        handle: None,
        sessions: BTreeMap::new(),
        backoff: Backoff::new(jitter()),
        port_busy_attempt: 0,
        port_busy_since: None,
    };
    let (msg_tx, mut msg_rx) = mpsc::channel::<TunnelMsg>(MSG_CAPACITY);

    // R——注意这里不调用 `ctx.set_state(State::Idle)`：`ctx.state` 在上面
    // 的结构体字面量里已经初始化成 `Idle`，这里只是"进程刚起来，状态
    // 还没变过"，不是一次真正的状态转移。如果这里也广播一次，`rx` 会在
    // 测试第一次 `recv()` 之前就已经缓冲到这条 `Idle` 事件（`broadcast`
    // 的缓冲不需要接收端先调用过 `recv`），导致 `happy_path_reaches_
    // connected` 断言 `seen[0]` 是 `Preflight` 时失败——实际
    // `seen[0]` 会是这条多余的 `Idle`。只在状态真的发生变化时才广播。
    //
    // 下一次尝试连接的时刻。None 表示不在重试中。
    let mut retry_at: Option<Instant> = None;
    // degraded 时下一次探测一体机的时刻。None 表示不在探测中。
    let mut probe_at: Option<Instant> = None;

    if let Some((username, password, addrs)) = initial {
        retry_at = begin_start(&mut ctx, username, password, addrs, &msg_tx).await;
    }

    loop {
        let idle = Instant::now() + Duration::from_secs(3600);
        let sleep_until = retry_at.unwrap_or(idle);
        let probe_until = probe_at.unwrap_or(idle);

        tokio::select! {
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { ctx.teardown().await; return };
                match cmd {
                    Command::Start { username, password, gateway, appliance } => {
                        if !matches!(ctx.state, State::Idle | State::Failed { .. }) {
                            continue;
                        }
                        match ValidatedAddresses::validate(gateway, appliance) {
                            Ok(addrs) => {
                                retry_at = begin_start(&mut ctx, username, password, addrs, &msg_tx).await;
                                probe_at = None;
                            }
                            Err(e) => {
                                // 地址关系本身不合法（一体机等于 Gateway、
                                // 一体机是本机回环）：这是配置错误，不是
                                // 网络问题，重试无意义，且这一步必须发生在
                                // 触达 Deps::factory 之前——见模块顶部第 7 条。
                                ctx.set_state(State::Failed { class: e.class(), message: e.to_string() });
                            }
                        }
                    }
                    Command::Cancel | Command::Stop => {
                        if matches!(ctx.state, State::Idle) {
                            continue;
                        }
                        ctx.set_state(State::Stopping);
                        ctx.teardown().await;
                        ctx.creds = None;
                        retry_at = None;
                        probe_at = None;
                        ctx.set_state(State::Idle);
                    }
                    Command::RetryNow => {
                        if matches!(ctx.state, State::Backoff { .. } | State::Failed { .. }) {
                            ctx.backoff.reset();
                            ctx.port_busy_since = None;
                            ctx.port_busy_attempt = 0;
                            retry_at = attempt(&mut ctx, &msg_tx).await;
                        }
                    }
                    Command::DisconnectRemoteSession { id } => {
                        if let Some(h) = ctx.handle.as_ref() {
                            let _ = h.close_remote_session(id).await;
                        }
                    }
                }
            }

            Ok(event) = sys.recv() => {
                // 网络变化与休眠恢复都清零退避并立刻重试。
                if matches!(ctx.state, State::Backoff { .. })
                    && matches!(event, SystemEvent::NetworkChanged | SystemEvent::ResumedFromSleep)
                {
                    ctx.backoff.reset();
                    retry_at = attempt(&mut ctx, &msg_tx).await;
                }
            }

            Some(msg) = msg_rx.recv() => {
                handle_msg(&mut ctx, msg, &mut retry_at, &mut probe_at).await;
            }

            _ = tokio::time::sleep_until(sleep_until), if retry_at.is_some() => {
                retry_at = attempt(&mut ctx, &msg_tx).await;
            }

            _ = tokio::time::sleep_until(probe_until), if probe_at.is_some() => {
                probe_at = probe_appliance(&mut ctx).await;
            }
        }
    }
}

/// `Command::Start`（校验通过后）与
/// `Supervisor::spawn_with_validated_start`（跳过校验，仅测试）共用的
/// "开始一次开启"逻辑：记下凭据、重置退避与端口占用计时、跑预检、
/// 预检通过就发起第一次连接尝试。
async fn begin_start(
    ctx: &mut Ctx,
    username: String,
    password: Zeroizing<String>,
    addrs: ValidatedAddresses,
    msg_tx: &mpsc::Sender<TunnelMsg>,
) -> Option<Instant> {
    ctx.creds = Some(Credentials {
        username,
        password,
        addrs,
    });
    ctx.backoff = Backoff::new((ctx.deps.jitter)());
    ctx.port_busy_since = None;
    ctx.port_busy_attempt = 0;
    if run_preflight(ctx).await {
        attempt(ctx, msg_tx).await
    } else {
        None
    }
}

async fn run_preflight(ctx: &mut Ctx) -> bool {
    let Some(creds) = ctx.creds.as_ref() else {
        return false;
    };
    let gateway = creds.addrs.gateway().clone();
    let appliance = creds.addrs.appliance().clone();
    ctx.set_state(State::Preflight);
    // 见模块顶部第 6 条：经 `Deps::preflight` 注入的 trait 调用，不是
    // `preflight::run` 自由函数。生产实现 `TransportPreflight` 内部才会
    // 真的碰网络；测试注入的假实现立即返回脚本化的报告，`start_paused`
    // 虚拟时钟因此不会被一次真实的 `TcpStream::connect` 卡住。
    let report = ctx.deps.preflight.run(&gateway, &appliance).await;
    let passed = report.passed();
    let failure = report.first_failure().cloned();
    let _ = ctx.ev.send(TunnelEvent::Preflight(report));
    if !passed {
        let (class, message) = match failure.map(|s| s.outcome) {
            Some(preflight::StepOutcome::Fail { class, detail }) => (class, detail),
            _ => (ErrorClass::Network, "预检未通过".to_string()),
        };
        // 预检失败没有 Backoff 分支——见方案 3.5 的状态图：Preflight 只有
        // "通过"/"失败"两个出口，失败恒定直接进 Failed，不自动重试，
        // 用户需要 RetryNow 或一次新的 Start。
        ctx.set_state(State::Failed { class, message });
        return false;
    }
    true
}

/// 尝试建立一次隧道。返回下一次重试的时刻，`None` 表示不再自动重试。
async fn attempt(ctx: &mut Ctx, msg_tx: &mpsc::Sender<TunnelMsg>) -> Option<Instant> {
    let creds = ctx.creds.as_ref()?;
    let params = creds.params(ctx.cfg.reverse_port);
    ctx.set_state(State::Connecting);

    match ctx.deps.factory.establish(params, msg_tx.clone()).await {
        Ok(handle) => {
            ctx.handle = Some(handle);
            ctx.port_busy_since = None;
            ctx.port_busy_attempt = 0;
            ctx.backoff.reset();
            let _ = ctx.ev.send(TunnelEvent::ConnectedSince(SystemTime::now()));
            ctx.set_state(State::Connected { degraded: false });
            None
        }
        Err(e) => schedule_retry(ctx, e),
    }
}

/// degraded 时每 [`APPLIANCE_PROBE`] 探测一次一体机，恢复即转回。返回
/// 下一次探测时刻，`None` 表示不需要再探测（已恢复，或隧道已不存在）。
async fn probe_appliance(ctx: &mut Ctx) -> Option<Instant> {
    let appliance = ctx.creds.as_ref()?.addrs.appliance().clone();
    match ctx
        .deps
        .transport
        .probe_tcp(&appliance, Duration::from_secs(5))
        .await
    {
        Ok(_) => {
            if matches!(ctx.state, State::Connected { degraded: true }) {
                ctx.set_state(State::Connected { degraded: false });
            }
            None
        }
        Err(_) => Some(Instant::now() + APPLIANCE_PROBE),
    }
}

/// 按错误分类决定是否以及何时重试。
///
/// 见模块顶部第 4 条：`ErrorClass::ApplianceUnreachable` 目前没有任何
/// 生产调用点会传到这里——`attempt()` 只会失败于 Gateway 侧的握手/认证/
/// 端口注册（`SshTunnelFactory::establish` 根本不拨号一体机），一体机
/// 不可达在已连接状态下经 `TunnelMsg::ApplianceDialFailed` 单独处理
/// （见 `handle_msg`），从不经过这个函数。但 `schedule_retry` 是按
/// `e.class()` 泛化处理的，如果把这个分类默认并进 `Network`，一旦未来
/// 某个调用点真的传入这个类别，会把"隧道保持、转 degraded、每 30 秒
/// 探测"错误地处理成"整条隧道拆了重建、指数退避"——这里单独给一条分支，
/// 用固定的 [`APPLIANCE_PROBE`] 节奏，不套用网络类的指数退避表，也不
/// 推进 `ctx.backoff` 的计数。
fn schedule_retry(ctx: &mut Ctx, e: Error) -> Option<Instant> {
    let class = e.class();
    // 见模块顶部第 3 条：除端口占用外的任何结果都清空端口占用的计时，
    // 让下一次端口占用序列从一份全新的 120 秒预算开始。
    if !matches!(class, ErrorClass::PortBusy) {
        ctx.port_busy_since = None;
        ctx.port_busy_attempt = 0;
    }
    match class {
        ErrorClass::Fatal => {
            ctx.set_state(State::Failed {
                class: ErrorClass::Fatal,
                message: e.to_string(),
            });
            None
        }
        ErrorClass::Auth => {
            // 回到 Idle 让界面提示重新输入，凭据同时清掉——不自动重试。
            ctx.creds = None;
            ctx.set_state(State::Idle);
            None
        }
        ErrorClass::PortBusy => {
            let since = *ctx.port_busy_since.get_or_insert_with(Instant::now);
            if since.elapsed() >= PORT_BUSY_BUDGET {
                ctx.set_state(State::Failed {
                    class: ErrorClass::PortBusy,
                    message: format!("{e}，{} 秒内未能注册", PORT_BUSY_BUDGET.as_secs()),
                });
                return None;
            }
            // 见模块顶部第 5 条：这条计数只在端口占用序列里递增，专门
            // 供界面显示"第几次重试"，不与下面 Network 分支的指数退避
            // 计数共用。
            ctx.port_busy_attempt = ctx.port_busy_attempt.saturating_add(1);
            ctx.set_state(State::Backoff {
                attempt: ctx.port_busy_attempt,
                delay: PORT_BUSY_RETRY,
            });
            Some(Instant::now() + PORT_BUSY_RETRY)
        }
        ErrorClass::ApplianceUnreachable => {
            let delay = APPLIANCE_PROBE;
            ctx.set_state(State::Backoff {
                attempt: ctx.backoff.attempt(),
                delay,
            });
            Some(Instant::now() + delay)
        }
        ErrorClass::Network => {
            let delay = ctx.backoff.next_delay();
            ctx.set_state(State::Backoff {
                attempt: ctx.backoff.attempt(),
                delay,
            });
            Some(Instant::now() + delay)
        }
    }
}

async fn handle_msg(
    ctx: &mut Ctx,
    msg: TunnelMsg,
    retry_at: &mut Option<Instant>,
    probe_at: &mut Option<Instant>,
) {
    match msg {
        TunnelMsg::Authenticated {
            host_key_fp,
            first_seen,
        } => {
            let _ = ctx.ev.send(TunnelEvent::HostKey {
                fingerprint: host_key_fp,
                first_seen,
            });
        }
        TunnelMsg::ForwardRegistered { .. } => {}
        TunnelMsg::RemoteSessionOpened { id } => {
            ctx.sessions.insert(
                id,
                RemoteSessionInfo {
                    id,
                    opened_at: SystemTime::now(),
                    to_appliance: 0,
                    from_appliance: 0,
                },
            );
            ctx.publish_sessions();
            // 有会话成功打开说明一体机恢复了，不必再靠定时探测。
            if matches!(ctx.state, State::Connected { degraded: true }) {
                ctx.set_state(State::Connected { degraded: false });
                *probe_at = None;
            }
        }
        TunnelMsg::RemoteSessionBytes {
            id,
            to_appliance,
            from_appliance,
        } => {
            if let Some(s) = ctx.sessions.get_mut(&id) {
                s.to_appliance = to_appliance;
                s.from_appliance = from_appliance;
                ctx.publish_sessions();
            }
        }
        TunnelMsg::RemoteSessionClosed { id } => {
            ctx.sessions.remove(&id);
            ctx.publish_sessions();
        }
        TunnelMsg::ApplianceDialFailed { .. } => {
            if matches!(ctx.state, State::Connected { degraded: false }) {
                ctx.set_state(State::Connected { degraded: true });
                // 进入 degraded 后开始周期探测一体机；隧道本身保持不动，
                // 不经过 schedule_retry，不拆隧道。
                *probe_at = Some(Instant::now() + APPLIANCE_PROBE);
            }
        }
        TunnelMsg::Disconnected { reason } => {
            ctx.teardown().await;
            *probe_at = None;
            if ctx.creds.is_some() {
                *retry_at = schedule_retry(ctx, Error::SshTransport(reason));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! 状态机的行为规约。全部用假隧道与 tokio 的时间控制，不碰真实网络
    //! ——唯一的例外是文件末尾"第十条"那条端到端测量，它需要真的经过
    //! `ssh::establish_over`，因为要测的正是 russh 客户端的 keepalive
    //! 定时器，脚本化的假隧道压根不会触发它。

    use super::*;
    use crate::addr::HostPort;
    use crate::backoff::FixedJitter;
    use crate::platform::{NoProxy, NoProxyAuth, NoSystemEvents, SystemEvent, SystemEvents};
    use crate::transport::tls::TlsRoots;
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::sync::Mutex;

    /// 给整条测试套一层超时：真正卡死时给出"判定为死锁"的清晰失败，而
    /// 不是让 `cargo test` 无限期挂起。即使在 `#[tokio::test(start_paused
    /// = true)]` 下，这层超时本身也是一个待处理的定时器——虚拟时钟在
    /// "没有别的活干"时会自动跳到下一个定时器，所以对"卡在等一个永远
    /// 不会送出的事件"这类死锁依然有效；测不到的只有"陷入真正的忙等
    /// 死循环"，那种情况会让 `cargo test` 占满 CPU、一眼可辨，不是这层
    /// 超时要防的那一类。这个项目已经被夹具死锁拖垮过一次，见
    /// `ssh::test_support` 模块文档"第一版死锁及其修复"。
    async fn guard<F: std::future::Future>(fut: F) -> F::Output {
        tokio::time::timeout(Duration::from_secs(300), fut)
            .await
            .expect("测试超过 300（虚拟或真实）秒仍未完成，判定为死锁")
    }

    /// establish 的一次结果。
    enum Outcome {
        /// 成功，随后按脚本向 tx 推送这些消息。
        Ok(Vec<TunnelMsg>),
        Err(Error),
    }

    /// 按队列逐次给出 establish 结果的假隧道工厂。
    struct Scripted {
        outcomes: Mutex<VecDeque<Outcome>>,
        calls: Arc<Mutex<Vec<TunnelParams>>>,
    }

    impl Scripted {
        fn new(outcomes: Vec<Outcome>) -> (Arc<Self>, Arc<Mutex<Vec<TunnelParams>>>) {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let me = Arc::new(Self {
                outcomes: Mutex::new(outcomes.into()),
                calls: calls.clone(),
            });
            (me, calls)
        }
    }

    struct FakeHandle;

    #[async_trait::async_trait]
    impl TunnelHandle for FakeHandle {
        // R——brief 原文这里写的是 `-> rmc_core::Result<()>`，跟
        // `tunnel::TunnelHandle::close_remote_session` 的真实签名
        // （`std::result::Result<(), UnknownSessionId>`，Task 7 交付）
        // 对不上，照抄编译不过。`UnknownSessionId` 不走 `ErrorClass`
        // 那套分类体系——见 tunnel.rs 上它的文档。
        async fn close_remote_session(
            &self,
            _id: u64,
        ) -> std::result::Result<(), crate::tunnel::UnknownSessionId> {
            Ok(())
        }
        async fn shutdown(self: Box<Self>) {}
    }

    #[async_trait::async_trait]
    impl TunnelFactory for Scripted {
        async fn establish(
            &self,
            params: TunnelParams,
            tx: mpsc::Sender<TunnelMsg>,
        ) -> crate::error::Result<Box<dyn TunnelHandle>> {
            self.calls.lock().unwrap().push(params);
            let outcome = self
                .outcomes
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Outcome::Err(Error::SshTransport("脚本用尽".into())));
            match outcome {
                Outcome::Err(e) => Err(e),
                Outcome::Ok(msgs) => {
                    tokio::spawn(async move {
                        for m in msgs {
                            if tx.send(m).await.is_err() {
                                return;
                            }
                        }
                    });
                    Ok(Box::new(FakeHandle))
                }
            }
        }
    }

    /// 立即返回全 Pass 的假预检——见模块顶部第 6 条。不碰网络、不等待，
    /// `Scripted` 假隧道工厂因此才有机会被真正调用到，而不是每条测试都
    /// 先卡死在对一个不存在的地址做真实 DNS/TCP 探测上。
    struct AlwaysPassPreflight;

    #[async_trait::async_trait]
    impl Preflight for AlwaysPassPreflight {
        async fn run(
            &self,
            _gateway: &HostPort,
            _appliance: &HostPort,
        ) -> preflight::PreflightReport {
            let pass = |name: &'static str| preflight::PreflightStep {
                name,
                outcome: preflight::StepOutcome::Pass {
                    detail: "ok".into(),
                },
            };
            preflight::PreflightReport {
                steps: vec![
                    pass(preflight::STEP_APPLIANCE_TCP),
                    pass(preflight::STEP_APPLIANCE_HOSTKEY),
                    pass(preflight::STEP_GATEWAY_DNS),
                    pass(preflight::STEP_GATEWAY_TLS),
                ],
            }
        }
    }

    fn config() -> Config {
        Config {
            gateway: "gateway.company.com:443".parse().unwrap(),
            appliance: "192.168.100.10:22".parse().unwrap(),
            reverse_port: 22001,
            known_hosts_path: PathBuf::from("/tmp/rmc-test/known_hosts"),
            log_dir: PathBuf::from("/tmp/rmc-test/logs"),
        }
    }

    struct ManualEvents(broadcast::Sender<SystemEvent>);

    impl SystemEvents for ManualEvents {
        fn subscribe(&self) -> broadcast::Receiver<SystemEvent> {
            self.0.subscribe()
        }
    }

    fn deps(factory: Arc<dyn TunnelFactory>, events: Arc<dyn SystemEvents>) -> Deps {
        Deps {
            factory,
            transport: Arc::new(Transport::new(
                Arc::new(NoProxy),
                Arc::new(NoProxyAuth),
                TlsRoots::webpki(),
            )),
            preflight: Arc::new(AlwaysPassPreflight),
            events,
            jitter: || Box::new(FixedJitter(1.0)),
        }
    }

    fn start() -> Command {
        Command::Start {
            username: "tunnel-zhang".into(),
            password: Zeroizing::new("pw".into()),
            gateway: "gateway.company.com:443".parse().unwrap(),
            appliance: "192.168.100.10:22".parse().unwrap(),
        }
    }

    /// 收集状态变迁，直到匹配 pred 或超时。
    async fn states_until(
        rx: &mut broadcast::Receiver<TunnelEvent>,
        pred: impl Fn(&State) -> bool,
    ) -> Vec<State> {
        let mut seen = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(300);
        while Instant::now() < deadline {
            match rx.recv().await {
                Ok(TunnelEvent::State(s)) => {
                    let hit = pred(&s);
                    seen.push(s);
                    if hit {
                        return seen;
                    }
                }
                Ok(_) => {}
                Err(e) => panic!("事件通道异常：{e}"),
            }
        }
        panic!("等待状态超时，已见：{seen:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn happy_path_reaches_connected() {
        guard(async {
            let (factory, _calls) = Scripted::new(vec![Outcome::Ok(vec![
                TunnelMsg::Authenticated {
                    host_key_fp: "SHA256:aaa".into(),
                    first_seen: true,
                },
                TunnelMsg::ForwardRegistered { port: 22001 },
            ])]);
            let (tx, mut rx) =
                Supervisor::spawn(config(), deps(factory, Arc::new(NoSystemEvents::default())));
            tx.send(start()).await.unwrap();

            let seen = states_until(&mut rx, |s| {
                matches!(s, State::Connected { degraded: false })
            })
            .await;
            assert!(matches!(seen[0], State::Preflight));
            assert!(seen.iter().any(|s| matches!(s, State::Connecting)));
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn auth_failure_returns_to_idle_and_does_not_retry() {
        guard(async {
            let (factory, calls) = Scripted::new(vec![Outcome::Err(Error::AuthRejected)]);
            let (tx, mut rx) = Supervisor::spawn(
                config(),
                deps(factory.clone(), Arc::new(NoSystemEvents::default())),
            );
            tx.send(start()).await.unwrap();

            let seen = states_until(&mut rx, |s| matches!(s, State::Idle)).await;
            assert!(
                !seen.iter().any(|s| matches!(s, State::Backoff { .. })),
                "{seen:?}"
            );
            tokio::time::sleep(Duration::from_secs(120)).await;
            assert_eq!(calls.lock().unwrap().len(), 1, "认证失败后不得自动重试");
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn host_key_mismatch_goes_to_failed_and_does_not_retry() {
        guard(async {
            let (factory, calls) = Scripted::new(vec![Outcome::Err(Error::HostKeyMismatch {
                expected: "SHA256:aaa".into(),
                actual: "SHA256:bbb".into(),
            })]);
            let (tx, mut rx) =
                Supervisor::spawn(config(), deps(factory, Arc::new(NoSystemEvents::default())));
            tx.send(start()).await.unwrap();

            let seen = states_until(&mut rx, |s| matches!(s, State::Failed { .. })).await;
            match seen.last().unwrap() {
                State::Failed { class, message } => {
                    assert_eq!(*class, ErrorClass::Fatal);
                    assert!(message.contains("host key"), "{message}");
                }
                other => panic!("{other:?}"),
            }
            tokio::time::sleep(Duration::from_secs(120)).await;
            assert_eq!(calls.lock().unwrap().len(), 1);
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn network_failure_backs_off_along_the_documented_sequence() {
        guard(async {
            let outcomes = (0..4)
                .map(|_| Outcome::Err(Error::Tcp("refused".into())))
                .chain(std::iter::once(Outcome::Ok(vec![
                    TunnelMsg::Authenticated {
                        host_key_fp: "SHA256:aaa".into(),
                        first_seen: false,
                    },
                    TunnelMsg::ForwardRegistered { port: 22001 },
                ])))
                .collect();
            let (factory, _calls) = Scripted::new(outcomes);
            let (tx, mut rx) =
                Supervisor::spawn(config(), deps(factory, Arc::new(NoSystemEvents::default())));
            tx.send(start()).await.unwrap();

            let seen = states_until(&mut rx, |s| matches!(s, State::Connected { .. })).await;
            let delays: Vec<u64> = seen
                .iter()
                .filter_map(|s| match s {
                    State::Backoff { delay, .. } => Some(delay.as_secs()),
                    _ => None,
                })
                .collect();
            assert_eq!(delays, vec![1, 2, 5, 10]);
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn port_busy_retries_every_five_seconds_then_fails_after_budget() {
        guard(async {
            let outcomes = (0..40)
                .map(|_| Outcome::Err(Error::ForwardPortBusy(22001)))
                .collect();
            let (factory, calls) = Scripted::new(outcomes);
            let (tx, mut rx) =
                Supervisor::spawn(config(), deps(factory, Arc::new(NoSystemEvents::default())));
            tx.send(start()).await.unwrap();

            let seen = states_until(&mut rx, |s| matches!(s, State::Failed { .. })).await;
            match seen.last().unwrap() {
                State::Failed { class, .. } => assert_eq!(*class, ErrorClass::PortBusy),
                other => panic!("{other:?}"),
            }
            let n = calls.lock().unwrap().len();
            let expected = (PORT_BUSY_BUDGET.as_secs() / PORT_BUSY_RETRY.as_secs()) as usize;
            assert!(
                (expected..=expected + 2).contains(&n),
                "预算内应重试约 {expected} 次，实际 {n}"
            );
            // R——见模块顶部第 5 条：界面显示的"第几次重连"不该在整段
            // 120 秒预算里恒为 0。会让这条断言变红的实现改法：
            // `schedule_retry` 的 `PortBusy` 分支不推进 `port_busy_attempt`，
            // 直接用 `ctx.backoff.attempt()`（从不因为 PortBusy 调用
            // `next_delay`，恒为 0）去填 `State::Backoff { attempt, .. }`。
            let attempts: Vec<u32> = seen
                .iter()
                .filter_map(|s| match s {
                    State::Backoff { attempt, .. } => Some(*attempt),
                    _ => None,
                })
                .collect();
            assert!(
                attempts.iter().any(|a| *a > 0),
                "端口占用重试期间界面不该一直显示第 0 次：{attempts:?}"
            );
            assert!(
                attempts.windows(2).all(|w| w[1] > w[0]),
                "端口占用重试计数应该严格递增：{attempts:?}"
            );
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn appliance_dial_failure_turns_degraded_and_recovers() {
        guard(async {
            let (factory, _calls) = Scripted::new(vec![Outcome::Ok(vec![
                TunnelMsg::Authenticated {
                    host_key_fp: "SHA256:aaa".into(),
                    first_seen: false,
                },
                TunnelMsg::ForwardRegistered { port: 22001 },
                TunnelMsg::ApplianceDialFailed {
                    id: 1,
                    reason: "refused".into(),
                },
                TunnelMsg::RemoteSessionOpened { id: 2 },
            ])]);
            let (tx, mut rx) =
                Supervisor::spawn(config(), deps(factory, Arc::new(NoSystemEvents::default())));
            tx.send(start()).await.unwrap();

            states_until(&mut rx, |s| {
                matches!(s, State::Connected { degraded: true })
            })
            .await;
            // 一条会话成功打开即视为恢复。
            states_until(&mut rx, |s| {
                matches!(s, State::Connected { degraded: false })
            })
            .await;
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn degraded_probe_recovers_when_the_appliance_comes_back() {
        guard(async {
            // 探测走真实 TCP。开一个本地监听充当恢复后的一体机。
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                loop {
                    if listener.accept().await.is_err() {
                        return;
                    }
                }
            });

            let (factory, _calls) = Scripted::new(vec![Outcome::Ok(vec![
                TunnelMsg::Authenticated {
                    host_key_fp: "SHA256:aaa".into(),
                    first_seen: false,
                },
                TunnelMsg::ForwardRegistered { port: 22001 },
                TunnelMsg::ApplianceDialFailed {
                    id: 1,
                    reason: "refused".into(),
                },
            ])]);
            // 一体机地址指向那个监听端口，探测应当成功。这是本任务
            // R33/R10 的 for_test 旁路——公开的 `Command::Start` 会拒绝
            // loopback 一体机，见模块顶部第 7 条与
            // `Supervisor::spawn_with_validated_start` 上的文档。
            let gateway: HostPort = "gateway.company.com:443".parse().unwrap();
            let appliance: HostPort = format!("127.0.0.1:{port}").parse().unwrap();
            let (_tx, mut rx) = Supervisor::spawn_with_validated_start(
                config(),
                deps(factory, Arc::new(NoSystemEvents::default())),
                "tunnel-zhang".into(),
                Zeroizing::new("pw".into()),
                ValidatedAddresses::for_test(gateway, appliance),
            );

            states_until(&mut rx, |s| {
                matches!(s, State::Connected { degraded: true })
            })
            .await;
            // 无需任何远程会话，仅靠 30 秒探测就应转回。
            states_until(&mut rx, |s| {
                matches!(s, State::Connected { degraded: false })
            })
            .await;
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn degraded_stays_degraded_while_the_appliance_is_still_down() {
        guard(async {
            let (factory, _calls) = Scripted::new(vec![Outcome::Ok(vec![
                TunnelMsg::Authenticated {
                    host_key_fp: "SHA256:aaa".into(),
                    first_seen: false,
                },
                TunnelMsg::ForwardRegistered { port: 22001 },
                TunnelMsg::ApplianceDialFailed {
                    id: 1,
                    reason: "refused".into(),
                },
            ])]);
            // 端口 1 上没人监听，探测一直失败。同样走
            // spawn_with_validated_start——见上一条测试的说明。
            let gateway: HostPort = "gateway.company.com:443".parse().unwrap();
            let appliance: HostPort = "127.0.0.1:1".parse().unwrap();
            let (_tx, mut rx) = Supervisor::spawn_with_validated_start(
                config(),
                deps(factory, Arc::new(NoSystemEvents::default())),
                "tunnel-zhang".into(),
                Zeroizing::new("pw".into()),
                ValidatedAddresses::for_test(gateway, appliance),
            );

            states_until(&mut rx, |s| {
                matches!(s, State::Connected { degraded: true })
            })
            .await;
            // 连续几个探测周期内都不应转回，也不应断开隧道。
            let deadline = Instant::now() + Duration::from_secs(120);
            while Instant::now() < deadline {
                match tokio::time::timeout(Duration::from_secs(35), rx.recv()).await {
                    Ok(Ok(TunnelEvent::State(s))) => {
                        assert!(
                            matches!(s, State::Connected { degraded: true }),
                            "一体机仍不可达时状态不该变成 {s:?}"
                        );
                    }
                    _ => break,
                }
            }
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn disconnect_reconnects_and_reuses_credentials_without_a_new_start() {
        guard(async {
            let (factory, calls) = Scripted::new(vec![
                Outcome::Ok(vec![
                    TunnelMsg::Authenticated {
                        host_key_fp: "SHA256:aaa".into(),
                        first_seen: false,
                    },
                    TunnelMsg::ForwardRegistered { port: 22001 },
                    TunnelMsg::Disconnected {
                        reason: "reset".into(),
                    },
                ]),
                Outcome::Ok(vec![
                    TunnelMsg::Authenticated {
                        host_key_fp: "SHA256:aaa".into(),
                        first_seen: false,
                    },
                    TunnelMsg::ForwardRegistered { port: 22001 },
                ]),
            ]);
            let (tx, mut rx) =
                Supervisor::spawn(config(), deps(factory, Arc::new(NoSystemEvents::default())));
            tx.send(start()).await.unwrap();

            states_until(&mut rx, |s| matches!(s, State::Backoff { .. })).await;
            states_until(&mut rx, |s| matches!(s, State::Connected { .. })).await;

            let calls = calls.lock().unwrap();
            assert_eq!(calls.len(), 2);
            assert_eq!(calls[0].username, calls[1].username);
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn network_event_clears_backoff_and_retries_at_once() {
        guard(async {
            let outcomes = vec![
                Outcome::Err(Error::Tcp("refused".into())),
                Outcome::Err(Error::Tcp("refused".into())),
                Outcome::Err(Error::Tcp("refused".into())),
                Outcome::Ok(vec![
                    TunnelMsg::Authenticated {
                        host_key_fp: "SHA256:aaa".into(),
                        first_seen: false,
                    },
                    TunnelMsg::ForwardRegistered { port: 22001 },
                ]),
            ];
            let (factory, _calls) = Scripted::new(outcomes);
            let (ev_tx, _) = broadcast::channel(8);
            let events = Arc::new(ManualEvents(ev_tx.clone()));
            let (tx, mut rx) = Supervisor::spawn(config(), deps(factory, events));
            tx.send(start()).await.unwrap();

            states_until(&mut rx, |s| matches!(s, State::Backoff { attempt: 2, .. })).await;
            ev_tx.send(SystemEvent::NetworkChanged).unwrap();

            let seen = states_until(&mut rx, |s| matches!(s, State::Connected { .. })).await;
            // 事件触发后下一次退避必须回到序列起点。
            let delays: Vec<u64> = seen
                .iter()
                .filter_map(|s| match s {
                    State::Backoff { delay, .. } => Some(delay.as_secs()),
                    _ => None,
                })
                .collect();
            assert_eq!(delays.last(), Some(&1), "退避未清零：{delays:?}");
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn stop_from_connected_returns_to_idle() {
        guard(async {
            let (factory, _calls) = Scripted::new(vec![Outcome::Ok(vec![
                TunnelMsg::Authenticated {
                    host_key_fp: "SHA256:aaa".into(),
                    first_seen: false,
                },
                TunnelMsg::ForwardRegistered { port: 22001 },
            ])]);
            let (tx, mut rx) =
                Supervisor::spawn(config(), deps(factory, Arc::new(NoSystemEvents::default())));
            tx.send(start()).await.unwrap();
            states_until(&mut rx, |s| matches!(s, State::Connected { .. })).await;

            tx.send(Command::Stop).await.unwrap();
            let seen = states_until(&mut rx, |s| matches!(s, State::Idle)).await;
            assert!(seen.iter().any(|s| matches!(s, State::Stopping)));
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn stop_during_backoff_returns_to_idle_and_stops_retrying() {
        guard(async {
            let outcomes = (0..20)
                .map(|_| Outcome::Err(Error::Tcp("refused".into())))
                .collect();
            let (factory, calls) = Scripted::new(outcomes);
            let (tx, mut rx) =
                Supervisor::spawn(config(), deps(factory, Arc::new(NoSystemEvents::default())));
            tx.send(start()).await.unwrap();
            states_until(&mut rx, |s| matches!(s, State::Backoff { .. })).await;

            tx.send(Command::Stop).await.unwrap();
            states_until(&mut rx, |s| matches!(s, State::Idle)).await;
            let before = calls.lock().unwrap().len();
            tokio::time::sleep(Duration::from_secs(120)).await;
            assert_eq!(calls.lock().unwrap().len(), before, "停止后仍在重试");
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn remote_sessions_are_reported_with_traffic_and_removed_on_close() {
        guard(async {
            let (factory, _calls) = Scripted::new(vec![Outcome::Ok(vec![
                TunnelMsg::Authenticated {
                    host_key_fp: "SHA256:aaa".into(),
                    first_seen: false,
                },
                TunnelMsg::ForwardRegistered { port: 22001 },
                TunnelMsg::RemoteSessionOpened { id: 7 },
                TunnelMsg::RemoteSessionBytes {
                    id: 7,
                    to_appliance: 100,
                    from_appliance: 200,
                },
                TunnelMsg::RemoteSessionClosed { id: 7 },
            ])]);
            let (tx, mut rx) =
                Supervisor::spawn(config(), deps(factory, Arc::new(NoSystemEvents::default())));
            tx.send(start()).await.unwrap();

            let mut with_traffic = false;
            let mut emptied = false;
            let deadline = Instant::now() + Duration::from_secs(60);
            while Instant::now() < deadline && !(with_traffic && emptied) {
                if let Ok(TunnelEvent::RemoteSessions(list)) = rx.recv().await {
                    if list.iter().any(|s| s.id == 7 && s.from_appliance == 200) {
                        with_traffic = true;
                    }
                    if with_traffic && list.is_empty() {
                        emptied = true;
                    }
                }
            }
            assert!(with_traffic, "没有收到带流量的会话列表");
            assert!(emptied, "会话关闭后列表未清空");
        })
        .await;
    }

    // --- 第七条：公开的 Command::Start 必须做地址校验，且必须有测试
    // 钉住它做了。---

    /// 一旦被调用就 panic 的工厂——跟 Task 9 那条 Pass 测试证明"预检
    // 失败时 establish 一次都不会被调用"用的是同一个手法：如果
    /// `Command::Start` 的处理跳过了 `ValidatedAddresses::validate`、
    /// 直接拿裸 `HostPort` 拼 `Credentials` 去 `attempt()`，这个工厂会
    /// 被调用到，测试当场 panic（红）。
    struct PanicsIfEstablishIsCalled;

    #[async_trait::async_trait]
    impl TunnelFactory for PanicsIfEstablishIsCalled {
        async fn establish(
            &self,
            _params: TunnelParams,
            _tx: mpsc::Sender<TunnelMsg>,
        ) -> crate::error::Result<Box<dyn TunnelHandle>> {
            panic!("地址校验应该在建立隧道之前就已经拒绝，establish 不该被调用");
        }
    }

    // 会让这条测试变红的实现改法：把 `Command::Start` 处理里的
    // `ValidatedAddresses::validate(gateway, appliance)` 删掉，直接用
    // 命令携带的裸 `gateway`/`appliance` 构造 `Credentials`——那样
    // `run_preflight` 会照常通过（`AlwaysPassPreflight` 不检查地址），
    // `attempt()` 会调用 `PanicsIfEstablishIsCalled::establish`，测试
    // panic。
    #[tokio::test(start_paused = true)]
    async fn start_rejects_appliance_equal_to_gateway_before_touching_the_factory() {
        guard(async {
            let (tx, mut rx) = Supervisor::spawn(
                config(),
                deps(
                    Arc::new(PanicsIfEstablishIsCalled),
                    Arc::new(NoSystemEvents::default()),
                ),
            );
            let gw: HostPort = "gateway.company.com:443".parse().unwrap();
            tx.send(Command::Start {
                username: "tunnel-zhang".into(),
                password: Zeroizing::new("pw".into()),
                gateway: gw.clone(),
                appliance: gw,
            })
            .await
            .unwrap();

            let seen = states_until(&mut rx, |s| matches!(s, State::Failed { .. })).await;
            match seen.last().unwrap() {
                State::Failed { class, message } => {
                    assert_eq!(*class, ErrorClass::Fatal);
                    assert!(message.contains("一体机"), "{message}");
                }
                other => panic!("{other:?}"),
            }
            assert!(
                !seen
                    .iter()
                    .any(|s| matches!(s, State::Preflight | State::Connecting)),
                "校验失败不该走到预检或建连：{seen:?}"
            );
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn start_rejects_loopback_appliance_before_touching_the_factory() {
        guard(async {
            let (tx, mut rx) = Supervisor::spawn(
                config(),
                deps(
                    Arc::new(PanicsIfEstablishIsCalled),
                    Arc::new(NoSystemEvents::default()),
                ),
            );
            tx.send(Command::Start {
                username: "tunnel-zhang".into(),
                password: Zeroizing::new("pw".into()),
                gateway: "gateway.company.com:443".parse().unwrap(),
                appliance: "127.0.0.1:22".parse().unwrap(),
            })
            .await
            .unwrap();

            let seen = states_until(&mut rx, |s| matches!(s, State::Failed { .. })).await;
            match seen.last().unwrap() {
                State::Failed { class, .. } => assert_eq!(*class, ErrorClass::Fatal),
                other => panic!("{other:?}"),
            }
        })
        .await;
    }

    // --- 第三条：port_busy_since 必须在非 PortBusy 错误时清零 ---

    fn test_ctx() -> Ctx {
        let (ev, _rx) = broadcast::channel(16);
        Ctx {
            cfg: config(),
            deps: deps(
                Arc::new(PanicsIfEstablishIsCalled),
                Arc::new(NoSystemEvents::default()),
            ),
            ev,
            state: State::Connected { degraded: false },
            creds: Some(Credentials {
                username: "tunnel-zhang".into(),
                password: Zeroizing::new("pw".into()),
                addrs: ValidatedAddresses::validate(
                    "gateway.company.com:443".parse().unwrap(),
                    "192.168.100.10:22".parse().unwrap(),
                )
                .unwrap(),
            }),
            handle: None,
            sessions: BTreeMap::new(),
            backoff: Backoff::new(Box::new(FixedJitter(1.0))),
            port_busy_attempt: 0,
            port_busy_since: None,
        }
    }

    // 会让这条测试变红的实现改法：删掉 `schedule_retry` 顶部"非
    // PortBusy 就清空 port_busy_since/port_busy_attempt"这几行——那样
    // 第二次 `ForwardPortBusy` 会沿用第一次记下的 `since`，快进 5 分钟
    // 之后 `since.elapsed() >= PORT_BUSY_BUDGET` 立刻成立，状态变成
    // `Failed` 而不是 `Backoff`，`next.is_some()` 断言失败。
    #[tokio::test(start_paused = true)]
    async fn port_busy_since_resets_when_a_different_error_class_intervenes() {
        guard(async {
            let mut ctx = test_ctx();

            // 第一次端口占用：记下 since，重试计数从 1 开始。
            let _ = schedule_retry(&mut ctx, Error::ForwardPortBusy(22001));
            assert!(ctx.port_busy_since.is_some());
            assert_eq!(ctx.port_busy_attempt, 1);

            // 换成网络错误：应清空端口占用的计时与计数。
            let _ = schedule_retry(&mut ctx, Error::Tcp("refused".into()));
            assert!(
                ctx.port_busy_since.is_none(),
                "非端口占用错误应清空 port_busy_since"
            );
            assert_eq!(ctx.port_busy_attempt, 0);

            // 时间快进 5 分钟——如果 since 没被清零、且用的是会被虚拟时钟
            // 骗过的 std::time::Instant，这里会直接判定预算耗尽、转 Failed。
            tokio::time::advance(Duration::from_secs(300)).await;

            // 全新的端口占用：预算应该从 0 重新计时，不应立刻 Failed。
            let next = schedule_retry(&mut ctx, Error::ForwardPortBusy(22001));
            assert!(
                matches!(ctx.state, State::Backoff { .. }),
                "{:?}",
                ctx.state
            );
            assert!(next.is_some(), "预算应该重新计时，不应该判定用完");
        })
        .await;
    }

    // --- 第四条：ApplianceUnreachable 不走网络类的指数退避 ---

    // 会让这条测试变红的实现改法：把 `schedule_retry` 里
    // `ErrorClass::ApplianceUnreachable` 的分支跟 `ErrorClass::Network`
    // 合并（`ErrorClass::Network | ErrorClass::ApplianceUnreachable =>
    // {...}`，brief 原文的写法）——`delay` 会变成
    // `ctx.backoff.next_delay()` 算出来的指数退避值（第一次是 1 秒，
    // 不等于 `APPLIANCE_PROBE` 的 30 秒），且 `ctx.backoff.attempt()`
    // 会被推进到 1，两条断言都会失败。
    #[tokio::test(start_paused = true)]
    async fn schedule_retry_routes_appliance_unreachable_to_a_fixed_probe_not_exponential_backoff()
    {
        guard(async {
            let mut ctx = test_ctx();
            let next = schedule_retry(&mut ctx, Error::ApplianceUnreachable("refused".into()));
            assert!(next.is_some());
            match &ctx.state {
                State::Backoff { delay, .. } => assert_eq!(*delay, APPLIANCE_PROBE),
                other => panic!("{other:?}"),
            }
            assert_eq!(ctx.backoff.attempt(), 0, "不该推进网络类的指数退避计数");
        })
        .await;
    }

    // --- 第五条：PortBusy 路径上 Backoff{attempt} 不该恒为 0 ---
    //
    // `port_busy_retries_every_five_seconds_then_fails_after_budget` 里已经
    // 有一条端到端的断言覆盖这一点；这条单独用 schedule_retry 直接调用，
    // 把"逐次递增"钉得更精确（1, 2, 3...），不依赖端到端时序。

    // 会让这条测试变红的实现改法：`schedule_retry` 的 `PortBusy` 分支不
    // 推进 `ctx.port_busy_attempt`，直接用 0 或 `ctx.backoff.attempt()`
    // （从不因为 PortBusy 调用 `next_delay`，恒为 0）填 `State::Backoff
    // { attempt, .. }`——第二次断言 `assert_eq!(*attempt, 2)` 会失败,
    // 实际会看到 1（或者一直是 0）。
    #[tokio::test(start_paused = true)]
    async fn port_busy_backoff_attempt_increments_across_retries() {
        guard(async {
            let mut ctx = test_ctx();
            for expected in 1..=3u32 {
                let _ = schedule_retry(&mut ctx, Error::ForwardPortBusy(22001));
                match &ctx.state {
                    State::Backoff { attempt, delay } => {
                        assert_eq!(
                            *attempt, expected,
                            "第 {expected} 次端口占用重试，界面不该一直显示同一个数"
                        );
                        assert_eq!(*delay, PORT_BUSY_RETRY);
                    }
                    other => panic!("{other:?}"),
                }
            }
        })
        .await;
    }

    // --- 第十条：keepalive 断线判定耗时的端到端实测 ---
    //
    // 不使用 Scripted 假隧道——这里要测的是"真实的 ssh::establish_over
    // 建立的隧道，在服务端不再应答之后，状态机需要多久才能感知并转入
    // State::Backoff"，脚本化假隧道压根不会经过 russh 的 keepalive
    // 定时器，测不出这个数。用 Task 7 的进程内 russh 服务端夹具
    // （`ssh::test_support::spawn_freezable_gateway`）造"服务端不再
    // 应答"的场景——冻结后连接既不报错也不产生任何字节，模拟网络黑洞，
    // 不需要 docker，也不需要真实网络。
    //
    // 实测结果与测量条件见 task-10-report.md 与 docs/方案设计.md §3.4。

    struct FreezeAfterEstablish {
        state: Mutex<
            Option<(
                crate::ssh::test_support::FreezeSwitch,
                crate::ssh::test_support::ReadTimestamps,
            )>,
        >,
    }

    #[async_trait::async_trait]
    impl TunnelFactory for FreezeAfterEstablish {
        async fn establish(
            &self,
            params: TunnelParams,
            tx: mpsc::Sender<TunnelMsg>,
        ) -> crate::error::Result<Box<dyn TunnelHandle>> {
            use crate::ssh::test_support::{
                spawn_freezable_gateway, test_gateway_hostport, tmp_known_hosts, GatewayConfig,
            };
            let (reads, switch, pending, conn) = spawn_freezable_gateway(GatewayConfig {
                permitted_port: params.reverse_port as u32,
                accept_password: true,
            });
            let known_hosts = Arc::new(tmp_known_hosts());
            let handle = crate::ssh::establish_over(
                conn,
                &test_gateway_hostport(),
                &known_hosts,
                params,
                tx,
            )
            .await?;
            *self.state.lock().unwrap() = Some((switch, reads));
            // 不需要驱动服务端 handle 做任何事，这条测试只关心客户端一侧
            // 的行为；丢弃它不影响后台的 `run_stream` 任务继续运行。
            drop(pending);
            Ok(handle)
        }
    }

    // 会让这条断言变红的实现改法：删掉 `ssh::mod::spawn_disconnect_watcher`
    // 对 `establish_over` 的接线（那样连接冻结之后永远不会有
    // `TunnelMsg::Disconnected` 送出，`states_until` 等不到
    // `State::Backoff`，300 秒的 `guard` 超时会先触发，测试失败但不是
    // 因为这条时间断言）；或者把 `ssh::client_config()` 里的
    // `keepalive_interval`/`keepalive_max` 改掉——耗时会明显偏离
    // 39～41 秒这个窗口。
    #[tokio::test(start_paused = true)]
    async fn keepalive_disconnect_is_measured_end_to_end_from_a_real_ssh_session() {
        guard(async {
            use crate::ssh::test_support::{TEST_PASSWORD, TEST_USER};

            let factory = Arc::new(FreezeAfterEstablish {
                state: Mutex::new(None),
            });
            let (tx, mut rx) = Supervisor::spawn(
                config(),
                deps(factory.clone(), Arc::new(NoSystemEvents::default())),
            );
            tx.send(Command::Start {
                username: TEST_USER.into(),
                password: Zeroizing::new(TEST_PASSWORD.into()),
                gateway: "gateway.company.com:443".parse().unwrap(),
                appliance: "192.168.100.10:61001".parse().unwrap(),
            })
            .await
            .unwrap();

            states_until(&mut rx, |s| {
                matches!(s, State::Connected { degraded: false })
            })
            .await;

            let (switch, reads) = factory
                .state
                .lock()
                .unwrap()
                .take()
                .expect("establish 应该已经记录冻结开关");
            // 掐表：从这一刻起，服务端不再应答任何字节（既不报错也不
            // 回复，模拟网络黑洞），直到状态机真的判定断线。
            switch.freeze();
            let t0 = reads
                .snapshot()
                .into_iter()
                .max()
                .expect("握手/认证/端口注册期间服务端应至少读到过字节");

            let seen = states_until(&mut rx, |s| matches!(s, State::Backoff { .. })).await;
            let elapsed = Instant::now().duration_since(t0);

            eprintln!(
                "[Task 10 实测] keepalive 断线判定（连接冻结到 State::Backoff）\
                 耗时：{elapsed:?}（{}ms）",
                elapsed.as_millis()
            );

            // 10 秒一次 keepalive、keepalive_max = 3：russh 客户端在
            // `alive_timeouts > keepalive_max` 时判定超时，也就是第 4 次
            // 未获应答的 keepalive（t = 4×10 = 40 秒），不是
            // 10×3 = 30 秒这个未经实测的乘法——这正是方案设计.md §3.4
            // 明确要求必须实测、不能直接推定的地方。窗口留了 ±1 秒，
            // 覆盖 watcher 200ms 轮询与调度带来的极小滞后。
            assert!(
                elapsed >= Duration::from_secs(39) && elapsed <= Duration::from_secs(41),
                "keepalive 断线判定耗时应接近实测的 40 秒，实际 {elapsed:?}；\
                 状态序列：{seen:?}"
            );
        })
        .await;
    }
}
