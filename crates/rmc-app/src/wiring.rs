//! 把平台实现装进 rmc-core 的 Supervisor，并给界面一条收事件的路。
//!
//! 前九个任务做出来的零件到这一轮为止**一个都还没接上**：代理解析器没有
//! 构造点、SSPI 认证器没有调用点、DPAPI 存储的落点没定、电源事件没人
//! 订阅。这个文件就是那个收口点。
//!
//! # W171：`#[cfg(windows)]` 里只准放搬运，不准放判断
//!
//! Task 5 用八枪实测过：`#[cfg(windows)]` 那一层里**任何还能编译的语义
//! 改动，本项目的六道闸门按构造检测不到**（闸门 5 是 `cargo zigbuild`，
//! 只编译；闸门 6 是同目标的 clippy，只静态检查；**两道都不跑测试**）。
//! 连把 `Box::leak` 换成一个悬垂的栈指针都六道全绿。
//!
//! 所以这个模块里 `cfg` 只出现在一个地方——[`Platform::detect`]，它的
//! 全部职责是「这台机器用哪四个实现」，一行判断都没有。别的全在平台中立
//! 的函数里，macOS 上 `cargo test` 每一次都跑到：
//!
//! - [`AppPaths::from_env`]：`%LOCALAPPDATA%\rmc\` 那个落点怎么算（W28）；
//! - [`wire_egress`]：出网那三件东西怎么串（W170，见下）；
//! - [`spawn_core`]：Supervisor 的 `Deps` 怎么拼。
//!
//! 形状照 Task 9 的 W158（把十格映射搬进 rmc-core，rmc-win 只剩转抄）。
//!
//! # W170：出网这三件东西怎么串，是这一轮最容易接错的地方
//!
//! brief 给的那段接线**四处都不对**，而且四处都不会在 macOS 上被发现
//! （它整段都在 `#[cfg(windows)]` 里）：
//!
//! 1. `SspiProxyAuthenticator::new` 收**两个**参数（`endpoint` 与
//!    `factory`），brief 只传了一个闭包；
//! 2. 工厂收的是 `(SspiPackage, &str /*SPN*/)`，brief 写的是 `Fn(&str)`；
//! 3. brief 拿**认证方案**（`"Negotiate"` / `"NTLM"`）去拼 SPN，拼出
//!    `HTTP/Negotiate`——**这正是 W3 当年花一整轮修掉的那个 bug**。SPN
//!    必须用代理主机名。rmc-win 把工厂签名改成收 SPN，就是为了让
//!    `HTTP/{scheme}` 写都写不出来；
//! 4. `ProxyEndpointRecorder` 整个缺席。它是协商器知道「这次连接实际
//!    要用哪台代理」的唯一途径——brief 直接把解析器当 resolver 传给
//!    `Transport`，协商器无从得知代理是谁，每一次协商都会落到
//!    `AuthOutcome::UnknownProxyEndpoint`，**而 CONNECT 失败这件事在
//!    界面上跟别的失败长得一模一样**。
//!
//! [`wire_egress`] 把这四件事全收进一个平台中立的函数，
//! [`tests::the_negotiator_asks_for_an_spn_built_from_the_proxy_host`]
//! 在这台机器上真的驱动一轮协商去看它问的是哪个 SPN。

use crate::logs;
use rmc_core::audit;
use rmc_core::backoff::RandJitter;
use rmc_core::config::Config;
use rmc_core::platform::{NoProxyAuth, ProxyAuthenticator, ProxyResolver, SystemEvents};
use rmc_core::preflight::TransportPreflight;
use rmc_core::ssh::SshTunnelFactory;
use rmc_core::state::{Command, TunnelEvent};
use rmc_core::supervisor::{Deps, Supervisor};
use rmc_core::transport::Transport;
use rmc_win::secret::{FileSecretStore, Sealer, SecretStore};
use rmc_win::sspi::{
    ProxyEndpoint, ProxyEndpointRecorder, SspiContextFactory, SspiProxyAuthenticator,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};

// =====================================================================
// W28：落点
// =====================================================================

/// 应用目录。方案 §3.8：`%LOCALAPPDATA%\rmc\`。
///
/// **落点一次接完**（W28）：审计日志、记住的密码、上一次记住密码的
/// 连接码（W200）。在这一轮之前它们各自等着一个落点——`Config::
/// default()` 给的是相对路径（`logs`，跟着进程的当前目录跑），
/// `FileSecretStore` 的构造函数上明写着「`dir` 从哪来由接线的那一层
/// 决定」。就是这一层。
///
/// Task 10：`known_hosts()` 删掉了——SSH host key 校验换成核对连接码
/// 里的指纹，没有本地文件需要落点，`Config` 也不再有 `known_hosts_path`
/// 字段。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPaths {
    root: PathBuf,
}

impl AppPaths {
    /// 从环境变量算落点。**纯函数**，两个入参就是两个环境变量的值。
    ///
    /// 写成收参数而不是自己去读 `std::env`，是为了让 Windows 那条路
    /// （`%LOCALAPPDATA%`）在这台 macOS 机器上也能被测到——否则它又是
    /// 一段只有 Windows 上才跑得到、因而没有任何东西看得见的判断。
    ///
    /// 三档回退：
    ///
    /// 1. `%LOCALAPPDATA%\rmc`——Windows 上的正解，每个用户账户私有，
    ///    访问控制靠 NTFS ACL（见 `rmc_core::audit` 里 R88 的说明）；
    /// 2. `$HOME/.rmc`——非 Windows 上跑界面时用（开发与将来的跨平台）；
    /// 3. `./rmc-data`——两个都没有时的兜底。**不是静默落在当前目录下的
    ///    `logs/`**：那正是这一轮之前的样子，日志会跟着进程的工作目录
    ///    到处跑，而用户根本不知道该去哪儿找。
    pub fn from_env(local_app_data: Option<&str>, home: Option<&str>) -> Self {
        let base = [local_app_data, home]
            .into_iter()
            .flatten()
            .map(str::trim)
            .find(|s| !s.is_empty());
        let root = match (base, local_app_data.map(str::trim).unwrap_or_default()) {
            // `%LOCALAPPDATA%` 已经是"每个应用建一个子目录"的地方，直接
            // 挂 `rmc`；`$HOME` 不是，按 Unix 惯例加一个点。
            (Some(b), lad) if !lad.is_empty() => PathBuf::from(b).join("rmc"),
            (Some(b), _) => PathBuf::from(b).join(".rmc"),
            (None, _) => PathBuf::from("rmc-data"),
        };
        Self { root }
    }

    /// 真正去读环境变量。`main()` 用它，测试用 [`Self::from_env`]。
    pub fn resolve() -> Self {
        Self::from_env(
            std::env::var("LOCALAPPDATA").ok().as_deref(),
            std::env::var("HOME").ok().as_deref(),
        )
    }

    /// 直接指定根目录，测试用。
    pub fn at(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// 审计日志目录（也是日志页读的地方、诊断包收的地方）。
    ///
    /// 单独一个子目录，不直接用根目录：`diag::bundle` 会把 `log_dir` 下
    /// 所有 `rmc-*.log` 收进包里，根目录下还躺着密文，混在一起早晚出事。
    pub fn log_dir(&self) -> PathBuf {
        self.root.join("logs")
    }

    /// 记住的密码（DPAPI 密文）落在哪儿。
    pub fn secrets_dir(&self) -> PathBuf {
        self.root.join("secrets")
    }

    /// 上一次连过的运维服务器的连接码（W200）。
    ///
    /// **不含任何秘密**：连接码本身没有秘密（账号、地址、指纹都是公开
    /// 信息，见 `rmc_core::code` 模块文档），一行纯文本。为什么需要它见
    /// [`crate::remember`] 的模块文档——key 是「账号@运维服务器」，而
    /// 启动那一刻表单是空的，不记下来就拼不出 key。
    ///
    /// Task 8：文件名从 `last-account.txt` 改成 `connection-code.txt`，
    /// 内容从「账号 + 主机 + 端口」三行纯文本改成一条连接码。
    ///
    /// **Task 11 起，这份记录跟「记住密码」那个勾完全无关**：
    /// [`crate::remember::persist_code`] 每次连接成功都写它，不看勾选。
    /// 「盘上那份密文到底属于哪个 key」这件事**不**由这份记录回答——
    /// 那是 [`Self::remembered_key`] 的职责，两者故意拆成两个文件（见
    /// R11-2 修复轮）：`persist_code` 这一路写坏了、或者写的时机跟
    /// `save` 不同步，都不该连带影响「上一次记住的密文是谁」这个答案。
    ///
    /// 放根目录下，不放 `secrets/`：那个目录里只该有密文，混进一个明文
    /// 文件迟早让人看错。也不放 `logs/`：`diag::bundle` 会把 `log_dir`
    /// 下的东西整个收进诊断包。
    pub fn connection_code(&self) -> PathBuf {
        self.root.join("connection-code.txt")
    }

    /// **盘上那份密文（如果有）属于哪个 key**——`remember::save` 唯一的
    /// 写方（只在 `SecretStore::save` 真的成功之后才写），
    /// `remember::clear` 负责删。
    ///
    /// R11-2 修复轮新增：Task 11 之前，「上一次记住的是谁」跟
    /// [`Self::connection_code`] 是同一份记录，两者共用一个写方
    /// （`remember::save`）。Task 11 给 `connection_code` 加了第二个写方
    /// （`persist_code`，不看 `save` 成没成功），于是「哪个 key 有密文」
    /// 这个问题的答案会被一个跟密文毫无关系的写方悄悄改掉——`save`
    /// 失败时 `persist_code` 照样把 `connection_code` 改成新账号，下次
    /// 取消勾选就会把旧账号的密文错当成「已经不是上一次了」，放它一条
    /// 生路，永久留成孤儿（复审的 W202 回归 PoC，[`crate::remember`]
    /// 模块测试 `persist_code_failing_a_save_does_not_orphan_the_
    /// previous_secret` 钉着）。
    ///
    /// 拆成独立文件之后，这个答案只可能被 `save` 的成功路径改动，
    /// `persist_code` 写它自己的 `connection_code` 完全碰不到这里。
    pub fn remembered_key(&self) -> PathBuf {
        self.root.join("remembered-key.txt")
    }

    /// 诊断包写到哪儿。放根目录下，不跟日志混在一起——包本身不是日志，
    /// 而且 `bundle` 每次都写一个带时间戳的新文件。
    pub fn export_dir(&self) -> PathBuf {
        self.root.clone()
    }

    /// 今天那份日志文件的完整路径。文件名怎么拼由 rmc-core 说了算。
    pub fn current_log(&self) -> PathBuf {
        audit::current_path_in(&self.log_dir())
    }

    /// 配好落点的一份配置。
    ///
    /// 地址那两项仍然是 `Config::default()` 的占位值：真正用来拨号的
    /// 地址由 `Command::Start` 携带（见 `rmc_core::state::Command` 上的
    /// 说明），Supervisor 不看 `Config` 里的那两个。
    pub fn config(&self) -> Config {
        Config {
            log_dir: self.log_dir(),
            ..Config::default()
        }
    }
}

// =====================================================================
// W171：唯一的 cfg 块
// =====================================================================

/// 这台机器上用哪四个实现。
///
/// **构造它是这个模块里唯一带 `cfg` 的事**，见模块文档 W171 一节。
/// 四个字段全是"零件"，没有一个带判断——怎么串是 [`wire_egress`] 与
/// [`spawn_core`] 的事，那两个函数在任何平台上都跑得到。
pub struct Platform {
    /// 系统代理配置从哪儿来。
    pub proxy: Arc<dyn ProxyResolver>,
    /// 怎么造 SSPI 安全上下文。`None` 表示这台机器不做代理认证协商
    /// （非 Windows），遇到 407 会如实失败，不是假装谈过。
    pub sspi: Option<SspiContextFactory>,
    /// 休眠恢复与网络变化事件从哪儿来。
    pub events: Arc<dyn SystemEvents>,
    /// 用什么把口令密封到盘上。`None` 表示这台机器不支持记住密码。
    pub sealer: Option<Box<dyn Sealer>>,
    /// 网络连通性轮询线程的凭据（W198）。
    ///
    /// **拿着它就等于那个线程还在跑**：它一 `Drop`，轮询就在下一轮退出。
    /// [`spawn_core`] 把它接进 [`Core`]，于是轮询跟整个客户端一起活、
    /// 一起停——不再是上一轮那个「进程活多久就每 2 秒醒一次多久、谁也
    /// 叫不停」的线程。
    ///
    /// `None` 表示这台机器上根本没有那个线程（非 Windows）。
    pub network_polling: Option<rmc_win::events::NetworkPolling>,
}

impl Platform {
    #[cfg(windows)]
    pub fn detect() -> Self {
        use rmc_win::events::{spawn_win32_listeners, EventHub};
        use rmc_win::proxy::{winhttp::WinHttpSource, SystemProxyResolver};
        use rmc_win::secret::DpapiSealer;
        use rmc_win::sspi::{NegotiateContext, SspiContext, SspiPackage};

        let hub = Arc::new(EventHub::new());
        // 注册电源与网络通知。失败只记日志（那两个函数自己记），客户端
        // 照常能用，只是恢复慢一些——见 `spawn_win32_listeners`。
        //
        // W198：返回的句柄**必须拿住**（那个函数是 `#[must_use]` 的）。
        // 丢掉它，网络轮询线程会在启动后的下一轮当场退出，而界面上
        // 一个字都看不出来。
        let network_polling = spawn_win32_listeners(Arc::clone(&hub));

        Self {
            network_polling: Some(network_polling),
            proxy: Arc::new(SystemProxyResolver::new(WinHttpSource::new())),
            // 工厂收的是 `(安全包, SPN)`，**SPN 由 rmc-win 自己用代理
            // 主机名拼好**（`spn_for_proxy`），这里拿不到 scheme，也就
            // 写不出 brief 那个 `HTTP/{scheme}`——见模块文档 W170。
            sspi: Some(Box::new(|package: SspiPackage, spn: &str| {
                NegotiateContext::new(package, spn).map(|c| Box::new(c) as Box<dyn SspiContext>)
            })),
            events: hub,
            sealer: Some(Box::new(DpapiSealer)),
        }
    }

    #[cfg(not(windows))]
    pub fn detect() -> Self {
        use rmc_core::platform::{NoProxy, NoSystemEvents};

        Self {
            proxy: Arc::new(NoProxy),
            // 没有 SSPI：遇到 407 会如实失败（`NoProxyAuth`），诊断页
            // 上写的是"代理要求认证，而这次协商没有通过"，不是假装谈过。
            sspi: None,
            events: Arc::new(NoSystemEvents::default()),
            // 没有 DPAPI：不支持记住密码。**不退回明文存盘**。
            sealer: None,
            // 没有 NLM：根本没有那个轮询线程（W198）。
            network_polling: None,
        }
    }
}

// =====================================================================
// W170：出网那三件东西怎么串
// =====================================================================

/// 串好的出网通道。
pub struct Egress {
    pub transport: Arc<Transport>,
    /// 同一个协商器，`Transport` 里那一份的另一个 `Arc`。
    /// [`tests::the_negotiator_asks_for_an_spn_built_from_the_proxy_host`]
    /// 靠它直接驱动一轮协商。
    pub authenticator: Arc<dyn ProxyAuthenticator>,
}

/// 把解析器、记录器、协商器、`Transport` 串起来。
///
/// **这个函数的全部要害是一件事**：`ProxyEndpointRecorder` 这一个对象
/// 要同时坐在两个位子上——`Transport` 的 resolver 位，和协商器的
/// endpoint 位。它是协商器知道「这次连接实际经过哪台代理」的唯一途径，
/// 而那个信息是拼 SPN 用的。两边各造一个（或者干脆不造），协商器会拿到
/// 一个永远是 `None` 的出口，每次协商都落进
/// `AuthOutcome::UnknownProxyEndpoint`。
///
/// 见模块文档 W170。
pub fn wire_egress(proxy: Arc<dyn ProxyResolver>, sspi: Option<SspiContextFactory>) -> Egress {
    let recorder = Arc::new(ProxyEndpointRecorder::new(proxy));

    let authenticator: Arc<dyn ProxyAuthenticator> = match sspi {
        Some(factory) => Arc::new(SspiProxyAuthenticator::new(
            // ★ 同一个 `Arc`，下面 `Transport::new` 收的是它的另一个
            //   克隆。这一行是 W170 的全部。
            Arc::clone(&recorder) as Arc<dyn ProxyEndpoint>,
            factory,
        )),
        None => Arc::new(NoProxyAuth),
    };

    let transport = Arc::new(Transport::new(
        recorder as Arc<dyn ProxyResolver>,
        Arc::clone(&authenticator),
    ));

    Egress {
        transport,
        authenticator,
    }
}

// =====================================================================
// 起 Supervisor
// =====================================================================

/// 界面跟内核之间的那根线。
///
/// `Clone` 是刻意的：`App` 持有一份用来发命令，`program()` 另留一份
/// 给订阅用。里面两样东西都是 `Arc`/`Sender`，克隆不复制任何状态。
#[derive(Clone)]
pub struct Core {
    /// 往内核发命令。
    pub commands: mpsc::Sender<Command>,
    /// 事件的源头。每次订阅 `resubscribe()` 一个新的接收端出来——
    /// **不共享同一个接收端**，那会让两个订阅者互相偷事件。
    events: Arc<broadcast::Receiver<TunnelEvent>>,
    pub paths: AppPaths,
    /// 记住的密码存在哪儿。`None` 表示这台机器不支持记住密码。
    pub secrets: Option<Arc<dyn SecretStore>>,
    /// 网络轮询线程的凭据（W198）。`Core` 拿着它，于是轮询跟客户端同生
    /// 共死；`Arc` 是因为 `Core` 是 `Clone` 的——界面一份、订阅一份，
    /// **最后一份丢掉时**轮询才停。
    polling: Option<Arc<rmc_win::events::NetworkPolling>>,
}

impl std::fmt::Debug for Core {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 不打印 `secrets`（里面是密码存储的句柄）也不打印通道内部。
        f.debug_struct("Core")
            .field("paths", &self.paths)
            .field("remembers_passwords", &self.secrets.is_some())
            .field("polls_network", &self.is_polling_network())
            .finish_non_exhaustive()
    }
}

impl Core {
    /// 拼一根线。生产路径上由 [`spawn_core`] 调用；测试里用它注入一个
    /// **假内核**——通道的另一头握在测试手里，于是「界面点了按钮到底
    /// 有没有发出命令」这件事是可观测的，不需要真起一个 Supervisor。
    pub fn new(
        commands: mpsc::Sender<Command>,
        events: broadcast::Receiver<TunnelEvent>,
        paths: AppPaths,
        secrets: Option<Arc<dyn SecretStore>>,
    ) -> Self {
        Self {
            commands,
            events: Arc::new(events),
            paths,
            secrets,
            polling: None,
        }
    }

    /// 接上网络轮询的凭据（W198）。生产路径上由 [`spawn_core`] 调用。
    pub fn with_polling(mut self, polling: Option<rmc_win::events::NetworkPolling>) -> Self {
        self.polling = polling.map(Arc::new);
        self
    }

    /// 网络轮询线程还在不在。`None` 表示这台机器上根本没有那个线程。
    pub fn is_polling_network(&self) -> Option<bool> {
        self.polling.as_ref().map(|p| p.is_polling())
    }

    /// 一个新的事件接收端。
    pub fn subscribe(&self) -> broadcast::Receiver<TunnelEvent> {
        self.events.resubscribe()
    }
}

/// 起 Supervisor，把平台零件全接上。**必须在一个 tokio 运行时里调用**
/// （`Supervisor::spawn` 里面是 `tokio::spawn`）。
///
/// 这个函数整个是平台中立的——`platform` 里装的是什么，它不问。
pub fn spawn_core(paths: AppPaths, platform: Platform) -> Core {
    let Platform {
        proxy,
        sspi,
        events,
        sealer,
        network_polling,
    } = platform;

    let egress = wire_egress(proxy, sspi);
    let config = paths.config();

    let factory = Arc::new(SshTunnelFactory::new(Arc::clone(&egress.transport)));
    let preflight = Arc::new(TransportPreflight::new(Arc::clone(&egress.transport)));

    let (commands, events_rx) = Supervisor::spawn(
        config,
        Deps {
            factory,
            transport: Arc::clone(&egress.transport),
            preflight,
            events,
            jitter: || Box::new(RandJitter),
        },
    );

    // W28 的第三处：记住的密码。`None`（非 Windows）时整个功能不存在，
    // 不退回明文。
    let remembers = sealer.is_some();
    let secrets = sealer
        .map(|s| Arc::new(FileSecretStore::new(paths.secrets_dir(), s)) as Arc<dyn SecretStore>);
    // W181：这台机器有密封器，就必须真的有一个密码存储。
    //
    // **这拦不住"勾选框不工作"**——那是另一件事（整条「记住密码」链路
    // 至今没有生产读方，见 task-10-report.md 的「后续完善」第 1 条）。
    // 它拦的是更窄也更阴的一种：有人把这一行改成 `None` 或者把落点摘掉，
    // 而 `Core::secrets` 今天没有任何读方，摘掉之后**一条测试都不会红**。
    assert_eq!(
        secrets.is_some(),
        remembers,
        "平台给了密封器，装配却没有造出密码存储"
    );

    // W198：把轮询句柄接进 `Core`，跟整个客户端一起活。
    //
    // **顺手丢掉它是这一路唯一会发生的事故**，而且没有任何界面表现：
    // 轮询线程在启动后的下一轮就退出，切网之后不再立刻重连，只是靠
    // 退避序列慢慢恢复。`rmc_win::events::NetworkPolling` 的 `Drop` 让
    // 这件事有后果，[`tests::the_network_polling_handle_lives_as_long_as_the_core`]
    // 让它可观测。
    Core::new(commands, events_rx, paths, secrets).with_polling(network_polling)
}

// =====================================================================
// W192：托盘
// =====================================================================

/// 造一个通知区图标。
///
/// **这是本模块的第二个 `cfg` 块**（第一个是 [`Platform::detect`]），
/// 而且跟第一个一样只做搬运：托盘要画什么颜色、写什么字、要不要弹通知，
/// 全在 [`crate::tray`] 那一层（macOS 上被真的跑到）。这里只回答
/// 「这台机器上用哪个实现」。
///
/// 返回 `None` 表示没有托盘——**不是错误**，界面照常工作。
pub fn open_tray() -> Option<Box<dyn crate::tray::TraySink>> {
    #[cfg(windows)]
    {
        win_tray::open()
    }
    #[cfg(not(windows))]
    {
        crate::tray::no_tray()
    }
}

#[cfg(windows)]
mod win_tray {
    //! `rmc_win::tray::Tray` 到 [`TraySink`] 的一层转接。**一条判断都
    //! 没有**：颜色怎么算、提示怎么截、通知弹不弹，全在
    //! [`crate::tray`]；字节怎么排、缓冲怎么填，全在 `rmc_win::tray`。
    //! 这里只把两边接上。

    use crate::tray::{icon_color, icon_rgba, tooltip, Notification, TraySink};

    pub struct WinTray(rmc_win::tray::Tray);

    impl std::fmt::Debug for WinTray {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            // 里面只有一个 HWND 和一个 HICON，印出来对谁都没用。
            f.write_str("WinTray")
        }
    }

    impl TraySink for WinTray {
        fn show_status(&self, tip: &str, color: iced::Color) {
            self.0.set_status(tip, &icon_rgba(color));
        }

        fn show_notification(&self, n: &Notification) {
            self.0.notify(&n.title, &n.body);
        }
    }

    pub fn open() -> Option<Box<dyn TraySink>> {
        // 初始样子就是「未开启」——跟界面刚起来时状态卡上画的一样，
        // 同一个 `Model::default()` 算出来，不另写一份。
        let initial = crate::model::Model::default();
        rmc_win::tray::Tray::open(&tooltip(&initial), &icon_rgba(icon_color(&initial)))
            .map(|t| Box::new(WinTray(t)) as Box<dyn TraySink>)
    }
}

// =====================================================================
// 打开日志目录
// =====================================================================

/// 这个系统上用哪个命令打开文件管理器，`None` 表示不知道。
///
/// **纯函数，收的是 `std::env::consts::OS` 那个字符串**，不是一对
/// `cfg`——这样三档全都在这台机器上测得到。写成 `cfg` 的话，Windows
/// 那一档（也就是唯一真正要用的那一档）没有任何东西看得见。
pub fn file_manager_for(os: &str) -> Option<&'static str> {
    match os {
        "windows" => Some("explorer"),
        "macos" => Some("open"),
        "linux" => Some("xdg-open"),
        _ => None,
    }
}

/// 在文件管理器里打开 `dir`。返回是否真的起了一个进程。
///
/// 失败不报错也不 panic：点一下「打开日志目录」没反应，比客户端崩掉
/// 好得多；真出问题时日志路径本身就画在页面底部那行字上。
pub fn open_dir(dir: &Path) -> bool {
    let Some(cmd) = file_manager_for(std::env::consts::OS) else {
        tracing::warn!(os = std::env::consts::OS, "不知道这个系统怎么打开目录");
        return false;
    };
    match std::process::Command::new(cmd).arg(dir).spawn() {
        Ok(_) => true,
        Err(e) => {
            tracing::warn!(error = %e, dir = ?dir, "打开日志目录失败");
            false
        }
    }
}

// =====================================================================
// 事件 → 界面消息
// =====================================================================

/// 把一个事件接收端变成一条永不主动结束的消息流。
///
/// # 三种结局一种都不许静默吃掉（同 W82/W94）
///
/// - `Ok(event)`：送上去；
/// - `Err(Lagged)`：**真的漏掉了若干条事件**。接着收，但记一行——界面
///   这一侧漏事件的后果是状态卡停在一个过期的状态上；
/// - `Err(Closed)`：内核没了。流到此为止。
///
/// 收 `Receiver` 而不是 `Core`，是为了让它能被直接喂一个测试自己造的
/// 通道（见 `crate::tests`）。
pub fn events_into<M>(
    rx: broadcast::Receiver<TunnelEvent>,
    wrap: fn(TunnelEvent) -> M,
) -> impl iced::futures::Stream<Item = M> {
    iced::futures::stream::unfold((rx, wrap), move |(mut rx, wrap)| async move {
        loop {
            match rx.recv().await {
                Ok(e) => return Some((wrap(e), (rx, wrap))),
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    tracing::warn!(missed, "界面落后于内核，漏掉了若干条事件");
                }
                Err(broadcast::error::RecvError::Closed) => {
                    tracing::warn!("内核的事件通道已关闭，界面不再收到任何更新");
                    return None;
                }
            }
        }
    })
}

/// 进程级的事件源。
///
/// # 为什么这里必须有一个全局
///
/// `iced::Subscription::run` 收的是一个**函数指针**
/// （`fn() -> impl Stream`），`run_with` 收的是「一个 `Hash` 的值 + 一个
/// 函数指针」。两者都没有地方能放一个 `broadcast::Receiver`——这是 iced
/// 订阅身份（同一个订阅跨帧要能被认出来是同一个）的设计后果，不是可以
/// 绕过的写法问题。
///
/// 一个进程只有一个 Supervisor，所以一个全局在语义上是诚实的。
/// **它只被订阅那一条路用**：`App` 自己持有一份 [`Core`]（发命令、取
/// 路径都走那一份），于是 `App::update` 的全部行为都能在测试里注入一个
/// 假内核来验，不依赖这个全局。
static EVENT_SOURCE: std::sync::OnceLock<Arc<broadcast::Receiver<TunnelEvent>>> =
    std::sync::OnceLock::new();

/// 登记进程级的事件源。第二次调用不会覆盖，返回 `false`。
pub fn install_event_source(core: &Core) -> bool {
    EVENT_SOURCE.set(Arc::clone(&core.events)).is_ok()
}

/// 订阅进程级事件源；还没登记过就是 `None`。
pub fn subscribe_installed() -> Option<broadcast::Receiver<TunnelEvent>> {
    EVENT_SOURCE.get().map(|rx| rx.resubscribe())
}

/// 今天那份日志文件**叫什么名字**。
///
/// 只跟日期有关，**不碰文件系统、不需要知道落点**——底部那行字因此在
/// 任何状态下都完整，包括还没接上内核的时候。名字怎么拼由 rmc-core 说
/// 了算（[`audit::current_path_in`]），这里只把文件名部分取出来。
pub fn current_log_name() -> String {
    audit::current_path_in(Path::new(""))
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// 读一次日志尾部。
///
/// **没有内核就不读**：那时候这个进程压根不知道落点在哪儿，去猜一个
/// （比如现算一次 [`AppPaths::resolve`]）意味着界面会把**另一次运行、
/// 另一份配置**留下的日志当成自己的画出来，而测试会去读开发机上真实的
/// `~/.rmc`。返回 [`logs::LogTail::NotWrittenYet`] 是这个状态下唯一的
/// 真话。
pub fn read_tail(core: Option<&Core>) -> logs::LogTail {
    match core {
        Some(c) => logs::tail(&c.paths.current_log(), logs::TAIL_LIMIT),
        None => logs::LogTail::NotWrittenYet,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmc_core::addr::HostPort;
    use rmc_win::sspi::{SspiContext, SspiPackage, SspiStep};
    use std::sync::Mutex;

    // ================= W28：落点 =================

    /// `%LOCALAPPDATA%\rmc\` 这个落点，一次接完。
    ///
    /// 改红：把 `log_dir()` 改回 `PathBuf::from("logs")`（也就是
    /// `Config::default()` 里那个跟着进程工作目录跑的相对路径）——
    /// 第二组断言当场红。
    #[test]
    fn all_landing_spots_live_under_the_app_directory() {
        let p = AppPaths::from_env(Some("C:\\Users\\zhang\\AppData\\Local"), None);
        assert_eq!(
            p.root(),
            Path::new("C:\\Users\\zhang\\AppData\\Local").join("rmc")
        );

        // Task 10：known_hosts 那一处随 SSH host key 校验一起删掉了
        // （见 `AppPaths` 上的说明）。R11-2 修复轮又加了一处：`remembered_
        // key`——「盘上那份密文属于哪个 key」，跟 `connection_code`
        // （「上一次连的是哪台」）拆成了两份独立记录。
        let spots = [
            p.log_dir(),
            p.secrets_dir(),
            p.connection_code(),
            p.remembered_key(),
        ];
        for spot in &spots {
            assert!(
                spot.starts_with(p.root()),
                "{spot:?} 没落在应用目录里，它会跟着进程的工作目录跑"
            );
        }
        // 四处互不重叠——诊断包会把 log_dir 下的东西整个收走。
        let mut distinct = std::collections::BTreeSet::new();
        for spot in &spots {
            assert!(distinct.insert(spot.clone()), "两处落点撞在一起：{spot:?}");
        }
        // 账号记录、密文定位键都不许落进日志目录（会被诊断包收走）或
        // 密文目录（那里只该有密文本身）。
        assert!(!p.connection_code().starts_with(p.log_dir()));
        assert!(!p.connection_code().starts_with(p.secrets_dir()));
        assert!(!p.remembered_key().starts_with(p.log_dir()));
        assert!(!p.remembered_key().starts_with(p.secrets_dir()));
        // 配置真的用上了这一处，不是算出来放着不用。
        let cfg = p.config();
        assert_eq!(cfg.log_dir, p.log_dir());
        assert!(cfg.validate().is_ok(), "接出来的配置本身不合法");
    }

    /// 三档回退，各走各的。
    #[test]
    fn the_app_directory_falls_back_in_a_predictable_order() {
        let win = AppPaths::from_env(Some("C:\\Local"), Some("/home/zhang"));
        assert_eq!(win.root(), Path::new("C:\\Local").join("rmc"));

        let unix = AppPaths::from_env(None, Some("/home/zhang"));
        assert_eq!(unix.root(), Path::new("/home/zhang/.rmc"));

        let nothing = AppPaths::from_env(None, None);
        assert_eq!(nothing.root(), Path::new("rmc-data"));

        // 空串跟没有是一回事——Windows 上 `%LOCALAPPDATA%` 偶尔是空的。
        assert_eq!(
            AppPaths::from_env(Some("  "), Some("/home/zhang")).root(),
            unix.root()
        );
        assert_eq!(AppPaths::from_env(Some(""), None).root(), nothing.root());
    }

    /// 日志页读的那份文件，跟 `audit` 写的那份是同一个。
    ///
    /// 改红：把 `current_log()` 改成 `log_dir().join("rmc.log")`
    /// （一个看着很合理、但 `audit` 从来不会写的名字）——这条红，而
    /// 日志页会永远是空的。
    #[test]
    fn the_log_page_reads_the_file_the_audit_log_really_writes() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let paths = AppPaths::at(dir.path().to_path_buf());
        let a = audit::Audit::open(paths.log_dir()).unwrap();
        a.record(audit::Level::Info, "一行样本");

        assert_eq!(paths.current_log(), a.current_path());
        assert!(paths.current_log().exists(), "{:?}", paths.current_log());
    }

    // ================= W170：SPN =================

    /// 记下工厂被问到的 `(安全包, SPN)`。
    #[derive(Default)]
    struct SpnSpy(Mutex<Vec<(SspiPackage, String)>>);

    impl SpnSpy {
        fn factory(self: &Arc<Self>) -> SspiContextFactory {
            let me = Arc::clone(self);
            Box::new(move |package, spn: &str| {
                me.0.lock().unwrap().push((package, spn.to_string()));
                // 不给上下文：这条测试只关心"问的是哪个 SPN"。
                None::<Box<dyn SspiContext>>
            })
        }

        fn asked(&self) -> Vec<(SspiPackage, String)> {
            self.0.lock().unwrap().clone()
        }
    }

    struct FixedProxy(Option<HostPort>);

    #[async_trait::async_trait]
    impl ProxyResolver for FixedProxy {
        async fn resolve(&self, _target: &HostPort) -> Option<HostPort> {
            self.0.clone()
        }
    }

    /// 一个绑上就关掉的端口：拨过去瞬间被拒，不碰 DNS、不碰外网。
    async fn closed_port() -> HostPort {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        drop(l);
        addr.parse().unwrap()
    }

    /// **协商器问的 SPN 是代理主机名拼出来的，而且那台代理正是
    /// `Transport` 这次真的走的那一跳。**
    ///
    /// 这条一次性钉住 W170 的第 3、4 两点：
    ///
    /// - 第 3 点（SPN 用代理主机，不是认证方案）：断言里写死了
    ///   `HTTP/127.0.0.1`。brief 那个 `HTTP/{scheme}` 会给出
    ///   `HTTP/Negotiate`。
    /// - 第 4 点（`ProxyEndpointRecorder` 不能缺席，而且必须是**同一
    ///   个**）：把 `wire_egress` 里 `Arc::clone(&recorder)` 那一行换成
    ///   `Arc::new(ProxyEndpointRecorder::new(Arc::new(NoProxy)))`
    ///   （另造一个），协商器的出口永远是 `None`，工厂**一次都不会被
    ///   调用**，`asked()` 是空的 —— 当场红。
    ///
    /// 为什么要先拨一次号：`ProxyEndpointRecorder` 记的是"最近一次
    /// `resolve()` 的结果"，而 `resolve()` 只在 `Transport::dial()`
    /// （Task 9 从 `connect()` 里拆出来的那一半，只做 TCP 拨号 + 可选
    /// CONNECT，不碰 TLS）里发生。这正是它与协商器必须共用一个对象的
    /// 原因；这几条测试只关心代理/SPN，用 `dial()` 不用 `connect()`。
    #[tokio::test]
    async fn the_negotiator_asks_for_an_spn_built_from_the_proxy_host() {
        let proxy = closed_port().await;
        let spy = Arc::new(SpnSpy::default());
        let egress = wire_egress(
            Arc::new(FixedProxy(Some(proxy.clone()))),
            Some(spy.factory()),
        );

        // 反向自证：还没连过时，工厂一次都没被问过。
        assert!(spy.asked().is_empty());

        // 走一次真实的 `Transport::dial`：`resolve()` 在这里发生，
        // 记录器于是记下了这台代理。
        let _ = egress
            .transport
            .dial(&"ops.example.com:443".parse().unwrap())
            .await;

        // 驱动一轮协商。
        egress.authenticator.begin_connection().await;
        let _ = egress.authenticator.next_token("Negotiate", None).await;

        let asked = spy.asked();
        assert_eq!(
            asked.len(),
            1,
            "协商器没有向工厂要过安全上下文——它多半根本不知道代理是谁"
        );
        assert_eq!(asked[0].0, SspiPackage::Negotiate, "安全包认错了");
        assert_eq!(
            asked[0].1,
            format!("HTTP/{}", proxy.host()),
            "SPN 不是用代理主机名拼的（W3 当年就是栽在这里：拿认证方案去拼）"
        );
        // 说死一点：SPN 里绝不能出现认证方案的名字，也不能带端口。
        assert!(!asked[0].1.contains("Negotiate"), "{:?}", asked[0].1);
        assert!(
            !asked[0].1.contains(&proxy.port().to_string()),
            "{:?}",
            asked[0].1
        );
    }

    /// 认证方案换成 NTLM 时，**只有安全包变，SPN 不变**。
    ///
    /// 这条是上面那条的解耦自证：如果哪天有人又把 scheme 塞进 SPN 里，
    /// 两次协商的 SPN 会跟着 scheme 变，而这条断言的是它们相等。
    #[tokio::test]
    async fn the_spn_does_not_follow_the_auth_scheme() {
        let proxy = closed_port().await;
        let spy = Arc::new(SpnSpy::default());
        let egress = wire_egress(Arc::new(FixedProxy(Some(proxy))), Some(spy.factory()));
        let _ = egress
            .transport
            .dial(&"ops.example.com:443".parse().unwrap())
            .await;

        for scheme in ["Negotiate", "NTLM"] {
            egress.authenticator.begin_connection().await;
            let _ = egress.authenticator.next_token(scheme, None).await;
        }

        let asked = spy.asked();
        assert_eq!(asked.len(), 2, "{asked:?}");
        assert_eq!(asked[0].0, SspiPackage::Negotiate);
        assert_eq!(asked[1].0, SspiPackage::Ntlm, "安全包没有跟着 scheme 走");
        assert_eq!(asked[0].1, asked[1].1, "SPN 跟着认证方案变了");
    }

    /// 判定直连时，协商器**不会**去要一个空 SPN 的上下文。
    #[tokio::test]
    async fn a_direct_connection_never_asks_for_a_security_context() {
        let gateway = closed_port().await;
        let spy = Arc::new(SpnSpy::default());
        let egress = wire_egress(Arc::new(FixedProxy(None)), Some(spy.factory()));
        let _ = egress.transport.dial(&gateway).await;

        egress.authenticator.begin_connection().await;
        assert!(egress
            .authenticator
            .next_token("Negotiate", None)
            .await
            .is_none());
        assert!(
            spy.asked().is_empty(),
            "直连时居然去建了安全上下文：{:?}",
            spy.asked()
        );
    }

    /// 没有 SSPI 的平台上遇到 407：如实失败，不假装谈过。
    #[tokio::test]
    async fn a_platform_without_sspi_refuses_instead_of_pretending() {
        let egress = wire_egress(Arc::new(FixedProxy(None)), None);
        egress.authenticator.begin_connection().await;
        assert!(egress
            .authenticator
            .next_token("Negotiate", None)
            .await
            .is_none());
        assert_eq!(
            egress.authenticator.auth_summary(),
            rmc_core::diagnostic::ProxyAuthSummary::NotAttempted
        );
    }

    /// 协商器给出的结局，真的经 `Transport::last_proxy()` 到得了界面。
    ///
    /// 这条把 W170 与 W173 接在一起：`wire_egress` 里 `Transport::new`
    /// 收的必须是**同一个**协商器（`Arc::clone(&authenticator)`），
    /// 另造一个的话这里读到的永远是 `NotAttempted`。
    #[tokio::test]
    async fn the_negotiation_outcome_reaches_the_observation() {
        let proxy = closed_port().await;
        let spy = Arc::new(SpnSpy::default());
        let egress = wire_egress(
            Arc::new(FixedProxy(Some(proxy.clone()))),
            Some(spy.factory()),
        );
        let _ = egress
            .transport
            .dial(&"ops.example.com:443".parse().unwrap())
            .await;
        egress.authenticator.begin_connection().await;
        let _ = egress.authenticator.next_token("Negotiate", None).await;

        match egress.transport.last_proxy() {
            Some(rmc_core::diagnostic::ProxyObservation::Via { endpoint, auth, .. }) => {
                assert_eq!(endpoint, proxy);
                assert_eq!(
                    auth,
                    rmc_core::diagnostic::ProxyAuthSummary::ContextUnavailable {
                        package: "Negotiate".into()
                    },
                    "协商器的结局没有到达观察结果——Transport 拿的多半是另一个协商器"
                );
            }
            other => panic!("{other:?}"),
        }
    }

    /// 反向自证：那个假工厂真的能造出上下文来（上面几条里它故意返回
    /// `None`，万一它**永远**造不出来，几条断言的含义就变了）。
    #[test]
    fn the_spy_factory_can_actually_produce_a_context() {
        struct Empty;
        impl SspiContext for Empty {
            fn step(&mut self, _challenge: Option<&[u8]>) -> SspiStep {
                SspiStep::Done
            }
        }
        let f: SspiContextFactory =
            Box::new(|_p, _spn| Some(Box::new(Empty) as Box<dyn SspiContext>));
        assert!(f(SspiPackage::Negotiate, "HTTP/proxy.example.com").is_some());
    }

    // ================= W181：有密封器就必须有存储 =================

    /// 一个什么都不做的假密封器。非 Windows 上 `Platform::detect()` 给的
    /// `sealer` 恒定是 `None`，没有它就没法在这台机器上走到那一支。
    struct NoopSealer;

    impl Sealer for NoopSealer {
        fn seal(&self, plain: &[u8]) -> Option<Vec<u8>> {
            Some(plain.to_vec())
        }
        fn unseal(&self, sealed: &[u8]) -> Option<zeroize::Zeroizing<Vec<u8>>> {
            Some(zeroize::Zeroizing::new(sealed.to_vec()))
        }
    }

    /// **平台给了密封器，装配就必须真的造出一个密码存储。**
    ///
    /// # 这条**拦不住**什么
    ///
    /// 拦不住「记住密码那个勾选框不工作」——`Core::secrets` 至今没有
    /// 任何生产读方，那是整条链路的功能缺口，见 task-10-report.md 的
    /// 「后续完善」第 1 条。两件事别混为一谈。
    ///
    /// 它拦的是更窄也更阴的一种：有人把 `spawn_core` 里造存储那一行
    /// 摘掉或者把落点改走。因为没有读方，摘掉之后**一条测试都不会红**
    /// （上一轮实测确认过）。
    ///
    /// # 为什么光有 `spawn_core` 里那句 `assert_eq!` 不够
    ///
    /// 非 Windows 上 `Platform::detect()` 的 `sealer` 恒定是 `None`，
    /// 于是那句断言的两边恒等——**它在这台机器上永远不会发火**。
    /// 实测过：把造存储那一行换成 `None`，`cargo test -p rmc-app`
    /// 全绿。要让它可达，就得自己塞一个密封器进去。
    #[tokio::test]
    async fn a_platform_with_a_sealer_really_gets_a_secret_store() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let paths = AppPaths::at(dir.path().to_path_buf());

        // 反向自证：没有密封器时确实没有存储（否则下面那条不带载）。
        let bare = spawn_core(
            paths.clone(),
            Platform {
                sealer: None,
                ..Platform::detect()
            },
        );
        assert!(bare.secrets.is_none());

        let core = spawn_core(
            paths.clone(),
            Platform {
                sealer: Some(Box::new(NoopSealer)),
                ..Platform::detect()
            },
        );
        let store = core.secrets.as_ref().expect("有密封器却没有密码存储");

        // 而且它真的落在应用目录下那一处，不是随便哪儿。
        store
            .save("tunnel-zhang@ops.example.com:443", "pw")
            .unwrap();
        let landed: Vec<String> = std::fs::read_dir(paths.secrets_dir())
            .expect("密码存储的落点不存在")
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(landed.len(), 1, "{landed:?}");
        assert!(landed[0].ends_with(".sealed"), "{landed:?}");
    }

    // ================= W178：事件源真的接上了 =================

    /// 数 `subscribe()` 被调了几次。
    struct SpyEvents {
        inner: broadcast::Sender<rmc_core::platform::SystemEvent>,
        hits: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl SystemEvents for SpyEvents {
        fn subscribe(&self) -> broadcast::Receiver<rmc_core::platform::SystemEvent> {
            self.hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.subscribe()
        }
    }

    /// **`Platform` 给的那个事件源真的被交给了 Supervisor。**
    ///
    /// # 断的是哪一根线
    ///
    /// `spawn_core` 里 `Deps { events }` 那一个字段。把它换成一个新造的
    /// `NoSystemEvents`（也就是把 `Platform::detect` 辛辛苦苦注册好的
    /// 那个 hub 直接丢掉），**600 条测试全绿**——上一轮的接线表第 6 行
    /// 就是这么虚报的：我写的是"断掉它 `the_assembled_core_starts_and_
    /// accepts_commands` 会红"，实测不会。
    ///
    /// Windows 上的后果是「合盖唤醒之后不再立刻重连」——**正是
    /// W82/W94 花一整轮堵的那个形状，从另一头漏出来**。
    ///
    /// 判据用 `subscribe()` 的调用次数，不用"发一条事件看 Supervisor
    /// 有没有反应"：后者要先把状态机推进 `Backoff` 才观察得到，那是
    /// 一整套建连脚本；而 `run()` 一启动就会 `subscribe()` 恰好一次，
    /// 这件事本身就足以证明这根线接上了。
    #[tokio::test]
    async fn the_platform_event_source_is_handed_to_the_supervisor() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let dir = tempfile::tempdir().expect("建临时目录");
        let hits = Arc::new(AtomicUsize::new(0));
        let platform = Platform {
            events: Arc::new(SpyEvents {
                inner: broadcast::channel(8).0,
                hits: Arc::clone(&hits),
            }),
            ..Platform::detect()
        };

        // 反向自证：装配之前一次都没订阅过。
        assert_eq!(hits.load(Ordering::SeqCst), 0);

        let _core = spawn_core(AppPaths::at(dir.path().to_path_buf()), platform);
        // `Supervisor::spawn` 里是 `tokio::spawn`，`run()` 的第一行才是
        // `deps.events.subscribe()`——给它一点时间被调度到。
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "Supervisor 没有订阅 Platform 给的那个事件源——\
             合盖唤醒之后不会再立刻重连，而没有任何地方会说一句"
        );
    }

    // ================= 打开目录 =================

    /// 三个系统各有各的命令，别的系统老老实实说不知道。
    ///
    /// 写成纯函数而不是 `cfg` 的价值就在这一条：Windows 那一档在这台
    /// macOS 机器上也验得到。改红：把 `"windows"` 那一支改成
    /// `Some("open")`——第一格红。
    #[test]
    fn each_operating_system_opens_directories_its_own_way() {
        assert_eq!(file_manager_for("windows"), Some("explorer"));
        assert_eq!(file_manager_for("macos"), Some("open"));
        assert_eq!(file_manager_for("linux"), Some("xdg-open"));
        assert_eq!(file_manager_for("freebsd"), None);
        // 本机这一档必须有命令，否则「打开日志目录」在这台机器上点了
        // 没反应，而我们不会知道。
        assert!(file_manager_for(std::env::consts::OS).is_some());
    }

    // ================= 事件流 =================

    /// 内核发的事件真的变成了界面消息，而且**漏事件不会让流断掉**。
    #[tokio::test]
    async fn events_become_messages_and_a_lagging_ui_keeps_going() {
        use iced::futures::StreamExt;

        let (tx, rx) = broadcast::channel::<TunnelEvent>(2);
        let mut stream = Box::pin(events_into(rx, |e| e));

        tx.send(TunnelEvent::State(rmc_core::state::State::Preflight))
            .unwrap();
        assert_eq!(
            stream.next().await,
            Some(TunnelEvent::State(rmc_core::state::State::Preflight))
        );

        // 塞爆容量：最早那条被挤掉，流必须**接着走**而不是停在这里。
        for _ in 0..5 {
            tx.send(TunnelEvent::State(rmc_core::state::State::Connecting))
                .unwrap();
        }
        tx.send(TunnelEvent::ConnectedSince(std::time::UNIX_EPOCH))
            .unwrap();
        // 漏掉的那几条不再出现，但后面的照样到。
        let mut seen = Vec::new();
        for _ in 0..2 {
            seen.push(stream.next().await);
        }
        assert!(
            seen.contains(&Some(TunnelEvent::ConnectedSince(std::time::UNIX_EPOCH))),
            "落后一次之后流就不走了：{seen:?}"
        );

        // 发送端没了，流就结束——不是永远挂着。
        drop(tx);
        // 缓冲里可能还剩东西，取到 None 为止。
        while stream.next().await.is_some() {}
    }

    // ================= W198：网络轮询的停止路径 =================

    /// **`spawn_core` 必须把轮询句柄接进 `Core`，而不是顺手丢掉。**
    ///
    /// 丢掉它没有任何界面表现：网络轮询线程在启动后的下一轮就退出，
    /// 切网之后不再立刻重连，只是靠退避序列慢慢恢复——跟「本来就没有
    /// 这个功能」长得一模一样。这正是本项目最怕的那种静默降级。
    ///
    /// 改红：把 `spawn_core` 末尾的 `.with_polling(network_polling)`
    /// 去掉——句柄会在 `spawn_core` 返回时就地 `Drop`，第二条断言当场红。
    #[tokio::test]
    async fn the_network_polling_handle_lives_as_long_as_the_core() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let (handle, stop) = rmc_win::events::NetworkPolling::new();
        let platform = Platform {
            network_polling: Some(handle),
            ..Platform::detect()
        };

        // 反向自证：装配之前轮询是该转的。
        assert!(stop.keep_polling());

        let core = spawn_core(AppPaths::at(dir.path().to_path_buf()), platform);

        assert!(
            stop.keep_polling(),
            "装配把轮询句柄丢掉了——网络轮询在启动后的下一轮就停了，\
             而界面上一个字都看不出来"
        );
        assert_eq!(core.is_polling_network(), Some(true));

        // `Core` 是 `Clone` 的（界面一份、订阅一份）：克隆还在的时候
        // 不许停。
        let twin = core.clone();
        drop(core);
        assert!(stop.keep_polling(), "还有一份 Core 活着，轮询就停了");

        // 最后一份丢掉，轮询才停——客户端退出时那个线程跟着走。
        drop(twin);
        assert!(
            !stop.keep_polling(),
            "客户端都没了，轮询线程还在每 2 秒醒一次"
        );
    }

    /// 这台机器上（非 Windows）本来就没有那个线程。
    ///
    /// 这条钉住「`None` 不等于 `Some(false)`」——前者是「没有这个功能」，
    /// 后者是「有，但停了」。
    #[test]
    fn a_platform_without_the_poller_says_so_instead_of_saying_it_stopped() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let core = Core::new(
            mpsc::channel(1).0,
            broadcast::channel(1).1,
            AppPaths::at(dir.path().to_path_buf()),
            None,
        );
        assert_eq!(core.is_polling_network(), None);
        // 反向自证：接上一个就有话说了。
        let (handle, _stop) = rmc_win::events::NetworkPolling::new();
        assert_eq!(
            core.with_polling(Some(handle)).is_polling_network(),
            Some(true)
        );
    }

    // ================= 真的起得来 =================

    /// **整套装配真的能跑起来，而且命令真的到得了内核。**
    ///
    /// 这条是这个模块的"接线通了"总闸：`spawn_core` 里任何一处
    /// （`Deps` 的五个字段、`TransportPreflight`）拼错都编译不过，而
    /// "拼对了但内核根本没起来"只有这条看得见。
    #[tokio::test]
    async fn the_assembled_core_starts_and_accepts_commands() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let paths = AppPaths::at(dir.path().to_path_buf());
        let core = spawn_core(paths.clone(), Platform::detect());

        let mut rx = core.subscribe();
        // 连接码只接受 IP，不接受域名——旧版那个 `ops.example.com:443`
        // 字面量没法沿用，现生成一条。
        let code = rmc_core::code::ConnectionCode::new(
            rmc_core::code::AccountName::parse("tunnel-zhang").unwrap(),
            "203.0.113.10".parse().unwrap(),
            22000,
            rmc_core::code::ServerFingerprint::of_ed25519_public(&[7u8; 32]),
        )
        .expect("夹具必须合法");
        core.commands
            .send(Command::Start {
                code,
                password: zeroize::Zeroizing::new("pw".into()),
                appliance: "192.168.100.10:61001".parse().unwrap(),
            })
            .await
            .expect("命令发不出去，内核没起来");

        // 预检会真的去拨号并失败（这台机器上那两个地址都不通），我们只
        // 要看到状态机动起来就够了。
        let first = tokio::time::timeout(std::time::Duration::from_secs(30), rx.recv())
            .await
            .expect("30 秒内一条事件都没有，Supervisor 没跑起来")
            .expect("事件通道断了");
        assert!(
            matches!(first, TunnelEvent::State(rmc_core::state::State::Preflight)),
            "第一条事件不是进入预检：{first:?}"
        );

        // 审计日志真的落在应用目录下（W28）。
        core.commands.send(Command::Stop).await.ok();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(
            paths.log_dir().exists(),
            "审计日志没有落在应用目录下：{:?}",
            paths.log_dir()
        );
    }
}
