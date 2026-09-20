//! 远程运维客户端的界面层。只发 `Command`、只读 `TunnelEvent`。
//!
//! # crate 级约定：判断逻辑不许住在视图函数里
//!
//! 跟 `rmc-win` 那条「纯逻辑子模块 / Win32 子模块」的约定同源，这里是它
//! 在界面侧的版本：
//!
//! - **视图函数**（`view::*` 里返回 `iced::Element` 的那些）只负责把已经
//!   算好的值摆进控件树。它们在这台 macOS 开发机上**跑不起真窗口**，
//!   CI 的非 Windows 阶段也跑不起——写进去的任何判断都没有任何东西看得见。
//! - **一切判断**——某个页签该用哪个颜色、某个按钮该不该禁用、某条状态
//!   该显示哪句话、某个计时器该不该触发——必须抽成一个不碰 `Element` 的
//!   纯函数（[`theme::tab_style`] 是第一个例子），放在 `theme` 或往后的
//!   `model` 里，并且有表驱动测试。
//!
//! 这条不是洁癖。这个项目已经抓到 20 个「测试通过但没验证名字声称的事」，
//! 其中四次是同一个形状：判断被埋进 `#[cfg(windows)]` 或视图函数里，
//! 六道闸门全绿，而需求整个反了。Task 7-11 还有五个任务要往这个 crate
//! 加界面代码，约定现在立下。
//!
//! 反例（不要这样写）：
//!
//! ```ignore
//! button(text(t.label()).color(if is_active { TEXT } else { TEXT_SUB }))
//! ```
//!
//! 正例：把 `tab_style(is_active) -> (Color, Color)` 抽出来单测，视图里
//! 只写 `let (fg, line) = tab_style(is_active);`。

pub mod diag;
pub mod form;
pub mod logs;
pub mod model;
pub mod theme;
pub mod view;
pub mod wiring;

use form::Form;
use logs::{LogFilter, LogTail};
use model::{Action, Model};
use rmc_core::state::{Command, TunnelEvent};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use theme::{Tab, WINDOW_SIZE};
use wiring::Core;
use zeroize::Zeroizing;

/// 窗口标题，也是标题栏里画的那行字。
///
/// 需求硬禁令：界面上叫「运维服务器」，不叫 Gateway/网关。
/// `tests/ui.rs` 的 `no_widget_in_the_tree_says_gateway` 扫整棵控件树守这条。
pub const WINDOW_TITLE: &str = "远程运维客户端";

/// 需求硬禁令的词表：界面上叫「运维服务器」，不叫 Gateway/网关。
///
/// **W125：词表已经搬到 rmc-core**（[`rmc_core::wording`]），这里只是原样
/// re-export，`rmc_app::BANNED_WORDS` 这个路径不变。搬家的理由是违反发生在
/// 源头：rmc-core 的 `Error` 文案会经 `State::Failed { message }` 变成状态
/// 卡副标题，`preflight::ALL_STEPS` 是诊断页的行首文字，审计日志是日志页的
/// 正文——实测有八处写着 Gateway，而界面侧这道控件树扫描**一条都抓不到**
/// （它扫的是当前渲染出来的那棵树，那些字符串只在特定状态下才出现）。
///
/// 现在四处防线共用这一份字面量：
/// - `rmc_core::wording` 的 `no_production_string_literal_says_gateway`
///   扫 rmc-core 生产代码里的全部字符串字面量；
/// - 同模块的 `no_error_variant_says_gateway` 按变体穷尽扫 `Error` 的 Display；
/// - `tests/ui.rs` 的 `no_widget_in_the_tree_says_gateway` 扫 `App::view`
///   的整棵树，`model.rs` 的 `nothing_the_status_card_says_is_banned` 扫
///   八条显示分支各自的状态卡与按钮；
/// - 本文件的 `program_view_is_the_app_view_and_says_no_gateway` 扫
///   **`main()` 实际装配进去的那棵**，
///   `window_title_is_chinese_and_never_says_gateway` 扫操作系统窗口标题。
///
/// 刻意不让它分叉成几份字面量：Task 8-11 还要加三个页面，
/// 词表一旦分叉，迟早有一份漏掉新加的词。
pub use rmc_core::BANNED_WORDS;

/// 单实例互斥体的名字。
///
/// 修复轮 1：从 `main.rs` 的字面量提到这里。理由跟 [`window_settings`]
/// 一样——`main()` 里的东西在无头机器上一个字都验不了。
pub const SINGLE_INSTANCE_NAME: &str = "rmc-client";

/// 界面主题，钉死浅色。
///
/// **这是 0.13 → 0.14 带进来的一处真实行为回归，不是洁癖**：
///
/// - 0.13：我们用 `default-features = false`，没开 `auto-detect-theme`，
///   `iced_core` 里 `Theme::default()` 直接 `Theme::Light`，跟系统设置无关。
/// - 0.14：`auto-detect-theme` 这个 feature 没了，深浅色探测挪进了
///   `iced_winit`（`event_loop.system_theme()` → `theme::Base::default(mode)`，
///   见 `iced_winit/src/window/state.rs:60`），**Windows/macOS 上没有 feature
///   开关可以关掉**。程序不显式指定主题时，用户开了 Windows 深色模式，
///   窗口底色就会变深。
///
/// 而 [`theme::color`] 这套画板是**固定浅色**的：`TEXT` 是 `#1c1c1c`，
/// 糊在深色底上等于看不见。所以这里必须钉死 `Light`。
///
/// 哪天要做真正的深色模式，改的是整套画板，不是把这一行删掉。
pub const APP_THEME: iced::Theme = iced::Theme::Light;

/// 窗口设置。
///
/// 修复轮 1：从 `main()` 里提出来的纯函数。`main()` 里不该有判断（见上面的
/// crate 级约定），但它确实有**配置**，而配置原来同样没有任何测试看得见：
/// 第一轮实测把 `resizable` 改成 `true`、把尺寸写死成 800×600，六道闸门
/// 全绿。提成纯函数之后这两条能测了。
///
/// **仍然测不到的**：`main()` 有没有真的调用这个函数。见
/// task-6-fix-1-report.md 的残余缺口一节。
pub fn window_settings() -> iced::window::Settings {
    iced::window::Settings {
        size: iced::Size::new(WINDOW_SIZE.0, WINDOW_SIZE.1),
        resizable: false,
        ..Default::default()
    }
}

/// 把 `main()` 的装配整块搬出来，`main()` 只剩 `program().run()`。
///
/// 抽出来的唯一理由：`iced::application(..)` 返回的
/// [`iced::application::Application<P>`] **自己就实现了公开的
/// [`iced::Program`]**（`iced-0.14.0/src/application.rs:459`），而 `Program`
/// 公开了 `title()` / `window()` / `theme()` / `view()`。也就是说
/// `.title(..)`、`.theme(..)`、`.window(..)` 的**装配结果是可读的**——
/// 不需要真启动窗口，也不需要去碰 `Application` 的私有字段。
///
/// 这堵的是 [`window_settings`] 与 [`APP_THEME`] 堵不掉的那一层：
/// 它们只证明「值是对的」，证明不了「`main()` 真的用了这个值」。评审实测过
/// `main()` 里 `.title("Gateway")`、绕开 `window_settings()` 就地写死、
/// 删掉 `.theme(APP_THEME)`、甚至挂一棵字面画着 `"Gateway"` 的控件树，
/// **九道闸门全绿**。提成这个函数之后，`tests` 里那两条测试逐条把它们打红。
///
/// **注意固有方法遮蔽**：`Application` 自己有同名的 `window(..)` /
/// `title(..)` / `theme(..)` **builder 方法**（消费 `self`、返回 `Self`），
/// 它们会盖过 trait 上的同名读取方法。所以测试里不要对具体类型直接
/// `p.title(..)`，要走泛型参数 `P: iced::Program<..>`（见 `tests`）——
/// 完全限定写法要先给 `Application<impl Program<..>>` 起类型别名，
/// 而那在 1.89 上是 `error[E0658]: impl Trait in type aliases is unstable`。
pub fn program(
    core: Option<Core>,
) -> iced::application::Application<
    impl iced::Program<State = App, Message = Message, Theme = iced::Theme>,
> {
    iced::application(move || App::with_core(core.clone()), App::update, App::view)
        .title(WINDOW_TITLE)
        .theme(APP_THEME)
        .window(window_settings())
        // W150：brief 的 `Message::Tick` 被 Task 8 静默丢掉了，后果是
        // 「已连接 HH:MM:SS」不会自己走字。这一行是它回来的地方，另一半
        // 在 [`subscription`]。
        .subscription(subscription)
}

/// 把内核接上去，交出一个可以 `run()` 的程序。
///
/// # W177：`main()` 里最后那两根线，这里才接得住
///
/// `main()` 是一个薄 bin（W103），里面的东西在这台无头机器上一个字都
/// 验不了。上一轮实测过两枪，**七道闸门全绿**：
///
/// - 删掉 `install_event_source(&core)` → 界面永远收不到任何内核事件，
///   状态卡停在"未开启"，而按钮照样点得动；
/// - 把 `program(Some(core))` 写成 `program(None)` → 内核根本没接上。
///
/// 出路是 Task 6 那把钥匙再往前一步：`iced::Program::boot()` 是**公开**
/// 的（`iced_program-0.14.0/src/lib.rs:47`），Task 6 只用它取过
/// `title`/`theme`/`window`/`view`，**没有用它取状态**。把这两根线从
/// `main()` 挪进这个函数之后，测试可以 `boot()` 出真正的 [`App`] 来看
/// 内核有没有到它手上。
///
/// `main()` 于是只剩 `rmc_app::assemble(core).run()` 一行。
///
/// 守它的是 [`tests::assemble_hands_the_core_to_the_ui_and_installs_the_event_source`]。
pub fn assemble(
    core: Core,
) -> iced::application::Application<
    impl iced::Program<State = App, Message = Message, Theme = iced::Theme>,
> {
    // 订阅那一条路只能走进程级的事件源，见
    // `wiring::subscribe_installed` 上关于"为什么这里必须有一个全局"
    // 的说明；命令与路径走 `App` 自己持有的那一份。
    wiring::install_event_source(&core);
    program(Some(core))
}

/// 每秒一跳。计时器与日志刷新都跟着它。
///
/// 一秒是「已连接时长」那个 `HH:MM:SS` 的最小刻度定的——再慢秒数会跳，
/// 再快是白烧电。
pub const TICK: Duration = Duration::from_secs(1);

/// 这一轮要订阅什么。
///
/// 两条：每秒一跳的 [`TICK`]，以及内核推上来的那条事件流。
///
/// **不看 `state`**：两条订阅在任何页签、任何状态下都该活着。日志页不在
/// 前台时也要收事件（状态卡在维护页上），计时器不在 `Connected` 时也要
/// 跳（`Model::elapsed` 自己会在别的状态下返回 `None`）。按状态开关订阅
/// 是 iced 里最容易写出"某个状态下界面就不动了"的地方。
pub fn subscription(_state: &App) -> iced::Subscription<Message> {
    iced::Subscription::batch([
        iced::time::every(TICK).map(tick_message),
        iced::Subscription::run(core_events),
    ])
}

/// 每一跳变成一条 [`Message::Tick`]。
///
/// 写成具名函数而不是闭包 `|_| Message::Tick`，是为了让这条订阅**可以
/// 被认出来**：`Subscription::map` 的 recipe 把映射函数的 `TypeId` 拌进
/// 哈希里，而每一处闭包字面量都是一个**独立的匿名类型**——测试里另写
/// 一个 `|_| Message::Tick` 算出来的哈希跟这里的对不上，那条
/// 「Tick 真的被订阅了」就只能退化成数个数。见
/// [`tests::the_ui_subscribes_to_a_one_second_tick_and_to_the_core_events`]。
fn tick_message(_now: std::time::Instant) -> Message {
    Message::Tick
}

/// 内核事件 → 界面消息。
///
/// 函数指针，不是闭包：`Subscription::run` 收的就是 `fn() -> impl
/// Stream`（订阅身份要能跨帧被认出来）。事件源从哪儿来见
/// [`wiring::subscribe_installed`] 上那段关于"为什么这里必须有一个
/// 全局"的说明。
fn core_events() -> iced::futures::stream::BoxStream<'static, Message> {
    use iced::futures::StreamExt;
    match wiring::subscribe_installed() {
        Some(rx) => wiring::events_into(rx, Message::CoreEvent).boxed(),
        // 没有内核（测试、或者装配失败）：一条永远不出东西、也永远不
        // 结束的流。**不是空流**——iced 对自己结束的订阅会打一行警告，
        // 而"没有内核"不是异常，是一个合法的状态。
        None => iced::futures::stream::pending().boxed(),
    }
}

/// 界面消息。
///
/// # W141 的延伸：`PasswordChanged` 不许被 `derive(Debug)` 打出来
///
/// `#[derive(Debug)]` 在这个枚举上会把口令原样印进任何一条
/// `tracing::debug!("{msg:?}")`——而 Task 10 要做的正是把消息接进
/// Supervisor，那种顺手的日志行几乎一定会出现。`Zeroizing` 帮不上忙，
/// 它的 `Debug` 是转发的。所以这里跟 [`form::Form`] 一样手写。
///
/// 载荷用 `Zeroizing<String>` 而不是裸 `String`，让这段口令在 `update`
/// 消费完之后被抹掉。**说清楚它不能做到什么**：iced 的 `TextInput` 内部
/// 自己持有一份输入内容（`text_input::Value`），那一份不归我们管，
/// 这个类型管不到。
#[derive(Clone)]
pub enum Message {
    TabSelected(Tab),
    ApplianceHostChanged(String),
    AppliancePortChanged(String),
    GatewayHostChanged(String),
    GatewayPortChanged(String),
    UsernameChanged(String),
    PasswordChanged(Zeroizing<String>),
    RememberToggled(bool),
    ActionPressed(model::Action),
    DisconnectSession(u64),
    /// W150：每秒一跳。「已连接 HH:MM:SS」靠它走字，日志页靠它刷新。
    Tick,
    /// 内核推上来的一条事件。
    CoreEvent(TunnelEvent),
    LogFilterSelected(LogFilter),
    LogQueryChanged(String),
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 变体名走 `stringify!`，不写字符串字面量。
        //
        // **这是 W138 那道新扫描当场抓到的一条**：手写 `Debug` 时顺手写的
        // `f.debug_tuple("GatewayHostChanged")` 是一条含禁用词的字符串
        // 字面量。它其实不上屏（`Debug` 只进日志与调试器），但扫描器的
        // 跳过规则是按**行首**匹配 `.field(` 的，`match` 的这种写法行首是
        // `Message::`，够不着。
        //
        // 没有去放宽跳过规则，而是让字面量整个消失：放宽规则等于在扫描器
        // 上开一个新的盲区，而 `stringify!` 顺带保证变体名跟枚举定义
        // 不会漂移。
        macro_rules! plain {
            ($name:ident, $value:expr) => {
                f.debug_tuple(stringify!($name)).field($value).finish()
            };
        }
        match self {
            Message::TabSelected(v) => plain!(TabSelected, v),
            Message::ApplianceHostChanged(v) => plain!(ApplianceHostChanged, v),
            Message::AppliancePortChanged(v) => plain!(AppliancePortChanged, v),
            Message::GatewayHostChanged(v) => plain!(GatewayHostChanged, v),
            Message::GatewayPortChanged(v) => plain!(GatewayPortChanged, v),
            Message::UsernameChanged(v) => plain!(UsernameChanged, v),
            // 唯一一条被遮住的：口令。
            Message::PasswordChanged(v) => plain!(
                PasswordChanged,
                &format_args!("<redacted {} chars>", v.len())
            ),
            Message::RememberToggled(v) => plain!(RememberToggled, v),
            Message::ActionPressed(v) => plain!(ActionPressed, v),
            Message::DisconnectSession(v) => plain!(DisconnectSession, v),
            Message::Tick => f.write_str(stringify!(Tick)),
            Message::CoreEvent(v) => plain!(CoreEvent, v),
            Message::LogFilterSelected(v) => plain!(LogFilterSelected, v),
            Message::LogQueryChanged(v) => plain!(LogQueryChanged, v),
        }
    }
}

/// 界面状态。
///
/// `Debug` 可以 `derive`：[`Form`] 自己手写了遮口令的那一份，派生出来的
/// `App::fmt` 调的是它。`app_debug_output_redacts_the_password` 守这条。
#[derive(Debug)]
pub struct App {
    tab: Tab,
    /// 视图模型。由 [`App::apply`] 按内核推上来的事件推进。
    model: Model,
    form: Form,
    /// 现在几点。**由 [`Message::Tick`] 推进，不是 `view` 里现取**
    /// （W150）——现取的话「已连接 HH:MM:SS」只在别的消息顺带触发重画时
    /// 才动一下，看起来就是一个偶尔跳一大格的计时器。
    now: SystemTime,
    /// 日志页读到的那一份。三种结局各说各的话，见 [`logs::LogTail`]。
    log_tail: LogTail,
    log_filter: LogFilter,
    log_query: String,
    /// 底部那行字里的文件名。跟着 [`Self::reload_logs`] 一起更新——
    /// 日志按天滚动，跨过零点之后读的是另一个文件，这行字得跟上。
    log_file_name: String,
    /// 通往内核的那根线。`None` 表示没接上（测试，或者装配失败）——
    /// 此时界面照常能画、按钮照常点得动，只是命令发不出去。
    core: Option<Core>,
    /// 上一次导出的诊断包落在哪儿。
    last_export: Option<PathBuf>,
    /// 诊断页底部那行环境信息。
    ///
    /// 算一次存着，不是每帧调一次 [`diag::environment_line`]：`view` 要
    /// 借出 `&str`，而现算的 `String` 是个临时值，借不出去。顺带也对——
    /// 这行字在一次运行里不会变。
    environment: String,
}

impl Default for App {
    fn default() -> Self {
        Self {
            // 默认停在维护页，那是用户唯一要操作的一屏。
            tab: Tab::Maintain,
            model: Model::default(),
            form: Form::default(),
            environment: diag::environment_line(),
            now: SystemTime::now(),
            // **不在这里读文件**：`Default` 应当是纯的，而且测试里的
            // `App::default()` 不该去摸开发机上的 `~/.rmc`。真正的第一次
            // 读在 [`App::with_core`] 与每一跳 [`Message::Tick`] 上。
            log_tail: LogTail::NotWrittenYet,
            log_filter: LogFilter::default(),
            log_query: String::new(),
            // 文件**名**算得出来（它只跟日期有关），文件**内容**要等
            // 第一次 `reload_logs`。底部那行字因此在任何状态下都完整。
            log_file_name: wiring::current_log_name(),
            core: None,
            last_export: None,
        }
    }
}

impl App {
    /// 接上内核。`program()` 的 boot 走这条。
    pub fn with_core(core: Option<Core>) -> Self {
        let mut app = Self {
            core,
            ..Self::default()
        };
        app.reload_logs();
        app
    }

    /// 当前选中的页签。
    pub fn tab(&self) -> Tab {
        self.tab
    }

    pub fn log_tail(&self) -> &LogTail {
        &self.log_tail
    }

    pub fn log_filter(&self) -> LogFilter {
        self.log_filter
    }

    /// 上一次导出的诊断包。`None` 表示这一轮还没导出过。
    pub fn last_export(&self) -> Option<&std::path::Path> {
        self.last_export.as_deref()
    }

    /// 重读一次日志尾部。
    fn reload_logs(&mut self) {
        // 名字只跟日期有关（跨过零点之后读的是另一个文件，底部那行字
        // 得跟上）；内容只有接上内核之后才读得到。
        self.log_file_name = wiring::current_log_name();
        self.log_tail = wiring::read_tail(self.core.as_ref());
    }

    /// 走一跳。`now` 显式传进来，[`Message::Tick`] 那条路上传的是
    /// `SystemTime::now()`——这样"时间往前走了之后界面画什么"在测试里
    /// 是可控的，不用去睡真实的一秒。
    pub fn tick(&mut self, now: SystemTime) {
        self.now = now;
        // 只在日志页在前台时重读文件。一秒一次的磁盘读在别的页签上纯属
        // 白烧——而这一页一旦切回来，第一跳（最多一秒）就会补上。
        if self.tab == Tab::Logs {
            self.reload_logs();
        }
    }

    /// 各个落点。没接上内核时是 `None`——那时候这个进程压根不知道
    /// 落点在哪儿，**不许去猜一个**，见 `Action::OpenLogDir` 那一支。
    fn paths(&self) -> Option<&wiring::AppPaths> {
        self.core.as_ref().map(|c| &c.paths)
    }

    /// 往内核发一条命令。发不出去只记一行，不崩。
    fn send(&self, command: Command) {
        let Some(core) = self.core.as_ref() else {
            tracing::warn!(?command, "还没接上内核，这条命令发不出去");
            return;
        };
        // `try_send` 不是 `send`：这里跑在界面线程上，通道满了就阻塞的话
        // 整个窗口会卡住。通道容量 32，而界面能按出来的命令是个位数级
        // 的——真满了说明内核已经不转了，那时候更不能连窗口一起卡死。
        if let Err(e) = core.commands.try_send(command) {
            tracing::error!(error = %e, "命令没能送进内核");
        }
    }

    /// 按下一个动作按钮。
    fn dispatch(&mut self, action: Action) {
        match action {
            Action::Start => match self.form.validate() {
                Ok(addrs) => self.send(Command::Start {
                    username: self.form.username.trim().to_string(),
                    password: self.form.password.clone(),
                    gateway: addrs.gateway().clone(),
                    appliance: addrs.appliance().clone(),
                }),
                // 按钮此时本来就该是灰的（`action_enabled`），走到这里
                // 说明有人绕过了那道门。什么都不做，不发一条注定被
                // Supervisor 拒掉的命令。
                Err(errors) => tracing::warn!(?errors, "表单还没填对，不发起连接"),
            },
            Action::Cancel => self.send(Command::Cancel),
            Action::Stop => self.send(Command::Stop),
            Action::RetryNow => self.send(Command::RetryNow),
            Action::ExportDiagnostics => self.export_diagnostics(),
            // 剪贴板要 `update` 返回 `iced::Task`，本轮没做，见
            // task-10-report.md 的「后续完善」。
            Action::CopyDiagnostics => tracing::info!("复制检查结果：本轮未实现"),
            Action::OpenLogDir => {
                // 没有内核就不知道落点在哪儿——**不去猜一个**。猜一个的
                // 代价实测过：`cargo test` 会在开发机真实的 `~/.rmc` 下
                // 建目录、还会真的弹出一个文件管理器窗口。
                let Some(dir) = self.paths().map(|p| p.log_dir()) else {
                    tracing::warn!("还没接上内核，不知道日志目录在哪儿");
                    return;
                };
                // 目录可能还不存在（今天还没写过日志），先建出来——
                // 否则资源管理器会弹一个"找不到路径"。
                let _ = std::fs::create_dir_all(&dir);
                wiring::open_dir(&dir);
            }
        }
    }

    /// 导出诊断包。**脱敏登记在 [`diag::export`] 里就地做完**（W172），
    /// 这里连一个能传错的参数都没有。
    fn export_diagnostics(&mut self) {
        // 同 `Action::OpenLogDir`：没有内核就不知道往哪儿写。猜一个的
        // 代价是 `cargo test` 每跑一次就往开发机真实的 `~/.rmc` 里扔一个
        // 诊断包（实测攒了 27 个才发现）。
        let Some(paths) = self.paths().cloned() else {
            tracing::warn!("还没接上内核，不知道诊断包该写到哪儿");
            return;
        };
        match diag::export(
            &self.form,
            self.model.preflight.as_ref(),
            &self.environment,
            &paths.log_dir(),
            &paths.export_dir(),
        ) {
            Ok(path) => {
                tracing::info!(?path, "诊断包已导出");
                self.last_export = Some(path);
            }
            Err(e) => tracing::error!(error = %e, "导出诊断包失败"),
        }
    }

    pub fn model(&self) -> &Model {
        &self.model
    }

    pub fn form(&self) -> &Form {
        &self.form
    }

    /// 把一条隧道事件喂给视图模型。[`subscription`] 接这里。
    ///
    /// 除了推进 [`Model`]，还有两件只有这一层能做的事：
    ///
    /// 1. **口令该不该抹掉**（[`model::should_clear_password`]）——
    ///    `Model` 看不见 `Form`；
    /// 2. **把检测到的代理同步给表单**（W152）。`Form::detected_proxy`
    ///    因此**不是第二个真相来源**：它每次都从 `self.model.proxy` 原样
    ///    派生，两者结构上不可能分叉。
    pub fn apply(&mut self, event: rmc_core::TunnelEvent) {
        let before = self.model.state.clone();
        self.model.apply(event);
        if model::should_clear_password(&before, &self.model.state) {
            self.form.clear_password();
        }
        self.form.detected_proxy = self.model.proxy.as_ref().map(|p| p.endpoint.clone());
    }

    pub fn update(&mut self, message: Message) {
        match message {
            Message::TabSelected(t) => self.tab = t,
            Message::ApplianceHostChanged(v) => self.form.appliance_host = v,
            Message::AppliancePortChanged(v) => self.form.appliance_port = v,
            Message::GatewayHostChanged(v) => self.form.gateway_host = v,
            Message::GatewayPortChanged(v) => self.form.gateway_port = v,
            Message::UsernameChanged(v) => self.form.username = v,
            Message::PasswordChanged(v) => self.form.password = v,
            Message::RememberToggled(v) => self.form.remember = v,
            Message::ActionPressed(a) => self.dispatch(a),
            Message::DisconnectSession(id) => self.send(Command::DisconnectRemoteSession { id }),
            Message::Tick => self.tick(SystemTime::now()),
            Message::CoreEvent(e) => self.apply(e),
            Message::LogFilterSelected(f) => self.log_filter = f,
            Message::LogQueryChanged(q) => self.log_query = q,
        }
    }

    pub fn view(&self) -> iced::Element<'_, Message> {
        use iced::widget::column;
        let page = match self.tab {
            // 时长用 `self.now`（由 `Tick` 推进），**不是现取的
            // `SystemTime::now()`**——现取的话这行字只在别的消息顺带
            // 触发重画时才动一下。见 `App::now` 上的说明。
            Tab::Maintain => {
                view::maintain::view(&self.model, &self.form, self.model.elapsed(self.now))
            }
            Tab::Diagnostics => view::diagnostics::view(
                &self.model,
                self.model.proxy.as_ref(),
                &self.environment,
                self.form.can_start(),
            ),
            Tab::Logs => view::logs::view(
                &self.log_tail,
                self.log_filter,
                &self.log_query,
                &self.log_file_name,
            ),
        };
        column![
            view::chrome::title_bar(),
            view::chrome::tabs(self.tab),
            page
        ]
        .into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `update` 是纯状态转移，不碰 `Element`，所以在无头机器上能直接跑。
    #[test]
    fn selecting_a_tab_switches_to_it() {
        let mut app = App::default();
        assert_eq!(app.tab(), Tab::Maintain, "默认应当停在维护页");

        for want in [Tab::Logs, Tab::Diagnostics, Tab::Maintain] {
            app.update(Message::TabSelected(want));
            assert_eq!(app.tab(), want);
        }
    }

    /// 修复轮 1：堵住第一轮 N4/N5 两条盲区。
    #[test]
    fn window_is_fixed_size_and_not_resizable() {
        let w = window_settings();
        assert_eq!(
            (w.size.width, w.size.height),
            WINDOW_SIZE,
            "窗口尺寸必须来自 WINDOW_SIZE，不能另写一份"
        );
        assert!(!w.resizable, "窗口不可缩放");
    }

    /// 修复轮 1：堵住第一轮 N6。
    #[test]
    fn single_instance_mutex_name_is_pinned() {
        assert_eq!(SINGLE_INSTANCE_NAME, "rmc-client");
    }

    /// iced 0.14 会跟随系统深浅色，而这套画板是固定浅色的。这条守住
    /// 「底色必须浅到 `color::TEXT` 读得出来」。
    #[test]
    fn app_theme_is_light_enough_for_the_fixed_palette() {
        use iced::theme::Base;

        let bg = APP_THEME.base().background_color;
        assert!(
            bg.r > 0.8 && bg.g > 0.8 && bg.b > 0.8,
            "主题底色不是浅色，固定浅色画板会糊成一片：{bg:?}"
        );
        // 文字与底色必须差得开。`color::TEXT` 是 #1c1c1c，浅底下没问题；
        // 换成深色主题时这条会连同上面一起红。
        let text = theme::color::TEXT;
        let gap = (bg.r - text.r).abs() + (bg.g - text.g).abs() + (bg.b - text.b).abs();
        assert!(gap > 1.5, "正文与底色对比不足：bg={bg:?} text={text:?}");
    }

    /// 装配结果这一层的防线：`main()` 有没有真的用上已经被测过的
    /// [`WINDOW_TITLE`] / [`APP_THEME`] / [`window_settings`]。
    ///
    /// 泛型 `check` 不是为了复用——是为了**绕开固有方法遮蔽**。
    /// `Application` 有同名的 builder 方法 `title(self, ..) -> Self` 等，
    /// 对具体类型写 `p.title(&state, id)` 会解析到 builder 上（`E0061`/
    /// `E0599`）。把 `p` 交给一个只知道 `P: iced::Program<..>` 的泛型函数，
    /// 方法解析就只剩 trait 上那一份。
    #[test]
    fn program_wires_the_tested_title_theme_and_window() {
        fn check<P>(p: &P)
        where
            P: iced::Program<State = App, Message = Message, Theme = iced::Theme>,
        {
            let (state, _task) = p.boot();
            let id = iced::window::Id::unique();

            // `.title()` 设的是**操作系统**窗口标题（任务栏、Alt+Tab），
            // 不在控件树里，`tests/ui.rs` 的禁用词扫描看不见它。
            let title = p.title(&state, id);
            assert_eq!(title, WINDOW_TITLE, "OS 窗口标题没有用 WINDOW_TITLE");
            for banned in BANNED_WORDS {
                assert!(
                    !title.contains(banned),
                    "OS 窗口标题出现需求禁用的词 {banned}：{title}"
                );
            }

            assert_eq!(
                p.theme(&state, id),
                Some(APP_THEME),
                "没有钉死浅色主题——iced 0.14 会跟随系统深浅色，见 APP_THEME"
            );

            let w = p.window().expect("Program::window 应当给出窗口设置");
            assert_eq!(
                (w.size.width, w.size.height),
                WINDOW_SIZE,
                "窗口尺寸没有来自 WINDOW_SIZE"
            );
            assert!(!w.resizable, "窗口不可缩放");
        }

        // 不接内核：这两条验的是装配（标题、主题、窗口、挂的是哪棵树），
        // 跟内核无关，而 `program(Some(..))` 会要一个 tokio 运行时。
        check(&program(None));
    }

    /// 同一层的另一半：`main()` 挂上去的 view 是不是 [`App::view`]。
    ///
    /// 少了这条，`program()` 里把 view 换成一棵字面画着 `"Gateway"` 的树
    /// 也不会有任何测试变红——`tests/ui.rs` 扫的是 `App::view()`，而不是
    /// `main()` 实际装配进去的那个。
    ///
    /// 两半各自带载，评审实测过：挂一棵只有 `text("Gateway")` 的树打红
    /// 反向自证那一半；挂 `column![App::view(), text("网关直连模式")]`
    /// （产品名与三个页签都在）打红禁用词扫描那一半。
    #[test]
    fn program_view_is_the_app_view_and_says_no_gateway() {
        fn check<P>(p: &P)
        where
            P: iced::Program<State = App, Message = Message, Theme = iced::Theme>,
            P::Renderer: iced_test::core::text::Renderer<Font = iced::Font> + 'static,
        {
            let (state, _task) = p.boot();
            let id = iced::window::Id::unique();
            let mut ui = iced_test::simulator(p.view(&state, id));

            // 反向自证：先确认扫描器真的遍历得到我们自己的文本控件。
            // 少了这一步，下面的禁用词断言在「树是空的」时是永远为真的空转。
            assert!(
                ui.find(WINDOW_TITLE).is_ok(),
                "main 装配进去的 view 没有画出产品名，这不是 App::view"
            );
            for label in Tab::ALL.map(|t| t.label()) {
                assert!(
                    ui.find(label).is_ok(),
                    "main 装配进去的 view 没有画出页签「{label}」"
                );
            }

            let hit = ui.find(|c: iced_test::selector::Candidate<'_>| match c {
                iced_test::selector::Candidate::Text { content, .. } => BANNED_WORDS
                    .iter()
                    .find(|w| content.contains(**w))
                    .map(|w| format!("「{content}」里含有 {w}")),
                _ => None,
            });
            assert!(
                hit.is_err(),
                "main 装配进去的控件树里出现了需求禁用的词：{}",
                hit.unwrap_or_default()
            );
        }

        // 不接内核：这两条验的是装配（标题、主题、窗口、挂的是哪棵树），
        // 跟内核无关，而 `program(Some(..))` 会要一个 tokio 运行时。
        check(&program(None));
    }

    /// W141 的第三道：`Message` 不许把口令印出来。
    ///
    /// 改红：把 `impl Debug for Message` 删掉换成 `#[derive(Debug)]`——
    /// `Zeroizing` 的 `Debug` 是转发的，`PasswordChanged` 会原样印出口令。
    #[test]
    fn message_debug_redacts_the_password() {
        const CANARY: &str = "canary-7f3a9e-must-never-be-printed";
        let m = Message::PasswordChanged(Zeroizing::new(CANARY.into()));
        let dumped = format!("{m:?}");

        // 反向自证：`Debug` 真的印了东西、真的认出了这个变体。
        assert!(dumped.contains("PasswordChanged"), "{dumped}");
        assert!(!dumped.contains(CANARY), "口令原样进了 Debug：{dumped}");
        assert!(!dumped.contains("7f3a9e"), "口令片段进了 Debug：{dumped}");

        // 其余变体照常可读——遮的只有口令那一条，不是整个枚举被掏空。
        assert!(format!("{:?}", Message::UsernameChanged("zhang".into())).contains("zhang"));
        assert!(format!("{:?}", Message::TabSelected(Tab::Logs)).contains("Logs"));
        assert!(format!("{:?}", Message::DisconnectSession(7)).contains('7'));
    }

    /// W141 的第四道：`App` 整份 `Debug` 出来也不许带口令。
    ///
    /// `App` 是 `derive(Debug)` 的，靠的是 [`Form`] 手写的那份。
    #[test]
    fn app_debug_output_redacts_the_password() {
        const CANARY: &str = "canary-7f3a9e-must-never-be-printed";
        let mut app = App::default();
        app.update(Message::PasswordChanged(Zeroizing::new(CANARY.into())));
        app.update(Message::UsernameChanged("tunnel-zhang".into()));
        let dumped = format!("{app:?}");

        assert!(dumped.contains("App"), "{dumped}");
        assert!(dumped.contains("tunnel-zhang"), "{dumped}");
        assert!(!dumped.contains(CANARY), "口令经 App 漏了出来：{dumped}");
    }

    /// 七条表单消息各自写进**自己**那个字段。
    ///
    /// 这个 `match` 有七条形状一样的分支，是复制粘贴最容易写串的地方
    /// （把 `GatewayHostChanged` 写成 `self.form.appliance_host = v`），
    /// 而写串之后界面看起来完全正常——只是改运维服务器地址会改到一体机上。
    ///
    /// 逐条验：每次只发一条消息，断言**只有那一个字段变了**。
    #[test]
    fn each_form_message_writes_only_its_own_field() {
        fn snapshot(app: &App) -> Vec<String> {
            let f = app.form();
            vec![
                f.appliance_host.clone(),
                f.appliance_port.clone(),
                f.gateway_host.clone(),
                f.gateway_port.clone(),
                f.username.clone(),
                f.password.to_string(),
                f.remember.to_string(),
            ]
        }

        let messages = [
            Message::ApplianceHostChanged("a".into()),
            Message::AppliancePortChanged("b".into()),
            Message::GatewayHostChanged("c".into()),
            Message::GatewayPortChanged("d".into()),
            Message::UsernameChanged("e".into()),
            Message::PasswordChanged(Zeroizing::new("f".into())),
            Message::RememberToggled(true),
        ];
        assert_eq!(messages.len(), snapshot(&App::default()).len());

        for (i, m) in messages.into_iter().enumerate() {
            let mut app = App::default();
            let before = snapshot(&app);
            app.update(m.clone());
            let after = snapshot(&app);
            for (j, (b, a)) in before.iter().zip(after.iter()).enumerate() {
                if i == j {
                    assert_ne!(b, a, "{m:?} 没有改动它自己那个字段");
                } else {
                    assert_eq!(b, a, "{m:?} 顺手改了第 {j} 个字段");
                }
            }
        }
    }

    /// 页签切换不碰表单，表单输入也不碰页签。
    #[test]
    fn typing_into_the_form_does_not_move_the_tab() {
        let mut app = App::default();
        app.update(Message::TabSelected(Tab::Logs));
        app.update(Message::UsernameChanged("zhang".into()));
        assert_eq!(app.tab(), Tab::Logs);
        assert_eq!(app.form().username, "zhang");
    }

    /// 隧道事件经 `App::apply` 推进视图模型。
    ///
    /// 改红：把 `apply` 的函数体换成 `{}`，这条立刻红。Task 10 的
    /// `Subscription` 接的就是这个入口。
    #[test]
    fn tunnel_events_reach_the_view_model() {
        use rmc_core::state::State;
        let mut app = App::default();
        assert_eq!(app.model().state, State::Idle);
        app.apply(rmc_core::TunnelEvent::State(State::Connecting));
        assert_eq!(app.model().state, State::Connecting);
        assert!(!app.model().credentials_visible(), "连接过程中凭据区该隐藏");
    }

    /// 需求硬禁令在常量这一层的防线；控件树那一层在 `tests/ui.rs`。
    #[test]
    fn window_title_is_chinese_and_never_says_gateway() {
        assert_eq!(WINDOW_TITLE, "远程运维客户端");
        for banned in BANNED_WORDS {
            assert!(
                !WINDOW_TITLE.contains(banned),
                "界面上不许出现 {banned}：{WINDOW_TITLE}"
            );
        }
    }

    // =================================================================
    // Task 10 的接线。**每一条都回答「断掉哪一行会让它红」。**
    //
    // 这一轮最危险的形状是接线本身：九个任务的零件在这里第一次真的连
    // 起来，而接错了**大多不会编译失败**——会安静地跑，只是某条线没接
    // 上。下面每一条对着一根线。
    // =================================================================

    use rmc_core::state::State;
    use std::time::Duration;
    use tokio::sync::{broadcast, mpsc};

    /// 一根接到测试手里的假线。
    ///
    /// 返回 `(App, 命令接收端, 事件发送端)`：命令那一头让「按钮真的发出
    /// 了命令」可观测，事件那一头让「事件真的到了界面」可观测。
    fn app_with_fake_core(
        root: &std::path::Path,
    ) -> (App, mpsc::Receiver<Command>, broadcast::Sender<TunnelEvent>) {
        let (cmd_tx, cmd_rx) = mpsc::channel(32);
        let (ev_tx, ev_rx) = broadcast::channel(32);
        let core = wiring::Core::new(
            cmd_tx,
            ev_rx,
            wiring::AppPaths::at(root.to_path_buf()),
            None,
        );
        (App::with_core(Some(core)), cmd_rx, ev_tx)
    }

    fn filled_form() -> Form {
        Form {
            appliance_host: "192.168.100.10".into(),
            appliance_port: "61001".into(),
            gateway_host: "ops.example.com".into(),
            gateway_port: "443".into(),
            username: "tunnel-zhang".into(),
            password: Zeroizing::new("pw".into()),
            remember: false,
            detected_proxy: None,
        }
    }

    // ---------- 线 1：按钮 → 命令 ----------

    /// **点「开启远程维护」真的会有一条 `Command::Start` 送进内核，而且
    /// 带的是表单上那四样东西。**
    ///
    /// 断的是哪一根线：`Model::buttons` 有表驱动测试、`tests/ui.rs` 验过
    /// 按钮点得动、`Form::validate` 有单测，**中间 `App::dispatch` 那一段
    /// 两头都没人守**。在这一轮之前 `Message::ActionPressed(_)` 的分支
    /// 体**就是一对空花括号**，六道闸门全绿。
    ///
    /// 改红：把 `Action::Start` 那一支改成 `{}`；或者把 `gateway` 与
    /// `appliance` 写反（那会让隧道去连一体机、把一体机当运维服务器，
    /// 而界面上一个字都看不出来）。
    #[test]
    fn pressing_start_sends_the_addresses_the_user_typed() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let (mut app, mut cmd_rx, _ev) = app_with_fake_core(dir.path());
        app.form = filled_form();

        app.update(Message::ActionPressed(Action::Start));

        match cmd_rx.try_recv().expect("没有任何命令送进内核") {
            Command::Start {
                username,
                password,
                gateway,
                appliance,
            } => {
                assert_eq!(username, "tunnel-zhang");
                assert_eq!(password.as_str(), "pw");
                assert_eq!(gateway.to_string(), "ops.example.com:443");
                assert_eq!(appliance.to_string(), "192.168.100.10:61001");
            }
            other => panic!("发出去的不是 Start：{other:?}"),
        }
        assert!(cmd_rx.try_recv().is_err(), "一次点击发了不止一条命令");
    }

    /// 表单没填对时**一条命令都不发**。
    ///
    /// 按钮此刻本来就是灰的（`action_enabled`），这条守的是第二道：
    /// 真有一条 `Start` 送上去，Supervisor 会拒掉它，而界面上只会闪一下。
    #[test]
    fn an_invalid_form_sends_nothing() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let (mut app, mut cmd_rx, _ev) = app_with_fake_core(dir.path());
        // 反向自证：确实是"没填对"，不是"没点到"。
        assert!(app.form().validate().is_err());
        app.update(Message::ActionPressed(Action::Start));
        assert!(cmd_rx.try_recv().is_err(), "表单没填对也把命令发出去了");
    }

    /// 三个止损动作与断开会话各发各的命令，**一条都不许串**。
    ///
    /// 改红：把 `Action::Stop` 那一支改成 `self.send(Command::Cancel)`
    /// ——「停止」会变成「取消」，在 `Connected` 状态下 Supervisor 的
    /// `Cancel` 准入判断直接把它丢掉，**隧道停不下来**，而界面上什么都
    /// 看不出来。这条当场红。
    #[test]
    fn every_action_sends_its_own_command() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let cases: [(Action, &str); 3] = [
            (Action::Cancel, "Cancel"),
            (Action::Stop, "Stop"),
            (Action::RetryNow, "RetryNow"),
        ];
        for (action, want) in cases {
            let (mut app, mut cmd_rx, _ev) = app_with_fake_core(dir.path());
            app.update(Message::ActionPressed(action));
            let got = format!("{:?}", cmd_rx.try_recv().expect("没有命令"));
            assert_eq!(got, want, "{action:?} 发出的命令不对");
        }

        let (mut app, mut cmd_rx, _ev) = app_with_fake_core(dir.path());
        app.update(Message::DisconnectSession(7));
        let got = cmd_rx.try_recv().expect("没有命令");
        assert!(
            matches!(got, Command::DisconnectRemoteSession { id: 7 }),
            "断开会话带的不是那个会话的 id：{got:?}"
        );
    }

    /// 没接上内核时点按钮**不崩，而且什么都不往盘上写**。
    ///
    /// `App::default()` 就是这个状态（`tests/ui.rs` 里全是它）。
    ///
    /// # W180：这条测试上一版名不副实
    ///
    /// 它叫 `..._touches_no_disk`，开头建了一个临时目录当"假 HOME"、
    /// 断言它是空的，**然后既没有把 `HOME` 指过去、也没有再查一次**。
    /// 那三行是**纯死代码**，名字里的 `touches_no_disk` 没有任何断言
    /// 支撑——跟上一轮刚修掉的那条空转断言是同一个形状。已删。
    ///
    /// 现在名字只说它证明得了的事，而"不往盘上写"这件事改由**两道**
    /// 更管用的防线守：
    ///
    /// 1. 下面这几条断言（没有内核就不会有 `last_export`、日志尾部恒定
    ///    是 `NotWrittenYet`）——它们直接观察"有没有发生"；
    /// 2. [`tests::only_main_decides_where_the_app_directory_is`] 那道
    ///    源码扫描——它挡住**故障的来源**（在别处退回
    ///    `AppPaths::resolve()`），而且不依赖任何一次真实的文件系统状态。
    ///
    /// 第 2 道尤其要紧：评审复现过，退回那个写法之后，**干净机器上的
    /// 第一次运行**里 `bundle` 会先建出 zip 再因为 `log_dir` 不存在而
    /// 返回 `Err`，于是 `last_export` 仍是 `None`——**测试绿，而 zip
    /// 已经落在盘上**，第二次跑才会红。也就是说靠观察 `last_export`
    /// 去防这场事故，恰恰会在事故发生的那一次放过它。
    /// （那个"先建 zip 后失败"本身也是个真 bug，已一并修掉，见
    /// `diag::tests::the_very_first_export_on_a_clean_machine_succeeds`。）
    ///
    /// 改红：把 `export_diagnostics` / `Action::OpenLogDir` 里那两句
    /// `let Some(..) = self.paths() else { return }` 换回
    /// `AppPaths::resolve()`——源码扫描那条当场红（这一条则未必，
    /// 见上）。
    #[test]
    fn pressing_buttons_without_a_core_is_harmless() {
        for action in Action::ALL {
            let mut app = App {
                form: filled_form(),
                ..App::default()
            };
            app.update(Message::ActionPressed(action));
            assert!(
                app.last_export().is_none(),
                "{action:?}：没有内核却导出了一个诊断包"
            );
        }
        let mut app = App::default();
        app.update(Message::DisconnectSession(1));
        app.update(Message::Tick);

        // 没有内核时日志页说的是"还没有日志"，而不是去读别处的文件。
        assert_eq!(app.log_tail(), &LogTail::NotWrittenYet);
        // 底部那行字照样完整——文件名只跟日期有关。
        assert!(
            app.log_file_name.starts_with("rmc-") && app.log_file_name.ends_with(".log"),
            "{}",
            app.log_file_name
        );
    }

    /// **只有 `main.rs` 可以决定落点在哪儿。**
    ///
    /// # 为什么这是一道闸门，而不是一句约定
    ///
    /// `AppPaths::resolve()` 读的是真实环境变量，指向的是**开发机的家
    /// 目录**。在 `main.rs` 之外调它，等于让某一段代码在"还不知道落点"
    /// 的时候自己猜一个——而这件事已经在本项目烧掉了整整一轮：
    /// 上一轮 `App::export_diagnostics` 与 `Action::OpenLogDir` 在没有
    /// 内核时退回它，于是**每跑一次 `cargo test` 就往真实的 `~/.rmc/`
    /// 里扔一个诊断包**（攒到 27 个才被发现），并且会真的弹出一个文件
    /// 管理器窗口。
    ///
    /// 这道扫描挡的是**故障的来源**，不是它的痕迹：它不依赖任何一次
    /// 真实的文件系统状态，也就不会像"事后查目录空不空"那样在干净机器
    /// 的第一次运行里放过去（W180，见
    /// [`tests::pressing_buttons_without_a_core_is_harmless`]）。
    ///
    /// 形状照 `diag.rs` 那条
    /// `this_crate_never_polls_the_transport_for_the_current_proxy`。
    ///
    /// 改红：在 `lib.rs`（或别的任何非 `main.rs` 的文件）里写一行
    /// `let p = wiring::AppPaths::resolve();`——这条当场红。
    #[test]
    fn only_main_decides_where_the_app_directory_is() {
        // needle 拼出来而不是写成字面量：写成字面量的话**这一行自己**
        // 就是一处命中，测试永远红。
        let needle = concat!("AppPaths::", "resolve");
        let hits = grep_src(needle);
        let outside: Vec<&String> = hits.iter().filter(|h| !h.starts_with("main.rs:")).collect();
        assert!(
            outside.is_empty(),
            "只有 main.rs 可以调 {needle}()——别处调它意味着有代码在\
             「还不知道落点」时自己猜了一个，而那个猜测指向开发机的家目录：\n{outside:#?}"
        );

        // 反向自证之一：`main.rs` 里确实有一处，扫描器真的会命中。
        assert!(
            hits.iter().any(|h| h.starts_with("main.rs:")),
            "main.rs 里居然没有调用 {needle}()——扫描器八成没走到，\
             上面那条断言是空转的：{hits:?}"
        );
        // 反向自证之二：扫描器真的走到了 src/ 的别的文件。
        let anchor = grep_src("pub const WINDOW_TITLE");
        assert!(
            anchor.iter().any(|h| h.starts_with("lib.rs:")),
            "扫描器没在 lib.rs 里找到 WINDOW_TITLE：{anchor:?}"
        );
    }

    /// rmc-app 的 `src/` 下含 `needle` 的**非注释行**，形如
    /// `main.rs:42: <原文>`。
    ///
    /// 跟 `diag.rs` 里那份是同一个形状；没有提出来共用，是因为它只有
    /// 二十行、而把它挪到某个公共位置会让两条扫描互相牵动。
    fn grep_src(needle: &str) -> Vec<String> {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut out = Vec::new();
        let mut stack = vec![root.clone()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("读 src 目录") {
                let path = entry.expect("读目录项").path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                let rel = path
                    .strip_prefix(&root)
                    .unwrap_or(&path)
                    .display()
                    .to_string();
                let text = std::fs::read_to_string(&path).expect("读源文件");
                for (i, line) in text.lines().enumerate() {
                    let t = line.trim_start();
                    if t.starts_with("//") {
                        continue;
                    }
                    if t.contains(needle) {
                        out.push(format!("{rel}:{}: {t}", i + 1));
                    }
                }
            }
        }
        out
    }

    // ---------- 线 1.5：W177 —— `main()` 最后那两根线 ----------

    /// **`assemble()` 真的把内核交到了界面手上，也真的登记了事件源。**
    ///
    /// # 断的是哪一根线
    ///
    /// 上一轮这两根线在 `main()` 里，而 `main()` 在这台无头机器上一个字
    /// 都验不了。实测两枪、七道闸门全绿：删掉 `install_event_source`
    /// （界面永远收不到任何内核事件），或者把 `program(Some(core))` 写成
    /// `program(None)`（内核根本没接上）。
    ///
    /// 钥匙是 `iced::Program::boot()` 本来就是**公开**的——Task 6 用它取
    /// 过 `title`/`theme`/`window`/`view`，**没取过状态**。取出状态之后
    /// 这两根线都看得见了：
    ///
    /// 1. **内核到没到界面手上**：往这个内核的落点里写一行带记号的审计
    ///    日志，断言 `App::log_tail()` 里读得到它。这个判据是免费的——
    ///    `App::with_core` 本来就会 `reload_logs()`，而
    ///    [`wiring::read_tail`] 在没有内核时**按设计**返回
    ///    `NotWrittenYet`，所以"读到了这个目录下的那一行"就等价于
    ///    "内核交到界面手上了"，不需要任何新 API。
    /// 2. **事件源登没登记**：[`wiring::subscribe_installed`] 本来就是
    ///    公开的，先反向自证它是 `None`，`assemble` 之后断言拿得到、
    ///    而且真的收得到一条事件。
    ///
    /// 两枪打在**两条不同的断言**上。
    ///
    /// **这条测试是整个测试二进制里唯一调用 `assemble()` 的**——
    /// `install_event_source` 用的是 `OnceLock`，第二次调用不生效，
    /// 所以第一条断言（登记之前必须是 `None`）只有在"只有这一条测试会
    /// 登记"的前提下才站得住。
    #[tokio::test]
    async fn assemble_hands_the_core_to_the_ui_and_installs_the_event_source() {
        const MARK: &str = "mark-assemble-3e7a";

        // 绕开固有方法遮蔽：`Application` 自己有同名的 builder 方法，
        // 对具体类型直接 `p.boot()` 解析不到 trait 上那一份。同
        // `program_wires_the_tested_title_theme_and_window`。
        fn boot_state<P>(p: &P) -> App
        where
            P: iced::Program<State = App, Message = Message, Theme = iced::Theme>,
        {
            let (state, _task) = p.boot();
            state
        }

        // 反向自证之一：还没登记过。
        assert!(
            wiring::subscribe_installed().is_none(),
            "有别的测试抢先登记了进程级事件源，这条测试的前提不成立"
        );

        let dir = tempfile::tempdir().expect("建临时目录");
        let paths = wiring::AppPaths::at(dir.path().to_path_buf());
        // 往**这个内核的落点**里写一行只有它才看得到的日志。
        let a = rmc_core::audit::Audit::open(paths.log_dir()).expect("建日志目录");
        a.record(rmc_core::audit::Level::Info, MARK);

        // 反向自证之二：不接内核的话读不到它——下面那条断言因此带载。
        assert_eq!(
            App::with_core(None).log_tail(),
            &LogTail::NotWrittenYet,
            "没有内核居然也读到了日志，下面那条断言证明不了内核接上了"
        );

        let (cmd_tx, _cmd_rx) = mpsc::channel(4);
        let (ev_tx, ev_rx) = broadcast::channel(4);
        let core = wiring::Core::new(cmd_tx, ev_rx, paths, None);

        let state = boot_state(&assemble(core));

        // 第一根线：内核到了界面手上。
        let got: Vec<&str> = state
            .log_tail()
            .lines()
            .iter()
            .map(|l| l.message.as_str())
            .collect();
        assert!(
            got.contains(&MARK),
            "界面没拿到内核——它读的不是这个内核的日志目录：{got:?}"
        );

        // 第二根线：事件源登记了，而且真的通。
        let mut rx = wiring::subscribe_installed().expect("进程级事件源没有登记");
        ev_tx
            .send(TunnelEvent::State(State::Preflight))
            .expect("发事件");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("登记的事件源收不到东西")
                .expect("事件通道断了"),
            TunnelEvent::State(State::Preflight)
        );
    }

    // ---------- 线 2：事件 → 界面 ----------

    /// **内核推上来的代理信息真的落到了诊断页要画的两个地方**（W152）。
    ///
    /// 断的是哪一根线：`Model::apply` 处理 `TunnelEvent::Proxy` 那一行，
    /// 以及 `App::apply` 里把它同步给表单那一行。在这一轮之前
    /// `Model.proxy` 与 `Form::detected_proxy` **一个写入方都没有**，
    /// 诊断页那三行在真实运行里一行都不会出现。
    ///
    /// 改红：把 `Model::apply` 里 `TunnelEvent::Proxy` 那一支改成 `{}`；
    /// 或者把 `App::apply` 里同步 `detected_proxy` 那一行删掉（第二组
    /// 断言红，维护页的「出网」会永远写着「直连」）。
    #[test]
    fn a_proxy_event_reaches_both_the_diagnostics_rows_and_the_form() {
        use rmc_core::diagnostic::{ConnectOutcome, ProxyAuthSummary, ProxyObservation};

        let mut app = App::default();
        assert!(app.model().proxy.is_none());
        assert_eq!(app.form().egress_label(), "直连");

        app.apply(TunnelEvent::Proxy(ProxyObservation::Via {
            endpoint: "proxy.company.com:8080".parse().unwrap(),
            connect: ConnectOutcome::Established,
            auth: ProxyAuthSummary::FinalTokenIssued {
                package: "NTLM".into(),
                rounds: 2,
            },
        }));

        let p = app.model().proxy.as_ref().expect("诊断页那三行没有数据");
        assert_eq!(p.endpoint, "proxy.company.com:8080");
        assert_eq!(p.connect, ConnectOutcome::Established);
        assert_eq!(
            app.form().egress_label(),
            "经系统代理 proxy.company.com:8080"
        );

        // 判定直连之后两边都要跟着回到「直连」——留着上一次的代理是
        // 另一个方向的假话。
        app.apply(TunnelEvent::Proxy(ProxyObservation::Direct));
        assert!(app.model().proxy.is_none(), "直连了还画着一台代理");
        assert_eq!(app.form().egress_label(), "直连");
    }

    /// 表单里那份代理**不是第二个真相来源**：它恒等于 `Model` 里那份。
    #[test]
    fn the_form_never_disagrees_with_the_model_about_the_proxy() {
        use rmc_core::diagnostic::{ConnectOutcome, ProxyAuthSummary, ProxyObservation};
        let mut app = App::default();
        for o in [
            ProxyObservation::Direct,
            ProxyObservation::Via {
                endpoint: "a.example.com:1".parse().unwrap(),
                connect: ConnectOutcome::Failed,
                auth: ProxyAuthSummary::NotAttempted,
            },
            ProxyObservation::Via {
                endpoint: "b.example.com:2".parse().unwrap(),
                connect: ConnectOutcome::Established,
                auth: ProxyAuthSummary::NotAttempted,
            },
            ProxyObservation::Direct,
        ] {
            app.apply(TunnelEvent::Proxy(o));
            assert_eq!(
                app.form().detected_proxy,
                app.model().proxy.as_ref().map(|p| p.endpoint.clone()),
                "表单与视图模型对代理的说法分叉了"
            );
        }
        // 别的事件不许顺手改掉它。
        app.apply(TunnelEvent::Proxy(ProxyObservation::Via {
            endpoint: "c.example.com:3".parse().unwrap(),
            connect: ConnectOutcome::Established,
            auth: ProxyAuthSummary::NotAttempted,
        }));
        app.apply(TunnelEvent::State(State::Connecting));
        assert_eq!(
            app.form().detected_proxy.as_deref(),
            Some("c.example.com:3")
        );
    }

    /// **回到 `Idle` 时口令被抹掉。**
    ///
    /// 改红：把 `App::apply` 里那次 `should_clear_password` 判断删掉。
    #[test]
    fn coming_back_to_idle_wipes_the_password() {
        const CANARY: &str = "canary-7f3a9e-must-never-be-printed";
        let mut app = App::default();
        app.update(Message::PasswordChanged(Zeroizing::new(CANARY.into())));
        app.update(Message::UsernameChanged("tunnel-zhang".into()));

        app.apply(TunnelEvent::State(State::Connecting));
        assert_eq!(
            app.form().password.as_str(),
            CANARY,
            "还在连接就把口令抹了，断线重连时会连不上"
        );

        app.apply(TunnelEvent::State(State::Idle));
        assert!(app.form().password.is_empty(), "回到未开启之后口令还留着");
        // 其余已填内容保留——抹的只有口令。
        assert_eq!(app.form().username, "tunnel-zhang");
    }

    // ---------- 线 3：Tick（W150） ----------

    /// **「已连接 HH:MM:SS」真的靠 `Tick` 走字。**
    ///
    /// 断的是哪一根线：`Model::elapsed` 有单测，`App::view` 把它画出来
    /// 也有测试（`tests/ui.rs` 的 `the_elapsed_timer_is_drawn_when_it_
    /// has_a_value`），**中间「现在几点」从哪儿来那一步没人守**。
    /// 在这一轮之前 `view` 里写的是现取的 `SystemTime::now()`，而
    /// **全 crate grep 不到任何 `Tick`**——这行字只在别的消息顺带触发
    /// 重画时才动一下。
    ///
    /// 改红：把 `App::view` 里的 `self.model.elapsed(self.now)` 换回
    /// `self.model.elapsed(std::time::SystemTime::now())`——第二帧的
    /// 断言当场红（真实时间跟这条测试注入的假时间差着十年）。
    #[test]
    fn the_elapsed_timer_walks_with_every_tick() {
        let since = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let mut app = App::default();
        app.apply(TunnelEvent::ConnectedSince(since));
        app.apply(TunnelEvent::State(State::Connected { degraded: false }));

        let drawn = |app: &App| {
            let mut ui = iced_test::simulator(app.view());
            for want in ["00:00:05", "00:01:05", "01:00:05"] {
                if ui.find(want).is_ok() {
                    return Some(want.to_string());
                }
            }
            None
        };

        app.tick(since + Duration::from_secs(5));
        assert_eq!(
            drawn(&app).as_deref(),
            Some("00:00:05"),
            "第一跳之后界面上没画出已连接时长"
        );

        app.tick(since + Duration::from_secs(65));
        assert_eq!(
            drawn(&app).as_deref(),
            Some("00:01:05"),
            "时间往前走了一分钟，界面上那行字没跟着走"
        );
    }

    /// **那两条订阅真的挂上去了**，而且计时器真的是一秒一跳。
    ///
    /// 这是 W150 的另一半：上面那条只证明「`tick()` 被调用之后界面会
    /// 动」，证明不了「真的有人每秒调它一次」。
    ///
    /// # 为什么要比哈希，不只是数个数
    ///
    /// `Subscription` 的公开面只有 `units()`（recipe 个数）。光数个数的
    /// 话，把 `TICK` 从 1 秒改成 60 秒、甚至改成一条完全不相干的订阅，
    /// 个数照样是 2。recipe 的哈希是 iced 用来认「这是不是同一个订阅」
    /// 的东西，它把 `Duration` 的值与映射函数的 `TypeId` 都拌了进去。
    ///
    /// 改红（都实测过）：把 `TICK` 改成 60 秒；把 `.map(tick_message)`
    /// 整条 tick 订阅删掉（个数与哈希一起红）；把
    /// `Subscription::run(core_events)` 删掉（事件那一半红，界面从此
    /// 收不到任何内核消息）。
    #[test]
    fn the_ui_subscribes_to_a_one_second_tick_and_to_the_core_events() {
        use iced_futures::subscription::{into_recipes, Hasher};
        use std::hash::Hasher as _;

        fn hashes(s: iced::Subscription<Message>) -> Vec<u64> {
            into_recipes(s)
                .into_iter()
                .map(|r| {
                    let mut h = Hasher::default();
                    r.hash(&mut h);
                    h.finish()
                })
                .collect()
        }

        let app = App::default();
        let got = hashes(subscription(&app));
        assert_eq!(got.len(), 2, "订阅的条数不对：{got:?}");

        let want_tick = hashes(iced::time::every(Duration::from_secs(1)).map(tick_message));
        assert_eq!(want_tick.len(), 1);
        assert!(
            got.contains(&want_tick[0]),
            "没有订阅「每秒一跳」——已连接时长不会自己走字（W150）"
        );

        let want_events = hashes(iced::Subscription::run(core_events));
        assert_eq!(want_events.len(), 1);
        assert!(
            got.contains(&want_events[0]),
            "没有订阅内核事件流——界面永远停在未开启"
        );

        // 反向自证：这个判据真的分得出不同的间隔。少了它，上面那条
        // `contains` 在「哈希恒等」时是永远为真的空转。
        let sixty = hashes(iced::time::every(Duration::from_secs(60)).map(tick_message));
        assert_ne!(want_tick, sixty, "间隔变了哈希却没变，这个判据没用");
        assert!(!got.contains(&sixty[0]), "订阅的是 60 秒一跳，不是 1 秒");
    }

    /// `Tick` 只在日志页在前台时才重读文件。
    ///
    /// 一秒一次的磁盘读在别的页签上纯属白烧，而切回来最多一秒就补上。
    #[test]
    fn a_tick_only_rereads_the_log_file_on_the_log_page() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let (mut app, _cmd, _ev) = app_with_fake_core(dir.path());
        let log = app.log_file_name.clone();
        assert!(!log.is_empty(), "日志文件名没算出来");

        // 现在写一份日志出来。
        let log_dir = dir.path().join("logs");
        std::fs::create_dir_all(&log_dir).unwrap();
        std::fs::write(
            log_dir.join(&log),
            "2026-09-13T11:00:00+08:00 INFO 新写的一行\n",
        )
        .unwrap();

        // 停在维护页：跳一下不重读。
        app.tick(SystemTime::now());
        assert!(app.log_tail().lines().is_empty(), "维护页上也在读日志文件");

        // 切到日志页再跳一下：读到了。
        app.update(Message::TabSelected(Tab::Logs));
        app.tick(SystemTime::now());
        assert_eq!(app.log_tail().lines().len(), 1, "日志页上没有重读文件");
        assert_eq!(app.log_tail().lines()[0].message, "新写的一行");
    }

    // ---------- 线 4：事件流 → `Message::CoreEvent` ----------

    /// **内核发一条事件，界面的状态真的跟着变。**
    ///
    /// 这条走的是 `Message::CoreEvent`（订阅那条流最终吐出来的东西），
    /// 不是直接调 `apply`。改红：把 `Message::CoreEvent(e)` 那一支改成
    /// `{}`——界面会永远停在「未开启」，而按钮照样点得动。
    #[tokio::test]
    async fn an_event_from_the_core_moves_the_status_card() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let (mut app, _cmd, ev_tx) = app_with_fake_core(dir.path());
        assert_eq!(app.model().state, State::Idle);

        // 走的就是 `subscription` 用的那条流。
        use iced::futures::StreamExt;
        let mut stream = Box::pin(wiring::events_into(
            app.core.as_ref().expect("有内核").subscribe(),
            Message::CoreEvent,
        ));
        ev_tx.send(TunnelEvent::State(State::Preflight)).unwrap();
        let msg = stream.next().await.expect("流里没有东西");

        app.update(msg);
        assert_eq!(app.model().state, State::Preflight);
        assert_eq!(app.model().status_card().title, "预检中");
    }

    // ---------- 线 5：导出诊断包（W172） ----------

    /// **点「导出诊断包」真的写出一个 zip，而且里面没有口令。**
    ///
    /// `diag.rs` 那条 `nothing_the_user_typed_into_the_form_reaches_the_
    /// diagnostics_zip` 守的是 `diag::export` 这一层；这一条守的是
    /// **界面到底有没有走那一层**。
    ///
    /// 改红：把 `Action::ExportDiagnostics` 那一支改成 `{}`（第一条
    /// 断言红）；或者让 `App::export_diagnostics` 绕开 `diag::export`
    /// 直接调 `diag::bundle` 并传一个空 `Redaction`（金丝雀那条红）。
    #[test]
    fn exporting_from_the_ui_writes_a_zip_without_the_password() {
        const CANARY: &str = "canary-pw-4f81c2-must-never-leave-this-machine";
        let dir = tempfile::tempdir().expect("建临时目录");
        let (mut app, _cmd, _ev) = app_with_fake_core(dir.path());
        app.form = filled_form();
        app.form.password = Zeroizing::new(CANARY.into());

        // 让日志目录里有一份带金丝雀的日志——诊断包会把它收进去。
        let log_dir = dir.path().join("logs");
        std::fs::create_dir_all(&log_dir).unwrap();
        std::fs::write(
            log_dir.join("rmc-2026-09-13.log"),
            format!("2026-09-13T11:00:00+08:00 INFO 调试行 password={CANARY}\n"),
        )
        .unwrap();

        assert!(app.last_export().is_none());
        app.update(Message::ActionPressed(Action::ExportDiagnostics));

        let zip = app.last_export().expect("点了导出却没有包").to_path_buf();
        assert!(zip.exists(), "{zip:?}");
        let raw = std::fs::read(&zip).unwrap();
        assert!(raw.len() > 100, "导出的包是空的：{} 字节", raw.len());

        // 解开来逐条扫。
        let f = std::fs::File::open(&zip).unwrap();
        let mut archive = zip::ZipArchive::new(f).unwrap();
        let mut names = Vec::new();
        for i in 0..archive.len() {
            use std::io::Read;
            let mut e = archive.by_index(i).unwrap();
            names.push(e.name().to_string());
            let mut buf = String::new();
            let _ = e.read_to_string(&mut buf);
            assert!(
                !buf.contains(CANARY),
                "界面导出的诊断包里带着明文口令：{}",
                e.name()
            );
        }
        // 反向自证：日志真的进包了，上面那条扫描不是在一个空包上空转。
        assert!(
            names.iter().any(|n| n == "logs/rmc-2026-09-13.log"),
            "日志没进包：{names:?}"
        );
    }

    /// 日志页上那个「打开日志目录」按钮**发的是自己那条动作**。
    ///
    /// 真去起一个资源管理器不在测试范围内（那是 `wiring::open_dir`，
    /// 它的判断部分有 `file_manager_for` 的表驱动测试）。
    #[test]
    fn the_log_page_button_carries_the_open_log_dir_action() {
        let mut app = App::default();
        app.update(Message::TabSelected(Tab::Logs));
        let mut ui = iced_test::simulator(app.view());
        ui.click("打开日志目录").expect("点不到「打开日志目录」");
        let messages: Vec<Message> = ui.into_messages().collect();
        assert_eq!(messages.len(), 1, "{messages:?}");
        assert!(
            matches!(messages[0], Message::ActionPressed(Action::OpenLogDir)),
            "{messages:?}"
        );
    }
}
