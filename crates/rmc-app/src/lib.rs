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
pub mod model;
pub mod theme;
pub mod view;

use form::Form;
use model::Model;
use theme::{Tab, WINDOW_SIZE};
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
pub fn program() -> iced::application::Application<
    impl iced::Program<State = App, Message = Message, Theme = iced::Theme>,
> {
    iced::application(App::default, App::update, App::view)
        .title(WINDOW_TITLE)
        .theme(APP_THEME)
        .window(window_settings())
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
    /// 视图模型。Task 10 把 `TunnelEvent` 接进来之后由 [`App::apply`] 推进。
    model: Model,
    form: Form,
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
        }
    }
}

impl App {
    /// 当前选中的页签。
    pub fn tab(&self) -> Tab {
        self.tab
    }

    pub fn model(&self) -> &Model {
        &self.model
    }

    pub fn form(&self) -> &Form {
        &self.form
    }

    /// 把一条隧道事件喂给视图模型。Task 10 的 `Subscription` 接这里。
    pub fn apply(&mut self, event: rmc_core::TunnelEvent) {
        self.model.apply(event);
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
            // Task 10 才接得上 Supervisor：这两条现在**确实什么都不做**。
            // 界面上按钮点得动、消息发得出来（`tests/ui.rs` 逐条验），
            // 但没有任何东西在另一头接。不写成 `todo!()` 是因为那会让
            // 一次误点直接崩掉进程。见 task-8-report.md 的「后续完善」。
            Message::ActionPressed(_) | Message::DisconnectSession(_) => {}
        }
    }

    pub fn view(&self) -> iced::Element<'_, Message> {
        use iced::widget::column;
        let page = match self.tab {
            Tab::Maintain => view::maintain::view(
                &self.model,
                &self.form,
                self.model.elapsed(std::time::SystemTime::now()),
            ),
            Tab::Diagnostics => view::diagnostics::view(
                &self.model,
                self.model.proxy.as_ref(),
                &self.environment,
                self.form.can_start(),
            ),
            // Task 11。日志页现在只有页签框架。
            Tab::Logs => iced::widget::space::vertical().into(),
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

        check(&program());
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

        check(&program());
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
}
