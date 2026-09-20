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

pub mod theme;
pub mod view;

use theme::{Tab, WINDOW_SIZE};

/// 窗口标题，也是标题栏里画的那行字。
///
/// 需求硬禁令：界面上叫「运维服务器」，不叫 Gateway/网关。
/// `tests/ui.rs` 的 `no_widget_in_the_tree_says_gateway` 扫整棵控件树守这条。
pub const WINDOW_TITLE: &str = "远程运维客户端";

/// 需求硬禁令的词表：界面上叫「运维服务器」，不叫 Gateway/网关。
///
/// 三处防线共用这一份——`tests/ui.rs` 的
/// `no_widget_in_the_tree_says_gateway` 扫 `App::view` 的整棵树，
/// 本文件的 `program_view_is_the_app_view_and_says_no_gateway` 扫
/// **`main()` 实际装配进去的那棵**，`window_title_is_chinese_and_never_says_gateway`
/// 扫操作系统窗口标题。
///
/// 刻意不让它分叉成三份字面量：Task 7-11 还要加三个页面，
/// 词表一旦分叉，迟早有一份漏掉新加的词。
pub const BANNED_WORDS: [&str; 4] = ["Gateway", "gateway", "GATEWAY", "网关"];

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

/// 界面消息。Task 7 起会往这里加隧道事件与表单输入。
#[derive(Debug, Clone)]
pub enum Message {
    TabSelected(Tab),
}

/// 界面状态。
#[derive(Debug)]
pub struct App {
    tab: Tab,
}

impl Default for App {
    fn default() -> Self {
        Self { tab: Tab::Maintain }
    }
}

impl App {
    /// 当前选中的页签。
    pub fn tab(&self) -> Tab {
        self.tab
    }

    pub fn update(&mut self, message: Message) {
        match message {
            Message::TabSelected(t) => self.tab = t,
        }
    }

    pub fn view(&self) -> iced::Element<'_, Message> {
        use iced::widget::column;
        column![view::chrome::title_bar(), view::chrome::tabs(self.tab)].into()
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
