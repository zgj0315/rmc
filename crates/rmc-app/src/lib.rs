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

    /// 需求硬禁令在常量这一层的防线；控件树那一层在 `tests/ui.rs`。
    #[test]
    fn window_title_is_chinese_and_never_says_gateway() {
        assert_eq!(WINDOW_TITLE, "远程运维客户端");
        for banned in ["Gateway", "gateway", "GATEWAY", "网关"] {
            assert!(
                !WINDOW_TITLE.contains(banned),
                "界面上不许出现 {banned}：{WINDOW_TITLE}"
            );
        }
    }
}
