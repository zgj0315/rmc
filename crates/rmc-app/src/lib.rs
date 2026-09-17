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

use theme::Tab;

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
}
