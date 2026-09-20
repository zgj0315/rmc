//! 视图层。这里的函数只摆控件，不做判断——见 crate 根的模块文档。
//!
//! [`section`] 与 [`card`] 原来住在 `maintain.rs`。Task 9 的诊断页要用
//! 同一套外框，brief 明写「把这两个辅助函数提到 `view/mod.rs` 供两页
//! 共用」——照抄一份的话，两页的卡片圆角与边框迟早分叉，而那种分叉没有
//! 任何测试看得出来（`iced_test` 的选择器看不到样式）。

use crate::theme::color;
use crate::Message;
use iced::widget::{container, text};
use iced::{Border, Element, Length};

pub mod chrome;
pub mod diagnostics;
pub mod maintain;

/// 分组小标题。
pub(crate) fn section(label: &str) -> Element<'_, Message> {
    text(label).size(12).color(color::TEXT_SUB).into()
}

/// 白底圆角卡片。
pub(crate) fn card(content: Element<'_, Message>) -> Element<'_, Message> {
    container(content)
        .style(|_| container::Style {
            background: Some(color::CARD.into()),
            border: Border {
                color: color::BORDER,
                width: 1.0,
                radius: 6.0.into(),
            },
            ..Default::default()
        })
        .width(Length::Fill)
        .into()
}
