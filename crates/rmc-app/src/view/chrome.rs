//! 标题栏与页签。窗口用系统装饰，标题栏这里只画应用名。
//!
//! 本文件里**不应该出现任何判断**。选中态的取色在
//! [`crate::theme::tab_style`]，那边有表驱动测试；这里只负责把它算出来的
//! 两个颜色摆进控件。

use crate::theme::{color, tab_style, Tab};
use crate::Message;
use iced::widget::{button, container, row, space, text};
use iced::{Alignment, Element};

pub fn title_bar<'a>() -> Element<'a, Message> {
    container(
        row![
            text(crate::WINDOW_TITLE).size(12).color(color::TEXT_SUB),
            // iced 0.14：`Space::with_width(Length::Fill)` 没了，换成
            // `space::horizontal()`。
            space::horizontal(),
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
        let (fg, line) = tab_style(t == active);
        r = r.push(
            button(text(t.label()).size(13).color(fg))
                .on_press(Message::TabSelected(t))
                .padding([8, 10])
                .style(move |_, _| button::Style {
                    background: None,
                    text_color: fg,
                    border: iced::Border {
                        color: line,
                        width: 2.0,
                        radius: 0.0.into(),
                    },
                    ..Default::default()
                }),
        );
    }
    container(r.align_y(Alignment::Center)).height(40).into()
}
