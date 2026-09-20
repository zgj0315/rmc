//! 维护页。用户真正操作的那一屏：填一体机与运维服务器地址、账号口令、
//! 点「开启远程维护」。
//!
//! 本文件里**不应该出现任何判断**——见 crate 根的模块文档。状态卡的四个
//! 值来自 [`Model::status_card`]，按钮来自 [`Model::buttons`]，「这个按钮
//! 该不该可按」来自 [`crate::model::action_enabled`]，「这个框该不该标红」
//! 来自 [`Form::is_marked`] + [`crate::theme::input_border`]，流量的人读
//! 写法来自 [`crate::model::session_traffic`]。这里只负责把它们摆进控件。
//!
//! # 哪些结构是「视图自己的判断」，因此被刻意排掉了
//!
//! 地址两行**任何状态下都画**，只有可编辑性跟着 [`Model::addresses_editable`]
//! 走；账号/口令两行则跟着 [`Model::credentials_visible`] 整块出现或消失。
//!
//! 这不是排版偏好，是**可测性**：两个判断在 `Model` 里是同一个
//! `editable()`，如果地址行也跟着一起藏起来，「地址框真的锁了」就永远
//! 观察不到——框根本不在树里。画出来、去掉 `on_input`，`iced_test` 才能
//! 按键进去确认一条消息都没发出来（`tests/ui.rs` 的
//! `locked_addresses_swallow_typing`）。顺带也对：连着的时候现场人员仍然
//! 需要看见自己连的是哪台一体机。

use super::{card, section};
use crate::form::{Field, Form};
use crate::model::{action_enabled, session_traffic, Model};
use crate::theme::{color, input_border};
use crate::Message;
use iced::widget::{button, checkbox, column, container, row, space, text, text_input, Space};
use iced::{Alignment, Border, Element, Length};
use zeroize::Zeroizing;

/// 卡片里的一行。
fn line(content: iced::widget::Row<'_, Message>) -> Element<'_, Message> {
    content
        .spacing(10)
        .align_y(Alignment::Center)
        .padding([9, 12])
        .into()
}

/// 行首的固定宽度标签，让几行的输入框左边对齐。
fn row_label(label: &str) -> Element<'_, Message> {
    text(label).size(13).width(66).into()
}

/// 一个输入框。边框颜色由 [`input_border`] 决定，`editable` 为假时不挂
/// `on_input`——iced 的 `TextInput` 没有 `on_input` 就是禁用态，敲不进去。
fn input<'a>(
    value: &'a str,
    placeholder: &'a str,
    invalid: bool,
    editable: bool,
    on_input: impl Fn(String) -> Message + 'a,
) -> iced::widget::TextInput<'a, Message> {
    let widget = text_input(placeholder, value)
        .size(13)
        .style(move |theme, status| iced::widget::text_input::Style {
            border: Border {
                color: input_border(invalid),
                ..iced::widget::text_input::default(theme, status).border
            },
            ..iced::widget::text_input::default(theme, status)
        });
    if editable {
        widget.on_input(on_input)
    } else {
        widget
    }
}

/// 「主机框改了」「端口框改了」两条消息的构造器。
type AddrMessages = (fn(String) -> Message, fn(String) -> Message);

/// 「主机 : 端口」一行。
fn addr_row<'a>(
    label: &'a str,
    form: &'a Form,
    values: (&'a str, &'a str),
    fields: (Field, Field),
    msgs: AddrMessages,
    editable: bool,
) -> Element<'a, Message> {
    line(row![
        row_label(label),
        input(
            values.0,
            "主机名或 IP",
            form.is_marked(fields.0),
            editable,
            msgs.0
        )
        .width(Length::Fill),
        text(":").size(12).color(color::TEXT_SUB),
        input(values.1, "端口", form.is_marked(fields.1), editable, msgs.1).width(64),
    ])
}

/// 状态卡。
fn status_card<'a>(model: &Model, elapsed: Option<String>) -> Element<'a, Message> {
    let c = model.status_card();
    let mut r = row![
        container(Space::new().width(10).height(10)).style(move |_| container::Style {
            background: Some(c.dot.into()),
            border: Border {
                radius: 5.0.into(),
                ..Default::default()
            },
            ..Default::default()
        }),
        column![
            text(c.title.clone()).size(15),
            text(c.subtitle.clone()).size(12).color(color::TEXT_SUB),
        ]
        .spacing(1)
        .width(Length::Fill),
    ]
    .spacing(11)
    .align_y(Alignment::Center);

    if let Some(e) = elapsed {
        r = r.push(
            column![
                text(e).size(17),
                text("已连接").size(12).color(color::TEXT_SUB),
            ]
            .spacing(1)
            .align_x(Alignment::End),
        );
    }

    container(r)
        .padding([13, 14])
        .style(move |_| container::Style {
            background: Some(c.background.into()),
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

/// 运维服务器那张卡：地址、出网，以及（仅未开启/失败时）账号、口令、
/// 记住密码。
fn server_card(form: &Form, editable: bool, credentials: bool) -> Element<'_, Message> {
    let egress = line(row![
        row_label("出网"),
        text(form.egress_label()).size(13),
        space::horizontal(),
        text("自动检测").size(12).color(color::TEXT_SUB),
    ]);

    let mut content = column![
        addr_row(
            "地址",
            form,
            (&form.gateway_host, &form.gateway_port),
            (Field::GatewayHost, Field::GatewayPort),
            (Message::GatewayHostChanged, Message::GatewayPortChanged),
            editable,
        ),
        egress,
    ];

    if credentials {
        content = content.push(line(row![
            row_label("账号"),
            input(
                &form.username,
                "账号",
                form.is_marked(Field::Username),
                editable,
                Message::UsernameChanged,
            )
            .width(Length::Fill),
        ]));
        content = content.push(line(row![
            row_label("密码"),
            input(
                &form.password,
                "密码",
                form.is_marked(Field::Password),
                editable,
                |s| Message::PasswordChanged(Zeroizing::new(s)),
            )
            // 口令框必须遮住内容。`tests/ui.rs` 的
            // `the_password_box_masks_what_it_draws` 用差分快照守这一行。
            .secure(true)
            .width(Length::Fill),
        ]));
        content = content.push(line(row![
            Space::new().width(66),
            checkbox(form.remember)
                .label("记住密码")
                .size(14)
                .text_size(13)
                .on_toggle(Message::RememberToggled),
            text("默认不保存，勾选后加密落盘")
                .size(12)
                .color(color::TEXT_SUB),
        ]));
    }

    card(content.into())
}

/// 填错的字段各一行红字。空字段不在里面，见 [`Form::visible_errors`]。
fn hints<'a>(form: &Form) -> Element<'a, Message> {
    let mut col = column![].spacing(3);
    for e in form.visible_errors() {
        col = col.push(text(e.message()).size(12).color(color::FAILED));
    }
    col.into()
}

/// 远程会话列表。连上之后占掉凭据区的位置。
fn sessions<'a>(model: &Model) -> Element<'a, Message> {
    let header = row![
        text("远程会话").size(12).color(color::TEXT_SUB),
        text(format!("{} 个进行中", model.sessions.len()))
            .size(12)
            .color(color::TEXT_SUB),
    ]
    .spacing(8);

    let mut body = column![];
    if model.sessions.is_empty() {
        body = body.push(
            container(text("暂无远程会话").size(12).color(color::TEXT_SUB))
                .padding([13, 12])
                .center_x(Length::Fill),
        );
    } else {
        for s in &model.sessions {
            body = body.push(line(row![
                text(format!("#{}", s.id))
                    .size(12)
                    .color(color::TEXT_SUB)
                    .width(20),
                text(session_traffic(s))
                    .size(12)
                    .color(color::TEXT_SUB)
                    .width(Length::Fill),
                button(text("断开").size(12))
                    .on_press(Message::DisconnectSession(s.id))
                    .padding([4, 11]),
            ]));
        }
    }

    column![header, card(body.into())].spacing(12).into()
}

pub fn view<'a>(model: &'a Model, form: &'a Form, elapsed: Option<String>) -> Element<'a, Message> {
    let editable = model.addresses_editable();
    let credentials = model.credentials_visible();

    let mut body = column![
        status_card(model, elapsed),
        section("维护目标"),
        card(addr_row(
            "一体机",
            form,
            (&form.appliance_host, &form.appliance_port),
            (Field::ApplianceHost, Field::AppliancePort),
            (Message::ApplianceHostChanged, Message::AppliancePortChanged),
            editable,
        )),
        section("运维服务器"),
        server_card(form, editable, credentials),
    ]
    .spacing(12)
    .padding(14);

    if credentials {
        body = body.push(hints(form));
    } else {
        body = body.push(sessions(model));
    }

    body = body.push(space::vertical());

    let buttons = model.buttons();
    if let Some((label, action)) = buttons.primary {
        let mut b = button(text(label).size(13))
            .width(Length::Fill)
            .padding([9, 0]);
        if action_enabled(action, form.can_start()) {
            b = b.on_press(Message::ActionPressed(action));
        }
        body = body.push(b);
    }
    if let Some((label, action)) = buttons.secondary {
        let mut b = button(text(label).size(13))
            .width(Length::Fill)
            .padding([9, 0]);
        if action_enabled(action, form.can_start()) {
            b = b.on_press(Message::ActionPressed(action));
        }
        body = body.push(b);
    }

    body.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::APP_THEME;
    use rmc_core::state::State;
    use zeroize::Zeroizing;

    /// 一份只改**运维服务器那一对地址**的表单。
    ///
    /// 一体机那两个框里的字（`192.168.100.10` / `61001`）在所有夹具里
    /// 逐字相同——这是下面那条测试成立的前提。
    fn form_with_server(host: &str, port: &str) -> Form {
        Form {
            appliance_host: "192.168.100.10".into(),
            appliance_port: "61001".into(),
            gateway_host: host.into(),
            gateway_port: port.into(),
            username: "tunnel-zhang".into(),
            // 这一页别的测试用金丝雀守 `Debug`，这里不测 `Debug`，
            // 只需要一个非空口令让 `validate` 走得到语义校验那一步。
            password: Zeroizing::new("placeholder".into()),
            remember: false,
            detected_proxy: None,
        }
    }

    /// 只渲染**一体机那一行**，跟基线哈希比。
    fn appliance_row_matches(form: &Form, baseline: &std::path::Path) -> bool {
        let element = addr_row(
            "一体机",
            form,
            (&form.appliance_host, &form.appliance_port),
            (Field::ApplianceHost, Field::AppliancePort),
            (Message::ApplianceHostChanged, Message::AppliancePortChanged),
            true,
        );
        let mut ui = iced_test::simulator(element);
        ui.snapshot(&APP_THEME)
            .expect("渲染一体机那一行")
            .matches_hash(baseline)
            .expect("读写基线哈希")
    }

    /// **「填错的框标红」这条连线是可观测的。**
    ///
    /// # 断的是哪一根线
    ///
    /// [`Form::is_marked`] 有单测，[`crate::theme::input_border`] 有表驱动，
    /// **中间那一个表达式两头都没人守**——就是 [`input`] 里的
    /// `color: input_border(invalid)`。
    ///
    /// 实测：把它改成 `input_border(false && invalid)`（填错的框永远不
    /// 标红），`cargo test --workspace --no-fail-fast` **一条都不红**。
    /// 原因是 `iced_test` 的选择器（`iced_selector::Candidate`，
    /// `iced_selector-0.14.0/src/target.rs:160-198`）只带
    /// `id` / `bounds` / `visible_bounds` / 文本内容，**样式、颜色、边框
    /// 一个字段都没有**。
    ///
    /// # 为什么要用 `Reason::Rejected` 来解耦
    ///
    /// 差分快照的难处在于：[`Form::visible_errors`] 同时驱动红框和红字。
    /// 通常「某个框被标红」必然伴随「那个框里的字是错的」，于是两帧的
    /// 差别绝不止边框一处，快照比出不同也说明不了是边框的功劳。
    ///
    /// [`Reason::Rejected`] 是唯一的例外。它挂在 [`Field::ApplianceHost`]
    /// 上，但触发条件是 rmc-core 对**一体机与运维服务器这对地址的关系**
    /// 的判断，跟一体机那两个框里的字一个都不沾。于是能造出两份表单：
    ///
    /// - `clean`：运维服务器是别的地址 → 合法 → 一体机地址框**不标红**
    /// - `marked`：运维服务器填得跟一体机一模一样 → rmc-core 拒 →
    ///   一体机地址框**标红**，而一体机那两个框里的字**逐字未变**
    ///
    /// # 为什么喂 `addr_row` 而不是整页
    ///
    /// 整页做不到：`marked` 那一帧还多着运维服务器那两个框里不同的字、
    /// 以及 [`hints`] 画出来的那行红字，两帧**无论标不标红都不同**——
    /// 这一点由 [`the_whole_page_cannot_isolate_the_border`] 反向钉住。
    ///
    /// 边框确实会落到像素上：`iced_widget-0.14.2/src/text_input.rs:1763`
    /// 的默认 `border.width` 是 `1.0`，[`input`] 的样式闭包只换 `color`、
    /// 保留宽度。
    ///
    /// # Task 9-11 照抄什么
    ///
    /// 「样式在 `iced_test` 这一层不可观测」不等于「不可测」。两步：
    ///
    /// 1. 找一个**让样式变化与文本变化解耦**的输入组合（这里是
    ///    `Reason::Rejected`）；
    /// 2. 把渲染范围缩到**能单独渲染的最小子元素**，而不是整页。
    ///
    /// 代价是那个子元素得从本模块的测试里够得到——所以这条测试住在
    /// `view/maintain.rs` 自己的 `mod tests` 里，而不是 `tests/ui.rs`
    /// （那里只看得见 `pub fn view`）。**零公开 API 变化、零新依赖。**
    #[test]
    fn a_marked_field_really_draws_a_different_border() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let baseline = dir.path().join("appliance-row");

        // 合法：一体机地址框不标红。
        let clean = form_with_server("ops.example.com", "443");
        assert!(clean.validate().is_ok(), "夹具 clean 本该通过校验");
        assert!(!clean.is_marked(Field::ApplianceHost));

        // 一体机 == 运维服务器：rmc-core 拒绝，错误挂在 ApplianceHost 上。
        let marked = form_with_server("192.168.100.10", "61001");
        assert!(
            marked.is_marked(Field::ApplianceHost),
            "夹具 marked 本该让一体机地址框标红：{:?}",
            marked.visible_errors()
        );
        // 解耦的自证：一体机那两个框里的字**逐字相同**，而且端口框两边
        // 都没被标红——两帧的差别只可能出在一体机地址框的边框上。
        assert_eq!(marked.appliance_host, clean.appliance_host);
        assert_eq!(marked.appliance_port, clean.appliance_port);
        assert!(!clean.is_marked(Field::AppliancePort));
        assert!(!marked.is_marked(Field::AppliancePort));

        // 第一帧：基线不存在，`matches_hash` 写一份并返回 true。
        assert!(
            appliance_row_matches(&clean, &baseline),
            "第一帧应当写入基线并返回 true"
        );
        // 反向自证：同一份表单画两次必须一致，否则下面那条只是在测
        // 渲染不稳定，而不是在测边框。
        assert!(
            appliance_row_matches(&clean, &baseline),
            "同一份表单渲染两次结果不一致，快照不可作为判据"
        );
        // 主断言。
        assert!(
            !appliance_row_matches(&marked, &baseline),
            "标红的一体机地址框跟正常的框画出来逐字节相同——\
             input_border 的结果没有进到 Border.color 里"
        );
    }

    /// [`a_marked_field_really_draws_a_different_border`] 为什么必须缩到
    /// 一行：同样那两份表单走**整页**，两帧无论标不标红都不同。
    ///
    /// 这条不是防回归，是把上面那条的**范围选择**钉成文档——少了它，
    /// 后人会顺手把它改成整页，然后得到一条永远为真的断言。
    #[test]
    fn the_whole_page_cannot_isolate_the_border() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let baseline = dir.path().join("whole-page");
        let model = Model {
            state: State::Idle,
            ..Model::default()
        };
        let page = |form: &Form| {
            let mut ui = iced_test::simulator(view(&model, form, None));
            ui.snapshot(&APP_THEME)
                .expect("渲染整页")
                .matches_hash(&baseline)
                .expect("读写基线哈希")
        };

        assert!(page(&form_with_server("ops.example.com", "443")));
        assert!(
            !page(&form_with_server("192.168.100.10", "61001")),
            "整页两帧居然相同"
        );
    }
}
