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
use rmc_core::code::ConnectionCode;
use rmc_core::state::State;
use zeroize::Zeroizing;

/// 「远程工程师请连接 … 端口 …」这一行的文案（Task 11）。
///
/// 只说 IP 与反向端口，不提账号或指纹——这两样运维方那边已经通过连接码
/// 知道了，这一行是讲给**现场人员念给工程师听**用的，越短越好。IPv6
/// 带方括号，跟连接码本体、`HostPort` 的 `Display` 一个规矩。
pub fn engineer_hint(code: &ConnectionCode, port: u16) -> String {
    let ip = match code.ip() {
        std::net::IpAddr::V6(v6) => format!("[{v6}]"),
        v4 => v4.to_string(),
    };
    format!("远程工程师请连接 {ip} 端口 {port}")
}

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
fn server_card<'a>(
    form: &'a Form,
    editable: bool,
    credentials: bool,
    password_note: Option<&'a str>,
) -> Element<'a, Message> {
    let egress = line(row![
        row_label("出网"),
        text(form.egress_label()).size(13),
        space::horizontal(),
        text("自动检测").size(12).color(color::TEXT_SUB),
    ]);

    let mut content = column![
        line(row![
            row_label("连接码"),
            input(
                &form.code,
                "粘贴运维发来的连接码",
                form.is_marked(Field::Code),
                editable,
                Message::CodeChanged,
            )
            .width(Length::Fill),
        ]),
        // 解析成功：「地址 203.0.113.10:22000 · 账号 tunnel-zhang」
        // （小字）；失败：空行占位，不挤动下面几行的位置。
        parsed_line(form),
        egress,
    ];

    if credentials {
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
        // W200 第 3 条：取回记住的密码的结局，画在密码框下面那一行。
        // 「换了 Windows 账号解不开」这句话终于有地方显示了。
        if let Some(note) = password_note {
            content = content.push(line(row![
                Space::new().width(66),
                text(note)
                    .size(12)
                    .color(color::TEXT_SUB)
                    .width(Length::Fill),
            ]));
        }
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

/// 连接码解析成功时画的只读小字：地址与账号。**不是输入项**，界面上
/// 没有分开的地址/账号框——见 `form::Form` 上「Task 8」一节。
///
/// 解析失败（还没填、格式不对）时画一个空行占位，不让下面几行随着
/// 这一行有没有字而上下窜动。
fn parsed_line<'a>(form: &Form) -> Element<'a, Message> {
    let t = match form.parsed_code() {
        Some(c) => format!("地址 {} · 账号 {}", c.server(), c.account()),
        None => String::new(),
    };
    line(row![row_label(""), text(t).size(12).color(color::TEXT_SUB),])
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

/// 维护页。
///
/// `password_note` 是密码框旁边那句话（W200 第 3 条）：启动时取回记住
/// 的密码的结局。`None` 表示没什么好说的。**它是收进来的，不是这里
/// 算的**——四种失败分类的文案来自 Task 4 的
/// `rmc_win::secret::LoadOutcome::diagnostic`，这一层一个字都不重写。
pub fn view<'a>(
    model: &'a Model,
    form: &'a Form,
    elapsed: Option<String>,
    password_note: Option<&'a str>,
) -> Element<'a, Message> {
    let editable = model.addresses_editable();
    let credentials = model.credentials_visible();

    let mut body = column![status_card(model, elapsed)];

    // Task 11：已连接、拿到反向端口、连接码解析得出，三样都有才画这
    // 一行——少了任何一样都没有一个确定的端口号可念给工程师听。未连接
    // 或还没拿到端口时**不画**（不是空行占位），见
    // `the_hint_line_appears_only_when_connected_with_a_port`。
    if let (State::Connected { .. }, Some(port), Some(code)) =
        (&model.state, model.forward_port, form.parsed_code())
    {
        body = body.push(text(engineer_hint(&code, port)).size(13));
    }

    let mut body = body
        .push(section("维护目标"))
        .push(card(addr_row(
            "一体机",
            form,
            (&form.appliance_host, &form.appliance_port),
            (Field::ApplianceHost, Field::AppliancePort),
            (Message::ApplianceHostChanged, Message::AppliancePortChanged),
            editable,
        )))
        .push(section("运维服务器"))
        .push(server_card(form, editable, credentials, password_note))
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
    use rmc_core::code::{AccountName, ConnectionCode, ServerFingerprint};
    use rmc_core::state::State;
    use zeroize::Zeroizing;

    /// 一份只改**运维服务器地址**（连接码里解析出来的那个 IP:端口）的
    /// 表单。连接码只接受 IP，不接受域名，所以旧版那个
    /// `"ops.example.com"` 字面量没法沿用。
    ///
    /// 一体机那两个框里的字（`192.168.100.10` / `61001`）在所有夹具里
    /// 逐字相同——这是下面那条测试成立的前提。
    fn form_with_server(ip: &str, port: u16) -> Form {
        let code = ConnectionCode::new(
            AccountName::parse("tunnel-zhang").unwrap(),
            ip.parse().unwrap(),
            port,
            ServerFingerprint::of_ed25519_public(&[7u8; 32]),
        )
        .expect("夹具必须合法")
        .to_string();
        Form {
            appliance_host: "192.168.100.10".into(),
            appliance_port: "61001".into(),
            code,
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
        let clean = form_with_server("203.0.113.10", 22000);
        assert!(clean.validate().is_ok(), "夹具 clean 本该通过校验");
        assert!(!clean.is_marked(Field::ApplianceHost));

        // 一体机 == 运维服务器：rmc-core 拒绝，错误挂在 ApplianceHost 上。
        let marked = form_with_server("192.168.100.10", 61001);
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

    /// `engineer_hint` 的用词与两种地址形态（Task 11）：IPv4 原样，IPv6
    /// 带方括号——跟连接码本体、`HostPort` 的 `Display` 一个规矩。
    #[test]
    fn engineer_hint_names_ip_and_port() {
        let c = ConnectionCode::new(
            AccountName::parse("tunnel-zhang").unwrap(),
            "203.0.113.10".parse().unwrap(),
            22000,
            ServerFingerprint::of_ed25519_public(&[7u8; 32]),
        )
        .expect("夹具必须合法");
        assert_eq!(
            engineer_hint(&c, 22003),
            "远程工程师请连接 203.0.113.10 端口 22003"
        );

        // IPv6：`.expect(...)`——`ConnectionCode::new` 只在端口 0 时才
        // 拒绝，这里端口是 22000，合法。
        let v6 = ConnectionCode::new(
            AccountName::parse("a").unwrap(),
            "::1".parse().unwrap(),
            22000,
            *c.fingerprint(),
        )
        .expect("夹具必须合法");
        assert_eq!(
            engineer_hint(&v6, 22003),
            "远程工程师请连接 [::1] 端口 22003"
        );
    }

    /// 整棵树里有没有一段文字**含有** `needle`——跟只认全字匹配的
    /// `Simulator::find(&str)` 不同（`iced_selector-0.14.0/src/lib.rs:53`
    /// 的 `&str` 实现是 `content == *self`，不是 `contains`）。这一行的
    /// 完整文本里带着 IP 与端口号，在还没连上、拿不到具体端口号之前，
    /// 没有一个能提前写死的全字符串可以拿来断言「不存在」，所以要用
    /// 子串匹配——跟 `tests/ui.rs` 的 `banned_in_tree`/`has_input` 同一
    /// 个写法（`Candidate::Text` 手动 `contains`）。
    fn contains_text(ui: &mut iced_test::Simulator<'_, Message>, needle: &str) -> bool {
        ui.find(|c: iced_test::selector::Candidate<'_>| match c {
            iced_test::selector::Candidate::Text { content, .. } if content.contains(needle) => {
                Some(())
            }
            _ => None,
        })
        .is_ok()
    }

    /// 已连接且拿到端口且连接码解析得出，三样都有才画这一行；未连接、
    /// 还没拿到端口、端口是「上一轮」留下的陈旧值（重连期间）、或者
    /// 连接码解析不出来，都不画（Task 11 + R11-6）。
    ///
    /// 四枪各打在不同的判断上，都**真的验过**（见 task-11-report.md、
    /// task-11-fix-1-report.md）：
    ///
    /// 1. 把 `Some(port)` 换成 `_`、端口写死成 `0`——第二组断言（应当
    ///    画出「…端口 22003」）会红，因为画出来的是「…端口 0」；
    /// 2. 单独把 `State::Connected { .. }` 换成 `_`（保留
    ///    `Some(port)`）——**这一枪打不红任何一组**，因为前两组场景里
    ///    「未连接」与「无端口」总是同时出现，状态判断从未被单独考验
    ///    过。第三组（Backoff + 陈旧端口）就是补这个洞的：`Backoff`
    ///    期间 `forward_port` 不清（Task 10 的语义），单独去掉状态判断
    ///    会让这一组红；
    /// 3. 把 `Some(code)` 换成 `_`（`ConnectionCode::server()`/
    ///    `account()` 换成写死的占位字符串）——第四组（连接码解析不出来
    ///    却画出了这一行）会红。
    #[test]
    fn the_hint_line_appears_only_when_connected_with_a_port() {
        let mut m = Model::default();
        let f = form_with_server("203.0.113.10", 22000);

        assert!(
            !contains_text(
                &mut iced_test::simulator(view(&m, &f, None, None)),
                "远程工程师请连接"
            ),
            "还没连接却画出了这一行"
        );

        m.apply(rmc_core::TunnelEvent::State(State::Connected {
            degraded: false,
        }));
        m.apply(rmc_core::TunnelEvent::ForwardPort(22003));
        assert!(
            contains_text(
                &mut iced_test::simulator(view(&m, &f, None, None)),
                "远程工程师请连接 203.0.113.10 端口 22003"
            ),
            "连上了、也拿到端口了，却没画出这一行"
        );

        // `forward_port` 在 `Backoff` 期间**不清**（Task 10 定的语义，
        // 见 `model.rs` 的 `forward_port_is_cleared_when_the_session_
        // really_ends`）——重连时它还留着上一轮那个端口号。这一行必须
        // 核对 `state` 也是 `Connected`，否则会在还没真的连上时照样念
        // 出一个可能已经失效的端口。
        m.apply(rmc_core::TunnelEvent::State(State::Backoff {
            attempt: 1,
            delay: std::time::Duration::from_secs(1),
        }));
        assert!(
            !contains_text(
                &mut iced_test::simulator(view(&m, &f, None, None)),
                "远程工程师请连接"
            ),
            "重连中（forward_port 还留着上一轮的值）却画出了这一行"
        );

        // R11-6：第三个必要条件——`form.parsed_code()`——单独验一次。
        // 回到 `Connected`（`forward_port` 还是 22003），但连接码这次
        // 解析不出来（用户粘贴坏了、或者手滑清空了）。
        m.apply(rmc_core::TunnelEvent::State(State::Connected {
            degraded: false,
        }));
        let mut broken = f.clone();
        broken.code = "不是连接码".into();
        assert!(
            !contains_text(
                &mut iced_test::simulator(view(&m, &broken, None, None)),
                "远程工程师请连接"
            ),
            "连接码解析不出来却画出了这一行"
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
            let mut ui = iced_test::simulator(view(&model, form, None, None));
            ui.snapshot(&APP_THEME)
                .expect("渲染整页")
                .matches_hash(&baseline)
                .expect("读写基线哈希")
        };

        assert!(page(&form_with_server("203.0.113.10", 22000)));
        assert!(
            !page(&form_with_server("192.168.100.10", 61001)),
            "整页两帧居然相同"
        );
    }
}
