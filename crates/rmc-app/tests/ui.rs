//! 控件树层面的测试（`iced_test` 0.14 的 headless 模拟器）。
//!
//! 为什么单独一个集成测试文件：Task 6 第一轮报出六条「改了实现但没有任何
//! 测试会红」的盲区，其中三条（标题栏文案、页签样式、页签点击）都在
//! `view/` 里，纯函数测试够不着。iced 0.13 没有任何 headless 控件树断言
//! 能力，0.14 才有 `iced_test`——这是升版本的唯一理由。
//!
//! 这个文件能存在本身也是 W103（拆 lib + 薄 bin）的直接收益：纯 bin crate
//! 没法被 `use`，`tests/` 目录下一行都写不出来。

use iced_test::selector::Candidate;
use iced_test::simulator;
use rmc_app::theme::Tab;
use rmc_app::{App, Message, APP_THEME};

/// 需求硬禁令：界面上叫「运维服务器」，不叫 Gateway/网关。
// 词表在 lib 里，三处防线共用一份——分叉了迟早有一份漏掉新加的词。
use rmc_app::BANNED_WORDS as BANNED;

/// 把三个页签都点一遍会得到三棵不同的树，禁用词要在每一棵里都不存在。
fn every_tab_state() -> [App; 3] {
    [Tab::Maintain, Tab::Diagnostics, Tab::Logs].map(|t| {
        let mut app = App::default();
        app.update(Message::TabSelected(t));
        app
    })
}

#[test]
fn title_bar_shows_the_chinese_product_name() {
    let app = App::default();
    let mut ui = simulator(app.view());

    assert!(ui.find("远程运维客户端").is_ok(), "标题栏没有画出产品名");
}

/// 第一轮的 N1：把 `title_bar()` 的文案改成 `"Gateway"`，六道闸门全绿。
/// 这条扫整棵控件树，对 Task 7-11 五个页面是现成的防线。
#[test]
fn no_widget_in_the_tree_says_gateway() {
    for (i, app) in every_tab_state().iter().enumerate() {
        let mut ui = simulator(app.view());

        // 反向自证：先确认扫描器真的遍历得到文本控件。少了这一步，一旦
        // 选择器因为 API 变动扫不到任何东西，下面那条断言就是永远为真的
        // 空转——这个项目已经抓到 20 个这种形状的假绿。
        let seen = ui.find(|c: Candidate<'_>| match c {
            Candidate::Text { content, .. } if content.contains("运维") => {
                Some(content.to_string())
            }
            _ => None,
        });
        assert!(
            seen.is_ok(),
            "第 {i} 棵树：扫描器一个文本控件都没遍历到，下面的禁用词断言会空转"
        );

        let hit = banned_in_tree(&mut ui);
        assert!(
            hit.is_none(),
            "第 {i} 棵树的控件里出现了需求禁用的词：{}",
            hit.unwrap_or_default()
        );
    }
}

#[test]
fn all_three_tab_labels_are_rendered() {
    let app = App::default();
    let mut ui = simulator(app.view());

    for label in ["维护", "诊断", "日志"] {
        assert!(ui.find(label).is_ok(), "控件树里找不到页签「{label}」");
    }
}

/// 第一轮的 N3：去掉 `.on_press(..)` 让页签点了没反应，六道闸门全绿。
#[test]
fn clicking_a_tab_emits_the_matching_message() {
    for (label, want) in [
        ("诊断", Tab::Diagnostics),
        ("日志", Tab::Logs),
        ("维护", Tab::Maintain),
    ] {
        let app = App::default();
        let mut ui = simulator(app.view());

        ui.click(label)
            .unwrap_or_else(|e| panic!("点不到页签「{label}」：{e:?}"));

        let messages: Vec<Message> = ui.into_messages().collect();
        assert_eq!(
            messages.len(),
            1,
            "点「{label}」应当恰好产生一条消息，实得 {messages:?}"
        );
        // Task 8 起 `Message` 不止一个变体，这里不能再写不可反驳的 let。
        let Message::TabSelected(got) = messages[0] else {
            panic!("点「{label}」发出的不是 TabSelected：{messages:?}");
        };
        assert_eq!(got, want, "点「{label}」发出的消息不对");
    }
}

/// 点一遍页签之后，`App` 的状态与重建出来的界面都要跟上。
#[test]
fn clicking_a_tab_actually_switches_the_page() {
    let mut app = App::default();
    let mut ui = simulator(app.view());
    ui.click("日志").expect("点不到「日志」");
    let messages: Vec<Message> = ui.into_messages().collect();
    for m in messages {
        app.update(m);
    }

    assert_eq!(app.tab(), Tab::Logs);
}

/// 第一轮的 N2：把 `tabs()` 里的 `tab_style` 调用换成写死的未选中样式，
/// 六道闸门全绿——因为 `iced_test` 的选择器只能看到文本、id 与 bounds，
/// **看不到任何样式**。
///
/// 这条用差分快照绕过去：选中「维护」与选中「日志」渲染出来的两帧必须
/// **不同**。页签样式一旦写死，三个页签无论选中哪个都长一个样，两帧会
/// 逐字节相等，这条立刻红。
///
/// 刻意不往仓库里放基线图片/哈希：那种快照测试要么跨平台字体渲染一变就红，
/// 要么基线文件缺失时 `matches_*` 会自动写一份并返回 `true`（自动变绿）。
/// 这里两帧都在同一次测试、同一台机器、同一套字体下渲染，基线写进临时
/// 目录，跑完即扔。
#[test]
fn switching_tabs_changes_what_is_actually_drawn() {
    let dir = tempfile::tempdir().expect("建临时目录");
    let baseline = dir.path().join("tabs");

    let mut maintain = App::default();
    maintain.update(Message::TabSelected(Tab::Maintain));
    let mut logs = App::default();
    logs.update(Message::TabSelected(Tab::Logs));

    // 第一帧：基线文件不存在，`matches_hash` 会写一份并返回 true。
    let mut ui = simulator(maintain.view());
    let first = ui
        .snapshot(&APP_THEME)
        .expect("渲染第一帧")
        .matches_hash(&baseline)
        .expect("写基线哈希");
    assert!(first, "第一帧应当写入基线并返回 true");

    // 第二帧：跟刚写下的基线比。选中项不同，画面必须不同。
    let mut ui = simulator(logs.view());
    let second = ui
        .snapshot(&APP_THEME)
        .expect("渲染第二帧")
        .matches_hash(&baseline)
        .expect("比对基线哈希");
    assert!(
        !second,
        "选中「维护」与选中「日志」渲染出的画面逐字节相同——页签样式没有跟着选中态走"
    );

    // 反向自证：同一个状态渲染两次必须一致，否则上面那条只是在测渲染
    // 不稳定，而不是在测页签样式。
    let mut ui = simulator(maintain.view());
    let again = ui
        .snapshot(&APP_THEME)
        .expect("再渲染一次第一帧")
        .matches_hash(&baseline)
        .expect("比对基线哈希");
    assert!(again, "同一状态渲染两次结果不一致，快照不可作为判据");
}

// ===================================================================
// W143：维护页的控件树测试。
//
// Task 6 已经证明「值被测过」不等于「视图真的用了它」——那一轮实测
// `main()` 可以挂一棵字面画着 "Gateway" 的树而 21 条测试全绿。维护页是
// 密码框、地址框、按钮的所在地，`model.rs` 里那些 `credentials_visible()`
// / `addresses_editable()` 的表驱动测试**只证明 Model 算对了**，证明不了
// 框真的藏了、真的锁了。
//
// **这些测试能证明什么、不能证明什么**（`iced_test` 的选择器只看得到
// 文本内容、widget id 与 bounds）：
//
// - 能证明：某段文字在不在树里；某个输入框的可见文本是什么；点/敲某个
//   控件会不会发出消息、发出哪一条。
// - **不能证明**：颜色、字号、边框、间距、对齐、控件的相对位置——一个字
//   都看不到。「填错的框标红」这件事在这一层是不可观测的，它由
//   `theme::input_border` 的表驱动测试守值、由人工验收守观感。
//   唯一的例外是差分快照（见 `the_password_box_masks_what_it_draws`）：
//   它比的是整帧像素哈希，能抓到"两个状态画出来一模一样"这类问题，
//   但说不出差在哪。
// ===================================================================

use rmc_app::diag::{ConnectOutcome, ProxyAuthSummary, ProxyStatus, PROXY_AUTH_ROW};
use rmc_app::form::{Field, Form};
use rmc_app::model::{Action, Model};
use rmc_app::view::{diagnostics, maintain};
use rmc_core::code::{AccountName, ConnectionCode, ServerFingerprint};
use rmc_core::state::{RemoteSessionInfo, State};
use std::time::SystemTime;
use zeroize::Zeroizing;

/// 一条能通过全部校验的连接码，账号 `tunnel-zhang`、地址
/// `203.0.113.10:22000`。**现生成，不手写常量**——手写的校验位会算错。
fn good_code() -> String {
    ConnectionCode::new(
        AccountName::parse("tunnel-zhang").unwrap(),
        "203.0.113.10".parse().unwrap(),
        22000,
        ServerFingerprint::of_ed25519_public(&[7u8; 32]),
    )
    .expect("夹具必须合法")
    .to_string()
}

/// 连接码解析成功之后，运维服务器组那一行只读小字的逐字内容。
fn parsed_line() -> &'static str {
    "地址 203.0.113.10:22000 · 账号 tunnel-zhang"
}

/// 整棵树里第一个禁用词命中，没有就是 `None`。
///
/// **返回 `Option<说明>` 而不是 `bool`** 是刻意的：`Simulator::find` 只
/// 返回第一个命中，所以「扫全树找违规」必须写成「命中违规时才返回
/// `Some`」，再断言结果为空。写反成 `assert!(find(..).is_ok())` 就是
/// 永远为真的空转。
///
/// 比 Task 6 那版多扫了 `Candidate::TextInput`：输入框的可见文本
/// （值为空时是 placeholder）原来**一个字都没人看**，而占位符正是最容易
/// 写进一个域名的地方。
fn banned_in_tree(ui: &mut iced_test::Simulator<'_, Message>) -> Option<String> {
    ui.find(|c: Candidate<'_>| match c {
        Candidate::Text { content, .. } => BANNED
            .iter()
            .find(|w| content.contains(**w))
            .map(|w| format!("文本「{content}」里含有 {w}")),
        Candidate::TextInput { state, .. } => {
            let content = state.text().to_string();
            BANNED
                .iter()
                .find(|w| content.contains(**w))
                .map(|w| format!("输入框「{content}」里含有 {w}"))
        }
        _ => None,
    })
    .ok()
}

/// 树里有没有一个**输入框**的可见文本恰好是 `want`。
///
/// 专门只认 `Candidate::TextInput`，不认 `Candidate::Text`——用它来区分
/// 「画了一行字」和「画了一个能敲字的框」。
fn has_input(ui: &mut iced_test::Simulator<'_, Message>, want: &str) -> bool {
    let want = want.to_string();
    ui.find(move |c: Candidate<'_>| match c {
        Candidate::TextInput { state, .. } if state.text() == want => Some(()),
        _ => None,
    })
    .is_ok()
}

/// 一份填满的、能通过校验的表单。
fn filled() -> Form {
    Form {
        appliance_host: "192.168.100.10".into(),
        appliance_port: "61001".into(),
        code: good_code(),
        password: Zeroizing::new("canary-7f3a9e-must-never-be-printed".into()),
        remember: false,
        detected_proxy: Some("proxy.company.com:8080".into()),
    }
}

fn model_in(state: State) -> Model {
    Model {
        state,
        ..Model::default()
    }
}

fn session(id: u64) -> RemoteSessionInfo {
    RemoteSessionInfo {
        id,
        opened_at: SystemTime::UNIX_EPOCH,
        to_appliance: 1024 * 1024,
        from_appliance: 340 * 1024,
    }
}

/// 未开启时：两个分组、五个输入框、勾选框、主按钮，一个不少。
#[test]
fn the_idle_maintain_page_draws_both_groups() {
    let (model, form) = (model_in(State::Idle), filled());
    let mut ui = simulator(maintain::view(&model, &form, None, None));

    for label in [
        "未开启",
        "维护目标",
        "运维服务器",
        "一体机",
        "连接码",
        "出网",
        "自动检测",
        "密码",
        "记住密码",
        "默认不保存，勾选后加密落盘",
        "开启远程维护",
    ] {
        assert!(ui.find(label).is_ok(), "维护页上找不到「{label}」");
    }

    // 出网那行画的是 `Form::egress_label()` 的结果，不是写死的「直连」。
    assert!(
        ui.find("经系统代理 proxy.company.com:8080").is_ok(),
        "出网那行没有画出检测到的代理"
    );

    // 连接码解析成功时，地址与账号的只读小字要画出来。
    assert!(
        ui.find(parsed_line()).is_ok(),
        "连接码解析成功却没有画出地址与账号"
    );

    // 三个输入框都在，而且里面装的是表单里的值——不是标签文字。
    for value in ["192.168.100.10", "61001", good_code().as_str()] {
        assert!(has_input(&mut ui, value), "没有一个输入框装着「{value}」");
    }
}

/// W143 的第一条：`credentials_visible()` **真的被视图遵守**。
///
/// 不是「Model 算对了」（`model.rs` 里已经有八条显示分支的表），是
/// 「框真的藏了」。
///
/// 改红：把 `view` 里的 `if credentials { ... }` 去掉（凭据区恒画），
/// 连上之后的三条 `assert!(!...)` 一起红；把它改成恒不画，Idle 那三条
/// 反向自证一起红。
#[test]
fn connecting_hides_the_credential_rows_and_keeps_the_addresses() {
    let form = filled();

    // 反向自证：未开启时这些东西确实在，下面的"不在"才有意义。
    let idle = model_in(State::Idle);
    let mut ui = simulator(maintain::view(&idle, &form, None, None));
    assert!(ui.find("记住密码").is_ok());
    assert!(has_input(&mut ui, good_code().as_str()));

    for state in [
        State::Preflight,
        State::Connecting,
        State::Connected { degraded: false },
        State::Connected { degraded: true },
        State::Stopping,
    ] {
        let model = model_in(state.clone());
        let mut ui = simulator(maintain::view(&model, &form, None, None));
        assert!(ui.find("记住密码").is_err(), "{state:?} 还画着「记住密码」");
        // 连接码与一体机地址两行**仍然**画着：现场人员得看得见自己连的
        // 是哪台运维服务器、哪台一体机，而且这是「地址框真的锁了」唯一
        // 可观测的前提。
        assert!(
            has_input(&mut ui, good_code().as_str()),
            "{state:?} 把连接码整个藏了，锁没锁就没法验了"
        );
        assert!(
            has_input(&mut ui, "192.168.100.10"),
            "{state:?} 把一体机地址整个藏了，锁没锁就没法验了"
        );
    }

    // `Failed` 跟 `Idle` 同侧：要让人改完重试。
    let failed = model_in(State::Failed {
        class: rmc_core::ErrorClass::Fatal,
        message: "x".into(),
    });
    let mut ui = simulator(maintain::view(&failed, &form, None, None));
    assert!(ui.find("记住密码").is_ok(), "失败后必须能重填凭据");
}

/// W143 的第二条：`addresses_editable()` **真的被视图遵守**。
///
/// 「框真的锁了」不是「Model 返回了 false」，是**敲进去一个字都不出来**。
/// iced 的 `TextInput` 没挂 `on_input` 就是禁用态，敲键盘不产生任何消息。
///
/// 改红：把 `input()` 里的 `if editable` 去掉（恒挂 `on_input`），
/// 下面「锁住时零消息」那半边立刻红。
#[test]
fn locked_addresses_swallow_typing() {
    let form = filled();

    // 未开启：敲得进去，而且发出的是一体机地址那条消息。
    let idle = model_in(State::Idle);
    let mut ui = simulator(maintain::view(&idle, &form, None, None));
    ui.click("192.168.100.10").expect("点不到一体机地址框");
    ui.typewrite("7");
    let messages: Vec<Message> = ui.into_messages().collect();
    assert_eq!(messages.len(), 1, "敲一个字应当恰好一条消息：{messages:?}");
    assert!(
        matches!(messages[0], Message::ApplianceHostChanged(_)),
        "敲一体机地址框发出的不是 ApplianceHostChanged：{messages:?}"
    );

    // 已连接：框还在、点得到，但敲进去什么都没有。
    let connected = model_in(State::Connected { degraded: false });
    let mut ui = simulator(maintain::view(&connected, &form, None, None));
    ui.click("192.168.100.10")
        .expect("已连接时一体机地址框应当还画着");
    ui.typewrite("7");
    let messages: Vec<Message> = ui.into_messages().collect();
    assert!(messages.is_empty(), "已连接时地址框还能改：{messages:?}");
}

/// 「开启远程维护」在表单填全之前按不动。
///
/// 改红：把 `view` 里的 `action_enabled(..)` 换成恒 `true`，
/// 第一半（空表单零消息）立刻红。
#[test]
fn the_start_button_waits_for_a_valid_form() {
    let idle = model_in(State::Idle);

    let blank = Form::default();
    let mut ui = simulator(maintain::view(&idle, &blank, None, None));
    ui.click("开启远程维护")
        .expect("按钮本身必须画出来，只是按不动");
    let messages: Vec<Message> = ui.into_messages().collect();
    assert!(messages.is_empty(), "表单还没填全就能开始：{messages:?}");

    let ready = filled();
    let mut ui = simulator(maintain::view(&idle, &ready, None, None));
    ui.click("开启远程维护").expect("点不到主按钮");
    let messages: Vec<Message> = ui.into_messages().collect();
    assert_eq!(
        messages.len(),
        1,
        "填全之后点开启应当恰好一条消息：{messages:?}"
    );
    assert!(
        matches!(messages[0], Message::ActionPressed(Action::Start)),
        "{messages:?}"
    );
}

/// 「记住密码」这个勾点得动，而且带的是**翻转后**的值。
///
/// 改红：把 `checkbox(..)` 上的 `.on_toggle(..)` 去掉（勾点了没反应），
/// 或者把 `checkbox(form.remember)` 写成 `checkbox(false)`（勾永远是空的，
/// 勾上之后还发 `true`），两种都红。
#[test]
fn the_remember_checkbox_toggles_both_ways() {
    let idle = model_in(State::Idle);

    for (before, want) in [(false, true), (true, false)] {
        let mut form = filled();
        form.remember = before;
        let mut ui = simulator(maintain::view(&idle, &form, None, None));
        ui.click("记住密码").expect("点不到「记住密码」");
        let messages: Vec<Message> = ui.into_messages().collect();
        assert_eq!(messages.len(), 1, "{messages:?}");
        assert!(
            matches!(messages[0], Message::RememberToggled(got) if got == want),
            "勾从 {before} 点一下应当发 {want}：{messages:?}"
        );
    }
}

/// 止损按钮任何时候都按得动，哪怕表单是空的。
///
/// 这条守的是 `action_enabled` 里那半边：把它写成 `form_ready`（四个动作
/// 一视同仁），表单一空就连「停止远程维护」都点不动了。
#[test]
fn stopping_never_depends_on_the_form() {
    let connected = model_in(State::Connected { degraded: false });
    let blank = Form::default();
    let mut ui = simulator(maintain::view(&connected, &blank, None, None));
    ui.click("停止远程维护").expect("点不到停止");
    let messages: Vec<Message> = ui.into_messages().collect();
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert!(
        matches!(messages[0], Message::ActionPressed(Action::Stop)),
        "{messages:?}"
    );
}

/// 会话列表：每条的「断开」带的是自己那条的 id，不是写死的。
#[test]
fn each_disconnect_button_carries_its_own_session_id() {
    let form = filled();
    for id in [7u64, 9] {
        let model = Model {
            state: State::Connected { degraded: false },
            sessions: vec![session(id)],
            ..Model::default()
        };
        let mut ui = simulator(maintain::view(&model, &form, None, None));
        assert!(ui.find("远程会话").is_ok());
        assert!(
            ui.find("发往一体机 1.0 MB · 来自一体机 340 KB").is_ok(),
            "会话那行没有画出流量"
        );
        ui.click("断开").expect("点不到「断开」");
        let messages: Vec<Message> = ui.into_messages().collect();
        assert_eq!(messages.len(), 1, "{messages:?}");
        assert!(
            matches!(messages[0], Message::DisconnectSession(got) if got == id),
            "断开按钮带的 id 不对：{messages:?}"
        );
    }

    // 一条会话都没有时画的是空态，不是一个空卡片。
    let model = model_in(State::Connected { degraded: false });
    let mut ui = simulator(maintain::view(&model, &form, None, None));
    assert!(ui.find("暂无远程会话").is_ok());
    assert!(ui.find("0 个进行中").is_ok());
}

/// 填错的框下面要画出**那个框**的错误，而且空字段不吭声。
#[test]
fn error_hints_name_the_field_that_is_wrong() {
    let idle = model_in(State::Idle);

    let mut bad = filled();
    bad.appliance_port = "abc".into();
    let mut ui = simulator(maintain::view(&idle, &bad, None, None));
    assert!(
        ui.find("一体机端口必须是 1-65535 的整数").is_ok(),
        "填错的端口没有在界面上说出来"
    );

    // 反向自证 + 「空字段不吭声」：全空的表单一行红字都没有。
    let blank = Form::default();
    let mut ui = simulator(maintain::view(&idle, &blank, None, None));
    assert!(
        ui.find("一体机端口必须是 1-65535 的整数").is_err(),
        "全空的表单不该画错误"
    );
    assert!(ui.find("一体机地址不能为空").is_err(), "空字段不该画成红字");
    // 但界面本身得画出来了，否则上面两条是空转。
    assert!(ui.find("维护目标").is_ok());
}

/// Task 8：粘一条好连接码，页面上出现解析出来的地址与账号；粘坏的，
/// 连接码这一行出现红字（而不是别的框）。
///
/// 改红：把 `view/maintain.rs` 里 `parsed_line` 换成恒返回空字符串——
/// 第一组断言当场红；或者把 `Field::Code` 传的 `on_input` 换成
/// `Field::ApplianceHost`——第二组断言里红字挂错框，`is_marked` 判断落空。
#[test]
fn pasting_a_good_code_shows_the_parsed_account_and_a_bad_one_is_marked() {
    let idle = model_in(State::Idle);

    let mut good = filled();
    good.code = good_code();
    let mut ui = simulator(maintain::view(&idle, &good, None, None));
    assert!(
        ui.find(parsed_line()).is_ok(),
        "粘对了却没有画出「{}」",
        parsed_line()
    );

    let mut bad = filled();
    bad.code = "rmc1:nonsense".into();
    let errs = bad.visible_errors();
    assert_eq!(errs.len(), 1, "{errs:?}");
    assert_eq!(errs[0].field, Field::Code, "红字挂错了框：{errs:?}");
    let mut ui = simulator(maintain::view(&idle, &bad, None, None));
    assert!(
        ui.find(errs[0].message().as_str()).is_ok(),
        "连接码格式错却没有画出红字"
    );
    // 反向自证：粘坏的连接码不该还画着「地址 · 账号」那行。
    assert!(
        ui.find(parsed_line()).is_err(),
        "格式错的连接码居然还解析出了地址与账号"
    );
}

/// 整棵维护页树的禁用词扫描，八条显示分支各走一遍。
#[test]
fn nothing_the_maintain_page_draws_is_banned() {
    let form = filled();
    let states = [
        State::Idle,
        State::Preflight,
        State::Connecting,
        State::Connected { degraded: false },
        State::Connected { degraded: true },
        State::Backoff {
            attempt: 3,
            delay: std::time::Duration::from_secs(5),
        },
        State::Stopping,
        State::Failed {
            class: rmc_core::ErrorClass::Fatal,
            message: rmc_core::Error::AuthRejected.to_string(),
        },
    ];

    for state in states {
        let mut model = model_in(state.clone());
        model.sessions = vec![session(1)];
        let mut ui = simulator(maintain::view(&model, &form, Some("01:34:14".into()), None));

        // 反向自证之一：扫描器真的遍历到了文本控件。
        assert!(
            ui.find("运维服务器").is_ok(),
            "{state:?}：一个文本控件都没遍历到，下面的断言会空转"
        );
        // 反向自证之二：`Candidate::TextInput` 这一支真的也走到了。
        // 少了它，扫描器漏掉全部输入框而这条测试照样全绿——占位符里写进
        // 一个含禁用词的值就谁也看不见了。
        assert!(
            has_input(&mut ui, good_code().as_str()),
            "{state:?}：输入框那一支没有被遍历到"
        );

        let hit = banned_in_tree(&mut ui);
        assert!(
            hit.is_none(),
            "{state:?} 的维护页里出现了需求禁用的词：{}",
            hit.unwrap_or_default()
        );
    }

    // 空表单单独走一遍：输入框为空时 `state.text()` 返回的是**占位符**，
    // 而占位符正是最容易写进一个域名的地方（画板上那个地址框写的就是
    // `gateway.company.com`）。填满的表单永远盖着占位符，扫不到它。
    let blank = Form::default();
    let idle = model_in(State::Idle);
    let mut ui = simulator(maintain::view(&idle, &blank, None, None));
    assert!(
        has_input(&mut ui, "主机名或 IP"),
        "空表单的占位符没有被遍历到，下面那条断言会空转"
    );
    let hit = banned_in_tree(&mut ui);
    assert!(
        hit.is_none(),
        "空表单的占位符里出现了需求禁用的词：{}",
        hit.unwrap_or_default()
    );

    // 反向自证之三：扫描器本身真的会对违规发火。喂一棵故意违规的树。
    // 连接码框只是把 `form.code` 原样画出来，不要求它先解析合法——
    // 一个含禁用词的任意字符串照样能敲进去、照样会被画出来。
    let mut bad = filled();
    bad.code = "gateway.company.com".into();
    let model = model_in(State::Idle);
    let mut ui = simulator(maintain::view(&model, &bad, None, None));
    assert!(
        banned_in_tree(&mut ui).is_some(),
        "往地址框里塞一个含禁用词的值，扫描器居然没响"
    );
}

/// 口令框必须**遮住它画出来的东西**。
///
/// `iced_test` 的选择器看不到样式，也看不到 `.secure(true)`：
/// `Candidate::TextInput` 的 `state.text()` 返回的是**原始值**，
/// 遮蔽发生在绘制那一步（`Value::secure()` 把每个字素换成 `•`）。
/// 所以这条只能用差分快照：
///
/// - 两个**等长**但内容不同的口令，画出来必须逐字节相同（都是同样多的
///   圆点）；
/// - 两个**不等长**的口令，画出来必须不同——这是反向自证，证明快照确实
///   对口令框有反应，否则上一条可以被「口令框根本没画出来」糊过去。
///
/// 改红：把 `view/maintain.rs` 里口令框那行的 `.secure(true)` 删掉，
/// 第一条断言立刻红（两个不同口令会画出不同的字）。
#[test]
fn the_password_box_masks_what_it_draws() {
    let dir = tempfile::tempdir().expect("建临时目录");
    let baseline = dir.path().join("password");
    let idle = model_in(State::Idle);

    let with = |pw: &str| {
        let mut f = filled();
        f.password = Zeroizing::new(pw.into());
        let mut ui = simulator(maintain::view(&idle, &f, None, None));
        ui.snapshot(&APP_THEME)
            .expect("渲染")
            .matches_hash(&baseline)
            .expect("基线哈希")
    };

    // 第一帧写基线。
    assert!(with("abcdefgh"), "第一帧应当写入基线并返回 true");
    // 等长、内容不同：必须一模一样。
    assert!(
        with("hgfedcba"),
        "两个等长口令画出来不一样——口令框没有遮蔽，用户输入直接显示在屏幕上"
    );
    assert!(with("!@#$%^&*"), "两个等长口令画出来不一样——口令框没有遮蔽");
    // 不等长：必须不同。这是反向自证。
    assert!(
        !with("abc"),
        "换一个长度不同的口令，画面居然没变——快照对口令框毫无反应，上面两条是空转"
    );
}

/// 已连接时右上角的计时器画的是传进来的那个值。
#[test]
fn the_elapsed_timer_is_drawn_when_it_has_a_value() {
    let connected = model_in(State::Connected { degraded: false });
    let form = filled();

    let mut ui = simulator(maintain::view(
        &connected,
        &form,
        Some("01:34:14".into()),
        None,
    ));
    assert!(ui.find("01:34:14").is_ok(), "计时器没画出来");
    assert!(ui.find("已连接").is_ok());

    // 没有值时不该凭空画一个。
    let mut ui = simulator(maintain::view(&connected, &form, None, None));
    assert!(ui.find("01:34:14").is_err());
    // 反向自证：树本身是画出来了的。
    assert!(ui.find("运维服务器").is_ok());
}

/// `App::view` 真的把维护页挂上去了——`tests/ui.rs` 上面那些
/// `maintain::view(..)` 直接调用证明不了这一点。
///
/// 这是 Task 6 那条教训的原样复用：`main()` 可以挂一棵完全不相干的树而
/// 所有针对 `view` 函数的测试全绿。
#[test]
fn the_app_actually_mounts_the_maintain_page() {
    let app = App::default();
    let mut ui = simulator(app.view());
    for label in ["维护目标", "运维服务器", "未开启", "开启远程维护"] {
        assert!(
            ui.find(label).is_ok(),
            "App::view 里找不到维护页的「{label}」"
        );
    }

    // 切到别的页签就不该还画着维护页。
    let mut app = App::default();
    app.update(Message::TabSelected(Tab::Logs));
    let mut ui = simulator(app.view());
    assert!(ui.find("维护目标").is_err(), "切到日志页还画着维护页");
    // 反向自证：页签框架还在。
    assert!(ui.find("日志").is_ok());
}

/// Backoff 下的**次按钮**是止损出口。
///
/// `Model::buttons()` 在 `Backoff` 下给的是 primary =「立即重试」、
/// **secondary =「停止远程维护」**——那是现场人员从一个反复重连的循环里
/// 脱身的唯一出路。
///
/// 补这条之前实测：把 `view` 里整块
/// `if let Some((label, action)) = buttons.secondary { .. }` 删掉，
/// `cargo test --workspace --no-fail-fast` **一条都不红**。没有任何 ui
/// 测试点过次按钮——`stopping_never_depends_on_the_form` 走的是
/// `Connected`（Stop 在主按钮位），`nothing_the_maintain_page_draws_is_banned`
/// 渲染了 `Backoff` 但只查禁用词。
///
/// 这跟 `the_remember_checkbox_toggles_both_ways` 补掉的那两条是**同一个
/// 形状**：控件画出来了，但从没有人点过它。
///
/// 表单刻意用 `Form::default()`（全空）：止损按钮不该跟表单绑在一起，
/// 表单填错了就停不下来是最糟的失败模式。
#[test]
fn the_secondary_button_is_the_way_out_of_a_backoff_loop() {
    let model = model_in(State::Backoff {
        attempt: 3,
        delay: std::time::Duration::from_secs(5),
    });
    let blank = Form::default();
    let mut ui = simulator(maintain::view(&model, &blank, None, None));

    // 反向自证：主按钮确实画出来了，而且它**不是**「停止远程维护」。
    // 少了这一步，次按钮整块消失、而主按钮恰好也叫这个名字时，
    // 下面的 click 会点到主按钮上，这条测试就变成空转。
    assert!(ui.find("立即重试").is_ok(), "Backoff 下主按钮没画出来");

    ui.click("停止远程维护")
        .expect("Backoff 下点不到次按钮「停止远程维护」");
    let messages: Vec<Message> = ui.into_messages().collect();
    assert_eq!(messages.len(), 1, "点次按钮应当恰好一条消息：{messages:?}");
    assert!(
        matches!(messages[0], Message::ActionPressed(Action::Stop)),
        "次按钮带的不是 Stop：{messages:?}"
    );
}

/// 顺带：`state.text()` 拿到的就是**遮蔽后**的值，所以口令框的遮蔽
/// 有一句不依赖字体与渲染器的直接断言。
///
/// `iced_widget` 的 `layout`/`update` 先算
/// `secure_value = is_secure.then(|| value.secure())`
/// （text_input.rs:328/407/462），写进 paragraph 的就是遮蔽后的那份，
/// 而 `operation::TextInput::text()` 读的正是它（text_input.rs:1568）。
///
/// 与 `the_password_box_masks_what_it_draws` 的分工：那条证的是**像素**
/// 这一层（两个等长口令画出来逐字节相同），这条证的是**paragraph** 这一层
/// 已经是圆点。两条都能抓 `.secure(true)` → `false`，但这一条不依赖
/// 字体与渲染器，跨平台更稳。
#[test]
fn the_password_box_reports_bullets_not_the_password() {
    let idle = model_in(State::Idle);
    let mut f = filled();
    f.password = Zeroizing::new("abcdefgh".into());
    let mut ui = simulator(maintain::view(&idle, &f, None, None));
    assert!(
        has_input(&mut ui, "••••••••"),
        "口令框报出来的不是 8 个圆点"
    );
}

// ===================================================================
// Task 9：诊断页的控件树测试。
//
// 同一条纪律：`diag.rs` 的单测只证明**算出来的行是对的**，证明不了那些
// 行真的画进了树；`theme::row_palette` 的表驱动只证明颜色的值对，证明
// 不了颜色进了控件（那一条在 `view/diagnostics.rs` 自己的 mod tests 里
// 用差分快照守，见 W146）。
// ===================================================================

/// 一份四步全过的预检结果。
fn all_pass() -> rmc_core::preflight::PreflightReport {
    use rmc_core::preflight::{PreflightStep, StepOutcome, ALL_STEPS};
    rmc_core::preflight::PreflightReport {
        steps: ALL_STEPS
            .iter()
            .map(|name| PreflightStep {
                name,
                outcome: StepOutcome::Pass {
                    detail: "通过".into(),
                },
            })
            .collect(),
    }
}

/// 一份指纹不符（现场最常见的那一种，通常是路径上有 TLS 审计设备）的
/// 预检结果。
///
/// Task 9：TLS 步骤不再校验证书链，核对的是连接码里的指纹——detail 换成
/// `wrap_tls`/`classify_tls_error` 真的会产出的文案形状
/// （`Error::TlsPinMismatch` 的 Display），`advice_for` 按这一句里含
/// 「指纹」分派处置建议，正文仍然会点名审计设备（新文案里的
/// 「中间人的 TLS 审计设备」一句包含「审计设备」四个字）。
fn tls_intercepted() -> rmc_core::preflight::PreflightReport {
    use rmc_core::preflight::{PreflightStep, StepOutcome, STEP_GATEWAY_TLS};
    let mut r = all_pass();
    *r.steps
        .iter_mut()
        .find(|s| s.name == STEP_GATEWAY_TLS)
        .unwrap() = PreflightStep {
        name: STEP_GATEWAY_TLS,
        outcome: StepOutcome::Fail {
            detail: "运维服务器的身份与连接码里的指纹不一致：invalid peer certificate: \
                     application verification failure"
                .into(),
            class: rmc_core::ErrorClass::Fatal,
        },
    };
    r
}

fn proxy_status(connect: ConnectOutcome) -> ProxyStatus {
    ProxyStatus {
        endpoint: "proxy.company.com:8080".into(),
        connect,
        auth: ProxyAuthSummary::FinalTokenIssued {
            package: "NTLM".into(),
            rounds: 2,
        },
    }
}

/// 没跑过预检时，诊断页仍然画出四行「还没有检查过」。
///
/// 这是现场第一次打开诊断页看到的那一屏。空白一片会让人以为页面坏了。
#[test]
fn the_untouched_diagnostics_page_still_lists_every_step() {
    let model = model_in(State::Idle);
    let mut ui = simulator(diagnostics::view(&model, None, "客户端 0.1.0", false));
    for name in rmc_core::preflight::ALL_STEPS {
        assert!(ui.find(*name).is_ok(), "诊断页上找不到步骤「{name}」");
    }
    assert!(ui.find("还没有检查过").is_ok());
    // 没有失败项就不画处置建议卡。
    assert!(
        ui.find("导出诊断包").is_ok(),
        "按钮任何时候都要在——现场要导出诊断包的时候恰恰就是连不上的时候"
    );
}

/// 预检失败时，失败原因与处置建议**都真的画在屏幕上**。
///
/// 改红：把 `view` 里 `if let Some(c) = advice_card(&advice)` 整块删掉
/// ——后两条断言变红。（删掉它不会让任何 `diag.rs` 的单测红：那边测的是
/// `advice_for` 的返回值，不是它有没有被画出来。）
#[test]
fn a_failing_preflight_puts_the_reason_and_the_advice_on_screen() {
    let mut model = model_in(State::Failed {
        class: rmc_core::ErrorClass::Fatal,
        message: "运维服务器的身份与连接码里的指纹不一致：invalid peer certificate: \
                  application verification failure"
            .into(),
    });
    model.preflight = Some(tls_intercepted());
    let mut ui = simulator(diagnostics::view(&model, None, "客户端 0.1.0", false));

    // `Simulator::find(&str)` 是**整段相等**，不是子串包含；失败原因是
    // 「运维服务器的身份与连接码里的指纹不一致：invalid peer
    // certificate: application verification failure」一整句，所以这里
    // 用谓词。第一次写成 `find("application verification failure")`
    // 当场红。
    let contains = |ui: &mut iced_test::Simulator<'_, Message>, want: &str| {
        let want = want.to_string();
        ui.find(move |c: Candidate<'_>| match c {
            Candidate::Text { content, .. } if content.contains(&want) => Some(()),
            _ => None,
        })
        .is_ok()
    };
    assert!(
        contains(&mut ui, "application verification failure"),
        "失败原因没有画出来"
    );
    // 处置建议卡的标题是失败的那一步，正文点名审计设备。
    assert!(
        ui.find(rmc_core::preflight::STEP_GATEWAY_TLS).is_ok(),
        "处置建议卡的标题没画出来"
    );
    let mut ui = simulator(diagnostics::view(&model, None, "客户端 0.1.0", false));
    assert!(contains(&mut ui, "审计设备"), "处置建议的正文没有画出来");
}

/// 代理那三行画出来了，而且代理认证那一行的行首文字就是
/// `rmc_core` 错误文案指着的那个常量（W164 的落地）。
#[test]
fn the_proxy_rows_reach_the_screen_under_the_name_the_error_text_points_at() {
    let mut model = model_in(State::Connecting);
    model.preflight = Some(all_pass());
    let p = proxy_status(ConnectOutcome::Established);
    let mut ui = simulator(diagnostics::view(&model, Some(&p), "客户端 0.1.0", false));

    assert!(
        ui.find("proxy.company.com:8080").is_ok(),
        "代理地址没画出来"
    );
    assert!(ui.find(PROXY_AUTH_ROW).is_ok(), "代理认证那一行没画出来");
}

/// 两个按钮各自带自己的动作，而且**跟表单无关**。
///
/// 表单刻意用「没填好」（`form_ready = false`）：现场需要导出诊断包的
/// 时候恰恰就是表单填不对、连不上的时候。把它们跟表单绑在一起等于
/// 「连不上就导不出证据」。
///
/// 改红：把 `actions` 里 `action_enabled(Action::ExportDiagnostics, ..)`
/// 换成 `form_ready`——`click` 点不到（按钮没有 `on_press`），当场红。
#[test]
fn both_diagnostics_buttons_work_even_when_the_form_is_not_ready() {
    let model = model_in(State::Idle);

    for (label, want) in [
        ("导出诊断包", Action::ExportDiagnostics),
        ("复制检查结果", Action::CopyDiagnostics),
    ] {
        let mut ui = simulator(diagnostics::view(&model, None, "客户端 0.1.0", false));
        ui.click(label)
            .unwrap_or_else(|e| panic!("点不到「{label}」：{e:?}"));
        let messages: Vec<Message> = ui.into_messages().collect();
        assert_eq!(
            messages.len(),
            1,
            "点「{label}」应当恰好一条消息：{messages:?}"
        );
        assert!(
            matches!(messages[0], Message::ActionPressed(a) if a == want),
            "「{label}」带的不是 {want:?}：{messages:?}"
        );
    }
}

/// 整棵诊断页树的禁用词扫描，把几种会改变树形状的输入都走一遍。
#[test]
fn nothing_the_diagnostics_page_draws_is_banned() {
    /// 一种会改变诊断页树形状的输入组合：说明、预检结果、代理、运维
    /// 服务器指纹。
    struct Case {
        why: &'static str,
        report: Option<rmc_core::preflight::PreflightReport>,
        proxy: Option<ProxyStatus>,
        server_fingerprint: Option<String>,
    }
    let case = |why, report, proxy, server_fingerprint| Case {
        why,
        report,
        proxy,
        server_fingerprint,
    };
    let cases: [Case; 5] = [
        case("还没跑过预检", None, None, None),
        case("四步全过", Some(all_pass()), None, None),
        case("TLS 被审计设备拦下", Some(tls_intercepted()), None, None),
        case(
            "经代理且 CONNECT 建立",
            Some(all_pass()),
            Some(proxy_status(ConnectOutcome::Established)),
            Some("SHA256:kM9v7bQe".to_string()),
        ),
        case(
            "经代理但 CONNECT 没建立",
            Some(tls_intercepted()),
            Some(proxy_status(ConnectOutcome::Failed)),
            Some("SHA256:kM9v7bQe".to_string()),
        ),
    ];

    for c in cases {
        let why = c.why;
        let mut model = model_in(State::Idle);
        model.preflight = c.report;
        model.server_fingerprint = c.server_fingerprint;
        let mut ui = simulator(diagnostics::view(
            &model,
            c.proxy.as_ref(),
            "客户端 0.1.0",
            false,
        ));

        // 反向自证：扫描器真的遍历到了这一页的文本控件。少了它，
        // 「树是空的」时下面那条是永远为真的空转。
        assert!(
            ui.find("导出诊断包").is_ok(),
            "{why}：一个文本控件都没遍历到，下面的断言会空转"
        );

        let hit = banned_in_tree(&mut ui);
        assert!(
            hit.is_none(),
            "{why} 的诊断页里出现了需求禁用的词：{}",
            hit.unwrap_or_default()
        );
    }

    // 反向自证之二：扫描器本身真的会对这一页发火。喂一棵故意违规的树
    // ——环境信息那一行是最容易顺手写进一个域名的地方。
    let model = model_in(State::Idle);
    let mut ui = simulator(diagnostics::view(
        &model,
        None,
        "客户端 0.1.0 · 经 gateway.company.com 出网",
        false,
    ));
    assert!(
        banned_in_tree(&mut ui).is_some(),
        "往环境信息里塞一个含禁用词的值，扫描器居然没响"
    );
}

/// `App::view` 真的把诊断页挂上去了。
///
/// 跟 `the_app_actually_mounts_the_maintain_page` 同一个理由：上面那些
/// `diagnostics::view(..)` 的直接调用证明不了 `App` 在「诊断」页签下画的
/// 是它。Task 6 实测过，`main()` 可以挂一棵完全不相干的树而所有针对
/// `view` 函数的测试全绿。
///
/// 改红：把 `App::view` 里 `Tab::Diagnostics` 那一支改回
/// `iced::widget::space::vertical().into()`——前三条断言一起红。
#[test]
fn the_app_actually_mounts_the_diagnostics_page() {
    let mut app = App::default();
    app.update(Message::TabSelected(Tab::Diagnostics));
    let mut ui = simulator(app.view());
    for label in ["连接诊断", "导出诊断包", "复制检查结果"] {
        assert!(
            ui.find(label).is_ok(),
            "App::view 里找不到诊断页的「{label}」"
        );
    }
    // 环境信息那一行也真的挂上去了（它来自 `App` 自己存的那份，不是
    // 视图现算的）。
    let mut ui = simulator(app.view());
    let env = ui.find(|c: Candidate<'_>| match c {
        Candidate::Text { content, .. } if content.contains(env!("CARGO_PKG_VERSION")) => Some(()),
        _ => None,
    });
    assert!(env.is_ok(), "诊断页底部的环境信息没有挂上去");

    // 切回维护页就不该还画着诊断页。
    let mut app = App::default();
    app.update(Message::TabSelected(Tab::Maintain));
    let mut ui = simulator(app.view());
    assert!(ui.find("导出诊断包").is_err(), "切回维护页还画着诊断页");
    assert!(ui.find("维护目标").is_ok(), "维护页没画出来");
}

// ===================================================================
// Task 10：日志页
// ===================================================================

/// `App` 在「日志」页签下画的真的是日志页。
///
/// 跟 `the_app_actually_mounts_the_diagnostics_page` 同一个理由：
/// `view/logs.rs` 里那些针对 `log_row` / `chip` 的测试证明不了 `App`
/// 挂的是它。Task 6 实测过，`main()` 可以挂一棵完全不相干的树而所有
/// 针对 `view` 函数的测试全绿。
///
/// 改红：把 `App::view` 里 `Tab::Logs` 那一支改回
/// `iced::widget::space::vertical().into()`（那正是这一轮之前的样子）
/// ——全部断言一起红。
#[test]
fn the_app_actually_mounts_the_logs_page() {
    let mut app = App::default();
    app.update(Message::TabSelected(Tab::Logs));
    let mut ui = simulator(app.view());

    // 四个筛选标签，各带自己的计数。
    for label in ["全部 0", "信息 0", "警告 0", "错误 0"] {
        assert!(ui.find(label).is_ok(), "日志页上找不到筛选标签「{label}」");
    }
    // 底部那行字与按钮。
    let mut ui = simulator(app.view());
    assert!(ui.find("打开日志目录").is_ok(), "没有「打开日志目录」");
    let mut ui = simulator(app.view());
    let footer = ui.find(|c: Candidate<'_>| match c {
        Candidate::Text { content, .. } if content.starts_with("最近 200 条") => Some(()),
        _ => None,
    });
    assert!(footer.is_ok(), "日志页底部那行字没挂上去");

    // 切回维护页就不该还画着日志页。
    let mut app = App::default();
    app.update(Message::TabSelected(Tab::Maintain));
    let mut ui = simulator(app.view());
    assert!(ui.find("打开日志目录").is_err(), "切回维护页还画着日志页");
}

/// 还没有日志时，页面上**说了一句话**，不是一片空白。
///
/// W174 在界面上的落地：「还没有日志」与「日志读不出来」必须长得不一样，
/// 而且两种都不能是静悄悄的空白——日志页正是用户出问题时唯一会去看的
/// 地方。
///
/// 改红：把 `view::logs::view` 里那段 `if let Some(n) = tail.notice()`
/// 删掉。
#[test]
fn an_empty_log_page_says_why_it_is_empty() {
    let mut app = App::default();
    app.update(Message::TabSelected(Tab::Logs));
    let mut ui = simulator(app.view());

    let notice = ui.find(|c: Candidate<'_>| match c {
        Candidate::Text { content, .. } if content.contains("还没有日志") => Some(()),
        _ => None,
    });
    assert!(notice.is_ok(), "日志页是一片空白，什么都没说");
}

/// 点一个筛选标签，`App` 的状态真的跟着变，画出来的也跟着变。
///
/// 改红：把 `App::update` 里 `Message::LogFilterSelected(f)` 那一支改成
/// `{}`——点了没反应，而按钮照样有按下去的动画。
#[test]
fn clicking_a_chip_actually_switches_the_filter() {
    use rmc_app::logs::{LogFilter, LogLevel};

    let mut app = App::default();
    app.update(Message::TabSelected(Tab::Logs));
    assert_eq!(app.log_filter(), LogFilter::All);

    let mut ui = simulator(app.view());
    ui.click("错误 0").expect("点不到「错误」标签");
    for m in ui.into_messages().collect::<Vec<Message>>() {
        app.update(m);
    }
    assert_eq!(app.log_filter(), LogFilter::Only(LogLevel::Error));
}

/// 搜索框敲进去的字真的写回了 `App`。
#[test]
fn typing_in_the_search_box_reaches_the_app() {
    let mut app = App::default();
    app.update(Message::TabSelected(Tab::Logs));
    let mut ui = simulator(app.view());
    // 搜索框是空的，可见文本就是占位符。
    ui.click("搜索").expect("点不到搜索框");
    ui.typewrite("22001");
    let messages: Vec<Message> = ui.into_messages().collect();
    assert!(!messages.is_empty(), "敲字没发出任何消息");
    for m in messages {
        app.update(m);
    }
    // 反向自证：确实是搜索框收的，不是别的输入框。
    let mut ui = simulator(app.view());
    assert!(has_input(&mut ui, "22001"), "敲进去的字没有回到搜索框里");
}

/// 日志页上的三种等级各画各的，而且**画的是等级那个词本身**。
///
/// 这条走 `App::view`（而不是 `view/logs.rs` 里的 `log_row`），因此同时
/// 证明了筛选真的作用在列表上。
#[test]
fn the_log_page_draws_each_level_and_the_filter_really_filters() {
    use rmc_app::logs::{LogFilter, LogLevel};

    let dir = tempfile::tempdir().expect("建临时目录");
    let paths = rmc_app::wiring::AppPaths::at(dir.path().to_path_buf());
    std::fs::create_dir_all(paths.log_dir()).unwrap();
    std::fs::write(
        paths.current_log(),
        concat!(
            "2026-09-13T11:12:44+08:00 INFO 预检通过\n",
            "2026-09-13T11:14:02+08:00 WARN 一体机首包延迟\n",
            "2026-09-13T11:52:31+08:00 ERROR 连接被重置\n",
        ),
    )
    .unwrap();

    let (tx, _rx) = tokio::sync::mpsc::channel(4);
    let (_ev_tx, ev_rx) = tokio::sync::broadcast::channel(4);
    let core = rmc_app::wiring::Core::new(tx, ev_rx, paths, None);
    let mut app = App::with_core(Some(core));
    app.update(Message::TabSelected(Tab::Logs));

    let drawn = |app: &App, want: &str| simulator(app.view()).find(want).is_ok();

    for text in [
        "11:12:44",
        "INFO",
        "预检通过",
        "WARN",
        "ERROR",
        "连接被重置",
    ] {
        assert!(drawn(&app, text), "日志页上找不到「{text}」");
    }
    // 计数也对得上。
    for label in ["全部 3", "信息 1", "警告 1", "错误 1"] {
        assert!(drawn(&app, label), "标签「{label}」的计数不对");
    }

    // 只看错误：另外两行必须从树里消失。
    app.update(Message::LogFilterSelected(LogFilter::Only(LogLevel::Error)));
    assert!(drawn(&app, "连接被重置"), "筛成错误之后错误那行也没了");
    assert!(
        !drawn(&app, "预检通过"),
        "筛成「错误」之后信息那一行还画着——筛选没作用在列表上"
    );

    // 搜索同理。
    app.update(Message::LogFilterSelected(LogFilter::All));
    app.update(Message::LogQueryChanged("延迟".into()));
    assert!(drawn(&app, "一体机首包延迟"));
    assert!(!drawn(&app, "预检通过"), "搜索没作用在列表上");
}

// =====================================================================
// W200：取回记住的密码的结局，真的画在密码框旁边
// =====================================================================

/// **「换了 Windows 账号解不开」这句话真的上屏了。**
///
/// 断的是哪一根线：`view/maintain.rs` 里 `if let Some(note) =
/// password_note` 那三行。没有它，`Recall::fill` 算出来的那句话只会被
/// `App` 存着，一个字都不显示——而那正是 W21 当初要带类型出口的**全部
/// 意义**：口令解不开时密码框空着、一句解释都没有。
///
/// 改红：把 `view/maintain.rs` 里那个 `if let Some(note) = ..` 整块
/// 删掉，第二组断言当场红。
#[test]
fn the_password_recall_note_is_drawn_next_to_the_password_box() {
    use rmc_app::view::maintain;

    let outcome = rmc_win::secret::LoadOutcome::UnsealFailed;
    let note = outcome.diagnostic().1;
    let idle = model_in(rmc_core::state::State::Idle);
    let form = filled();

    // 反向自证：没有那句话的时候树里确实找不到它。
    let mut ui = simulator(maintain::view(&idle, &form, None, None));
    assert!(
        ui.find(note.as_str()).is_err(),
        "没有给说明却画出来了，下面那条断言证明不了什么"
    );
    // 而且这一帧本身不是空的（凭据区在）。
    assert!(ui.find("记住密码").is_ok());

    // 主断言：给了就画出来。
    let mut ui = simulator(maintain::view(&idle, &form, None, Some(note.as_str())));
    assert!(
        ui.find(note.as_str()).is_ok(),
        "取回失败的说明没有上屏：{note}"
    );

    // 它也不许含禁用词——这是一条会上屏的、来自 rmc-win 的文案。
    for banned in BANNED {
        assert!(!note.contains(banned), "说明里含禁用词 {banned}：{note}");
    }
}

/// 凭据区整块藏起来的时候，那句话也跟着不见——密码框都没了，旁边挂一
/// 句「记住的密码解不开」只会让人摸不着头脑。
#[test]
fn the_recall_note_goes_away_with_the_credential_rows() {
    use rmc_app::view::maintain;

    let outcome = rmc_win::secret::LoadOutcome::UnsealFailed;
    let note = outcome.diagnostic().1;
    let connected = model_in(rmc_core::state::State::Connected { degraded: false });
    let form = filled();
    let mut ui = simulator(maintain::view(&connected, &form, None, Some(note.as_str())));
    assert!(
        ui.find(note.as_str()).is_err(),
        "连上之后密码框没了，那句话还挂在页面上"
    );
}
