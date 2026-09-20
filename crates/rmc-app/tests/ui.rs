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
const BANNED: [&str; 4] = ["Gateway", "gateway", "GATEWAY", "网关"];

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

        let hit = ui.find(|c: Candidate<'_>| match c {
            Candidate::Text { content, .. } => BANNED
                .iter()
                .find(|w| content.contains(**w))
                .map(|w| format!("「{content}」里含有 {w}")),
            _ => None,
        });
        assert!(
            hit.is_err(),
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
        let Message::TabSelected(got) = messages[0];
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
