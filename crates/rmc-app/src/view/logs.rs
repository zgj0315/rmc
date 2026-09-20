//! 日志页。出问题时用户唯一会去看的那一屏。
//!
//! 本文件里**不应该出现任何判断**——见 crate 根的模块文档。每一行画什么
//! 来自 [`crate::logs::filter`]，四个标签上的数字来自
//! [`crate::logs::counts`]，每一行取什么颜色来自
//! [`crate::theme::log_row_palette`]，列表为空时该说什么来自
//! [`crate::logs::LogTail::notice`]，底部那行字来自
//! [`crate::logs::footer`]。这里只负责把它们摆进控件。
//!
//! # 跟画板 `design/body-Logs.html` 的两处出入
//!
//! 1. 画板的搜索框里有一个放大镜图标。这里只有占位文字——图标要一个
//!    SVG 资源，而本轮没有任何东西能验证它真的画出来了。
//! 2. 画板的错误行等级列写的是 `ERR`，这里写 `ERROR`。**这是刻意的**：
//!    这一列的字直接取自 [`crate::logs::LogLevel::tag`]，而那个方法同时
//!    是解析日志文件时认等级用的那一份。分叉成两份（一份解析、一份显示）
//!    正是本项目反复抓到的那类缺陷，`logs.rs` 的
//!    `every_level_this_page_knows_is_a_level_the_audit_log_writes` 守着
//!    这条。宽度按 `ERROR` 排。
//!
//! 两条都记在 task-10-report.md 的「后续完善」里。

use super::card;
use crate::logs::{counts, filter, LevelCounts, LogFilter, LogLine, LogTail};
use crate::model::{action_enabled, Action};
use crate::theme::{chip_style, color, log_row_palette};
use crate::Message;
use iced::widget::{button, column, container, row, scrollable, space, text, text_input};
use iced::{Alignment, Border, Element, Font, Length};

/// 等级那一列的宽度。按最长的 `ERROR` 排，让时间、等级、正文三列对齐。
const TAG_WIDTH: f32 = 44.0;

/// 一个带计数的筛选胶囊。
///
/// 颜色**全部**来自 [`chip_style`]，这里一个 `if` 都没有。那条「算出来的
/// 颜色真的画到了像素上」由本文件末尾的
/// [`tests::the_selected_chip_really_draws_differently`] 用差分快照守着
/// （W146 的技法）。
// 生命周期写成自由的 `'a`：标签是 `&'static str`，数字拼成了 `String`，
// 返回的树一个字节都不借调用方的东西。
fn chip<'a>(f: LogFilter, count: usize, is_active: bool) -> Element<'a, Message> {
    let p = chip_style(is_active);
    button(
        text(format!("{} {count}", f.label()))
            .size(12)
            .color(p.text),
    )
    .padding([5, 11])
    .on_press(Message::LogFilterSelected(f))
    .style(move |_, _| button::Style {
        background: Some(p.background.into()),
        text_color: p.text,
        border: Border {
            color: p.border,
            width: 1.0,
            radius: 13.0.into(),
        },
        ..Default::default()
    })
    .into()
}

/// 四个胶囊加一个搜索框。
fn toolbar<'a>(active: LogFilter, c: LevelCounts, query: &str) -> Element<'a, Message> {
    let mut r = row![].spacing(6).align_y(Alignment::Center);
    for f in LogFilter::ALL {
        r = r.push(chip(f, c.of(f), f == active));
    }
    r = r.push(space::horizontal());
    r = r.push(
        text_input("搜索", query)
            .size(12)
            .padding([4, 8])
            .width(104)
            .on_input(Message::LogQueryChanged),
    );
    r.into()
}

/// 日志页左边两列用的等宽字体族，`None` 表示这个系统上不知道该用哪个。
///
/// # W179：**绝对不能用 `iced::Font::MONOSPACE`**
///
/// 根因：cosmic-text 把"等宽"这个泛族**硬编码**绑在 `Noto Sans Mono`
/// 上（`cosmic-text-0.15.0/src/font/system.rs:158` 的
/// `db.set_monospace_family("Noto Sans Mono")`），而那个字体
/// **默认安装的 Windows 11 不带**（出厂的等宽是 Consolas /
/// Cascadia Mono / Courier New / Lucida Console），这台 macOS 开发机也
/// 没有。族名解析不到任何字面时，ASCII 还能经别的回退路画出来，
/// **中文那条回退路会算出一个巨大的字形 x 坐标**，
/// `cosmic-text-0.15.0/src/glyph_cache.rs:100` 的 `trunc + 1` 当场
/// 溢出 panic（`attempt to add with overflow`）。
///
/// **这不是 `iced_test` 特有的。** 运行时用的
/// `iced_graphics::text::font_system()` 是同一个
/// `FontSystem::new_with_fonts`（`iced_graphics-0.14.0/src/text.rs:121`），
/// 内嵌的 Fira Sans 只是多两个 face，补不上那个族名——所以这个崩溃
/// **在 Windows 上同样会复现**。上一轮把它判成"测试环境特有"是错的，
/// 订正见 task-10-fix-1-report.md 的 W179。
///
/// 换成一个**这个系统上真的装着**的族就同时解决两件事：拿回画板要的
/// 对齐，而且中文有正常的回退路。
///
/// **写成收 `os` 的纯函数而不是一对 `cfg`**（同
/// [`crate::wiring::file_manager_for`]）：Windows 那一档是唯一真正要用
/// 的一档，写成 `cfg` 的话它在这台机器上没有任何东西看得见。
pub fn monospace_family(os: &str) -> Option<&'static str> {
    match os {
        // Consolas 从 Vista 起每一版 Windows 都带（Cascadia Mono 要
        // Win11 才有，不能指望）。
        "windows" => Some("Consolas"),
        // Menlo 从 10.6 起每一版 macOS 都带。
        "macos" => Some("Menlo"),
        // 装了什么全看发行版。猜一个不如不猜：回到默认比例字体，两列会
        // 参差，但**不会崩**——崩是这里唯一不能接受的结局。
        _ => None,
    }
}

/// 本机该用的那个字体。
fn mono() -> Font {
    match monospace_family(std::env::consts::OS) {
        Some(name) => Font::with_name(name),
        None => Font::default(),
    }
}

/// 日志列表里的一行：时间、等级、正文。
///
/// # 等宽字体只给左边两列（画板给三列都上了 `mono`）
///
/// 等宽在这里的作用是让 200 行的时间与等级**对齐成两列**；正文不需要
/// 对齐，所以不给它。W179 查清根因（见 [`monospace_family`]）之后，
/// 给正文也上等宽已经是**安全**的了——但那是纯视觉，按用户方针记进
/// 「后续完善」，不在这一轮做。
fn log_row<'a>(l: &LogLine) -> Element<'a, Message> {
    log_row_with(l, log_row_palette(l.level))
}

/// [`log_row`] 的可测版本：取色由调用方给。
///
/// # 为什么要把取色提成一个参数
///
/// 差分快照要成立，两帧必须**只差颜色**。而日志行的等级那一列画的就是
/// `INFO`/`WARN`/`ERROR` 这三个词——两个等级的行**文字本来就不同**，
/// 拿两个等级去比，比出的差别说明不了是颜色的功劳。
///
/// 这一条是本轮实测出来的：第一版测试拿 `log_row(&info)` 与
/// `log_row(&warn)` 比，把三处取色全换成写死的 `color::TEXT` / `None`
/// 之后**它照样绿**（等级那一列的文字还是不同的）。形状与
/// `view/diagnostics.rs` 那条 `going_through_rows_cannot_isolate_the_colors`
/// 完全一样，只是这次踩上去的是我自己。
///
/// 拆成两层之后两条断言各管一件事，见
/// [`tests::every_part_of_the_palette_really_reaches_the_pixels`] 与
/// [`tests::the_row_looks_up_the_palette_by_its_own_level`]。
fn log_row_with<'a>(l: &LogLine, p: crate::theme::LogRowPalette) -> Element<'a, Message> {
    container(
        row![
            text(l.time.clone())
                .size(12)
                .font(mono())
                .color(color::LOG_TIME),
            text(l.level.tag())
                .size(12)
                .font(mono())
                .color(p.tag)
                .width(TAG_WIDTH),
            text(l.message.clone()).size(12).color(p.text),
        ]
        .spacing(9),
    )
    .padding([3, 12])
    .width(Length::Fill)
    .style(move |_| container::Style {
        background: p.background.map(Into::into),
        ..Default::default()
    })
    .into()
}

/// 日志页。
///
/// `tail` 由调用方读好之后交进来（[`crate::wiring::read_tail`]）——这一页
/// 不自己去碰文件系统，理由跟诊断页不自己去查代理是同一条：视图函数每
/// 重画一帧就跑一次，而重画的次数不由这一页说了算。
pub fn view<'a>(
    tail: &'a LogTail,
    active: LogFilter,
    query: &'a str,
    log_file_name: &'a str,
) -> Element<'a, Message> {
    let all = tail.lines();
    let shown = filter(all, active, query);

    let mut list = column![];
    for l in shown {
        list = list.push(log_row(l));
    }

    let mut body = column![toolbar(active, counts(all), query)]
        .spacing(12)
        .padding(14);

    // 读不出来 / 还没有日志 / 有坏行——三句不同的话，来自
    // `LogTail::notice`。这一页最要紧的一件事就是别让这三种情况长得
    // 一模一样（W174）。
    if let Some(n) = tail.notice() {
        body = body.push(text(n).size(12).color(color::TEXT_SUB));
    }

    body = body.push(
        container(scrollable(card(list.into())))
            .height(Length::Fill)
            .width(Length::Fill),
    );

    let mut open = button(text("打开日志目录").size(12)).padding([5, 11]);
    if action_enabled(Action::OpenLogDir, false) {
        open = open.on_press(Message::ActionPressed(Action::OpenLogDir));
    }
    body = body.push(
        row![
            text(crate::logs::footer(log_file_name))
                .size(12)
                .color(color::TEXT_SUB)
                .width(Length::Fill),
            open,
        ]
        .spacing(10)
        .align_y(Alignment::Center),
    );

    body.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logs::LogLevel;
    use crate::APP_THEME;

    fn line(level: LogLevel) -> LogLine {
        LogLine {
            time: "11:52:31".into(),
            // 三帧的文字**逐字相同**，差别只可能出在颜色上——这是 W146
            // 那个技法的第一步：找一个让样式变化与文本变化解耦的输入。
            // `LogLine` 是个普通结构体，`level` 与 `time`/`message` 本来
            // 就是三个独立字段，不需要像维护页那样费劲去凑。
            message: "同一句话，三帧逐字相同".into(),
            level,
        }
    }

    /// 只渲染**一行**，跟基线哈希比。
    ///
    /// W146 的第二步：把渲染范围缩到能单独渲染的最小子元素。代价是
    /// [`log_row_with`] 得从本模块的测试里够得到——所以这几条测试住在
    /// `view/logs.rs` 自己的 `mod tests` 里，而不是 `tests/ui.rs`。
    fn matches(element: Element<'_, Message>, baseline: &std::path::Path) -> bool {
        let mut ui = iced_test::simulator(element);
        ui.snapshot(&APP_THEME)
            .expect("渲染日志的一行")
            .matches_hash(baseline)
            .expect("读写基线哈希")
    }

    /// **取色的三样东西，每一样都真的画到了像素上。**
    ///
    /// # 断的是哪一根线
    ///
    /// [`crate::theme::log_row_palette`] 有表驱动测试，
    /// [`crate::logs::parse_line`] 给出的 `level` 有单测，**中间那三个
    /// 表达式两头都没人守**——就是 [`log_row_with`] 里的 `.color(p.tag)`、
    /// `.color(p.text)` 与 `background: p.background.map(Into::into)`。
    /// 把它们换成写死的值，`cargo test --workspace` 里除了这一条之外
    /// 一条都不红：`iced_test` 的选择器只带 `id` / `bounds` / 文本内容，
    /// **样式、颜色、底色一个字段都没有**。
    ///
    /// # 为什么要**一样一样**地比
    ///
    /// 本轮实测过两次假绿，两次都是"两帧确实不同，但不同的不是我说的
    /// 那件事"：
    ///
    /// 1. 第一版拿 `log_row(&info)` 跟 `log_row(&warn)` 比——等级那一列
    ///    画的是 `INFO` 与 `WARN`，**文字本来就不同**，三处取色全写死它
    ///    照样绿；
    /// 2. 第二版改成同一个 `LogLine` 配两份 `LogRowPalette`——文字一样
    ///    了，但**只把底色写死成 `None`** 仍然绿，因为 `tag` 与 `text`
    ///    那两处还在跟着换。
    ///
    /// 现在每一轮只动 [`crate::theme::LogRowPalette`] 的**一个字段**，
    /// 两帧之间除了那一个字段完全相同。三个字段各一格，哪一处被写死就
    /// 是哪一格红。
    #[test]
    fn every_part_of_the_palette_really_reaches_the_pixels() {
        use crate::theme::{color, LogRowPalette};

        let dir = tempfile::tempdir().expect("建临时目录");
        let l = line(LogLevel::Info);
        let base = LogRowPalette {
            background: None,
            tag: color::IDLE,
            text: color::TEXT,
        };
        // 每一格：(这一样叫什么, 只改了这一样的另一份取色)
        let cases = [
            (
                "底色",
                LogRowPalette {
                    background: Some(color::ROW_WARN_BG),
                    ..base
                },
            ),
            (
                "等级标签色",
                LogRowPalette {
                    tag: color::FAILED,
                    ..base
                },
            ),
            (
                "正文色",
                LogRowPalette {
                    text: color::ROW_FAIL_TEXT,
                    ..base
                },
            ),
        ];

        for (what, other) in cases {
            let baseline = dir.path().join(format!("only-{what}"));
            // 解耦的自证：这一份取色跟基准**只差这一样**。
            let mut differences = 0;
            differences += usize::from(other.background != base.background);
            differences += usize::from(other.tag != base.tag);
            differences += usize::from(other.text != base.text);
            assert_eq!(differences, 1, "{what}：夹具不止差了一样");

            assert!(
                matches(log_row_with(&l, base), &baseline),
                "第一帧应当写入基线"
            );
            assert!(
                matches(log_row_with(&l, base), &baseline),
                "同一份取色渲染两次结果不一致，快照不可作为判据"
            );
            assert!(
                !matches(log_row_with(&l, other), &baseline),
                "只换了{what}，画出来逐字节相同——这一处取色没进到控件里"
            );
        }
    }

    /// 警告与错误必须**互相**分得开。
    ///
    /// 上面那条只证明"每一样取色都有用"，证明不了这两个等级配出来的
    /// 整体不一样——只给"非信息"一律上同一个底色、同一个字色，上面那条
    /// 照样全过，而现场最要紧的恰恰是一眼分出错误。
    #[test]
    fn a_warning_and_an_error_never_look_the_same() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let baseline = dir.path().join("warn-vs-error");
        // 同一个 `LogLine`：连等级那个词都一样，差别只可能在取色上。
        let l = line(LogLevel::Info);
        assert!(matches(
            log_row_with(&l, log_row_palette(LogLevel::Warn)),
            &baseline
        ));
        assert!(
            !matches(
                log_row_with(&l, log_row_palette(LogLevel::Error)),
                &baseline
            ),
            "警告与错误画出来逐字节相同——两种等级在屏幕上分不开"
        );
    }

    /// **一行真的按自己的等级去查取色。**
    ///
    /// 上面那条证明"给什么色画什么色"，这一条证明"给的是自己那一份"。
    /// 两条都要：只有上面那条的话，把 [`log_row`] 写成
    /// `log_row_with(l, log_row_palette(LogLevel::Info))`（所有行一个
    /// 颜色）一条都不红。
    ///
    /// 比的两帧**文字完全相同**（同一个 `LogLine`），差别只可能是取色。
    #[test]
    fn the_row_looks_up_the_palette_by_its_own_level() {
        let dir = tempfile::tempdir().expect("建临时目录");
        for level in LogLevel::ALL {
            let l = line(level);
            let baseline = dir.path().join(format!("by-level-{}", level.tag()));

            // 基线 = 用**这个等级自己那一份**取色画出来的样子。
            assert!(
                matches(log_row_with(&l, log_row_palette(level)), &baseline),
                "第一帧应当写入基线"
            );
            // 真正的 `log_row` 必须画成一模一样。
            assert!(
                matches(log_row(&l), &baseline),
                "{level:?} 这一行没有用自己那一份取色"
            );
            // 反向自证：换成别的等级的取色就该不一样，否则上一条是空转。
            for other in LogLevel::ALL.into_iter().filter(|o| *o != level) {
                assert!(
                    !matches(log_row_with(&l, log_row_palette(other)), &baseline),
                    "{level:?} 与 {other:?} 的取色画出来一样"
                );
            }
        }
    }

    // ============== W179：字体 ==============

    /// 三个系统各有各的等宽字体，不知道的老实说不知道。
    ///
    /// 写成纯函数而不是 `cfg` 的价值就在这一条：**Windows 那一档
    /// （唯一真正要用的一档）在这台 macOS 机器上也验得到**。
    ///
    /// 改红：把 `"windows"` 那一支改回 `None`，或者改成一个 Windows
    /// 不带的族——第一格红。
    #[test]
    fn each_operating_system_has_its_own_monospace_family() {
        assert_eq!(monospace_family("windows"), Some("Consolas"));
        assert_eq!(monospace_family("macos"), Some("Menlo"));
        assert_eq!(monospace_family("freebsd"), None);
        assert_eq!(monospace_family("linux"), None);
        // 本机这一档必须有字体，否则下面那条渲染测试是在测"默认字体
        // 能不能画中文"，跟等宽一个关系都没有。
        assert!(
            monospace_family(std::env::consts::OS).is_some(),
            "这台机器这一档没有等宽字体，下面那条渲染测试会空转"
        );
    }

    /// **本机选的那个等宽字体画得出中文，不会把渲染管线炸掉。**
    ///
    /// # 断的是哪一根线
    ///
    /// `iced::Font::MONOSPACE` 在这个项目里是**有毒的**：cosmic-text 把
    /// 它绑在一个通常没装的族上（根因见 [`monospace_family`]），族名解析
    /// 不到时中文会让 `glyph_cache.rs:100` 溢出 panic，而那个 panic 会
    /// **连带毒掉全局字体锁**——上一轮实测过，一条测试炸掉，另外四条
    /// 快照测试一起变成 `Write font system: PoisonError`。
    ///
    /// 所以这条测试**不能**用 `catch_unwind` 去证明 `MONOSPACE` 会炸
    /// （那会把同一个测试二进制里别的快照测试全带下水）。它分两半：
    ///
    /// 1. **结构上**断言我们用的不是 `MONOSPACE`——有人换回去，这条
    ///    立刻红，而且**不会炸**；
    /// 2. **行为上**真的用本机这个族去渲染一段中文——族名要是写错
    ///    （比如 Windows 那一档写成一个不存在的字体），这条当场 panic。
    #[test]
    fn the_monospace_font_really_draws_chinese() {
        // 第一半：结构。
        assert_ne!(
            mono(),
            Font::MONOSPACE,
            "又用回 Font::MONOSPACE 了——它绑在一个通常没装的族上，\
             中文会让渲染管线溢出 panic，见 monospace_family 的文档"
        );
        assert_eq!(
            mono(),
            Font::with_name(monospace_family(std::env::consts::OS).expect("本机该有等宽字体")),
            "用的不是 monospace_family 给出的那个族"
        );

        // 第二半：行为。
        //
        // **这一半目前钉不住任何东西，如实记在这里。** 复审报告说「把夹具
        // 换成 `log_row` 形状即可带载」，我照做之后实测**仍然不红**：
        // `mono()` 换成不存在的族名 → 九条全绿；换成 `Font::MONOSPACE`
        // → 九条全绿（两次都把上面那两条结构断言一起废掉才测的）。
        //
        // 根因是设计本身：**生产代码里中文根本不走等宽字体**。消息列是
        // 整行里唯一可能出现中文的地方，而它用的是默认字体；走 `mono()`
        // 的只有 ASCII 的时间与 ASCII 的等级标签。所以任何「生产形状」的
        // 夹具都触发不了那次溢出——上一轮之所以炸，是因为当时**正文列也
        // 加了 `.font(mono())`**。
        //
        // 于是这一半现在的作用只剩「`mono()` 至少画得出中文而不 panic」
        // 这条弱保证。真正守着这件事的是上面那两条结构断言（实测带载）
        // 与 `parse_line` 对时间列的 ASCII 校验（`logs.rs` 里那条，也带载）。
        // 要让它真带载得造一个**非生产形状**的夹具（中文经 `mono()` 画在
        // 撑满的行里），那属于为测试而造场景；更该做的是 W182 的
        // windows-latest job——Consolas 解析不解析得到，只有那里验得到。
        //
        // 这一段中文就是日志里最常见的那种。
        let element: Element<'_, Message> =
            text("一体机首包延迟 480 ms").size(12).font(mono()).into();
        let mut ui = iced_test::simulator(element);
        let _ = ui.snapshot(&APP_THEME).expect("用本机的等宽字体渲染中文");
    }

    /// 时间那一列走的也是同一个字体，**而且它现在不再靠「只准 ASCII」
    /// 那条校验保命**。
    ///
    /// 上一轮时间列用的是 `Font::MONOSPACE`，唯一挡着崩溃的是
    /// `logs::parse_line` 里那条"时间必须全是数字与冒号"的校验——
    /// 而那条校验的存在理由是**格式**，不是防崩。评审实测过：把时间
    /// 夹具换成 `"11时52分"`，不 panic，但那一列被挤出可见区，
    /// **行为损坏在 panic 之前就发生了**。
    ///
    /// 换成真实存在的族之后，这一列对非 ASCII 的时间也只是画得出来
    /// 而已。这条测试把那件事钉住。
    #[test]
    fn a_time_column_with_non_ascii_still_renders() {
        let l = LogLine {
            time: "11时52分".into(),
            level: LogLevel::Warn,
            message: "一体机首包延迟".into(),
        };
        // 不崩就是这条测试的全部——上一轮这一行的安全完全依赖
        // `parse_line` 那条校验，而那条校验随时可能被放宽。
        let mut ui = iced_test::simulator(log_row(&l));
        let _ = ui.snapshot(&APP_THEME).expect("渲染一行非 ASCII 的时间");
        // 顺带：它确实还画得出来，不是被挤成了零宽。
        let mut ui = iced_test::simulator(log_row(&l));
        let bounds = ui.find("11时52分").expect("时间那一列").bounds();
        assert!(bounds.width > 1.0, "时间那一列被挤没了：{bounds:?}");
    }

    /// **三列的横向顺序：时间在左，等级居中，正文在右。**
    ///
    /// W165 的技法：`iced_test` 看不到样式，但看得到位置与尺寸。
    /// `iced_selector` 的 `&str` 选择器按内容整段相等匹配，三段文字各不
    /// 相同，三次 `find` 各拿各的候选，`Candidate::Text::bounds()` 直接
    /// 给 `Rectangle`。
    ///
    /// 改红（三种形状都实测过）：把 `row![]` 里三个 `text` 的顺序打乱；
    /// 把时间与正文对调；把等级那一列的 `.width(TAG_WIDTH)` 删掉
    /// （第三条断言红——正文会紧贴着等级，三列对不齐）。
    #[test]
    fn the_row_puts_the_time_left_of_the_level_left_of_the_message() {
        let l = LogLine {
            time: "AAA".into(),
            level: LogLevel::Warn,
            message: "BBB".into(),
        };
        let mut ui = iced_test::simulator(log_row(&l));
        let time = ui.find("AAA").expect("时间那一列").bounds();
        let tag = ui.find("WARN").expect("等级那一列").bounds();
        let message = ui.find("BBB").expect("正文那一列").bounds();

        assert!(time.x < tag.x, "时间没画在等级左边：{time:?} {tag:?}");
        assert!(tag.x < message.x, "等级没画在正文左边：{tag:?} {message:?}");
        // 三列在同一行上——竖着排的话上面两条 x 的比较仍然可能碰巧成立。
        assert!(
            (time.y - message.y).abs() < 1.0,
            "三列没在同一行上：{time:?} {message:?}"
        );
        // 等级那一列占住了固定宽度，正文才对得齐：等级文字本身
        // （`WARN`）比 `TAG_WIDTH` 窄，正文必须从这一列的右边界之后开始。
        assert!(
            message.x >= tag.x + TAG_WIDTH,
            "等级那一列没占住固定宽度，200 行的正文会参差不齐：\
             tag={tag:?} message={message:?}"
        );
    }

    /// **选中的胶囊真的画成另一个样子。**
    ///
    /// 同一个技法，解耦来得更便宜：[`chip`] 的三个参数里，`is_active`
    /// 跟另外两个（决定文字）完全独立，同一个 `(f, count)` 画两次，
    /// 文字必然逐字相同。
    ///
    /// 改红：把 `chip` 里的 `chip_style(is_active)` 换成
    /// `chip_style(false)`——四个标签全长一个样，用户看不出自己选的是
    /// 哪一个，而这条当场红。
    #[test]
    fn the_selected_chip_really_draws_differently() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let baseline = dir.path().join("chip");
        let render = |active: bool| {
            let mut ui = iced_test::simulator(chip(LogFilter::All, 15, active));
            ui.snapshot(&APP_THEME)
                .expect("渲染一个胶囊")
                .matches_hash(&baseline)
                .expect("读写基线哈希")
        };

        assert!(render(false), "第一帧应当写入基线");
        assert!(render(false), "同一个胶囊渲染两次结果不一致");
        assert!(
            !render(true),
            "选中的胶囊跟没选中的画出来逐字节相同——chip_style 的结果没进到控件里"
        );
    }

    /// 点一个胶囊会发出对应的那一条消息，**四个各发各的**。
    ///
    /// 改红：把 `chip` 里的 `Message::LogFilterSelected(f)` 写成
    /// `Message::LogFilterSelected(LogFilter::All)`（四个胶囊点了都回到
    /// 「全部」）——这条当场红。
    #[test]
    fn each_chip_carries_its_own_filter() {
        for want in LogFilter::ALL {
            let mut ui = iced_test::simulator(chip(want, 3, false));
            ui.click(format!("{} 3", want.label()).as_str())
                .unwrap_or_else(|e| panic!("点不到胶囊 {want:?}：{e:?}"));
            let messages: Vec<Message> = ui.into_messages().collect();
            assert_eq!(messages.len(), 1, "{want:?} 应当恰好产生一条消息");
            let Message::LogFilterSelected(got) = messages[0] else {
                panic!("点 {want:?} 发出的不是 LogFilterSelected：{messages:?}");
            };
            assert_eq!(got, want);
        }
    }
}
