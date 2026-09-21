//! 诊断页。现场工程师连不上时看的那一屏，也是诊断包的出口。
//!
//! 本文件里**不应该出现任何判断**——见 crate 根的模块文档。每一行画什么
//! 来自 [`crate::diag::rows`]，处置建议来自 [`crate::diag::advice_for`]，
//! 每一行取什么颜色来自 [`crate::theme::row_palette`]，「这个按钮该不该
//! 可按」来自 [`crate::model::action_enabled`]。这里只负责把它们摆进控件。
//!
//! # 跟画板 `design/body-Diagnostics.html` 的两处出入
//!
//! 1. 画板每一行是「行首文字 … 右对齐的一小段说明」。这里改成上下两行
//!    （行首文字在上，说明在下）：画板上的说明短到「6 ms」「已建立」，
//!    而真实的说明里有整句话（代理认证那一行最长），520 宽的窗口里单行
//!    放不下。
//! 2. 画板顶上有一个「重新检查」按钮。重新跑预检要 Task 10 的
//!    Supervisor 接线才有意义，本任务不画。
//!
//! 两条都记在 task-9-report.md 的「后续完善」里。

use super::{card, section};
use crate::diag::{rows, Advice, DiagRow, ProxyStatus};
use crate::model::{action_enabled, Action, Model};
use crate::theme::{color, row_palette};
use crate::Message;
use iced::widget::{button, column, container, row, space, text};
use iced::{Alignment, Border, Element, Length};

/// 诊断结果里的一行。
///
/// 颜色**全部**来自 [`row_palette`]，这里一个 `if` 都没有。那条
/// 「算出来的颜色真的画到了像素上」由本文件末尾的
/// [`tests::a_failed_row_really_draws_in_different_colors`] 用差分快照
/// 守着（W146 的技法）。
// 生命周期刻意写成自由的 `'a`：三个字段全都 `clone` 过了，返回的树
// 一个字节都不借 `r`。写成 `'_` 会让 `view` 里那个装行的 `Vec` 被
// 借住，返回时就是 `E0515`。
fn diag_line<'a>(r: &DiagRow) -> Element<'a, Message> {
    let palette = row_palette(r.verdict);
    container(
        column![
            text(r.name.clone()).size(13).color(palette.text),
            text(r.detail.clone()).size(12).color(palette.text),
        ]
        .spacing(1),
    )
    .padding([7, 12])
    .width(Length::Fill)
    .style(move |_| container::Style {
        background: palette.background.map(Into::into),
        ..Default::default()
    })
    .into()
}

/// 处置建议卡。没有失败项时整张卡不画（[`Advice::NoFailure`]）。
fn advice_card<'a>(advice: &Advice) -> Option<Element<'a, Message>> {
    let c = advice.card()?;
    Some(
        container(
            column![
                text(c.failed_step.clone()).size(13),
                text(c.body.clone()).size(12).color(color::TEXT_SUB),
            ]
            .spacing(4),
        )
        .padding([11, 13])
        .width(Length::Fill)
        .style(|_| container::Style {
            background: Some(color::CARD.into()),
            border: Border {
                color: color::BORDER,
                width: 1.0,
                radius: 6.0.into(),
            },
            ..Default::default()
        })
        .into(),
    )
}

/// 底部那一排按钮：左边是强调色的「导出诊断包」，右边是「复制检查结果」。
///
/// 两个动作都**不跟表单绑在一起**（[`action_enabled`] 里那两格），理由
/// 写在那边：现场需要导出诊断包的时候，恰恰就是连不上的时候。
fn actions<'a>(form_ready: bool) -> Element<'a, Message> {
    let primary = {
        let mut b = button(text("导出诊断包").size(13).color(color::CARD))
            .width(Length::Fill)
            .padding([9, 0])
            .style(|_, _| button::Style {
                background: Some(color::ACCENT.into()),
                text_color: color::CARD,
                border: Border {
                    radius: 4.0.into(),
                    ..Default::default()
                },
                ..Default::default()
            });
        if action_enabled(Action::ExportDiagnostics, form_ready) {
            b = b.on_press(Message::ActionPressed(Action::ExportDiagnostics));
        }
        b
    };
    let secondary = {
        let mut b = button(text("复制检查结果").size(13))
            .width(Length::Fill)
            .padding([9, 0]);
        if action_enabled(Action::CopyDiagnostics, form_ready) {
            b = b.on_press(Message::ActionPressed(Action::CopyDiagnostics));
        }
        b
    };
    row![primary, secondary].spacing(8).into()
}

/// 诊断页。
///
/// `proxy` 由调用方取好之后交进来——**这一页不得自己去查**
/// （W43/W160，见 [`crate::diag`] 的模块文档）。`environment` 同理，
/// 通常是 [`crate::diag::environment_line`] 的结果。
pub fn view<'a>(
    model: &'a Model,
    proxy: Option<&'a ProxyStatus>,
    environment: &'a str,
    form_ready: bool,
) -> Element<'a, Message> {
    let server_verified =
        model
            .server_fingerprint
            .as_ref()
            .map(|fingerprint| crate::diag::ServerVerified {
                fingerprint: fingerprint.clone(),
            });
    let lines = rows(model.preflight.as_ref(), proxy, server_verified.as_ref());

    let mut list = column![];
    for r in &lines {
        list = list.push(diag_line(r));
    }

    let mut body = column![section("连接诊断"), card(list.into())]
        .spacing(12)
        .padding(14);

    let advice = crate::diag::advice_for(model.preflight.as_ref());
    if let Some(c) = advice_card(&advice) {
        body = body.push(c);
    }

    body = body.push(space::vertical());
    body = body.push(
        text(environment.to_string())
            .size(12)
            .color(color::TEXT_SUB),
    );
    body = body.push(actions(form_ready));
    body.align_x(Alignment::Start).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diag::Verdict;
    use crate::APP_THEME;

    /// **「两段文字画反了」也是可观测的——靠 `bounds`，不是靠快照。**
    ///
    /// 实现者原先判这条守不住，理由是「行首文字与说明都是
    /// `Candidate::Text`，只有字号与上下顺序不同，`iced_test` 两样都看不见；
    /// 要堵得写一个按 `bounds` 收集全部文本的收集器，因为 `Simulator::find`
    /// 只返回第一个命中」。**这个前提是错的**：`iced_selector` 的 `&str`
    /// 选择器按**内容整段相等**匹配（`iced_selector-0.14.0/src/lib.rs:53-83`），
    /// 只要两段文字本身不同，两次 `find` 就分别拿得到各自那一个
    /// `Candidate::Text`；而 `target::Text::bounds()`（`target.rs:266-272`）
    /// 直接给出 `Rectangle`。**不需要收集器。**
    ///
    /// 差分快照在这里反而够不着：[`a_failed_row_really_draws_in_different_colors`]
    /// 用的是每次现建的临时基线，画反之后基线与对照帧**一起变**，恒为真。
    ///
    /// # Task 10/11 照抄什么
    ///
    /// 跟 W146 并列的第二条：**`iced_test` 看不到样式，但看得到位置与尺寸。**
    /// 凡是「谁在上、谁更大、谁更宽」这类版面语义，都能用 `bounds` 钉住，
    /// 而不必等一个收集器。
    ///
    /// 改红（三种形状都实测过）：把 `name` 与 `detail` 整个画反；
    /// 只对调两个字号（13↔12）；只对调上下顺序。
    #[test]
    fn the_row_puts_its_name_above_its_detail_and_in_a_bigger_type() {
        let r = DiagRow {
            name: "AAA".into(),
            detail: "BBB".into(),
            verdict: Verdict::Pass,
        };
        let mut ui = iced_test::simulator(diag_line(&r));
        let name = ui.find("AAA").expect("行首文字").bounds();
        let detail = ui.find("BBB").expect("说明").bounds();
        assert!(
            name.y < detail.y,
            "行首文字没画在说明上面：{name:?} {detail:?}"
        );
        assert!(
            name.height > detail.height,
            "行首文字没用更大的字号：{name:?} {detail:?}"
        );
    }

    /// 两份**文字逐字相同、只有结论不同**的行。
    ///
    /// 这是 W146 那个技法的第一步：找一个**让样式变化与文本变化解耦**的
    /// 输入组合。在维护页那边要靠 `Reason::Rejected` 才凑得出来；这里
    /// 便宜得多——[`DiagRow`] 是一个可以直接构造的普通结构体，`verdict`
    /// 与 `name`/`detail` 本来就是三个独立字段。
    ///
    /// **但便宜不等于自动成立**：如果拿 [`crate::diag::rows`] 去造这两帧
    /// （喂一份 `Pass` 的报告和一份 `Fail` 的报告），`detail` 必然跟着变，
    /// 两帧就会因为文字不同而不同，快照比出差别说明不了是颜色的功劳。
    /// 所以这里刻意**绕过 `rows`、直接构造 `DiagRow`**。
    fn row_with(verdict: Verdict) -> DiagRow {
        DiagRow {
            name: "运维服务器 TLS".to_string(),
            detail: "同一句话，两帧逐字相同".to_string(),
            verdict,
        }
    }

    /// 只渲染**一行**，跟基线哈希比。
    ///
    /// W146 的第二步：把渲染范围缩到**能单独渲染的最小子元素**。代价是
    /// `diag_line` 得从本模块的测试里够得到——所以这条测试住在
    /// `view/diagnostics.rs` 自己的 `mod tests` 里，而不是 `tests/ui.rs`
    /// （那里只看得见 `pub fn view`）。
    fn line_matches(r: &DiagRow, baseline: &std::path::Path) -> bool {
        let mut ui = iced_test::simulator(diag_line(r));
        ui.snapshot(&APP_THEME)
            .expect("渲染诊断结果的一行")
            .matches_hash(baseline)
            .expect("读写基线哈希")
    }

    /// **「失败的行真的画成另一个样子」这条连线是可观测的。**
    ///
    /// # 断的是哪一根线
    ///
    /// [`crate::theme::row_palette`] 有表驱动测试，[`crate::diag::rows`]
    /// 给出的 `verdict` 有单测，**中间那两个表达式两头都没人守**——就是
    /// [`diag_line`] 里的 `.color(palette.text)` 与
    /// `background: palette.background.map(Into::into)`。
    ///
    /// 把它们换成写死的 `color::TEXT` 与 `None`（也就是「失败的行跟通过
    /// 的行长得一模一样」），`cargo test --workspace` 里**除了这一条之外
    /// 一条都不红**：`iced_test` 的选择器（`iced_selector::Candidate`）
    /// 只带 `id` / `bounds` / `visible_bounds` / 文本内容，**样式、颜色、
    /// 底色一个字段都没有**。这跟维护页那条
    /// `a_marked_field_really_draws_a_different_border` 是同一个盲区。
    ///
    /// # 反向自证
    ///
    /// 同一份行画两次必须一致，否则下面那条只是在测渲染不稳定。
    #[test]
    fn a_failed_row_really_draws_in_different_colors() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let baseline = dir.path().join("diag-line");

        let ok = row_with(Verdict::Pass);
        let bad = row_with(Verdict::Fail);
        let unknown = row_with(Verdict::Undecided);
        // 解耦的自证：三帧的**文字逐字相同**，差别只可能出在颜色上。
        assert_eq!(ok.name, bad.name);
        assert_eq!(ok.detail, bad.detail);
        assert_eq!(ok.name, unknown.name);
        assert_eq!(ok.detail, unknown.detail);

        // 第一帧：基线不存在，`matches_hash` 写一份并返回 true。
        assert!(
            line_matches(&ok, &baseline),
            "第一帧应当写入基线并返回 true"
        );
        // 反向自证：同一份行画两次必须一致。
        assert!(
            line_matches(&ok, &baseline),
            "同一份行渲染两次结果不一致，快照不可作为判据"
        );

        assert!(
            !line_matches(&bad, &baseline),
            "失败的行跟通过的行画出来逐字节相同——row_palette 的结果没有进到控件里"
        );
        assert!(
            !line_matches(&unknown, &baseline),
            "「还没检查过」的行跟通过的行画出来逐字节相同——三种结论在屏幕上分不开"
        );
    }

    /// [`a_failed_row_really_draws_in_different_colors`] 为什么必须
    /// **绕过 [`crate::diag::rows`]**：走它造出来的两帧，文字本身就不同，
    /// 于是两帧无论上不上色都不同。
    ///
    /// 这条不是防回归，是把上面那条的**输入选择**钉成文档——少了它，
    /// 后人会顺手把它改成「喂两份报告给 `rows`」，然后得到一条永远为真
    /// 的断言。形状与维护页的 `the_whole_page_cannot_isolate_the_border`
    /// 完全一样。
    #[test]
    fn going_through_rows_cannot_isolate_the_colors() {
        use rmc_core::error::ErrorClass;
        use rmc_core::preflight::{PreflightReport, PreflightStep, StepOutcome, STEP_GATEWAY_TLS};

        let mk = |outcome| PreflightReport {
            steps: vec![PreflightStep {
                name: STEP_GATEWAY_TLS,
                outcome,
            }],
        };
        let pass = rows(
            Some(&mk(StepOutcome::Pass {
                detail: "握手成功".into(),
            })),
            None,
            None,
        );
        let fail = rows(
            Some(&mk(StepOutcome::Fail {
                detail: "证书链不受信任".into(),
                class: ErrorClass::Fatal,
            })),
            None,
            None,
        );
        assert_eq!(pass[0].name, fail[0].name);
        assert_ne!(
            pass[0].detail, fail[0].detail,
            "两帧的文字居然相同——那 `rows` 这条路本来也能用来隔离颜色，\
             上面那条测试的范围选择说明就该重写"
        );
    }
}
