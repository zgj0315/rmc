//! W138：rmc-app 自己的源码扫描。
//!
//! # 为什么需要这个文件
//!
//! Task 7 把禁用词的源码扫描立在了 rmc-core，**只覆盖 rmc-core**。当时
//! 评审核过 rmc-win 没有任何用户可见文案，所以不漏。
//!
//! **Task 8 起这条不成立了。** 维护页的每一个字都是 rmc-app 的字符串
//! 字面量：输入框标签、六条校验错误、按钮、分组标题、输入框占位符。
//! Task 9-11 还有三页要写。rmc-app 从这一轮起是文案的主产地。
//!
//! 而原有的两道界面侧防线各自够不着这里：
//!
//! - `tests/ui.rs` 的控件树扫描只看**当前渲染出来的那棵树**。六条校验
//!   错误各自只在一种输入组合下才出现，八条状态分支各画各的——真要靠
//!   控件树扫全，得把所有组合都渲染一遍。
//! - `model.rs` 的 `nothing_the_status_card_says_is_banned` 只走状态卡与
//!   按钮，不走表单。
//!
//! 源码扫描是唯一一道**跟渲染状态无关**的：字符串只要写在 `src/` 里就被
//! 看见，不管它什么时候才上屏。
//!
//! # 扫描器是**共用**的，不是复制的
//!
//! 调的是 `rmc_core::wording::scan_string_literals`——就是 rmc-core 自己
//! 那道扫描用的那一个函数，上一轮刚给它补过 `\` 续行的静默盲区。选择
//! 「共用」而不是「在 rmc-app 里照着写一份」的理由与代价，见
//! task-8-report.md。

use rmc_core::wording::{banned_word_in, scan_string_literals, strip_placeholders, SourceLiteral};
use std::path::PathBuf;

fn rmc_app_src() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// rmc-app 的生产代码里的全部字符串字面量。
///
/// **一个文件都不跳过**：rmc-app 没有 rmc-core 那两个例外（词表自己的家、
/// 进程内假服务端），这里所有 `src/` 下的字面量都该被看见。
fn literals() -> Vec<SourceLiteral> {
    scan_string_literals(&rmc_app_src(), &[])
}

/// 反向自证：扫描器真的走到了 rmc-app 的源码，真的切出了字面量。
///
/// 少了这条，下面那条主断言在「路径写错了」「截断规则把整份源码切没了」
/// 「切词被一个 `'\"'` 字符字面量带偏」时全是永远为真的空转——这个项目
/// 已经抓到 20 个这种形状的假绿。
#[test]
fn the_scan_really_reaches_this_crates_source() {
    let lits = literals();
    assert!(
        lits.len() > 40,
        "只切出 {} 条字面量，扫描器八成没走到 rmc-app 的 src/",
        lits.len()
    );

    // 四个文件各钉一条**已知的生产文案**。路径、目录递归、`mod tests {`
    // 截断、切词，四件事同时成立才找得到。
    for (file, text) in [
        ("lib.rs", "远程运维客户端"),
        ("theme.rs", "维护"),
        ("form.rs", "运维服务器地址"),
        ("view/maintain.rs", "记住密码"),
    ] {
        assert!(
            lits.iter().any(|l| l.file == file && l.text == text),
            "扫描结果里找不到 {file} 的已知文案「{text}」——截断规则或切词坏了"
        );
    }

    // `mod tests {` 之后的东西不该进来。`form.rs` 的测试模块里有一个
    // 独一无二的金丝雀串，它必须**不在**结果里。
    assert!(
        !lits
            .iter()
            .any(|l| l.text.contains("canary-7f3a9e-must-never-be-printed")),
        "测试模块里的字面量被扫进来了，截断规则失效"
    );
}

/// W138 的主防线：rmc-app 生产代码里的任何一条字符串字面量都不许含禁用词。
///
/// 改红：把 `form.rs` 的 `Field::GatewayHost => "运维服务器地址"` 改回
/// brief 原稿那个 `"Gateway 地址"`，这条立刻红——而在 Task 8 之前，
/// **没有任何一道闸门会响**。
#[test]
fn no_string_literal_in_this_crate_says_gateway() {
    // 反向自证：匹配器真的会发火。
    assert_eq!(banned_word_in("Gateway 地址"), Some("Gateway"));
    assert_eq!(banned_word_in("经网关转发"), Some("网关"));
    assert_eq!(banned_word_in("运维服务器地址"), None);

    let hits: Vec<String> = literals()
        .iter()
        .filter_map(|l| {
            banned_word_in(&strip_placeholders(&l.text))
                .map(|w| format!("{}:{} 的「{}」里含有 {w}", l.file, l.line, l.text))
        })
        .collect();

    assert!(
        hits.is_empty(),
        "rmc-app 的生产代码字符串里出现了需求禁用的词（这些字都会上屏）：\n{}",
        hits.join("\n")
    );
}

/// rmc-app 的词表必须原样是 rmc-core 那一份，不许分叉。
#[test]
fn the_word_list_is_not_forked() {
    assert_eq!(rmc_app::BANNED_WORDS, rmc_core::wording::BANNED_WORDS);
}
