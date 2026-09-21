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
        // Task 8：运维服务器那三个框（地址/端口/账号）合并成一条连接码
        // 之后，"运维服务器地址" 这句字面量已经从 form.rs 消失，换成
        // 这个字面量当锚点——它就是 `Field::Code` 的界面标签。
        ("form.rs", "连接码"),
        ("view/maintain.rs", "记住密码"),
        // Task 9 新增的两个文件也要真的被走到。
        ("diag.rs", "系统代理"),
        ("view/diagnostics.rs", "导出诊断包"),
        // Task 11 新增的两个文件同样要被走到——托盘提示与通知正文是
        // **会弹到用户屏幕上**的字，而它们一条都不在控件树里，
        // `tests/ui.rs` 那道扫描一个字都看不见。
        ("tray.rs", "远程维护"),
        ("remember.rs", "账号记录的格式不对，当作没有记过"),
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

/// W162（落实 W153）：**rmc-app 的生产代码里不许有原始字符串字面量。**
///
/// # 为什么这是一条测试，而不是一句约定
///
/// `rmc_core::wording` 的切词器**不认原始字符串**（它自己的文档写明了：
/// 只处理转义的引号，遇上 `r` 打头的字面量会把后面的切词整段带偏）。
/// 今天整个 workspace 里一条都没有，所以不漏。
///
/// 而 Task 9 的诊断页是这条纪律第一次真的受考验的地方：处置建议是五段
/// 带标点的长中文，**写成原始字符串是最顺手的写法**。一旦有人那么写，
/// 上面那条禁用词扫描会对那整段文案**一声不响地失明**——跟上一轮刚修掉
/// 的「反斜杠续行整条字面量被丢掉」是同一个形状（W130）。
///
/// 裁决给的是两条路：先补切词器，或者明确不用。本任务选**不用**
/// （五段文案用续行写，切词器上一轮刚补过那一支），并把这个选择从一句
/// 承诺变成一道闸门。哪天真要用原始字符串，先去补切词器，然后连这条
/// 测试一起改——两件事绑在一起，不会有人只做前一半。
///
/// 改红：把 `diag.rs` 里任意一段处置建议改成原始字符串写法。
#[test]
fn no_production_code_in_this_crate_uses_a_raw_string_literal() {
    let hits = scan_lines(has_raw_string);
    assert!(
        hits.is_empty(),
        "rmc-app 的生产代码里出现了原始字符串，禁用词扫描对它整段失明\n\
         （要么先补 rmc_core::wording 的切词器，要么换成续行写法）：\n{}",
        hits.join("\n")
    );

    // 反向自证之一：探测器真的认得出原始字符串。两种写法都用 `concat!`
    // 拼出来——直接写字面量的话，**这几行自己**就是命中，测试永远红。
    let plain = concat!("r", "\"");
    let hashed = concat!("r", "#\"");
    assert!(
        has_raw_string(&format!("let s = {plain}abc\";")),
        "探测器认不出不带井号的原始字符串"
    );
    assert!(
        has_raw_string(&format!("let s = {hashed}abc\"#;")),
        "探测器认不出带井号的原始字符串"
    );
    assert!(
        has_raw_string(&format!("let s = b{plain}abc\";")),
        "探测器认不出字节原始字符串"
    );

    // 反向自证之二：不会把普通字面量误判。这四条**全是本仓库真实踩过的
    // 形状**——第一版探测器只查「r 后面跟着引号」，于是
    // `"UnknownIssuer"`、`.field("remember", ..)`、`"placeholder"` 三处
    // 全被判成原始字符串，测试一上来就红。
    for ok in [
        "let s = \"UnknownIssuer\";",
        ".field(\"remember\", &self.remember)",
        "password: Zeroizing::new(\"placeholder\".into()),",
        "for r in &lines {",
    ] {
        assert!(!has_raw_string(ok), "误判成原始字符串：{ok}");
    }

    // 反向自证之三：扫描器真的走到了 rmc-app 的源码——拿一条已知存在的
    // 生产代码行当锚点。
    let anchor = scan_lines(|line| line.contains("pub const WINDOW_TITLE"));
    assert!(
        anchor.iter().any(|h| h.starts_with("lib.rs:")),
        "扫描器没在 lib.rs 里找到 WINDOW_TITLE，它八成没走到 src/：{anchor:?}"
    );
}

/// 这一行里有没有原始字符串字面量的开头。
///
/// 判据是 Rust 词法本身：一个 `r`（或字节串的 `br`），**前面不是标识符
/// 字符**，后面跟零个或多个 `#`，再跟一个引号。
///
/// 「前面不是标识符字符」这一条不能省——省掉它，`"UnknownIssuer"` 的
/// `r"` 就是一处命中。第一版就是这么写的，一上来打出三处误判。
fn has_raw_string(line: &str) -> bool {
    let b = line.as_bytes();
    let is_ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    for i in 0..b.len() {
        if b[i] != b'r' {
            continue;
        }
        if i > 0 && is_ident(b[i - 1]) {
            // 唯一的例外：`br"..."`，此时真正的左边界在 `b` 之前。
            let byte_prefix = b[i - 1] == b'b' && (i < 2 || !is_ident(b[i - 2]));
            if !byte_prefix {
                continue;
            }
        }
        let mut j = i + 1;
        while j < b.len() && b[j] == b'#' {
            j += 1;
        }
        if j < b.len() && b[j] == b'"' {
            return true;
        }
    }
    false
}

/// `src/` 下满足 `pred` 的**非注释行**，形如 `diag.rs:123: <原文>`。
fn scan_lines(pred: impl Fn(&str) -> bool) -> Vec<String> {
    let root = rmc_app_src();
    let mut out = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("读 src 目录") {
            let path = entry.expect("读目录项").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let rel = path
                .strip_prefix(&root)
                .unwrap_or(&path)
                .display()
                .to_string();
            let text = std::fs::read_to_string(&path).expect("读源文件");
            for (i, line) in text.lines().enumerate() {
                let t = line.trim_start();
                // 注释里写一个原始字符串不会被编译器当成字面量，扫描器
                // 也不看注释——本文件的文档注释因此不会命中自己。
                if t.starts_with("//") {
                    continue;
                }
                if pred(t) {
                    out.push(format!("{rel}:{}: {t}", i + 1));
                }
            }
        }
    }
    out
}
