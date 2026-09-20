//! 需求硬禁令的词表，以及守它的扫描。
//!
//! W125：「界面上叫运维服务器，不叫 Gateway/网关」这条硬禁令**在源头就被
//! 违反了**——`error.rs` 有三条 `#[error]` 文案、`preflight.rs` 有两个步骤
//! 名、`config.rs` 与 `transport/tls.rs` 各有一处 `Error::Config`、
//! `supervisor.rs` 有两行审计日志，一共八处写着 Gateway。它们全都会上屏：
//! `supervisor.rs` 把 `Error::to_string()` 原样塞进
//! `State::Failed { message }` → `rmc_app::model::Model::status_card()`
//! 的副标题 → 状态卡；预检步骤名是诊断页（Task 9）的行首文字；审计日志是
//! 日志页（Task 11）的正文。
//!
//! 而界面侧 Task 6 立的那道「控件树全树扫描」抓不到任何一条：它扫的是
//! **当前渲染出来的那棵树**，这些字符串只在特定状态下才出现。所以扫描必须
//! 往下搬一层，搬到字符串出生的地方。
//!
//! # 这个文件本身是扫描的盲区，这是故意的
//!
//! [`BANNED_WORDS`] 的四个元素就是四个禁用词，扫到自己身上必然报警。
//! [`production_string_literals`] 因此按文件名整个跳过 `wording.rs`——
//! 把词表单独拿出来住一个文件，就是为了让这个例外能按文件名写死，而不是
//! 写成"跳过某一行"那种会被 rustfmt 换行冲掉的规则。**代价**：往这个
//! 文件里加用户可见文案不会被扫到。这个文件里不该有用户可见文案。

/// 需求硬禁令的词表：产品里叫「运维服务器」，不叫 Gateway/网关。
///
/// **为什么这份词表住在 rmc-core，而不是界面 crate**（W125）：违反发生在
/// 源头。`supervisor.rs` 把 `Error::to_string()` 原样塞进
/// `State::Failed { message }`，界面把 `message` 当状态卡副标题画出来；
/// `preflight::ALL_STEPS` 的四个步骤名是诊断页直接画的行首文字。也就是
/// 说 **rmc-core 的用户可见字符串就是界面文案的一部分**，词表必须能被
/// rmc-core 自己的测试看见。
///
/// 界面侧的 `rmc_app::BANNED_WORDS` 原样 re-export 这一份——四处防线
/// （rmc-core 源码扫描、rmc-core 错误文案扫描、`App::view` 控件树扫描、
/// 操作系统窗口标题）共用同一个字面量，分叉了迟早有一份漏掉新加的词。
pub const BANNED_WORDS: [&str; 4] = ["Gateway", "gateway", "GATEWAY", "网关"];

/// 文本里第一个命中的禁用词。
///
/// 刻意做成返回 `Option<&str>`（命中才是 `Some`）而不是返回 `bool`：
/// 调用方一律写成「断言结果是 `None`」，失败信息里自带是哪个词、哪句话。
pub fn banned_word_in(text: &str) -> Option<&'static str> {
    BANNED_WORDS.into_iter().find(|w| text.contains(w))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::preflight::ALL_STEPS;

    /// `Error` 的变体数。见 [`variant_index`]。
    const ERROR_VARIANTS: usize = 14;

    /// 每个 `Error` 变体一个槽位。**穷尽 match**——往 `Error` 加变体时
    /// 这里直接编译不过；补上一个 `=> 14` 的分支又会让下面
    /// `[false; ERROR_VARIANTS]` 越界。两道闸都逼着把新变体填进
    /// [`error_corpus`]，新文案因此不可能绕开禁用词扫描。
    fn variant_index(e: &Error) -> usize {
        match e {
            Error::HostKeyMismatch { .. } => 0,
            Error::TlsInvalidCert(_) => 1,
            Error::ProxyAuthFailed(_) => 2,
            Error::AuthRejected => 3,
            Error::ForwardPortBusy(_) => 4,
            Error::Dns(_) => 5,
            Error::Tcp(_) => 6,
            Error::TlsHandshake(_) => 7,
            Error::KeepaliveTimeout => 8,
            Error::SshTransport(_) => 9,
            Error::ApplianceUnreachable(_) => 10,
            Error::Config(_) => 11,
            Error::Io(_) => 12,
            Error::LocalIo(_) => 13,
        }
    }

    /// 每个变体一个代表值。占位文本刻意用不含任何禁用词的字符串——
    /// 扫描要抓的是 `#[error("...")]` 里的固定文案，不是调用方塞进来的细节。
    fn error_corpus() -> Vec<Error> {
        vec![
            Error::HostKeyMismatch {
                expected: "SHA256:aaa".into(),
                actual: "SHA256:bbb".into(),
            },
            Error::TlsInvalidCert("unknown issuer".into()),
            Error::ProxyAuthFailed("Negotiate".into()),
            Error::AuthRejected,
            Error::ForwardPortBusy(22001),
            Error::Dns("no such host".into()),
            Error::Tcp("connection refused".into()),
            Error::TlsHandshake("reset by peer".into()),
            Error::KeepaliveTimeout,
            Error::SshTransport("channel closed".into()),
            Error::ApplianceUnreachable("connection refused".into()),
            Error::Config("port must be in 22000-22999".into()),
            Error::Io(std::io::Error::other("connection reset")),
            Error::LocalIo(std::io::Error::other("permission denied")),
        ]
    }

    #[test]
    fn error_corpus_covers_every_variant_exactly_once() {
        let corpus = error_corpus();
        assert_eq!(
            corpus.len(),
            ERROR_VARIANTS,
            "语料条数对不上变体数——别拿同一个变体填两遍糊过穷尽性检查"
        );
        let mut seen = [false; ERROR_VARIANTS];
        for e in &corpus {
            let i = variant_index(e);
            assert!(!seen[i], "第 {i} 个变体在语料里出现了两次：{e}");
            seen[i] = true;
        }
        for (i, hit) in seen.iter().enumerate() {
            assert!(*hit, "第 {i} 个变体没进语料，它的文案没有任何东西扫得到");
        }
    }

    /// W125 的主防线：`Error` 的 Display 会原样进
    /// `State::Failed { message }`，再原样成为状态卡副标题。
    #[test]
    fn no_error_variant_says_gateway() {
        for e in error_corpus() {
            let text = e.to_string();
            assert!(
                !text.is_empty(),
                "{:?} 的 Display 是空串，下面那条断言会空转",
                variant_index(&e)
            );
            assert_eq!(
                banned_word_in(&text),
                None,
                "错误文案会原样画成状态卡副标题，不许出现禁用词：{text}"
            );
        }
    }

    /// 预检步骤名是诊断页直接画的行首文字。
    #[test]
    fn no_preflight_step_name_says_gateway() {
        assert_eq!(ALL_STEPS.len(), 4, "步骤数变了，先确认表是完整的");
        for name in ALL_STEPS {
            assert!(!name.is_empty(), "步骤名是空串，下面那条断言会空转");
            assert_eq!(
                banned_word_in(name),
                None,
                "预检步骤名会直接画在诊断页上，不许出现禁用词：{name}"
            );
        }
    }

    /// 把 `\` 续行接成一条逻辑行，返回 `(首行行号, 逻辑行)`。
    ///
    /// **这是评审抓到的一个静默盲区的修补。** 原先是逐物理行切词，
    /// 于是跨行字面量
    ///
    /// ```text
    /// format!(
    ///     "第一段 \
    ///      第二段"
    /// )
    /// ```
    ///
    /// 的第一行那个 `"` 永远等不到闭合，**整条字面量被丢掉、一声不响**。
    /// 这不是假想：rmc-core 的生产代码已经在用这种写法写用户可见文案
    /// （`knownhosts.rs` 的 `corrupt(format!(..))` 经 `Error` 进
    /// `State::Failed{message}` 上屏，`supervisor.rs` 的审计行经 Task 11
    /// 的日志页上屏）。评审实测：把禁用词埋进那样一条续行里，**八条防线
    /// 一条都没响**。
    ///
    /// 接法跟 Rust 自己一致：吃掉换行与下一行的前导空白。
    fn join_continuations(text: &str) -> Vec<(usize, String)> {
        let mut out: Vec<(usize, String)> = Vec::new();
        let mut pending: Option<(usize, String)> = None;
        for (i, line) in text.lines().enumerate() {
            let continues = line.trim_end().ends_with('\\');
            let piece = line.trim_end().trim_end_matches('\\');
            match pending.as_mut() {
                // 已经在接续中：吃掉前导空白再拼上去。
                Some((_, buf)) => buf.push_str(piece.trim_start()),
                None => pending = Some((i + 1, piece.to_string())),
            }
            if !continues {
                out.push(pending.take().expect("刚刚填过"));
            }
        }
        if let Some(last) = pending {
            out.push(last);
        }
        out
    }

    /// 把一行 Rust 源码里的双引号字符串字面量切出来。
    ///
    /// 只够用于本 crate 的源码形态：处理 `\"` 转义，不处理 `r#"..."#`。
    /// **跨行字面量不在这里处理**——调用方先用 [`join_continuations`]
    /// 把 `\` 续行接成一条逻辑行再喂进来。
    fn string_literals_in(line: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = String::new();
        let mut in_str = false;
        let mut escaped = false;
        for ch in line.chars() {
            if in_str {
                if escaped {
                    escaped = false;
                    cur.push(ch);
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    in_str = false;
                    out.push(std::mem::take(&mut cur));
                } else {
                    cur.push(ch);
                }
            } else if ch == '"' {
                in_str = true;
            }
        }
        out
    }

    /// 剥掉 `format!` 的 `{...}` 占位符——占位符里是变量名，渲染出来是
    /// 变量的值，那个名字本身不上屏。
    fn strip_placeholders(lit: &str) -> String {
        let mut out = String::new();
        let mut depth = 0usize;
        for ch in lit.chars() {
            match ch {
                '{' => depth += 1,
                '}' => depth = depth.saturating_sub(1),
                _ if depth == 0 => out.push(ch),
                _ => {}
            }
        }
        out
    }

    /// 明确豁免的字面量：`(文件名, 字面量, 理由)`。
    ///
    /// 只有一条，而且它**确实会上屏**——所以写在这里而不是悄悄放过：
    /// `gateway.company.com` 是方案设计.md §3.10 界面示意图里原样给出的
    /// 地址框占位值（`地址 [ gateway.company.com ] : [ 443 ]`），是一个
    /// 域名、不是对这台机器的称呼。改它等于改方案文档里的示意图，超出
    /// 本任务范围；已记进 task-7-report.md 的「后续完善」交给产品定夺。
    const ALLOWED: [(&str, &str, &str); 1] = [(
        "config.rs",
        "gateway.company.com",
        "方案设计.md §3.10 的地址框占位域名，是数据不是称呼",
    )];

    /// 扫 rmc-core **生产代码**里的全部字符串字面量。
    ///
    /// 返回 `(文件名, 行号, 字面量)`。两条截断规则，都写明代价：
    ///
    /// - 每个文件扫到第一行 `mod tests {` 为止。本 crate 的约定是测试一律
    ///   放在同一文件末尾的 `#[cfg(test)] mod tests`（见 `audit.rs` 模块
    ///   文档第 4 条），所以这一刀切掉的正好是测试。**代价**：写在
    ///   `mod tests` 之后的生产代码扫不到——本 crate 没有这种写法。
    /// - 整个跳过 `wording.rs`（词表自己的家）与 `ssh/test_support.rs`
    ///   （进程内假服务端，全文件是测试脚手架，里面的那个词是给开发者
    ///   看的，不上屏）。
    ///
    /// 三条跳过规则，都写明代价：
    ///
    /// - 行首是 `//` 的整行跳过（注释、文档注释里的说明不上屏）。
    /// - 行首是 `.field(` 的整行跳过：那是手写 `Debug` 的字段名
    ///   （`state.rs`/`tunnel.rs` 给 `Command::Start`/`TunnelParams` 各写了
    ///   一份），`Debug` 输出进日志与调试器，从不上屏。**代价**：把一句
    ///   用户可见文案写在一行 `.field(` 里就扫不到——没有理由那样写。
    /// - `{...}` 格式占位符在匹配前被剥掉：`format!("连接 {gateway} 超时")`
    ///   渲染出来是地址，不是 "gateway" 这个词。留着它会把变量名误判成
    ///   文案，而给变量改名只是为了骗过扫描器，不会让界面变好。
    fn production_string_literals() -> Vec<(String, usize, String)> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
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
                // `wording.rs` 是词表自己的家（见模块文档），
                // `test_support.rs` 是进程内假服务端的测试脚手架。
                let base = path.file_name().and_then(|f| f.to_str()).unwrap_or("");
                if base == "wording.rs" || base == "test_support.rs" {
                    continue;
                }
                let name = path
                    .strip_prefix(&root)
                    .unwrap_or(&path)
                    .display()
                    .to_string();
                let text = std::fs::read_to_string(&path).expect("读源文件");
                for (i, line) in join_continuations(&text) {
                    let trimmed = line.trim_start();
                    if trimmed.starts_with("mod tests {") {
                        break;
                    }
                    if trimmed.starts_with("//") || trimmed.starts_with(".field(") {
                        continue;
                    }
                    for lit in string_literals_in(&line) {
                        out.push((name.clone(), i, lit));
                    }
                }
            }
        }
        out
    }

    /// 反向自证：扫描器与匹配器本身真的会对违规文本发火。
    ///
    /// 少了这条，下面 `no_production_string_literal_says_gateway` 在
    /// 「切词切错了、一条字面量都没切出来」时就是永远为真的空转。
    #[test]
    fn the_scanner_itself_catches_a_planted_violation() {
        let line = r#"    #[error("Gateway TLS 证书链无效：{0}")]"#;
        let lits = string_literals_in(line);
        assert_eq!(lits.len(), 1, "切词切错了：{lits:?}");
        assert_eq!(banned_word_in(&lits[0]), Some("Gateway"));

        // 中文那条也要能抓到——它跟 ASCII 那三条走的是同一个 `contains`，
        // 但真出过「只测了英文」的漏。
        assert_eq!(banned_word_in("经网关转发"), Some("网关"));
        assert_eq!(banned_word_in("运维服务器 TLS"), None);

        // 剥占位符这一步也要自证：把 `strip_placeholders` 改成恒返回空串，
        // 扫描器就永远抓不到任何东西而 `no_production_string_literal_says_gateway`
        // 照样全绿——这正是这个项目抓过 20 次的形状。
        assert_eq!(strip_placeholders("连接 {gateway} 超时"), "连接  超时");
        assert_eq!(
            strip_placeholders("运维服务器 {0} 证书链无效"),
            "运维服务器  证书链无效"
        );
        assert_eq!(
            strip_placeholders("经网关转发"),
            "经网关转发",
            "正文不许被剥掉"
        );
        assert_eq!(
            banned_word_in(&strip_placeholders("连接 {gateway} 超时")),
            None
        );

        // 转义引号不该把一条字面量切成两条。
        assert_eq!(
            string_literals_in(r#"let s = "他说\"好\"了";"#),
            vec![r#"他说"好"了"#.to_string()]
        );
    }

    /// W125 的第二道防线：`Error::Config(format!("..."))` 这类**在构造点
    /// 拼文案**的写法，上面那条按变体走 Display 的扫描抓不到（文案不在
    /// `#[error]` 里，在调用方手上）。实测抓到的两处就是这个形状：
    /// `config.rs` 的地址校验与 `transport/tls.rs` 的 SNI 校验。
    /// 审计日志的 `format!` 同理（日志页 Task 11 要显示它们）。
    #[test]
    fn no_production_string_literal_says_gateway() {
        let lits = production_string_literals();

        // 反向自证之一：扫描器真的走到了文件、真的切出了字面量。
        // 实测这一版是 176 条；下限取 100，既够抓住"扫描器整个瞎了"
        // （返回 0 条或只扫到一个文件），又不会因为正常增删文案而误报。
        assert!(
            lits.len() > 100,
            "只切出 {} 条字面量，扫描器八成没走到源码，下面的断言会空转",
            lits.len()
        );
        // 反向自证之二：一条已知的生产文案必须在结果里。它在 `error.rs`
        // 的 `#[error]` 里，路径、截断规则、切词三件事同时成立才找得到。
        assert!(
            lits.iter().any(|(_, _, s)| s == "账号或口令不正确"),
            "扫描结果里找不到一条已知的生产文案，截断规则或切词坏了"
        );

        let hits: Vec<String> = lits
            .iter()
            .filter(|(f, _, s)| !ALLOWED.iter().any(|(af, al, _)| af == f && al == s))
            .filter_map(|(f, n, s)| {
                banned_word_in(&strip_placeholders(s))
                    .map(|w| format!("{f}:{n} 的「{s}」里含有 {w}"))
            })
            .collect();
        assert!(
            hits.is_empty(),
            "rmc-core 的生产代码字符串里出现了需求禁用的词（它们会经\n\
             State::Failed / 预检步骤名 / 审计日志上屏）：\n{}",
            hits.join("\n")
        );
    }

    /// 豁免表不许有过期条目：某条被豁免的字面量一旦从源码里消失（或被
    /// 改掉），这条测试会红，逼着把豁免一起删掉。否则豁免表会越攒越长，
    /// 最后把扫描器掏空。
    #[test]
    fn every_allowlist_entry_is_still_there_and_still_needs_the_exemption() {
        let lits = production_string_literals();
        for (file, lit, why) in ALLOWED {
            assert!(
                banned_word_in(lit).is_some(),
                "{file} 的「{lit}」已经不含禁用词了，这条豁免没有存在的理由（{why}）"
            );
            assert!(
                lits.iter().any(|(f, _, s)| f == file && s == lit),
                "豁免表里的 {file} 「{lit}」在源码里找不到了，删掉这条豁免"
            );
        }
    }
}
