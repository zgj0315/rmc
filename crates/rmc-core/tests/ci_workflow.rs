//! 对 `.github/workflows/core.yml` 的纯解析测试，不起 docker、不碰
//! GitHub Actions。
//!
//! 写法与立意继承自一份 python 测试（`gateway/tests/test_ci_workflow.py`），
//! **那份文件连同整个 `gateway/` 目录已在 Task 13 删除**。它带过来的两条
//! 教训不再靠"去翻那个文件"传递，已经原地写在下面「定位 step 必须按 `name`
//! 精确匹配」与「守得住整个 step/job 被静默关掉」两节里。
//!
//! # Task 12 的改动
//!
//! 1. 辅助函数搬进了 `tests/workflow_yaml/`，跟守 `app.yml` 的
//!    `tests/app_workflow.rs` 共用。
//! 2. 新增 `dependency_audit_triggers_on_every_file_that_can_change_the_
//!    dependency_graph`：`deny` job 一直都在（W219 的「cargo deny 根本不在
//!    CI 里」不成立，订正见 task-12-report.md），但**它的触发条件原来没被
//!    钉住**——`Cargo.lock` 与 `deny.toml` 从 paths 过滤器里掉出去，
//!    依赖审计就会对一次 `cargo update` 视而不见。
//! 3. **`integration` job 连同守它的那 8 条断言一起删掉了**。它跑的是
//!    docker compose 起 sshd+haproxy、再在容器里执行 17 条 `#[ignore]`
//!    测试；Task 12 把网关换成一个自研二进制之后，那套夹具描述的世界
//!    已经不存在，17 条用例也随之删除（Task 10/13）。顶替它的位置的是
//!    `gateway-release` job（musl 静态二进制 + 产物上传），以及 `unit`
//!    job 里多出来的 `-p rmc-gateway`——15 条进程内端到端从此跑在每一次
//!    `cargo test` 里，不再需要任何人记得传 `--ignored`。
//!    `env_assignment_value()`/`major_minor()` 两个只服务于容器内工具链
//!    断言的辅助函数跟着删了，留着会被 `-D warnings` 判成 dead_code。
//!
//! Task 12 要还的债是"本仓库至今没有任何 CI 会构建 Rust"，这份工作流
//! 是还债的实物。但工作流本身是一份不会被 `cargo check` 校验的 YAML：
//! 路径过滤器漏写一个目录、`--ignored` 被删掉、`if: always()` 被误删、
//! 清理步骤被挪到测试步骤前面——这些回归都不会让 `cargo build` 报错，
//! 只会在下一次真的推到 GitHub 上时才现形，而且现形的方式往往是
//! "安静地不跑"，不是一次响亮的失败（旧那套 docker 夹具上的
//! `RMC_KEEP_ENV` 回归就是这种形状——那批测试已随 `gateway/` 一起删除，
//! 这里留下的是失败的**形状**，不是一个还能去翻的出处）。
//! 这份测试把工作流 YAML 解析成结构化数据，
//! 逐条钉住"改哪一行会让这份工作流退化成什么样"。
//!
//! 用 `yaml-rust2` 而不是手写一个只覆盖当前文件形状的迷你解析器：这份
//! 测试的价值全部来自"精确复现工作流实际会怎样执行"，一个自己写的、
//! 只认识当前缩进方式的解析器，它自己的 bug 会悄悄掩盖它本该盯住的
//! 工作流回归——见 `Cargo.toml` 里这条 dev-dependency 上的说明。
//!
//! # 定位 step 必须按 `name` 精确匹配，不能按关键字子串
//!
//! 这是从那份已删除的 python 测试继承来的第一条教训，原地记在这里：
//! 按关键字子串去找 step（"名字里带 test 的那个"）会在有人新增一个同样
//! 带该关键字的 step 时**悄悄挑错对象**，断言照样通过。所以
//! `step_by_name` 按 `name` 整串精确匹配，找不到、或撞上不止一个同名
//! step，都直接 `panic`，不返回哨兵值——静默的查找失败会让后面的断言
//! 在错误的 step 上稳定通过，等于没测。
//!
//! # 复审追加：守得住"某个 flag 被删掉"，也要守得住"整个 step/job 被
//! # 静默关掉"
//!
//! 第一版的断言全部停在"这个 step 的 `run`/`if`/`uses` 内容对不对"这
//! 一层——复审用探针实测过（当时 `integration` job 还在）：给它加
//! `continue-on-error: true`、给某个 step 加 `if: false`、给 `unit`
//! job 加 `if: false`、把单测命令悄悄收窄成 `--lib`、给单测命令接
//! `|| true`、把 `cargo-deny` 的检查范围收窄成只查 licenses——原来的
//! 断言一条都不红。`no_job_has_a_continue_on_error_or_a_top_level_
//! conditional`、`no_step_in_any_job_is_silently_disabled_with_if_
//! false`、`unit_test_step_runs_the_complete_test_suite_not_a_
//! narrowed_subset`、`cargo_deny_step_checks_all_four_categories_
//! not_a_narrowed_subset` 四条补上这一层。这是从那份已删除的 python
//! 测试继承来的第二条教训：它当年也只钉住了"步骤排序对不对"，
//! "把它整个关掉"这条路一直没堵——同一族退化。
//!
//! MSRV 的漂移是另一类没堵住的洞：`dtolnay/rust-toolchain` 那一步的
//! 版本号字面量不是 CI 实际用的编译器版本——`rust-toolchain.toml` 的
//! 目录级 override 优先级更高，而它原来不在 paths 过滤器里，改它不
//! 触发这份工作流。`unit_job_pins_the_toolchain_to_the_documented_msrv`
//! 与 `gateway_release_job_pins_the_toolchain_to_the_documented_msrv`
//! 现在直接读 `rust-toolchain.toml` 的 `channel` 字段做交叉校验，不是
//! 把同一个版本号分别硬编码在两处。

mod workflow_yaml;
use workflow_yaml::*;
use yaml_rust2::Yaml;

/// 这份测试守的是 `core.yml`。`app.yml` 由 `tests/app_workflow.rs` 守，
/// 两边共用 `tests/workflow_yaml/` 里的辅助（搬过去的理由见那份文件顶部）。
const WORKFLOW: &str = "core.yml";

fn doc() -> Yaml {
    load_workflow(WORKFLOW)
}

const UNIT_JOB: &str = "unit";
const GATEWAY_RELEASE_JOB: &str = "gateway-release";
const DENY_JOB: &str = "deny";

/// 本工作流里全部的 job。上面这三个常量之外再加一个 job 而不更新这张
/// 表，`workflow_file_parses_as_yaml_with_exactly_three_jobs` 会红；
/// 那些"对所有 job 扫一遍"的断言（`if: false`、`continue-on-error`、
/// step 有没有 name）也都遍历它，不会漏掉新 job。
const ALL_JOBS: [&str; 3] = [UNIT_JOB, GATEWAY_RELEASE_JOB, DENY_JOB];

const STEP_INSTALL_TOOLCHAIN: &str = "安装 Rust 工具链";
const STEP_FMT: &str = "格式检查";
const STEP_CLIPPY: &str = "clippy";
const STEP_UNIT_TESTS: &str = "单元与端到端测试";
const STEP_ENSURE_MUSL_TARGET: &str = "确保 musl target 装在 override 选中的工具链上";
const STEP_MUSL_TOOLS: &str = "安装 musl 工具链";
const STEP_MUSL_BUILD: &str = "构建 musl 静态二进制";
const STEP_STATIC_CHECK: &str = "确认是静态链接";
const STEP_UPLOAD_GATEWAY: &str = "上传运维服务器二进制";
const STEP_CARGO_DENY: &str = "cargo-deny";

/// `unit` job 的测试命令，一个字都不能多、不能少。见
/// `unit_test_step_runs_the_complete_test_suite_not_a_narrowed_subset`。
/// `-p rmc-gateway` 是那 15 条进程内端到端在 CI 里唯一的运行处。
const UNIT_TEST_COMMAND: &str = "cargo test -p rmc-core -p rmc-gateway";

/// 运维服务器的发布目标与产物名。下面三个常量必须说的是同一个三元组
/// （构建命令的 `--target`、静态性检查读的那个路径、上传的 `path`/`name`），
/// 否则会出现"构建了 A、检查了 B、上传了 C"这种各自为政、每一步单看都对、
/// 合起来毫无意义的退化——`gateway_release_job_builds_a_static_musl_binary_
/// and_uploads_it` 拿这三个常量把三步焊在一起。
///
/// （修复轮 1/5，复审 R12-5：这段注释上一版误挂在 `UNIT_TEST_COMMAND`
/// 头上，而下面这三个常量一条注释都没有。）
const MUSL_TARGET: &str = "x86_64-unknown-linux-musl";
/// 见 [`MUSL_TARGET`]。`--target` 决定了产物落在这个路径下。
const GATEWAY_BINARY: &str = "target/x86_64-unknown-linux-musl/release/rmc-gateway";
/// 见 [`MUSL_TARGET`]。下载发布产物的人按这个名字找它。
const GATEWAY_ARTIFACT: &str = "rmc-gateway-linux-x86_64";

#[test]
fn workflow_file_parses_as_yaml_with_exactly_three_jobs() {
    assert_eq!(
        job_names(&doc()),
        vec![
            DENY_JOB.to_string(),
            GATEWAY_RELEASE_JOB.to_string(),
            UNIT_JOB.to_string()
        ],
        "工作流应该正好三个 job：unit/gateway-release/deny"
    );
}

// 这条过滤器守的是「改了什么，这份工作流就必须跑一遍」。今天它必须覆盖
// 的是下面断言里那七条，每一条都对应一种"改了它、CI 却不跑"的静默失效：
//
// - `crates/**`：全部 Rust 源码与测试，包括 `crates/rmc-gateway/tests/
//   e2e.rs` 那 15 条进程内端到端。这是整份工作流当初要还的债的根——在它
//   之前，本仓库唯一的工作流是 `gateway.yml`，那份过滤器从来没覆盖过
//   `crates/**`，改 rmc-core 一个字都不会触发任何 CI；
// - `Cargo.toml` / `Cargo.lock` / `deny.toml`：依赖图与审计规则，见下面
//   `dependency_audit_triggers_on_every_file_that_can_change_the_
//   dependency_graph`；
// - `rust-toolchain.toml`：它决定 CI 实际用的编译器（目录级 override，
//   优先级比 `dtolnay/rust-toolchain` 那一步更高），漏了它，改工具链版本
//   不会触发任何验证，见 `unit_job_pins_the_toolchain_to_the_documented_msrv`；
// - `.github/workflows/core.yml` 自己，以及 `.github/workflows/app.yml`
//   （理由见 core.yml 顶部那段注释：守 app.yml 的那份测试跑在
//   `cargo test -p rmc-core` 里，也就是**这份**工作流里）。
//
// **`"gateway/**"` 在 Task 13 从这份列表里去掉了**：它当年在这里是为了让
// `integration` job 的 docker 夹具（docker-compose.yml、sshd_tunnel_config、
// haproxy.cfg）改动也能触发 CI。那个 job 在 Task 12 被整个删掉，`gateway/`
// 那个目录本身在 Task 13 被 `git rm -r` 删掉——**这条路径今天指向一个不存在的
// 目录**，留着只会让人以为仓库里还有那么一块东西。留下这段说明而不是无声删掉，
// 是因为"过滤器里少了一条"和"过滤器里多了一条死路径"是两种不同的问题，
// 后者读代码的人看不出来。
//
// **这条断言只管"少了一条"**：`assert_paths_filter_covers` 做的是包含
// 检查（它还要服务 `app_workflow.rs` 里一处只传一条路径的调用，所以不能
// 改成全等）。"多了一条指向不存在目录的死路径"——也就是 Task 13 刚从
// core.yml 里清掉的那种——它抓不到，由下面
// `paths_filter_has_no_entries_beyond_the_documented_seven` 那条全等断言
// 补上。两条合起来才是"不多不少正好这七条"。
//
// 会让这条测试变红的实现改法：把 `on.push.paths`/`on.pull_request.
// paths` 里的任意一条删掉，或者只写在 push 里、漏了 pull_request
// （反之亦然）——PR 上的检查和推到默认分支后的检查必须是同一套触发
// 条件，少了任何一侧都会让一部分改动逃过 CI。
#[test]
fn paths_filter_covers_the_directories_and_files_this_workflow_depends_on() {
    assert_paths_filter_covers(
        &doc(),
        WORKFLOW,
        &[
            "crates/**",
            // `"gateway/**"` 曾经在这里，Task 13 随 `gateway/` 目录一起删除，
            // 理由见上面那段注释。
            "Cargo.toml",
            "Cargo.lock",
            "deny.toml",
            "rust-toolchain.toml",
            ".github/workflows/core.yml",
            ".github/workflows/app.yml",
        ],
    );
}

/// 上面那条断言的另一半：paths 里**只**有那七条，一条都不多。
///
/// Task 13 新增。动机是这一轮真实发生过的事：`"gateway/**"` 在
/// `integration` job 被删（Task 12）之后又在过滤器里多活了一整轮，指向的
/// 目录到 Task 13 才真的消失。一条指向不存在目录的路径不会让任何东西变红
/// ——GitHub 不校验它，包含式断言也只问"该有的在不在"。它的害处不是让 CI
/// 少跑，而是让读这份过滤器的人以为仓库里还有那么一块东西。
///
/// 会让这条测试变红的实现改法：往 `core.yml` 的 `on.push.paths` 或
/// `on.pull_request.paths` 里加任意一条（比如把 `"gateway/**"` 加回去），
/// 或者把两侧写成不一样的两套。
#[test]
fn paths_filter_has_no_entries_beyond_the_documented_seven() {
    let doc = doc();
    let expected = [
        "crates/**",
        "Cargo.toml",
        "Cargo.lock",
        "deny.toml",
        "rust-toolchain.toml",
        ".github/workflows/core.yml",
        ".github/workflows/app.yml",
    ];
    for trigger in ["push", "pull_request"] {
        let paths = doc["on"][trigger]["paths"]
            .as_vec()
            .unwrap_or_else(|| panic!("{WORKFLOW} 的 on.{trigger}.paths 应该是一个序列"));
        let texts: Vec<&str> = paths.iter().filter_map(Yaml::as_str).collect();
        assert_eq!(
            texts, expected,
            "{WORKFLOW} 的 on.{trigger}.paths 必须不多不少正好这七条"
        );
    }
}

// Task 12 追加。**这条测试是对 W219 的订正的落地。**
//
// W219 的原话是「`cargo deny` 根本不在 CI 里……所有依赖审计的结论全部零
// 强制」。这是**不成立的**：`deny` job 从 12f1ff2 起就在这份工作流里，
// `deny_job_uses_the_cargo_deny_action` 与
// `cargo_deny_step_checks_all_four_categories_not_a_narrowed_subset`
// 两条测试一直钉着它。（那次 grep 大概是找字面的 `cargo deny` 命令，而这
// 一步是 `uses: EmbarkStudios/cargo-deny-action@v2`。）
//
// 但顺着那条怀疑真查出来一个**小一号、真实存在**的洞：上面那条 paths 断言
// 原来只要求三条路径（`crates/**`、`rust-toolchain.toml`，以及当时还在的
// `gateway/**`），**`Cargo.lock` 与 `deny.toml` 谁都没钉**。一次只动 `Cargo.lock` 的
// `cargo update`（引进一条新的 RUSTSEC 公告、或者一个新的许可证），在
// 「有人手滑把 `Cargo.lock` 从 paths 里删掉」之后就再也不会触发
// `deny` job——形状跟 W219 担心的一模一样，只是范围小得多。
// `deny.toml` 同理：放宽豁免的那次提交本身必须重新跑一遍审计。
//
// 这条测试把「依赖图能被什么文件改动」与「改这些文件会不会触发 deny job」
// 这两件事焊在一起。
//
// 会让这条测试变红的实现改法：把 `Cargo.lock`、`Cargo.toml`、`deny.toml`
// 或 `crates/**` 里的任意一条从 `on.push.paths` / `on.pull_request.paths`
// 删掉；或者删掉 `deny` job 本身。
#[test]
fn dependency_audit_triggers_on_every_file_that_can_change_the_dependency_graph() {
    let doc = doc();
    // 先正向确认审计这一步真的在——否则下面那组 paths 断言是在守一个不
    // 存在的 job，全绿也说明不了任何事。
    let step = step_by_name(steps(job(&doc, DENY_JOB)), STEP_CARGO_DENY);
    assert!(
        uses_text(step).is_some_and(|u| u.starts_with("EmbarkStudios/cargo-deny-action@")),
        "deny job 的 {STEP_CARGO_DENY} 步骤不见了，下面的 paths 断言就没有意义：{step:?}"
    );
    assert_paths_filter_covers(
        &doc,
        WORKFLOW,
        &["crates/**", "Cargo.toml", "Cargo.lock", "deny.toml"],
    );
}

// `-p rmc-gateway` 那一半是 Task 12 加的，而且是这条测试现在最要紧的
// 部分：rmc-gateway 在此之前**一次都没进过 CI 的 clippy**（原命令只点名
// rmc-core，只有 `cargo fmt --all` 覆盖全工作区）。只查 `cargo clippy` +
// `-D warnings` 挡不住"有人把 `-p rmc-gateway` 顺手删掉"——那会让整个
// crate 重新退回到零 lint 强制，而 CI 面板上仍然是绿的。
//
// 会让这条测试变红的实现改法：删掉 `-D warnings`、删掉 `-p rmc-core` 或
// `-p rmc-gateway` 中的任意一个、或者把这一步的 `run` 换成别的命令。
#[test]
fn unit_job_runs_clippy_with_deny_warnings_and_fmt_check() {
    let doc = doc();
    let steps = steps(job(&doc, UNIT_JOB));

    let fmt = run_code(step_by_name(steps, STEP_FMT));
    assert!(
        fmt.contains("cargo fmt") && fmt.contains("--check"),
        "格式检查步骤应该跑 cargo fmt --check，实际 {fmt:?}"
    );

    let clippy = run_code(step_by_name(steps, STEP_CLIPPY));
    assert!(
        clippy.contains("cargo clippy") && clippy.contains("-D warnings"),
        "clippy 步骤必须带 -D warnings，实际 {clippy:?}"
    );
    assert_eq!(
        clippy.trim(),
        "cargo clippy -p rmc-core -p rmc-gateway --all-targets -- -D warnings",
        "clippy 必须同时覆盖 rmc-core 与 rmc-gateway，一个都不能少，实际 {clippy:?}"
    );
}

// MSRV 的唯一权威来源是 `rust-toolchain.toml`（目录级 override，
// 优先级比 `dtolnay/rust-toolchain` 那一步做的 `rustup default` 更
// 高——`unit` job 的 cargo 命令实际用哪个编译器，由它说了算，不是由
// 这一步的版本号字面量说了算）；这条测试直接读那份文件，不是把 MSRV
// 这个数字在两处分别硬编码——硬编码两份、只在其中一份上加断言，防不住
// "改了 rust-toolchain.toml、忘了同步这一步"这类漂移（复审发现的
// 原始问题）。
//
// 会让这条测试变红的实现改法：把 `dtolnay/rust-toolchain@1.89` 改成
// 跟 `rust-toolchain.toml` 的 `channel` 不一致的任何版本号（包含改回
// brief 原文的 1.82），或者反过来只改 `rust-toolchain.toml` 的
// `channel`、不动这一步。
#[test]
fn unit_job_pins_the_toolchain_to_the_documented_msrv() {
    let doc = doc();
    let steps = steps(job(&doc, UNIT_JOB));
    let step = step_by_name(steps, STEP_INSTALL_TOOLCHAIN);
    let uses = uses_text(step).unwrap_or_else(|| panic!("{STEP_INSTALL_TOOLCHAIN} 没有 uses 字段"));
    let channel = toolchain_channel();
    assert_eq!(
        uses,
        format!("dtolnay/rust-toolchain@{channel}"),
        "工具链版本必须跟 rust-toolchain.toml 的 channel（{channel}）一致，实际 {uses:?}"
    );
}

// 这个 crate 已经被"失败路径报不出错、只会一直挂着"坑过不止一次——
// 单元测试步骤必须有一层外部 timeout，卡死时给出清楚的诊断，而不是
// 干等到 GitHub Actions 自己的 job 级超时（没有任何输出）。
//
// 会让这条测试变红的实现改法：把 `run` 里的 `timeout 600` 删掉，直接
// 裸跑 `cargo test -p rmc-core`。
#[test]
fn unit_test_step_has_an_inner_timeout_wrapper() {
    let doc = doc();
    let steps = steps(job(&doc, UNIT_JOB));
    let run = run_code(step_by_name(steps, STEP_UNIT_TESTS));
    assert!(
        run.trim_start().starts_with("timeout "),
        "单元测试步骤必须用 timeout 包一层，实际 {run:?}"
    );
    assert!(run.contains(UNIT_TEST_COMMAND), "{run:?}");
}

// 复审发现：只查 `contains("cargo test -p rmc-core")` 挡不住"悄悄
// 缩小范围"这类退化——把命令改成 `cargo test -p rmc-core --lib`
// （少跑一批集成测试，包含 connect.rs 那些代理用例）、或者在命令后面接
// `|| true`，`contains` 对这两种改法都仍然是 `true`。这条测试要求
// `timeout <N>` 之后的内容跟 [`UNIT_TEST_COMMAND`] 完全相等，不多不少。
//
// Task 12：`-p rmc-gateway` 进了这个常量。**它是那 15 条进程内端到端在
// CI 里唯一的运行处**——删掉它，`crates/rmc-gateway/tests/e2e.rs` 会
// 安静地一条都不跑，而 CI 面板照样全绿。这正是原来那个 `integration`
// job 的失效形态（17 条 `#[ignore]` 挂在一个没人触发的工作流后面），
// 这条断言就是不让它换个样子再来一次。
//
// 会让这条测试变红的实现改法：在命令后面追加任何内容（`--lib`、
// `--test e2e`、`-- --ignored`、`|| true` 等），在前面插入任何内容，
// 或者删掉 `-p rmc-core`/`-p rmc-gateway` 中的任意一个。
#[test]
fn unit_test_step_runs_the_complete_test_suite_not_a_narrowed_subset() {
    let doc = doc();
    let steps = steps(job(&doc, UNIT_JOB));
    let run = run_code(step_by_name(steps, STEP_UNIT_TESTS));
    let trimmed = run.trim();
    let after_timeout = trimmed
        .strip_prefix("timeout ")
        .unwrap_or_else(|| panic!("run 应该以 `timeout <秒数>` 开头：{trimmed:?}"));
    let after_seconds = after_timeout
        .trim_start_matches(|c: char| c.is_ascii_digit())
        .trim_start();
    assert_eq!(
        after_seconds, UNIT_TEST_COMMAND,
        "单元测试步骤必须是完整的 `{UNIT_TEST_COMMAND}`，不能带 --lib、\
         额外的 --test 过滤器，也不能接 || true 之类的尾巴，实际命令是 {trimmed:?}"
    );
}

// ---------------------------------------------------- gateway-release job

// `gateway-release` 顶替了被删掉的 `integration`。它要证的事情换了：不是
// "那套 docker 拼装还跑得起来"，而是"运维服务器这一个二进制真的能静态
// 链接出来、真的可以丢到任意一台 Linux 上跑"。
//
// 四件事必须说的是**同一个**三元组（target / 产物路径 / 产物名），
// 分开各自断言挡不住"构建了 A、检查了 B、上传了 C"这种每一步单看都对、
// 合起来毫无意义的退化——那正是这份文件通篇在防的形状。
//
// `file ... | grep` 那一条尤其不能省（2026-09-22 订正：匹配式现在是
// `-qE 'statically linked|static-pie linked'` 加一条 `! ... grep -q
// 'dynamically linked'` 的反向检查——原来只认 `statically linked`，
// 而真 musl-gcc 链出来的是 static-PIE，CI 上就是这么红的；本机
// cargo-zigbuild 链的又恰好是非 PIE，所以本地验不出来）：
// `--target x86_64-unknown-linux-musl` 构建成功**不等于**产物是静态的
// （任何一条走 build.rs 链了系统库的依赖都会让它退化成动态链接），而
// 那种退化不会让 `cargo build` 失败，只会在客户那台机器上表现成一句
// "No such file or directory"。
//
// 会让这条测试变红的实现改法：从构建命令里删掉 `--target
// x86_64-unknown-linux-musl`（产出就成了 glibc 动态链接的）；删掉
// "确认是静态链接"这一步，或者把里面的 `grep` 换成只 `file` 一下不判断、
// 把两种静态说法砍掉一种、删掉那条反向检查；把上传的 `path` 改成别的路径；改掉产物名；
// 或者删掉 `if-no-files-found: error`（二进制没产出时会上传一个空产物
// 并让这一步变绿）。
#[test]
fn gateway_release_job_builds_a_static_musl_binary_and_uploads_it() {
    let doc = doc();
    let steps = steps(job(&doc, GATEWAY_RELEASE_JOB));

    // 2026-09-22 第一次真跑这个 job 红在「target 没装上」。根因是
    // `rust-toolchain.toml` 的目录级 override 让 cargo 用的不是上一步设成
    // default 的那个工具链，而 rustup **按拼写**区分工具链（`1.89` 与
    // `1.89.0` 是两个 sysroot）。所以真正管用的是这一步显式的
    // `rustup target add`——它在仓库目录里跑，按 override 解析。
    //
    // 改红：把这一步从 `core.yml` 里删掉，或者把它的 `run` 换成别的命令。
    let ensure = run_code(step_by_name(steps, STEP_ENSURE_MUSL_TARGET));
    assert!(
        ensure.contains("rustup target add") && ensure.contains(MUSL_TARGET),
        "这一步必须显式把 musl target 装到 override 选中的工具链上，实际 {ensure:?}"
    );

    let musl = run_code(step_by_name(steps, STEP_MUSL_TOOLS));
    assert!(
        musl.contains("musl-tools"),
        "musl 目标需要 musl-gcc 当链接器，实际 {musl:?}"
    );

    let build = run_code(step_by_name(steps, STEP_MUSL_BUILD));
    assert!(
        build.contains("cargo build") && build.contains("--release"),
        "必须是 release 构建，实际 {build:?}"
    );
    assert!(
        build.contains("-p rmc-gateway"),
        "构建的必须是 rmc-gateway，实际 {build:?}"
    );
    assert!(
        build.contains(&format!("--target {MUSL_TARGET}")),
        "必须构建 musl 目标，否则产物是 glibc 动态链接的，实际 {build:?}"
    );

    let check = run_code(step_by_name(steps, STEP_STATIC_CHECK));
    assert!(
        check.contains(GATEWAY_BINARY),
        "静态性检查必须针对构建出来的那一个产物，实际 {check:?}"
    );
    assert!(
        check.contains("statically linked") && check.contains("static-pie linked"),
        "两种静态说法都要认：非 PIE 的产物 file 说 statically linked，\
         static-PIE 说 static-pie linked，实际 {check:?}"
    );
    assert!(
        check.contains("dynamically linked"),
        "还要有一条反向检查挡住真的动态链接，实际 {check:?}"
    );
    assert!(
        check.contains("grep -q"),
        "核对必须以非零退出让这一步失败，不能只打印一行 file 输出，实际 {check:?}"
    );
    assert!(
        !check.contains("|| true"),
        "这一步不能用 || true 吞掉失败，实际 {check:?}"
    );

    let upload = step_by_name(steps, STEP_UPLOAD_GATEWAY);
    assert!(
        uses_text(upload).is_some_and(|u| u.starts_with("actions/upload-artifact@")),
        "{upload:?}"
    );
    assert_eq!(upload["with"]["name"].as_str(), Some(GATEWAY_ARTIFACT));
    assert_eq!(upload["with"]["path"].as_str(), Some(GATEWAY_BINARY));
    assert_eq!(
        upload["with"]["if-no-files-found"].as_str(),
        Some("error"),
        "默认的 warn 会在二进制没产出时上传一个空产物并让这一步变绿"
    );
}

// 顺序：装工具链 → 装 musl-tools → 构建 → 核对静态性 → 上传。
//
// 会让这条测试变红的实现改法：把"确认是静态链接"挪到"构建 musl 静态
// 二进制"前面（对着还不存在的文件跑 `file`），把"上传"挪到"核对"前面
// （没核对过的产物就被发出去了），或者把"安装 musl 工具链"挪到构建
// 之后（`cargo build` 会因为找不到 musl-gcc 链接器失败）。
#[test]
fn gateway_release_steps_run_in_the_documented_order() {
    let doc = doc();
    let steps = steps(job(&doc, GATEWAY_RELEASE_JOB));
    let toolchain = step_index_by_name(steps, STEP_INSTALL_TOOLCHAIN);
    let ensure_target = step_index_by_name(steps, STEP_ENSURE_MUSL_TARGET);
    let musl = step_index_by_name(steps, STEP_MUSL_TOOLS);
    let build = step_index_by_name(steps, STEP_MUSL_BUILD);
    let check = step_index_by_name(steps, STEP_STATIC_CHECK);
    let upload = step_index_by_name(steps, STEP_UPLOAD_GATEWAY);
    assert!(toolchain < musl, "Rust 工具链要先装");
    assert!(
        toolchain < ensure_target,
        "要先有工具链，才谈得上往它上面加 target"
    );
    assert!(musl < build, "musl-gcc 必须在 cargo build 之前就位");
    assert!(
        ensure_target < build,
        "target 必须在 cargo build 之前装好——这一步就是 2026-09-22 那次红的修复"
    );
    assert!(build < check, "先构建才有东西可核对");
    assert!(check < upload, "核对过静态性才能上传");
}

// 这个 job 的编译器也得是声明的那个 MSRV——它跟 `unit` job 是两个独立的
// 漂移点（各自一条 `dtolnay/rust-toolchain@<版本>`）。同上一条测试的
// 做法：直接读 `rust-toolchain.toml` 的 `channel` 做交叉校验，不把同一个
// 版本号硬编码第三份。
//
// `targets:` 那个输入同样要钉，但**订正一句原来写错的话**：原文说「少了它
// `cargo build --target ...` 会失败」——2026-09-22 第一次真跑这个 job 证明
// 那不成立，**带着它照样失败**。真正管用的是 `STEP_ENSURE_MUSL_TARGET` 那一步
// 显式的 `rustup target add`（理由见那条断言上面的注释）。`targets:` 留着是
// 兜底（万一哪天 `rust-toolchain.toml` 没了，它就重新成为有效的那条路），
// 仍然钉住，防的是一次"看起来无关的清理"把它删掉。
//
// 会让这条测试变红的实现改法：把版本号改成跟 `rust-toolchain.toml` 的
// `channel` 不一致的任何值，或者删掉 `with.targets`。
#[test]
fn gateway_release_job_pins_the_toolchain_to_the_documented_msrv() {
    let doc = doc();
    let steps = steps(job(&doc, GATEWAY_RELEASE_JOB));
    let step = step_by_name(steps, STEP_INSTALL_TOOLCHAIN);
    let uses = uses_text(step).unwrap_or_else(|| panic!("{STEP_INSTALL_TOOLCHAIN} 没有 uses 字段"));
    let channel = toolchain_channel();
    assert_eq!(uses, format!("dtolnay/rust-toolchain@{channel}"));
    assert_eq!(
        step["with"]["targets"].as_str(),
        Some(MUSL_TARGET),
        "不装 musl 的 std，构建那一步会失败"
    );
}

// 会让这条测试变红的实现改法：把 deny job 换成别的 action，或者删掉
// 这个 job 本身（job 数量的断言见
// workflow_file_parses_as_yaml_with_exactly_three_jobs）。
#[test]
fn deny_job_uses_the_cargo_deny_action() {
    let doc = doc();
    let steps = steps(job(&doc, DENY_JOB));
    let step = step_by_name(steps, STEP_CARGO_DENY);
    let uses = uses_text(step).unwrap_or_else(|| panic!("{STEP_CARGO_DENY} 没有 uses 字段"));
    assert!(
        uses.starts_with("EmbarkStudios/cargo-deny-action@"),
        "{uses:?}"
    );
}

// 复审发现：`cargo-deny-action` 不带 `with:` 时，默认跑
// `cargo deny check`（advisories/bans/licenses/sources 全查）——这条
// 断言钉住"没人偷偷加一个 `with: command: check licenses` 之类的
// 输入把检查范围收窄掉"，四类检查缺一类都不该悄悄发生。
//
// 会让这条测试变红的实现改法：给这一步加 `with:`，不管是
// `command: check licenses` 这种直接窄化，还是任何其它收窄检查范围
// 的输入。
#[test]
fn cargo_deny_step_checks_all_four_categories_not_a_narrowed_subset() {
    let doc = doc();
    let steps = steps(job(&doc, DENY_JOB));
    let step = step_by_name(steps, STEP_CARGO_DENY);
    assert!(
        step["with"].is_badvalue(),
        "cargo-deny 步骤不该有 with 输入——留空才是跑完整的四类检查，实际 {step:?}"
    );
}

// 复审用六个探针实测过：给 `integration` job 加
// `continue-on-error: true`、给 `unit` job 加 `if: false`，
// `ci_workflow.rs` 原来的 15 条断言一条都不红——它们全部在 step 内容
// 层面盯 run/if/uses，没有一条管到"整个 job 被静默关掉"这件事本身。
//
// 会让这条测试变红的实现改法：给 unit/gateway-release/deny 任意一个 job
// 加上 `continue-on-error` 或 `if` 字段（哪怕值是 `true`——job 级
// `if` 本来就不该出现在这三个 job 上，它们该始终按 paths 过滤器的
// 结果无条件运行）。
#[test]
fn no_job_has_a_continue_on_error_or_a_top_level_conditional() {
    let doc = doc();
    for name in ALL_JOBS {
        let j = job(&doc, name);
        assert!(
            j["continue-on-error"].is_badvalue(),
            "job {name} 不该有 continue-on-error，否则失败也不会让整条工作流变红"
        );
        assert!(
            j["if"].is_badvalue(),
            "job {name} 不该有 job 级 if 条件，否则可能被静默跳过"
        );
    }
}

// 复审用探针实测过：给"运行 --ignored 集成测试"这一步加 `if: false`，
// 原来的断言一条都不红（`step_by_name` 还是能找到这一步、`run` 字段
// 内容还是老样子，只是这一步压根不会被执行）。`ignored_tests_step_
// really_runs_the_ignored_tests_and_can_fail_the_build` 只查过这一步
// 的 `continue-on-error`，没查过 `if`；这条测试对**所有** job 的
// **所有** step 都查一遍 `if: false`（不管是布尔字面量还是字符串
// 形式，见 `step_is_disabled` 上的说明），覆盖面比只查一条 step 更宽。
//
// 会让这条测试变红的实现改法：给任意一个 job 的任意一个 step 加上
// `if: false`。
#[test]
fn no_step_in_any_job_is_silently_disabled_with_if_false() {
    let doc = doc();
    for job_name in ALL_JOBS {
        for step in steps(job(&doc, job_name)) {
            let name = step["name"].as_str().unwrap_or("<unnamed>");
            assert!(
                !step_is_disabled(step),
                "job {job_name} 的 step {name:?} 带 if: false，会被静默跳过"
            );
        }
    }
}

// **修复轮 1/5，复审 R12-2，must-fix。**
//
// 上一版随那 9 条 `integration` 断言一起，把 core.yml 的 **step 级**
// `continue-on-error` 守卫也丢掉了（原来它只以一条
// `ignored_tests_step_really_runs_the_ignored_tests_and_can_fail_the_build`
// 里的单点检查存在，跟着那一步一起没了）。复审实测：给「单元与端到端
// 测试」这一步加一行 `continue-on-error: true`，`ci_workflow.rs` **16 条
// 一条不红**——也就是说新写的那 15 条端到端在 CI 里失败也不会让 job 变红。
// 「确认是静态链接」那一步同理：核不过也照样上传、照样绿。
//
// `no_job_has_a_continue_on_error_or_a_top_level_conditional` 守的是
// **job 级**那个同名字段，管不到 step 级——这是两个独立的字段、两个
// 独立的洞。`tests/app_workflow.rs` 早就对 app.yml 的每个 step 查了这一
// 条（它那段注释里记着同一次实测：加上它，14 条全绿），这里补齐。
//
// 这个洞的成本**是随时间涨的**：工作流的步骤只会越加越多。
//
// 改红（**两处都实测过**）：
//
// 1. 给 `unit` job 的「单元与端到端测试」加一行 `continue-on-error: true`：
//    ```text
//    test no_step_in_any_job_has_continue_on_error ... FAILED
//    job unit 的 step "单元与端到端测试" 带 continue-on-error：它失败了
//    job 还是绿的。这一步如果是跑测试或核对产物，等于把它整个关掉了
//    ```
// 2. 给 `gateway-release` job 的「确认是静态链接」加同一行：
//    ```text
//    job gateway-release 的 step "确认是静态链接" 带 continue-on-error：…
//    ```
//
// 两次都是 `16 passed; 1 failed`——也就是说这个洞**只**被这一条拦住，
// 原有的 16 条一条都不红。值是 `false` 也一样红：这里要求的是这个字段
// **根本不出现**，见下面的说明。
#[test]
fn no_step_in_any_job_has_continue_on_error() {
    let doc = doc();
    for job_name in ALL_JOBS {
        for step in steps(job(&doc, job_name)) {
            let name = step["name"].as_str().unwrap_or("<unnamed>");
            // 要求字段**不存在**，而不是"值不能是 true"：`continue-on-error`
            // 接受表达式（`${{ ... }}`），按值判真假会漏掉表达式写法，
            // 那正是 `step_is_disabled` 在 `if: ${{ false }}` 上栽过的同一
            // 个形状。今天这三个 job 的 step 一个都没有这个字段；将来真要
            // 加，来改这条断言的人必须显式想一遍「这一步失败了该不该让
            // 整条工作流变红」。
            assert!(
                step["continue-on-error"].is_badvalue(),
                "job {job_name} 的 step {name:?} 带 continue-on-error：\
                 它失败了 job 还是绿的。这一步如果是跑测试或核对产物，\
                 等于把它整个关掉了"
            );
        }
    }
}

// 每个 job 都该有自己的 timeout-minutes，不依赖 GitHub Actions 默认的
// 360 分钟——那个默认值对一个会被死锁坑过的 crate 来说太宽松，一旦真的
// 挂住会占着 runner 6 小时才被杀。
//
// 会让这条测试变红的实现改法：删掉某个 job 的 timeout-minutes 字段，
// 或者把它调得比这里的下限更大。
#[test]
fn every_job_has_a_bounded_timeout() {
    let doc = doc();
    for (name, at_most) in [(UNIT_JOB, 20), (GATEWAY_RELEASE_JOB, 20), (DENY_JOB, 10)] {
        let minutes = job(&doc, name)["timeout-minutes"]
            .as_i64()
            .unwrap_or_else(|| panic!("job {name} 没有 timeout-minutes"));
        assert!(
            minutes > 0 && minutes <= at_most,
            "job {name} 的 timeout-minutes 应该在 (0, {at_most}] 之间，实际 {minutes}"
        );
    }
}

// 每个 step 都该有 name：这份测试的其它用例全部靠精确的 name 定位
// step，一个漏了 name 的 step 会让上面那些查找悄悄绕过它。
#[test]
fn every_step_in_every_job_has_a_name() {
    let doc = doc();
    for job_name in ALL_JOBS {
        for (i, name) in step_names(job(&doc, job_name)).iter().enumerate() {
            assert!(name.is_some(), "job {job_name} 的第 {i} 个 step 没有 name");
        }
    }
}
