//! 对 `.github/workflows/core.yml` 的纯解析测试，不起 docker、不碰
//! GitHub Actions——写法与立意都照抄 `gateway/tests/test_ci_workflow.py`
//! （见该文件顶部模块文档，那边有一次真实踩坑的完整记录）。
//!
//! Task 12 要还的债是"本仓库至今没有任何 CI 会构建 Rust"，这份工作流
//! 是还债的实物。但工作流本身是一份不会被 `cargo check` 校验的 YAML：
//! 路径过滤器漏写一个目录、`--ignored` 被删掉、`if: always()` 被误删、
//! 清理步骤被挪到测试步骤前面——这些回归都不会让 `cargo build` 报错，
//! 只会在下一次真的推到 GitHub 上时才现形，而且现形的方式往往是
//! "安静地不跑"，不是一次响亮的失败（gateway 那条分支上的 `RMC_KEEP_
//! ENV` 回归就是这种形状）。这份测试把工作流 YAML 解析成结构化数据，
//! 逐条钉住"改哪一行会让这份工作流退化成什么样"。
//!
//! 用 `yaml-rust2` 而不是手写一个只覆盖当前文件形状的迷你解析器：这份
//! 测试的价值全部来自"精确复现工作流实际会怎样执行"，一个自己写的、
//! 只认识当前缩进方式的解析器，它自己的 bug 会悄悄掩盖它本该盯住的
//! 工作流回归——见 `Cargo.toml` 里这条 dev-dependency 上的说明。
//!
//! # 定位 step 必须按 `name` 精确匹配，不能按关键字子串
//!
//! 同 `test_ci_workflow.py` 踩过的坑（该文件模块文档"定位 step 必须按
//! name 精确匹配"一节）：`step_by_name` 找不到、或撞上不止一个同名
//! step，都直接 `panic`，不返回哨兵值——静默的查找失败会让后面的断言
//! 在错误的 step 上稳定通过，等于没测。
//!
//! # 复审追加：守得住"某个 flag 被删掉"，也要守得住"整个 step/job 被
//! # 静默关掉"
//!
//! 第一版的断言全部停在"这个 step 的 `run`/`if`/`uses` 内容对不对"这
//! 一层——复审用探针实测过：给 `integration` job 加
//! `continue-on-error: true`、给某个 step 加 `if: false`、给 `unit`
//! job 加 `if: false`、把单测命令悄悄收窄成 `--lib`、给单测命令接
//! `|| true`、把 `cargo-deny` 的检查范围收窄成只查 licenses——原来的
//! 断言一条都不红。`no_job_has_a_continue_on_error_or_a_top_level_
//! conditional`、`no_step_in_any_job_is_silently_disabled_with_if_
//! false`、`unit_test_step_runs_the_complete_test_suite_not_a_
//! narrowed_subset`、`cargo_deny_step_checks_all_four_categories_
//! not_a_narrowed_subset` 四条补上这一层——跟 gateway 那次踩的坑
//! （步骤排序对了，但"把它整个关掉"这条路没堵）是同一族退化。
//!
//! MSRV 的漂移是另一类没堵住的洞：`dtolnay/rust-toolchain` 那一步的
//! 版本号字面量不是 CI 实际用的编译器版本——`rust-toolchain.toml` 的
//! 目录级 override 优先级更高，而它原来不在 paths 过滤器里，改它不
//! 触发这份工作流。`unit_job_pins_the_toolchain_to_the_documented_
//! msrv`/`integration_job_container_toolchain_matches_the_documented_
//! msrv` 现在直接读 `rust-toolchain.toml` 的 `channel` 字段做交叉
//! 校验，不是把同一个版本号分别硬编码在两处。

use std::path::PathBuf;
use yaml_rust2::{Yaml, YamlLoader};

fn workflow_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/core.yml")
}

fn load_workflow() -> Yaml {
    let text = std::fs::read_to_string(workflow_path())
        .unwrap_or_else(|e| panic!("读取 {:?} 失败：{e}", workflow_path()));
    let docs = YamlLoader::load_from_str(&text).expect("core.yml 不是合法的 YAML");
    assert_eq!(docs.len(), 1, "工作流文件应该正好一个 YAML 文档");
    docs.into_iter().next().unwrap()
}

/// 按 job 名取整份 job 定义，找不到直接 panic（列出现有 job 名）。
fn job<'a>(doc: &'a Yaml, name: &str) -> &'a Yaml {
    let jobs = &doc["jobs"];
    let hash = jobs
        .as_hash()
        .unwrap_or_else(|| panic!("workflow 里没有 jobs 映射，或它不是一个 mapping"));
    let names: Vec<String> = hash
        .keys()
        .map(|k| k.as_str().unwrap_or("<non-string>").to_string())
        .collect();
    let found = &jobs[name];
    if found.is_badvalue() {
        panic!("没有名为 {name:?} 的 job；现有 job：{names:?}");
    }
    found
}

fn steps(job: &Yaml) -> &Vec<Yaml> {
    job["steps"]
        .as_vec()
        .unwrap_or_else(|| panic!("这个 job 没有 steps 序列"))
}

/// 按 step 的 `name` 字段精确定位，找不到（或撞了不止一个）就直接
/// panic——不能退回子串匹配，也不能返回 -1/0 之类的哨兵值。
fn step_index_by_name(steps: &[Yaml], name: &str) -> usize {
    let matches: Vec<usize> = steps
        .iter()
        .enumerate()
        .filter(|(_, s)| s["name"].as_str() == Some(name))
        .map(|(i, _)| i)
        .collect();
    match matches.as_slice() {
        [] => {
            let names: Vec<Option<&str>> = steps.iter().map(|s| s["name"].as_str()).collect();
            panic!("没有 name 精确等于 {name:?} 的 step；现有 step 名：{names:?}");
        }
        [i] => *i,
        many => panic!("有不止一个 step 的 name 都是 {name:?}：下标 {many:?}"),
    }
}

fn step_by_name<'a>(steps: &'a [Yaml], name: &str) -> &'a Yaml {
    &steps[step_index_by_name(steps, name)]
}

fn run_text(step: &Yaml) -> &str {
    step["run"].as_str().unwrap_or("")
}

/// `run_text` 去掉整行的 shell 注释之后的**代码**部分。
///
/// R96 实测踩到的坑：`等待测试环境就绪` 这一步第一版把"到点 exit 1 让
/// 这一步失败"这句说明写在 `run:` 脚本体内的 `#` 注释里，而
/// `readiness_gate_really_waits_for_the_services_and_fails_on_timeout`
/// 断言的是 `run.contains("exit 1")`——于是把代码里真正的 `exit 1` 换成
/// `echo '继续往下跑'` 之后，这条断言被那句注释满足，测试照样全绿。
/// 一条"守住超时会让 CI 失败"的断言，被自己要守的那段文字喂饱了。
///
/// 这份文件里别的步骤没有这个问题：它们的说明是写在 `run:` **外面**的
/// YAML 注释，压根不进 `run` 字符串（已逐条核对）。但这条防线不该依赖
/// "后人也记得把注释写在外面"，所以凡是断言"脚本里真的有某个东西"的
/// 地方一律走这个函数。
///
/// 只剥整行注释（`^\s*#`），不碰行尾注释——行尾注释在这份工作流里不
/// 存在，而要正确处理它就得分辨 `#` 是不是在引号里，那是一个真正的
/// 词法分析问题，不值得为了一个不存在的形状引进来。
fn run_code(step: &Yaml) -> String {
    run_text(step)
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

fn uses_text(step: &Yaml) -> Option<&str> {
    step["uses"].as_str()
}

/// `step["if"]` 在 YAML 里可能是字符串（`"failure()"`）也可能是没加
/// 引号的布尔字面量（`false`/`true` 会被解析成 `Yaml::Boolean`，不是
/// `Yaml::String`）——只查 `as_str()` 会让 `if: false` 这种写法完全
/// 从视野里消失（`as_str()` 对 `Boolean` 返回 `None`，看起来跟"这一步
/// 压根没有 if 字段"一样）。这个函数把两种写法都判成"这一步被静默
/// 关掉了吗"。
fn step_is_disabled(step: &Yaml) -> bool {
    match &step["if"] {
        Yaml::Boolean(b) => !*b,
        Yaml::String(s) => s.trim() == "false",
        _ => false,
    }
}

/// 从 `rust-toolchain.toml` 里读 `channel` 字段的值——这份文件的格式
/// 固定是三行的 `[toolchain]` 表，手写一个只找这一个字段的小函数比
/// 引入一个通用 TOML 解析器依赖更划算：跟本文件用 `yaml-rust2` 解析
/// `core.yml` 是两种不同的取舍——`core.yml` 的结构本身就是这份测试
/// 要盯住的对象（手写解析器的 bug 会掩盖它该盯住的回归，见模块文档），
/// 而这里只是读一个格式早就固定死的配置文件里的一个字段，不存在这层
/// 风险。
fn toolchain_channel() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rust-toolchain.toml");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("读取 {path:?} 失败：{e}"));
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("channel") {
            if let Some(value) = rest.trim_start().strip_prefix('=') {
                return value.trim().trim_matches('"').to_string();
            }
        }
    }
    panic!("{path:?} 里没找到 channel 字段");
}

/// 在一段 shell 脚本文本里找 `NAME=value` 这种环境变量赋值，取
/// `value`（到下一个空白字符或 `\` 续行符为止）。用于从 `docker run`
/// 命令里挖出 `-e RUSTUP_TOOLCHAIN=1.89.0` 这类参数的值。
fn env_assignment_value<'a>(shell_text: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("{name}=");
    let start = shell_text.find(&needle)? + needle.len();
    let rest = &shell_text[start..];
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '\\')
        .unwrap_or(rest.len());
    Some(&rest[..end])
}

/// 取字符串版本号的 `major.minor` 前缀（`"1.89.0"` -> `"1.89"`，
/// `"1.89"` -> `"1.89"`）——比较镜像标签/`RUSTUP_TOOLCHAIN` 的值跟
/// `rust-toolchain.toml` 的 `channel` 是不是同一个 MSRV 时，只关心
/// major.minor，不关心具体 patch 号（patch 号会随镜像更新而变，不是
/// 这里要盯住的漂移）。
fn major_minor(version: &str) -> String {
    let mut parts = version.split('.');
    let major = parts.next().unwrap_or("");
    let minor = parts.next().unwrap_or("");
    format!("{major}.{minor}")
}

const UNIT_JOB: &str = "unit";
const INTEGRATION_JOB: &str = "integration";
const DENY_JOB: &str = "deny";

const STEP_INSTALL_TOOLCHAIN: &str = "安装 Rust 工具链";
const STEP_FMT: &str = "格式检查";
const STEP_CLIPPY: &str = "clippy";
const STEP_UNIT_TESTS: &str = "单元与假隧道测试";
const STEP_COMPOSE_UP: &str = "拉起测试环境";
const STEP_WAIT_READY: &str = "等待测试环境就绪";
const STEP_HARNESS_CERT: &str = "生成 harness 证书";
const STEP_IGNORED_TESTS: &str = "运行 --ignored 集成测试";
const STEP_LOG_EXPORT: &str = "失败时导出容器日志";
const STEP_CLEANUP: &str = "清理测试环境";
const STEP_CARGO_DENY: &str = "cargo-deny";

#[test]
fn workflow_file_parses_as_yaml_with_exactly_three_jobs() {
    let doc = load_workflow();
    let hash = doc["jobs"].as_hash().expect("jobs 应该是一个 mapping");
    let mut names: Vec<String> = hash
        .keys()
        .map(|k| k.as_str().unwrap_or("<non-string>").to_string())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            DENY_JOB.to_string(),
            INTEGRATION_JOB.to_string(),
            UNIT_JOB.to_string()
        ],
        "工作流应该正好三个 job：unit/integration/deny"
    );
}

// 这是整个任务要还的债的根：`gateway.yml` 的 paths 过滤器从来没覆盖过
// `crates/**`，改 rmc-core 一个字都不会触发任何工作流。
//
// `gateway/**` 与 `rust-toolchain.toml` 是复审加的两条：`integration`
// job 的整套夹具（docker-compose.yml、sshd_tunnel_config 等）住在
// `gateway/test-env/` 与 `gateway/` 下，漏了这条路径，改夹具只会触发
// `gateway.yml`（不跑 cargo），17 条集成测试根本验证不到这处改动；
// `rust-toolchain.toml` 决定 CI 实际用的编译器（见下面
// `unit_job_pins_the_toolchain_to_the_documented_msrv`），漏了这条
// 路径，改工具链版本不会触发任何验证。
//
// 会让这条测试变红的实现改法：把 `on.push.paths`/`on.pull_request.
// paths` 里的任意一条删掉，或者只写在 push 里、漏了 pull_request
// （反之亦然）——PR 上的检查和推到默认分支后的检查必须是同一套触发
// 条件，少了任何一侧都会让一部分改动逃过 CI。
#[test]
fn paths_filter_covers_the_directories_and_files_this_workflow_depends_on() {
    let doc = load_workflow();
    for trigger in ["push", "pull_request"] {
        let paths = doc["on"][trigger]["paths"]
            .as_vec()
            .unwrap_or_else(|| panic!("on.{trigger}.paths 应该是一个序列"));
        let texts: Vec<&str> = paths.iter().filter_map(Yaml::as_str).collect();
        for required in ["crates/**", "gateway/**", "rust-toolchain.toml"] {
            assert!(
                texts.contains(&required),
                "on.{trigger}.paths 必须包含 {required:?}，实际 {texts:?}"
            );
        }
    }
}

// 会让这条测试变红的实现改法：删掉 `-D warnings`（clippy 又能悄悄放行
// 新告警了），或者把这一步的 `run` 换成别的命令。
#[test]
fn unit_job_runs_clippy_with_deny_warnings_and_fmt_check() {
    let doc = load_workflow();
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
    let doc = load_workflow();
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

// `integration` job 的 17 条 --ignored 测试跑在 `rust:<channel>`
// 镜像的一个临时容器里，不是走 `dtolnay/rust-toolchain`——它自己的
// MSRV 一致性要单独钉住，跟上一条测试是两个独立的漂移点。
//
// `RUSTUP_TOOLCHAIN` 那个环境变量存在的唯一理由是绕开 rust-toolchain.
// toml 的 `channel = "1.89"` 与镜像预装工具链名 `1.89.0-<triple>` 之间
// 因为少写一个 `.0` 而对不上号、导致每次都重新下载的问题（见该处注释
// 与 task-12-report.md）——它的 major.minor 必须跟 `channel` 一致，
// 否则这个环境变量本身就会指向一个镜像里不存在的工具链，`cargo test`
// 直接失败；镜像标签的 major.minor 也要跟 `channel` 一致，否则是在用
// 一个跟声明的 MSRV 不一样的编译器验证代码。
//
// 会让这条测试变红的实现改法：只改 `rust-toolchain.toml` 的
// `channel`，不同步改这一步的镜像标签或 `RUSTUP_TOOLCHAIN`（复审发现
// 的原始问题——今天两者都是 1.89 所以看不出来，但 CI 从不会因为这个
// 漂移而变红）。
#[test]
fn integration_job_container_toolchain_matches_the_documented_msrv() {
    let doc = load_workflow();
    let steps = steps(job(&doc, INTEGRATION_JOB));
    let run = run_code(step_by_name(steps, STEP_IGNORED_TESTS));
    let channel = toolchain_channel();

    assert!(
        run.contains(&format!("rust:{channel}")),
        "容器镜像标签必须跟 rust-toolchain.toml 的 channel（{channel}）一致，实际 run={run:?}"
    );

    let rustup_toolchain = env_assignment_value(&run, "RUSTUP_TOOLCHAIN")
        .unwrap_or_else(|| panic!("run 里没找到 RUSTUP_TOOLCHAIN= 这个环境变量赋值：{run:?}"));
    assert_eq!(
        major_minor(rustup_toolchain),
        channel,
        "RUSTUP_TOOLCHAIN（{rustup_toolchain}）的 major.minor 必须跟 channel（{channel}）一致"
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
    let doc = load_workflow();
    let steps = steps(job(&doc, UNIT_JOB));
    let run = run_code(step_by_name(steps, STEP_UNIT_TESTS));
    assert!(
        run.trim_start().starts_with("timeout "),
        "单元测试步骤必须用 timeout 包一层，实际 {run:?}"
    );
    assert!(run.contains("cargo test -p rmc-core"), "{run:?}");
}

// 复审发现：只查 `contains("cargo test -p rmc-core")` 挡不住"悄悄
// 缩小范围"这类退化——把命令改成 `cargo test -p rmc-core --lib`
// （少跑 35 条非 ignored 集成测试，包含 connect.rs 那 9 条代理用例）、
// 或者在命令后面接 `|| true`，`contains` 对这两种改法都仍然是
// `true`。这条测试要求 `timeout <N>` 之后的内容跟
// `"cargo test -p rmc-core"` 完全相等，不多不少。
//
// 会让这条测试变红的实现改法：在 `cargo test -p rmc-core` 后面追加
// 任何内容（`--lib`、`--test connect`、`-- --ignored`、`|| true` 等），
// 或者在前面插入任何内容。
#[test]
fn unit_test_step_runs_the_complete_test_suite_not_a_narrowed_subset() {
    let doc = load_workflow();
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
        after_seconds, "cargo test -p rmc-core",
        "单元测试步骤必须是完整的 `cargo test -p rmc-core`，不能带 --lib、\
         额外的 --test 过滤器，也不能接 || true 之类的尾巴，实际命令是 {trimmed:?}"
    );
}

// --build 不能省：早于某个提交的缓存镜像里还是有问题的旧证书（见
// fetch-harness-cert.sh 与 tests/transport.rs 顶部的说明）。
//
// 会让这条测试变红的实现改法：把 `docker compose up -d --build` 里的
// `--build` 删掉。
#[test]
fn compose_up_step_always_rebuilds_the_images() {
    let doc = load_workflow();
    let steps = steps(job(&doc, INTEGRATION_JOB));
    let run = run_code(step_by_name(steps, STEP_COMPOSE_UP));
    assert!(
        run.contains("docker compose up") && run.contains("--build"),
        "拉起测试环境必须带 --build，实际 {run:?}"
    );
}

// 四步顺序必须是：拉起环境 → 等就绪 → 生成证书 → 跑 --ignored 测试。
//
// 会让这条测试变红的实现改法：把"生成 harness 证书"挪到"拉起测试
// 环境"前面（容器还没起，`docker compose exec` 会对着不存在的服务
// 报错），或者把"运行 --ignored 集成测试"挪到"生成 harness 证书"
// 前面（读不到证书文件，两条需要真实 TLS 的用例会连不上/验不过），
// 或者把"等待测试环境就绪"挪到"拉起测试环境"前面 / "运行 --ignored
// 集成测试"后面（等的时机不对，等于没等）。
#[test]
fn integration_steps_run_in_the_documented_order() {
    let doc = load_workflow();
    let steps = steps(job(&doc, INTEGRATION_JOB));
    let compose_up = step_index_by_name(steps, STEP_COMPOSE_UP);
    let ready = step_index_by_name(steps, STEP_WAIT_READY);
    let cert = step_index_by_name(steps, STEP_HARNESS_CERT);
    let ignored = step_index_by_name(steps, STEP_IGNORED_TESTS);
    assert!(compose_up < ready, "等待就绪必须排在拉起测试环境之后");
    assert!(ready < cert, "等待就绪必须排在生成证书之前");
    assert!(cert < ignored, "生成证书必须排在运行 --ignored 测试之前");
}

// R96（最终复审发现，低）：`docker compose up -d` 只保证容器被创建并
// 启动，不保证里面的 haproxy/sshd 已经在监听——随后 17 条测试立刻就去
// 连 8443/2322。这一步原来根本不存在，靠的是容器里那句 `apt-get
// install openssh-client` 偶然多花的十几秒兜住；一个刚建起来、偶发变红
// 的 integration job，最危险的地方是下一个人会直接去把它关掉。
//
// 三件事各自钉住：
//
// 1. 等的是 8443（Gateway 的 TLS 前端，17 条里 15 条第一步要连的端口）
//    与 2322（一体机 sshd）。
// 2. 等法是"真的说上话"，不是裸 TCP connect——docker 的 userland proxy
//    在容器创建那一刻就把宿主端口绑好了，容器里的服务还没起来时它照样
//    accept 再立刻关掉，裸连接永远成功、等于没等（docker-compose.yml
//    里对 22001 的注释写的是同一件事）。所以必须看到真实 TLS 握手
//    （`openssl s_client`）与 SSH 版本横幅（`SSH-`）。
// 3. 等待有上限，且超时要让这一步**失败**（`exit 1`），不是打印一句
//    警告继续往下走——那样只会把"环境没起来"伪装成"测试自己连不上"。
//
// 三条断言全部走 `run_code`（剥掉脚本里的整行注释）而不是 `run_text`
// ——理由见 `run_code` 上的说明：这条测试的第一版栽在这里，把代码里的
// `exit 1` 换成 `echo` 之后，断言被脚本注释里那句"到点 exit 1 让这一步
// 失败"喂饱了，测试照样全绿。
//
// 会让这条测试变红的实现改法（四个探针，逐一实测过）：删掉这一步；把
// 探测换成裸的 `/dev/tcp/127.0.0.1/8443` 连通性判断（拿掉
// `openssl s_client`）；把超时分支的 `exit 1` 换成 `echo` 之后继续；
// 或者把 `until` 循环换成一句无上限的死等。
#[test]
fn readiness_gate_really_waits_for_the_services_and_fails_on_timeout() {
    let doc = load_workflow();
    let steps = steps(job(&doc, INTEGRATION_JOB));
    let step = step_by_name(steps, STEP_WAIT_READY);
    let run = run_code(step);

    for port in ["8443", "2322"] {
        assert!(
            run.contains(port),
            "就绪探测必须覆盖端口 {port}，实际 {run:?}"
        );
    }
    assert!(
        run.contains("openssl s_client"),
        "Gateway 侧必须做真实 TLS 握手，裸 TCP connect 会被 docker 的 \
         userland proxy 永远放行、等于没等，实际 {run:?}"
    );
    assert!(
        run.contains("SSH-"),
        "一体机侧必须读到 SSH 版本横幅才算就绪，实际 {run:?}"
    );
    assert!(
        run.contains("until "),
        "必须是轮询等待，不是一次性探测，实际 {run:?}"
    );
    assert!(
        run.contains("exit 1"),
        "等待超时必须让这一步失败，不能打印警告继续，实际 {run:?}"
    );
    assert!(
        !run.contains("|| true"),
        "这一步不能用 || true 吞掉失败，实际 {run:?}"
    );
    assert!(
        step["continue-on-error"].is_badvalue(),
        "这一步不能带 continue-on-error，否则等待失败也不会让 job 变红"
    );
}

// 这一步必须显式传 --ignored 并且以非零退出让构建失败——普通的
// `cargo test -p rmc-core` 对这 17 条只会报一行 "17 ignored"、以 0
// 退出收场，混在别的测试步骤里等于没跑；`--test-threads=1` 是必须的，
// 几条用例会真的把反向端口 22001 绑起来，并发跑会互相抢占；这一步也
// 不能带 `continue-on-error: true`，否则失败了也不会让 job 变红。
//
// 会让这条测试变红的实现改法：删掉 `-- --ignored`、删掉
// `--test-threads=1`、或者给这一步加上 `continue-on-error: true`
// （或者在 run 里把命令接上 `|| true`）。
#[test]
fn ignored_tests_step_really_runs_the_ignored_tests_and_can_fail_the_build() {
    let doc = load_workflow();
    let steps = steps(job(&doc, INTEGRATION_JOB));
    let step = step_by_name(steps, STEP_IGNORED_TESTS);
    let run = run_code(step);
    assert!(run.contains("-- --ignored"), "{run:?}");
    assert!(run.contains("--test-threads=1"), "{run:?}");
    assert!(!run.contains("|| true"), "{run:?}");
    assert!(
        step["continue-on-error"].is_badvalue(),
        "这一步不能带 continue-on-error，否则失败也不会让 job 变红"
    );
}

// 用容器内跑测试进程 + --network host + --add-host 绕开"gateway.test
// 需要能解析"这个前提，不需要 sudo、不需要改宿主的 /etc/hosts——见
// task-12-report.md 里对这个组合的本地验证。MSRV 一致性单独由
// `integration_job_container_toolchain_matches_the_documented_msrv`
// 盯住，这里不重复硬编码版本号。
//
// 会让这条测试变红的实现改法：把 `--network host` 或
// `--add-host gateway.test:127.0.0.1` 删掉（改回写宿主 /etc/hosts 之类
// 需要特权的步骤）。
#[test]
fn ignored_tests_run_inside_a_container_with_network_host_and_add_host() {
    let doc = load_workflow();
    let steps = steps(job(&doc, INTEGRATION_JOB));
    let run = run_code(step_by_name(steps, STEP_IGNORED_TESTS));
    assert!(run.contains("--network host"), "{run:?}");
    assert!(run.contains("--add-host gateway.test:127.0.0.1"), "{run:?}");
}

// 卡死时要有清楚的诊断，理由与 unit_test_step_has_an_inner_timeout_
// wrapper 相同。
//
// 会让这条测试变红的实现改法：把 run 里的 `timeout 1200` 删掉。
#[test]
fn ignored_tests_step_has_an_inner_timeout_wrapper() {
    let doc = load_workflow();
    let steps = steps(job(&doc, INTEGRATION_JOB));
    let run = run_code(step_by_name(steps, STEP_IGNORED_TESTS));
    assert!(
        run.contains("timeout 1200"),
        "运行 --ignored 集成测试必须用 timeout 包一层，实际 {run:?}"
    );
}

// 失败时导出容器日志：必须带 if: failure()，且真的在导出日志，且排在
// 跑测试的步骤之后（对着还没起来的环境导出不出任何东西）。
//
// 会让这条测试变红的实现改法：删掉 `if: failure()`（改成无条件执行，
// 或者干脆不设条件）、把 run 换成不含 "logs" 的命令、或者把这一步
// 挪到"运行 --ignored 集成测试"前面。
#[test]
fn log_export_step_runs_only_on_failure_after_the_tests() {
    let doc = load_workflow();
    let steps = steps(job(&doc, INTEGRATION_JOB));
    let idx = step_index_by_name(steps, STEP_LOG_EXPORT);
    let ignored_idx = step_index_by_name(steps, STEP_IGNORED_TESTS);
    assert_eq!(steps[idx]["if"].as_str(), Some("failure()"));
    assert!(run_code(&steps[idx]).contains("logs"), "{:?}", steps[idx]);
    assert!(idx > ignored_idx, "日志导出必须排在测试步骤之后");
}

// 清理步骤：必须带 if: always()，真的执行 docker compose down -v，且
// 排在所有测试相关步骤之后——提前清理会让"运行 --ignored 集成测试"
// 对着已经被拆掉的环境执行。
//
// 会让这条测试变红的实现改法：删掉 `if: always()`（环境会在失败时永远
// 留在 runner 上）、把 run 换成不含 "down -v" 的命令、或者把这一步挪到
// "运行 --ignored 集成测试"前面。
#[test]
fn cleanup_step_always_tears_down_after_every_test_related_step() {
    let doc = load_workflow();
    let steps = steps(job(&doc, INTEGRATION_JOB));
    let idx = step_index_by_name(steps, STEP_CLEANUP);
    assert_eq!(steps[idx]["if"].as_str(), Some("always()"));
    assert!(
        run_code(&steps[idx]).contains("down -v"),
        "{:?}",
        steps[idx]
    );
    for other in [
        STEP_COMPOSE_UP,
        STEP_WAIT_READY,
        STEP_HARNESS_CERT,
        STEP_IGNORED_TESTS,
        STEP_LOG_EXPORT,
    ] {
        let other_idx = step_index_by_name(steps, other);
        assert!(idx > other_idx, "清理步骤必须排在 {other:?} 之后");
    }
}

// 会让这条测试变红的实现改法：把 deny job 换成别的 action，或者删掉
// 这个 job 本身（job 数量的断言见
// workflow_file_parses_as_yaml_with_exactly_three_jobs）。
#[test]
fn deny_job_uses_the_cargo_deny_action() {
    let doc = load_workflow();
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
    let doc = load_workflow();
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
// 会让这条测试变红的实现改法：给 unit/integration/deny 任意一个 job
// 加上 `continue-on-error` 或 `if` 字段（哪怕值是 `true`——job 级
// `if` 本来就不该出现在这三个 job 上，它们该始终按 paths 过滤器的
// 结果无条件运行）。
#[test]
fn no_job_has_a_continue_on_error_or_a_top_level_conditional() {
    let doc = load_workflow();
    for name in [UNIT_JOB, INTEGRATION_JOB, DENY_JOB] {
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
    let doc = load_workflow();
    for job_name in [UNIT_JOB, INTEGRATION_JOB, DENY_JOB] {
        for step in steps(job(&doc, job_name)) {
            let name = step["name"].as_str().unwrap_or("<unnamed>");
            assert!(
                !step_is_disabled(step),
                "job {job_name} 的 step {name:?} 带 if: false，会被静默跳过"
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
    let doc = load_workflow();
    for (name, at_most) in [(UNIT_JOB, 20), (INTEGRATION_JOB, 30), (DENY_JOB, 10)] {
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
    let doc = load_workflow();
    for job_name in [UNIT_JOB, INTEGRATION_JOB, DENY_JOB] {
        for (i, step) in steps(job(&doc, job_name)).iter().enumerate() {
            assert!(
                step["name"].as_str().is_some(),
                "job {job_name} 的第 {i} 个 step 没有 name"
            );
        }
    }
}
