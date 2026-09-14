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

fn uses_text(step: &Yaml) -> Option<&str> {
    step["uses"].as_str()
}

const UNIT_JOB: &str = "unit";
const INTEGRATION_JOB: &str = "integration";
const DENY_JOB: &str = "deny";

const STEP_INSTALL_TOOLCHAIN: &str = "安装 Rust 工具链";
const STEP_FMT: &str = "格式检查";
const STEP_CLIPPY: &str = "clippy";
const STEP_UNIT_TESTS: &str = "单元与假隧道测试";
const STEP_COMPOSE_UP: &str = "拉起测试环境";
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
// 会让这条测试变红的实现改法：把 `on.push.paths`/`on.pull_request.
// paths` 里的 `"crates/**"` 删掉，或者只写在 push 里、漏了
// pull_request（反之亦然）——PR 上的检查和推到默认分支后的检查必须
// 是同一套触发条件，少了任何一侧都会让一部分改动逃过 CI。
#[test]
fn paths_filter_covers_crates_dir_on_both_push_and_pull_request() {
    let doc = load_workflow();
    for trigger in ["push", "pull_request"] {
        let paths = doc["on"][trigger]["paths"]
            .as_vec()
            .unwrap_or_else(|| panic!("on.{trigger}.paths 应该是一个序列"));
        let texts: Vec<&str> = paths.iter().filter_map(Yaml::as_str).collect();
        assert!(
            texts.contains(&"crates/**"),
            "on.{trigger}.paths 必须包含 \"crates/**\"，实际 {texts:?}"
        );
    }
}

// 会让这条测试变红的实现改法：删掉 `-D warnings`（clippy 又能悄悄放行
// 新告警了），或者把这一步的 `run` 换成别的命令。
#[test]
fn unit_job_runs_clippy_with_deny_warnings_and_fmt_check() {
    let doc = load_workflow();
    let steps = steps(job(&doc, UNIT_JOB));

    let fmt = run_text(step_by_name(steps, STEP_FMT));
    assert!(
        fmt.contains("cargo fmt") && fmt.contains("--check"),
        "格式检查步骤应该跑 cargo fmt --check，实际 {fmt:?}"
    );

    let clippy = run_text(step_by_name(steps, STEP_CLIPPY));
    assert!(
        clippy.contains("cargo clippy") && clippy.contains("-D warnings"),
        "clippy 步骤必须带 -D warnings，实际 {clippy:?}"
    );
}

// MSRV 是 1.89（workspace Cargo.toml 与 rust-toolchain.toml 都这么写）；
// brief 原始草稿钉的是 1.82，比 MSRV 还低，工具链版本必须跟 MSRV 对齐，
// 不能比它更旧。
//
// 会让这条测试变红的实现改法：把 `dtolnay/rust-toolchain@1.89` 改成
// 任何其他版本号（包含改回 brief 原文的 1.82）。
#[test]
fn unit_job_pins_the_toolchain_to_the_documented_msrv() {
    let doc = load_workflow();
    let steps = steps(job(&doc, UNIT_JOB));
    let step = step_by_name(steps, STEP_INSTALL_TOOLCHAIN);
    let uses = uses_text(step).unwrap_or_else(|| panic!("{STEP_INSTALL_TOOLCHAIN} 没有 uses 字段"));
    assert_eq!(
        uses, "dtolnay/rust-toolchain@1.89",
        "工具链版本必须钉在 1.89（MSRV），实际 {uses:?}"
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
    let run = run_text(step_by_name(steps, STEP_UNIT_TESTS));
    assert!(
        run.trim_start().starts_with("timeout "),
        "单元测试步骤必须用 timeout 包一层，实际 {run:?}"
    );
    assert!(run.contains("cargo test -p rmc-core"), "{run:?}");
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
    let run = run_text(step_by_name(steps, STEP_COMPOSE_UP));
    assert!(
        run.contains("docker compose up") && run.contains("--build"),
        "拉起测试环境必须带 --build，实际 {run:?}"
    );
}

// 三步顺序必须是：拉起环境 → 生成证书 → 跑 --ignored 测试。
//
// 会让这条测试变红的实现改法：把"生成 harness 证书"挪到"拉起测试
// 环境"前面（容器还没起，`docker compose exec` 会对着不存在的服务
// 报错），或者把"运行 --ignored 集成测试"挪到"生成 harness 证书"
// 前面（读不到证书文件，两条需要真实 TLS 的用例会连不上/验不过）。
#[test]
fn integration_steps_run_in_the_documented_order() {
    let doc = load_workflow();
    let steps = steps(job(&doc, INTEGRATION_JOB));
    let compose_up = step_index_by_name(steps, STEP_COMPOSE_UP);
    let cert = step_index_by_name(steps, STEP_HARNESS_CERT);
    let ignored = step_index_by_name(steps, STEP_IGNORED_TESTS);
    assert!(compose_up < cert, "拉起测试环境必须排在生成证书之前");
    assert!(cert < ignored, "生成证书必须排在运行 --ignored 测试之前");
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
    let run = run_text(step);
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
// task-12-report.md 里对这个组合的本地验证。
//
// 会让这条测试变红的实现改法：把 `--network host` 或
// `--add-host gateway.test:127.0.0.1` 删掉（改回写宿主 /etc/hosts 之类
// 需要特权的步骤），或者把镜像换成一个跟 MSRV（1.89）不一致的版本。
#[test]
fn ignored_tests_run_inside_a_container_with_network_host_and_add_host() {
    let doc = load_workflow();
    let steps = steps(job(&doc, INTEGRATION_JOB));
    let run = run_text(step_by_name(steps, STEP_IGNORED_TESTS));
    assert!(run.contains("--network host"), "{run:?}");
    assert!(run.contains("--add-host gateway.test:127.0.0.1"), "{run:?}");
    assert!(run.contains("rust:1.89"), "镜像版本应与 MSRV 一致：{run:?}");
}

// 卡死时要有清楚的诊断，理由与 unit_test_step_has_an_inner_timeout_
// wrapper 相同。
//
// 会让这条测试变红的实现改法：把 run 里的 `timeout 1200` 删掉。
#[test]
fn ignored_tests_step_has_an_inner_timeout_wrapper() {
    let doc = load_workflow();
    let steps = steps(job(&doc, INTEGRATION_JOB));
    let run = run_text(step_by_name(steps, STEP_IGNORED_TESTS));
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
    assert!(run_text(&steps[idx]).contains("logs"), "{:?}", steps[idx]);
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
        run_text(&steps[idx]).contains("down -v"),
        "{:?}",
        steps[idx]
    );
    for other in [
        STEP_COMPOSE_UP,
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
