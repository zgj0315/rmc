//! `tests/ci_workflow.rs`（守 `core.yml`）与 `tests/app_workflow.rs`
//! （守 `app.yml`）共用的 YAML 辅助。
//!
//! # 为什么搬到这里而不是在第二份测试里再抄一套
//!
//! Task 12 的派发单点名要求：新的 `app.yml` 要照 `ci_workflow.rs` 同一形状
//! 被钉住，**别新开一套辅助**。抄一套的具体害处不是重复代码本身，是
//! `run_code()`——那个函数存在的唯一理由是这个项目的第 18 个假绿（断言被
//! `run:` 脚本自己的注释喂饱）。抄一份出去，两份里只有一份带这层防护时，
//! 新的那份会安静地退回踩过的坑。
//!
//! # 哪些东西**没有**搬进来
//!
//! `env_assignment_value()` 与 `major_minor()` 只有 `ci_workflow.rs` 用得上
//! （它们是为了从 `docker run ... -e RUSTUP_TOOLCHAIN=1.89.0` 里挖值），
//! 留在那边。理由见 `tests/common/mod.rs` 顶部那段实测记录：每个
//! `tests/*.rs` 各自编译成一个独立二进制，`mod` 进来的源码在**没用到它的
//! 那个二进制里**就是货真价实的 `dead_code`，`pub` 挡不住，
//! `cargo clippy -p rmc-core --all-targets -- -D warnings` 会因此变红。
//! 所以这里只放两边都真的调用到的项——**不用 `#![allow(dead_code)]` 糊过
//! 去**：那会让「搬进来之后再也没人用」这件事永远不被发现。

use std::path::PathBuf;
use yaml_rust2::{Yaml, YamlLoader};

/// `.github/workflows/<name>` 的绝对路径。
pub fn workflow_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.github/workflows")
        .join(name)
}

/// 解析 `.github/workflows/<name>`，失败直接 panic。
pub fn load_workflow(name: &str) -> Yaml {
    let path = workflow_path(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("读取 {path:?} 失败：{e}"));
    let docs =
        YamlLoader::load_from_str(&text).unwrap_or_else(|e| panic!("{name} 不是合法的 YAML：{e}"));
    assert_eq!(docs.len(), 1, "{name} 应该正好一个 YAML 文档");
    docs.into_iter().next().unwrap()
}

/// 这份工作流里所有 job 的名字，排序后返回。
pub fn job_names(doc: &Yaml) -> Vec<String> {
    let hash = doc["jobs"]
        .as_hash()
        .unwrap_or_else(|| panic!("workflow 里没有 jobs 映射，或它不是一个 mapping"));
    let mut names: Vec<String> = hash
        .keys()
        .map(|k| k.as_str().unwrap_or("<non-string>").to_string())
        .collect();
    names.sort();
    names
}

/// 按 job 名取整份 job 定义，找不到直接 panic（列出现有 job 名）。
pub fn job<'a>(doc: &'a Yaml, name: &str) -> &'a Yaml {
    let found = &doc["jobs"][name];
    if found.is_badvalue() {
        panic!("没有名为 {name:?} 的 job；现有 job：{:?}", job_names(doc));
    }
    found
}

pub fn steps(job: &Yaml) -> &Vec<Yaml> {
    job["steps"]
        .as_vec()
        .unwrap_or_else(|| panic!("这个 job 没有 steps 序列"))
}

/// 一个 job 里所有 step 的 `name`，**按出现顺序**。没有 name 的一律记成
/// `None`——不要在这里悄悄跳过它们。
pub fn step_names(job: &Yaml) -> Vec<Option<&str>> {
    steps(job).iter().map(|s| s["name"].as_str()).collect()
}

/// 按 step 的 `name` 字段精确定位，找不到（或撞了不止一个）就直接
/// panic——不能退回子串匹配，也不能返回 -1/0 之类的哨兵值。静默的查找
/// 失败会让后面的断言在错误的 step 上稳定通过，等于没测。
pub fn step_index_by_name(steps: &[Yaml], name: &str) -> usize {
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

pub fn step_by_name<'a>(steps: &'a [Yaml], name: &str) -> &'a Yaml {
    &steps[step_index_by_name(steps, name)]
}

pub fn run_text(step: &Yaml) -> &str {
    step["run"].as_str().unwrap_or("")
}

/// `run_text` 去掉整行的 shell 注释之后的**代码**部分。
///
/// R96 实测踩到的坑（这个项目的第 18 个假绿）：`core.yml` 的「等待测试
/// 环境就绪」这一步第一版把「到点 exit 1 让这一步失败」这句说明写在
/// `run:` 脚本体内的 `#` 注释里，而断言查的是 `run.contains("exit 1")`
/// ——于是把代码里真正的 `exit 1` 换成 `echo` 之后，这条断言被那句注释
/// 满足，测试照样全绿。一条「守住超时会让 CI 失败」的断言，被自己要守的
/// 那段文字喂饱了。
///
/// 凡是断言「脚本里真的有某个东西」的地方一律走这个函数。`pwsh` 的行
/// 注释也是 `#`，所以 `app.yml` 那段 PowerShell 同样受这层保护。
///
/// 只剥整行注释（`^\s*#`），不碰行尾注释——要正确处理行尾注释就得分辨
/// `#` 是不是在引号里，那是一个真正的词法分析问题。两份工作流里都不存在
/// 行尾注释（已逐条核对）。
pub fn run_code(step: &Yaml) -> String {
    run_text(step)
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn uses_text(step: &Yaml) -> Option<&str> {
    step["uses"].as_str()
}

/// `step["if"]` 在 YAML 里可能是字符串（`"failure()"`）也可能是没加引号的
/// 布尔字面量（`false`/`true` 会被解析成 `Yaml::Boolean`，不是
/// `Yaml::String`）——只查 `as_str()` 会让 `if: false` 这种写法完全从视野里
/// 消失（`as_str()` 对 `Boolean` 返回 `None`，看起来跟「这一步压根没有 if
/// 字段」一样）。这个函数把两种写法都判成「这一步被静默关掉了吗」。
pub fn step_is_disabled(step: &Yaml) -> bool {
    match &step["if"] {
        Yaml::Boolean(b) => !*b,
        Yaml::String(s) => s.trim() == "false",
        _ => false,
    }
}

/// 从 `rust-toolchain.toml` 里读 `channel` 字段的值。
///
/// 这份文件的格式固定是三行的 `[toolchain]` 表，手写一个只找这一个字段的
/// 小函数比引入一个通用 TOML 解析器依赖更划算：跟用 `yaml-rust2` 解析工作
/// 流是两种不同的取舍——工作流的结构本身就是这些测试要盯住的对象（手写
/// 解析器的 bug 会掩盖它该盯住的回归），而这里只是读一个格式早就固定死的
/// 配置文件里的一个字段。
///
/// **MSRV 的唯一权威来源是它**：`rust-toolchain.toml` 是目录级 override，
/// 优先级比 `dtolnay/rust-toolchain` 那一步做的 `rustup default` 更高。
/// 两份工作流里的版本号都拿它来交叉校验，不在任何地方第二次硬编码。
pub fn toolchain_channel() -> String {
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

/// `on.push.paths` 与 `on.pull_request.paths` 两侧都必须包含 `required` 里
/// 的每一条——PR 上的检查和推到默认分支后的检查必须是同一套触发条件，
/// 少了任何一侧都会让一部分改动逃过 CI。
pub fn assert_paths_filter_covers(doc: &Yaml, what: &str, required: &[&str]) {
    for trigger in ["push", "pull_request"] {
        let paths = doc["on"][trigger]["paths"]
            .as_vec()
            .unwrap_or_else(|| panic!("{what} 的 on.{trigger}.paths 应该是一个序列"));
        let texts: Vec<&str> = paths.iter().filter_map(Yaml::as_str).collect();
        for item in required {
            assert!(
                texts.contains(item),
                "{what} 的 on.{trigger}.paths 必须包含 {item:?}，实际 {texts:?}"
            );
        }
    }
}
