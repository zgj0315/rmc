//! 对 `.github/workflows/app.yml` 的纯解析测试，不起 runner、不碰 GitHub
//! Actions。立意与写法全部沿用 `tests/ci_workflow.rs`（那边守 `core.yml`），
//! 辅助函数搬进了 `tests/workflow_yaml/`，两份测试共用——**派发单明确要求
//! 别新开一套辅助**，具体理由见那份文件顶部。
//!
//! # 这份工作流为什么值得一份专门的守卫
//!
//! `app.yml` 的 `windows-build` job 是 **677 条测试里 395 条的唯一出口**：
//! 托盘那 114 行 unsafe、整个 DPAPI 封装、SSPI 协商、日志页
//! `monospace_family()` 挑 Consolas 的那一档，只有在真 Windows 上才会被
//! 编译、被执行。这个 job 安静地不跑，等于这十二轮里一大半的 Windows 代码
//! 回到零验证——而「安静地不跑」正是这个项目在 CI 配置上最怕的形状
//! （`gateway.yml` 的 `RMC_KEEP_ENV` 回归、`core.yml` 那次被脚本注释喂饱的
//! 断言，都是同一族）。
//!
//! # 这份测试自己最大的风险
//!
//! 我没法在这台机器上真跑一遍 GitHub Actions，所以下面每一条断言都是对
//! **YAML 文本**的断言——极容易写成「文件里有这个词」而不是「这一步真的
//! 会跑」。三层防护：
//!
//! 1. 凡是查脚本内容的一律走 `run_code()`（剥掉整行 `#` 注释）。
//!    `app.yml` 里那段清单校验是 PowerShell，行注释同样是 `#`，
//!    照样受这层保护。
//! 2. 「这一步会不会被关掉」单独查：job 级 `if`/`continue-on-error`、
//!    step 级 `if: false`（布尔与字符串两种写法，见 `step_is_disabled`）。
//! 3. 命令用**全等**而不是 `contains` 钉死，挡住「悄悄收窄成 `--lib`」
//!    与「接一个 `|| true`」这两种 `contains` 一概放行的退化。
//!
//! 每条测试上面都写着「会让这条测试变红的实现改法」，而且那些改法在
//! task-12-report.md 的变异表里逐条真的打过、真的看过输出。

mod workflow_yaml;
use workflow_yaml::*;
use yaml_rust2::Yaml;

const WORKFLOW: &str = "app.yml";

fn doc() -> Yaml {
    load_workflow(WORKFLOW)
}

const LINUX_JOB: &str = "linux-checks";
const WINDOWS_JOB: &str = "windows-build";

const STEP_CHECKOUT: &str = "检出代码";
const STEP_INSTALL_TOOLCHAIN: &str = "安装 Rust 工具链";
const STEP_CACHE: &str = "缓存 cargo";
const STEP_FMT: &str = "格式检查";
const STEP_CLIPPY: &str = "clippy";
const STEP_TESTS: &str = "界面与平台层测试";
const STEP_RELEASE_BUILD: &str = "构建发布二进制";
const STEP_MANIFEST_CHECK: &str = "确认清单已嵌入";
const STEP_UPLOAD: &str = "上传便携包";

/// 两个 job 的测试步骤跑的都是这一条，一个字都不能多、不能少。
// `--no-fail-fast` 是这条命令里**唯一**允许的附加项，而且是刻意的：
// 第一次真跑 CI 时 `tests/wording.rs` 一红，cargo 就停在那里——rmc-win 那
// 152 条在 Windows 上**一条都没跑到**。（那 152 条全是纯逻辑层的：
// `#[cfg(windows)]` 那几层 Win32 封装**没有任何测试**，这条命令跑不到
// DPAPI、托盘、电源事件；它验的是同一批逻辑在 Windows 的 std 与文件系统
// 语义下成不成立。）每暴露一个问题就是一轮 20 分钟。它不削弱任何东西：
// 有失败时退出码仍然非零，只是把所有测试目标跑完、一次把失败报全。
// Task 12：多了 `-p rmc-gateway`。**加它是为了让 Windows 真跑端到端。**
// `crates/rmc-gateway/tests/e2e.rs` 那 15 条把真客户端内核（rmc-core 的
// Transport / TLS 指纹钉扣 / russh / pump / Supervisor）与真运维服务器
// 接在一起跑；被它驱动的那一半代码最终交付在 Windows 上，而原来那套
// docker 集成测试只在 Linux 容器里跑过——这条链路在 Windows 的 socket
// 与文件系统语义下从来没有被端到端验证过一次。**只有 `windows-build`
// 那一侧是这个理由。**
//
// **修复轮 1/5（复审 R12-6）订正一句假话。** 上一版这里写的是"两边都跑
// 不是重复：它们验的是两个不同的平台"——这句话对 `linux-checks` **不
// 成立**：它跑在 ubuntu-24.04，跟 `core.yml` 的 `unit` job 同平台、
// 同一批 e2e，就是在同一个操作系统上把同样的 15 条又跑了一遍，是**真的
// 冗余**。
//
// 那为什么还留着（brief 要求两个 job 都加，本轮不改行为）：这条命令是
// **两个 job 共用的同一个常量**，让它们一致，"Windows 上跑的跟 Linux 上
// 跑的是同一条命令"这件事就由类型/常量保证，不靠人记。真要给
// `linux-checks` 单开一条窄一点的命令，就多出一个会各自漂移的真相来源，
// 而省下的只是一台便宜 runner 上的三秒钟。代价与收益不对等，所以保持
// 冗余，但**不再把它说成"两个平台"**。
const TEST_COMMAND: &str = "cargo test -p rmc-win -p rmc-app -p rmc-gateway --no-fail-fast";
const CLIPPY_COMMAND: &str = "cargo clippy -p rmc-win -p rmc-app --all-targets -- -D warnings";

// 会让这条测试变红的实现改法：删掉两个 job 里的任意一个、改名、或者再加
// 一个 job 而不更新这张表。
#[test]
fn the_workflow_has_exactly_the_two_documented_jobs() {
    assert_eq!(
        job_names(&doc()),
        vec![LINUX_JOB.to_string(), WINDOWS_JOB.to_string()],
        "app.yml 应该正好两个 job：linux-checks / windows-build"
    );
}

// `rust-toolchain.toml` 决定 CI 实际用的编译器（目录级 override，优先级比
// `dtolnay/rust-toolchain` 那一步高），漏了它，改 MSRV 不会触发这份工作流
// ——`core.yml` 上一轮踩过同一个坑。`Cargo.lock` 同理：一次只动锁文件的
// `cargo update` 必须重新编译与跑一遍两个 crate。
//
// 会让这条测试变红的实现改法：把这五条里的任意一条从 `on.push.paths` 或
// `on.pull_request.paths` 删掉（只写在一侧、漏掉另一侧也会红）。
#[test]
fn paths_filter_covers_the_files_this_workflow_depends_on() {
    assert_paths_filter_covers(
        &doc(),
        WORKFLOW,
        &[
            "crates/**",
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            ".github/workflows/app.yml",
        ],
    );
}

// **这是本轮最要紧的一条断言。**
//
// `runs-on` 写错（或被人「顺手统一成 ubuntu」）不会让任何东西编译失败，
// 也不会让这份工作流变黄——它只会让 395 条 Windows 专属测试**一条都不再
// 执行**，而 CI 面板上依然是两个绿勾。`#[cfg(windows)]` 那一大片在
// 非 Windows 上连编译器都看不见，所以连一条「该跑的测试没跑」的提示都
// 不会有。
//
// 会让这条测试变红的实现改法：把 `runs-on: windows-2022` 换成任何不以
// `windows` 开头的 runner 标签。
#[test]
fn the_windows_job_really_runs_on_a_windows_runner() {
    let doc = doc();
    let runs_on = job(&doc, WINDOWS_JOB)["runs-on"]
        .as_str()
        .unwrap_or_else(|| panic!("{WINDOWS_JOB} 没有 runs-on 字段"));
    assert!(
        runs_on.starts_with("windows"),
        "{WINDOWS_JOB} 必须跑在 Windows runner 上——它是 395 条 Windows \
         专属测试的唯一出口，换成别的 runner 只会让它们静默不跑，实际 {runs_on:?}"
    );
    let linux_runs_on = job(&doc, LINUX_JOB)["runs-on"]
        .as_str()
        .unwrap_or_else(|| panic!("{LINUX_JOB} 没有 runs-on 字段"));
    assert!(
        linux_runs_on.starts_with("ubuntu"),
        "{LINUX_JOB} 应该跑在 ubuntu runner 上，实际 {linux_runs_on:?}"
    );
}

// MSRV 的唯一权威来源是 `rust-toolchain.toml`，这里直接读它做交叉校验，
// 不把版本号在两处分别硬编码——硬编码两份、只在其中一份上加断言，防不住
// 「改了 rust-toolchain.toml、忘了同步这一步」这类漂移。
//
// **这条就是 W218 的落地**：brief 原文两个 job 都写
// `dtolnay/rust-toolchain@1.82`，而本仓库 MSRV 是 1.89，`core.yml` 里
// 早就写着 1.89、还有一条同形状的测试钉着。
//
// 会让这条测试变红的实现改法：把任意一个 job 的 `dtolnay/rust-toolchain@`
// 后面那个版本号改成跟 `rust-toolchain.toml` 的 `channel` 不一致的任何值
// （包括改回 brief 原文的 1.82），或者反过来只改 `rust-toolchain.toml`。
#[test]
fn both_jobs_pin_the_toolchain_to_the_documented_msrv() {
    let doc = doc();
    let channel = toolchain_channel();
    let expected = format!("dtolnay/rust-toolchain@{channel}");
    for job_name in [LINUX_JOB, WINDOWS_JOB] {
        let step = step_by_name(steps(job(&doc, job_name)), STEP_INSTALL_TOOLCHAIN);
        let uses =
            uses_text(step).unwrap_or_else(|| panic!("{job_name} 的工具链步骤没有 uses 字段"));
        assert_eq!(
            uses, expected,
            "{job_name} 的工具链版本必须跟 rust-toolchain.toml 的 channel（{channel}）一致"
        );
    }
}

// 395 条的唯一出口跑的必须是**完整的** `cargo test -p rmc-win -p rmc-app`。
//
// 用全等而不是 `contains`：`contains` 对 `cargo test -p rmc-win -p rmc-app
// --lib`（少跑 rmc-app 的 33 条 ui 与 4 条 wording 集成测试）、以及
// `cargo test -p rmc-win -p rmc-app || true`（失败也不让 job 变红）
// **一律放行**——这两种退化正是 `core.yml` 那边复审用探针实测出来的。
//
// 会让这条测试变红的实现改法：在命令前后追加任何内容（`--lib`、
// `--test ui`、`-- --skip xxx`、`|| true`），或者删掉其中一个 `-p`。
#[test]
fn both_jobs_run_the_complete_test_suite_for_both_crates() {
    let doc = doc();

    // Linux 侧包了一层 `timeout`：这条流水线抓到的第 21 个假绿形态是
    // 「不是绿，是永不结束」，卡死时要有一条清楚的「超时被杀」。
    let linux = run_code(step_by_name(steps(job(&doc, LINUX_JOB)), STEP_TESTS));
    let linux = linux.trim();
    let after_timeout = linux
        .strip_prefix("timeout ")
        .unwrap_or_else(|| panic!("{LINUX_JOB} 的测试步骤应该以 `timeout <秒数>` 开头：{linux:?}"));
    let after_seconds = after_timeout
        .trim_start_matches(|c: char| c.is_ascii_digit())
        .trim_start();
    assert_eq!(
        after_seconds, TEST_COMMAND,
        "{LINUX_JOB} 的测试步骤必须是完整的 `{TEST_COMMAND}`，不能带 --lib、\
         额外的过滤器，也不能接 || true 之类的尾巴，实际 {linux:?}"
    );

    // Windows 侧没有 `timeout`：runner 的默认 shell 是 pwsh，没有
    // coreutils。卡死靠 job 级 `timeout-minutes` 兜住（见
    // `every_job_has_a_bounded_timeout`），代价是没有诊断输出，已记在
    // task-12-report.md 的「交付前还剩什么」表里。
    let windows = run_code(step_by_name(steps(job(&doc, WINDOWS_JOB)), STEP_TESTS));
    assert_eq!(
        windows.trim(),
        TEST_COMMAND,
        "{WINDOWS_JOB} 的测试步骤必须是完整的 `{TEST_COMMAND}`"
    );
}

// **这条是 W204 的落地。** 闸门 5（`cargo zigbuild -p rmc-app --tests
// --target x86_64-pc-windows-gnu`）只编译、不带 `-D warnings`，所以
// `#[must_use]`、`unused_must_use`、以及 clippy 对整片 `#[cfg(windows)]`
// 代码一直形同虚设。`windows-build` 这一步是 Windows 上**原生**跑的第一道
// `-D warnings` clippy。
//
// 两个 job 都查：Linux 那一侧管得到两个 crate 的平台中立部分，Windows
// 那一侧才管得到 `#[cfg(windows)]` 那一片。少任何一侧都有一大块代码没人
// 用 `-D warnings` 看过。
//
// 会让这条测试变红的实现改法：删掉任意一侧的 `-D warnings`、去掉
// `--all-targets`（测试与 build.rs 就不受 clippy 管了）、或者把 `-p`
// 收窄成只剩一个 crate。
#[test]
fn both_jobs_run_clippy_with_deny_warnings_over_all_targets() {
    let doc = doc();
    for job_name in [LINUX_JOB, WINDOWS_JOB] {
        let run = run_code(step_by_name(steps(job(&doc, job_name)), STEP_CLIPPY));
        assert_eq!(
            run.trim(),
            CLIPPY_COMMAND,
            "{job_name} 的 clippy 步骤必须是完整的 `{CLIPPY_COMMAND}`"
        );
    }
}

// 会让这条测试变红的实现改法：删掉 `--check`（`cargo fmt` 就会**改文件**
// 而不是报错，CI 永远绿），或者把这一步换成别的命令。
#[test]
fn the_linux_job_checks_formatting_without_rewriting_files() {
    let doc = doc();
    let run = run_code(step_by_name(steps(job(&doc, LINUX_JOB)), STEP_FMT));
    assert_eq!(
        run.trim(),
        "cargo fmt --all -- --check",
        "格式检查必须是 `cargo fmt --all -- --check`"
    );
}

// 便携包这条链路有三步，顺序不能乱：先 `cargo build --release`，再验清单
// 真的嵌进去了，最后才上传。
//
// **`if-no-files-found: error` 不能省**：默认值是 `warn`——exe 没产出时
// `upload-artifact` 会上传一个**空产物**、这一步还是绿的，发布的人下载
// 下来才发现是空的。这正是这个项目一直在防的那类静默成功。
//
// 会让这条测试变红的实现改法：把三步中任意两步换顺序；删掉
// `if-no-files-found: error`（或把它改成 `warn`/`ignore`）；改掉产物名
// `rmc-portable` 或路径 `target/release/rmc.exe`；把 `--release` 从构建
// 命令里删掉（产物路径当场对不上）。
#[test]
fn the_portable_exe_is_built_verified_and_uploaded_in_that_order() {
    let doc = doc();
    let s = steps(job(&doc, WINDOWS_JOB));

    let build = step_index_by_name(s, STEP_RELEASE_BUILD);
    let verify = step_index_by_name(s, STEP_MANIFEST_CHECK);
    let upload = step_index_by_name(s, STEP_UPLOAD);
    assert!(build < verify, "清单校验必须排在发布构建之后");
    assert!(verify < upload, "上传必须排在清单校验之后");

    assert_eq!(
        run_code(&s[build]).trim(),
        "cargo build --release -p rmc-app",
        "发布构建命令不对"
    );

    let up = &s[upload];
    assert!(
        uses_text(up).is_some_and(|u| u.starts_with("actions/upload-artifact@")),
        "上传步骤必须用 actions/upload-artifact：{up:?}"
    );
    assert_eq!(up["with"]["name"].as_str(), Some("rmc-portable"));
    assert_eq!(
        up["with"]["path"].as_str(),
        Some("target/release/rmc.exe"),
        "上传路径要跟 [[bin]] name = \"rmc\" 对上"
    );
    assert_eq!(
        up["with"]["if-no-files-found"].as_str(),
        Some("error"),
        "if-no-files-found 必须是 error——默认的 warn 会上传一个空产物并且照样变绿"
    );
}

// `crates/rmc-app/build.rs` 那两个链接器参数（`/MANIFEST:EMBED` +
// `/MANIFESTINPUT:`）在这台机器上（macOS）一次都没有跑过，**这一步是它们
// 唯一的验证**。所以这一步自己必须够硬：
//
// - 三条**正向**断言（asInvoker / PerMonitorV2 / longPathAware 都得在
//   exe 里找得到）；只写「不许有 requireAdministrator」这一条反向断言的
//   话，「清单压根没嵌进去」也是绿的——那正是这个项目抓过的「只查不存在」
//   形状（W22/W127）。
// - 一条反向断言（不许出现 requireAdministrator）。
// - 失败必须 `throw`（pwsh 下非零退出让这一步变红），不是 `Write-Host`
//   一句警告接着往下跑。
//
// 全部走 `run_code()`：pwsh 的行注释也是 `#`，不剥的话这些关键词写在
// 脚本注释里就能把断言喂饱——`core.yml` 那边的 `exit 1` 就是这么被喂饱
// 过一次的（本项目第 18 个假绿）。
//
// 会让这条测试变红的实现改法：把任意一条 `throw` 换成 `Write-Host`；
// 删掉三个关键词里的任意一个；删掉 `requireAdministrator` 那条反向断言；
// 或者把整步的关键词挪进 `#` 注释里（`run_code` 会把它们剥掉）。
#[test]
fn the_manifest_check_fails_loudly_instead_of_warning() {
    let doc = doc();
    let step = step_by_name(steps(job(&doc, WINDOWS_JOB)), STEP_MANIFEST_CHECK);
    assert_eq!(
        step["shell"].as_str(),
        Some("pwsh"),
        "清单校验这一步必须显式指定 pwsh"
    );
    let run = run_code(step);

    for needle in ["asInvoker", "PerMonitorV2", "longPathAware"] {
        assert!(
            run.contains(needle),
            "清单校验必须正向确认 {needle} 真的在 exe 里，实际 {run:?}"
        );
    }
    assert!(
        run.contains("requireAdministrator"),
        "清单校验还要反向确认没有 requireAdministrator，实际 {run:?}"
    );
    assert!(
        run.contains("target/release/rmc.exe"),
        "校验的对象必须是发布产物本身，实际 {run:?}"
    );
    // 四条断言（三正一反）各配一个 throw，外加「exe 不存在」那一条。
    assert!(
        run.matches("throw").count() >= 3,
        "每一条断言失败都必须 throw（pwsh 下才会让这一步变红），而不是打印一句警告继续，实际 {run:?}"
    );
    assert!(
        !run.contains("Get-Content"),
        "别用 `Get-Content -Encoding Byte`：`-Encoding Byte` 在 PowerShell 7 \
         已经删掉了（`shell: pwsh` 就是 7），而逐字节 ForEach-Object 过十几 MB \
         要跑上几分钟。实际 {run:?}"
    );
}

// 守住 app.yml 的这份测试跑在 `cargo test -p rmc-core` 里，而 app.yml 自己
// 的两个 job 跑的是 `-p rmc-win -p rmc-app`——只改 app.yml 的提交不会执行
// 这份守卫，除非 `core.yml` 的 paths 过滤器点名了 `.github/workflows/
// app.yml`。
//
// 少了那一行的后果正是本文件最怕的形状：有人把 `runs-on` 改成 ubuntu、
// 或者给 windows job 加个 `if: false`，**这一整份测试一条都不会跑**，
// PR 上看到的是「没有任何工作流被触发」。
//
// 会让这条测试变红的实现改法：把 `.github/workflows/app.yml` 从
// `core.yml` 的 `on.push.paths` / `on.pull_request.paths` 里删掉。
#[test]
fn editing_app_yml_triggers_the_workflow_that_runs_its_guard_test() {
    assert_paths_filter_covers(
        &load_workflow("core.yml"),
        "core.yml",
        &[".github/workflows/app.yml"],
    );
}

// `core.yml` 那边复审用六个探针实测过：给 job 加 `continue-on-error: true`
// 或 `if: false`，所有在 step 内容层面的断言一条都不红——它们全部盯
// run/if/uses，没有一条管到「整个 job 被静默关掉」这件事本身。
//
// 会让这条测试变红的实现改法：给两个 job 里任意一个加上
// `continue-on-error` 或 job 级 `if` 字段（哪怕值是 `true`）。
#[test]
fn no_job_has_a_continue_on_error_or_a_top_level_conditional() {
    let doc = doc();
    for name in [LINUX_JOB, WINDOWS_JOB] {
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

// 同 `core.yml`：`step_by_name` 还是能找到一个 `if: false` 的 step、`run`
// 字段内容还是老样子，只是这一步压根不会被执行。布尔字面量与字符串两种
// 写法都要认（见 `step_is_disabled`）。
//
// 会让这条测试变红的实现改法：给任意一个 job 的任意一个 step 加上
// `if: false`（或 `if: "false"`）。
#[test]
fn no_step_in_any_job_is_silently_disabled_with_if_false() {
    let doc = doc();
    for job_name in [LINUX_JOB, WINDOWS_JOB] {
        for step in steps(job(&doc, job_name)) {
            let name = step["name"].as_str().unwrap_or("<unnamed>");
            assert!(
                !step_is_disabled(step),
                "job {job_name} 的 step {name:?} 带 if: false，会被静默跳过"
            );
            // 复审实测：光守 `if: false` 不够。**给 windows 的测试步骤加
            // `continue-on-error: true`，14 条全绿**——那一步失败、job 照样
            // 绿、产物照样上传，而它是 401 条测试唯一的出口。
            // `if: ${{ false }}` 同理：`step_is_disabled` 认 `false` 与
            // `"false"`，不认 `${{ }}` 那种表达式写法。
            //
            // 所以这里改成**全等**：这两个 job 的 step 今天一个 `if` 都没有，
            // 一个 `continue-on-error` 也没有。将来真要加条件步骤，
            // 来改这条断言的人必须显式想一遍「这一步被跳过会怎样」。
            //
            // 这个洞的成本**是随时间涨的**——工作流步骤只会越加越多。
            //
            // 改红：给任意一个 step 加 `continue-on-error: true`
            // 或任意形式的 `if:`。
            assert!(
                step["continue-on-error"].is_badvalue(),
                "job {job_name} 的 step {name:?} 带 continue-on-error：\
                 它失败了 job 还是绿的"
            );
            assert!(
                step["if"].is_badvalue(),
                "job {job_name} 的 step {name:?} 带 if: 条件。\
                 要加条件步骤先想清楚「这一步被跳过会怎样」，再来改这条断言"
            );
        }
    }
}

// 每个 job 都该有自己的 timeout-minutes，不依赖 GitHub Actions 默认的
// 360 分钟。`windows-build` 那一侧尤其要紧：它是这条流水线上唯一没有内层
// `timeout` 包装的测试步骤（pwsh 里没有 coreutils 的 `timeout`），job 级
// 上限是它卡死时唯一的兜底。
//
// 会让这条测试变红的实现改法：删掉某个 job 的 timeout-minutes 字段，或者
// 把它调得比这里的上限更大。
#[test]
fn every_job_has_a_bounded_timeout() {
    let doc = doc();
    for (name, at_most) in [(LINUX_JOB, 25), (WINDOWS_JOB, 35)] {
        let minutes = job(&doc, name)["timeout-minutes"]
            .as_i64()
            .unwrap_or_else(|| panic!("job {name} 没有 timeout-minutes"));
        assert!(
            minutes > 0 && minutes <= at_most,
            "job {name} 的 timeout-minutes 应该在 (0, {at_most}] 之间，实际 {minutes}"
        );
    }
}

// 两个 job 的步骤清单，**按顺序全等**。
//
// 这条是上面那些逐步断言之外的一层：它管的是「有没有人加了一步、或者少了
// 一步」。两个具体用处：
//
// 1. W223 的落地。brief 原文给 linux job 加了一步
//    `sudo apt-get install -y libxkbcommon-dev libwayland-dev pkg-config`，
//    核实下来三个都不需要（iced 是 `default-features = false`，依赖图里
//    根本没有 wayland/x11 的 -sys crate，唯一沾边的 `xkbcommon-dl` 是
//    dlopen 绑定、没有 build.rs）。把它删掉之后，需要有一条断言在「有人
//    又把它加回来」时变红并逼着他解释——一条「不许出现 apt-get」的反向
//    断言做不到这件事（空工作流也满足它），一张有序全等的清单可以。
// 2. 挡住「悄悄删掉一步」。比如把 `确认清单已嵌入` 整步删掉：
//    `the_manifest_check_fails_loudly_instead_of_warning` 会因为
//    `step_by_name` 找不到而 panic，但那是碰巧；这条是正面钉住。
//
// 会让这条测试变红的实现改法：给任意一个 job 加一步、删一步、改一个
// step 的 name、或者调换两步的顺序。
#[test]
fn each_job_has_exactly_the_documented_steps_in_order() {
    let doc = doc();
    assert_eq!(
        step_names(job(&doc, LINUX_JOB)),
        vec![
            Some(STEP_CHECKOUT),
            Some(STEP_INSTALL_TOOLCHAIN),
            Some(STEP_CACHE),
            Some(STEP_FMT),
            Some(STEP_CLIPPY),
            Some(STEP_TESTS),
        ],
        "{LINUX_JOB} 的步骤清单跟文档记录的不一致"
    );
    assert_eq!(
        step_names(job(&doc, WINDOWS_JOB)),
        vec![
            Some(STEP_CHECKOUT),
            Some(STEP_INSTALL_TOOLCHAIN),
            Some(STEP_CACHE),
            Some(STEP_CLIPPY),
            Some(STEP_TESTS),
            Some(STEP_RELEASE_BUILD),
            Some(STEP_MANIFEST_CHECK),
            Some(STEP_UPLOAD),
        ],
        "{WINDOWS_JOB} 的步骤清单跟文档记录的不一致"
    );
}
