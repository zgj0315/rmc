// 把 `rmc.manifest` 嵌进 Windows 可执行文件。
//
// **这个文件里刻意没有任何判断**：判断全在 `src/manifest_embed.rs`，那边
// 有测试。构建脚本不是 crate 的一部分，`cargo test` 不会编译它的
// `#[cfg(test)]`——写在这里的逻辑就是零覆盖，而它的失败形态恰恰是
// 「静默什么都不做」。这里只剩读两个环境变量、把结果打印成 cargo 指令。
//
// # 为什么不用 `winres`（brief 原文那条 build-dependency）
//
// brief 写的是 `winres = "0.1"` + `WindowsResource::set_manifest_file`。
// 改用「直接给 MSVC 链接器传两个参数」这条路，理由按分量排：
//
// 1. **`Cargo.lock` 零变动。** Task 11 刚刚用「托盘自己写 Win32 而不是引
//    `tray-icon`」换来过一次锁文件零变动；依赖审计的每一条豁免都是这
//    十二轮反复拍板出来的，能不动就不动。
// 2. **少一个不会被 CI 验证的运行环境假设。** `winres` 要找得到 Windows
//    SDK 的 `rc.exe`（或 MinGW 的 `windres`）；`/MANIFEST:EMBED` 走的是
//    链接器本来就要走的那条路。
// 3. **失败是响亮的。** brief 原文把 `winres` 的失败写成
//    `println!("cargo:warning=嵌入清单失败：{e}")`——清单没嵌进去，构建
//    照样绿。这里没有可吞的错误：链接器认不了参数就直接链接失败。
//
// **代价说清楚**：`winres` 顺带能写 VERSIONINFO（文件属性里的「文件说明 /
// 产品名称 / 版本号」），这条路写不了。记在 task-12-report.md 的「交付前
// 还剩什么」表里，不做。

// `#[path]` 而不是 `include!`：`include!` 展开出来的位置不允许内部属性，
// 那份模块顶部的 `//!` 文档会直接编译失败（实测过）。
#[path = "src/manifest_embed.rs"]
mod manifest_embed;

use manifest_embed::{plan, ManifestPlan};
use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=rmc.manifest");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/manifest_embed.rs");

    let manifest =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("cargo 一定会设置 CARGO_MANIFEST_DIR"))
            .join("rmc.manifest");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();

    match plan(&target_os, &target_env, &manifest) {
        ManifestPlan::NotWindows => {}
        // 跳过必须出声：静默跳过跟「嵌成功了」在构建日志里长得一模一样。
        ManifestPlan::UnsupportedLinker { target_env } => {
            println!(
                "cargo:warning=目标是 windows-{target_env}（不是 msvc），\
                 跳过嵌入 rmc.manifest——这一档不产出发布二进制，属预期行为"
            );
        }
        ManifestPlan::EmbedWithMsvcLinker { link_args } => {
            assert!(
                manifest.is_file(),
                "找不到 {}——这份清单是方案 §3.9「不需要管理员权限」的实物，\
                 缺了它产出的 exe 会退回 Windows 的安装程序检测启发式",
                manifest.display()
            );
            // 只作用于本包的 bin（`rmc.exe`），不作用于测试二进制。
            for arg in link_args {
                println!("cargo:rustc-link-arg-bins={arg}");
            }
        }
    }
}
