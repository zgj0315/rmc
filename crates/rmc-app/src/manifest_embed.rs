//! 「Windows 清单要不要嵌、怎么嵌」这一个判断。
//!
//! # 为什么这段逻辑不留在 `build.rs` 里
//!
//! **构建脚本不是 crate 的一部分**：`cargo test` 不会编译它的
//! `#[cfg(test)]`，也没有任何 target 能把它跑起来。判断留在 `build.rs` 里
//! 就是货真价实的零覆盖——而它的失败形态恰恰是这个项目最怕的那一种：
//! **静默什么都不做**。清单没嵌进去，`cargo build` 照样绿，双击 exe 才
//! 知道；真正踩上去的人是拿到便携包的现场工程师。
//!
//! brief 原文那版 `#[cfg(windows)]` 正是这个形状：构建脚本是**给宿主编译**
//! 的，`cfg!(windows)` 问的是「跑这个脚本的机器是不是 Windows」，不是
//! 「产物给谁用」。从 Linux 交叉编译到 Windows 时它是 `false`，清单静默不嵌。
//!
//! 所以判断写在这里（普通模块，下面有测试），`build.rs` 用
//! `#[path = "src/manifest_embed.rs"] mod manifest_embed;` 把它引进去，
//! 自己只剩「读两个环境变量、把结果打印成 cargo 指令」这一层纯搬运。
//!
//! **不能用 `include!`**——`include!` 展开出来的位置不允许内部属性，
//! 上面这段 `//!` 文档会直接编译失败（`build.rs` 那边实测过）。
//!
//! # 这份判断**证明不了**的事
//!
//! 它证明不了 `link.exe` 真的认这两个参数、也证明不了清单真的进了 PE 的
//! 资源段。**还有一层**：`build.rs` 打印时用的那个指令键名
//! （`cargo:rustc-link-arg-bins=`）本身一条测试都没有，而 cargo 对单冒号的
//! 未知 `cargo:` 指令是**当 metadata 静默忽略**的——手滑写成
//! `cargo:rustc-link-arg-bin=` 就是「测试全绿、构建全绿、清单静默不嵌」。
//!
//! 那件事的唯一验证是 `app.yml` 的「确认清单已嵌入」那一步。
//! **注意那一步的三个关键词里 `asInvoker` 不带载**：MSDN 明写，指定
//! `/MANIFEST` 而未指定 `/MANIFESTUAC`/`/DLL` 时链接器会自动插一段
//! level 为 `asInvoker` 的 UAC 片段——就算 `/MANIFESTINPUT:` 完全没生效，
//! 它照样出现在 exe 字节里。真正钉住「我们这份文件进去了」的是
//! `PerMonitorV2` 与 `longPathAware` 这两条。原文是
//! （在 exe 的字节里找 `asInvoker` / `PerMonitorV2` / `longPathAware`），
//! 而那一步在开发机上跑不了。别把这里的绿灯读成「清单嵌好了」。

use std::path::Path;

/// MSVC 链接器开启「把清单嵌进资源段」的开关。
///
/// 写成常量而不是字面量散在两处：下面的测试与 `build.rs` 打印出去的东西
/// 必须是同一个字符串，否则测试绿着、产物是错的。
pub const MSVC_EMBED_FLAG: &str = "/MANIFEST:EMBED";

/// 指定清单文件。**MSVC 要求它跟 [`MSVC_EMBED_FLAG`] 成对出现**，单独给
/// 这一个参数是无效的——所以 [`plan`] 要么两个都给，要么一个都不给。
pub const MSVC_INPUT_FLAG_PREFIX: &str = "/MANIFESTINPUT:";

/// 对一个具体的编译目标，清单该怎么处理。
///
/// 三个变体都带载，没有一个是「没什么可说」的占位：`build.rs` 对
/// [`ManifestPlan::UnsupportedLinker`] 会打一条 `cargo:warning`——
/// **跳过必须出声**，静默跳过跟「嵌成功了」在构建日志里长得一模一样。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestPlan {
    /// 不是 Windows 目标，压根没有清单这回事。
    NotWindows,
    /// Windows 目标，但链接器不是 MSVC 的 `link.exe`（今天只可能是
    /// `windows-gnu`，即闸门 5/6 的 `cargo zigbuild --target
    /// x86_64-pc-windows-gnu`）。那一档用的是 lld/ld 系链接器，认不了下面
    /// 两个参数；要嵌清单得走 `windres` 编 `.rc`。发布二进制是 MSVC 构建
    /// 的，gnu 那一档只做交叉编译检查、不产出发布物，所以跳过。
    UnsupportedLinker { target_env: String },
    /// 按顺序传给链接器的参数。
    EmbedWithMsvcLinker { link_args: Vec<String> },
}

/// 按**目标**（不是宿主）判断清单怎么处理。
///
/// `target_os` / `target_env` 就是 cargo 传给构建脚本的
/// `CARGO_CFG_TARGET_OS` / `CARGO_CFG_TARGET_ENV`。
pub fn plan(target_os: &str, target_env: &str, manifest: &Path) -> ManifestPlan {
    if target_os != "windows" {
        return ManifestPlan::NotWindows;
    }
    if target_env != "msvc" {
        return ManifestPlan::UnsupportedLinker {
            target_env: target_env.to_string(),
        };
    }
    ManifestPlan::EmbedWithMsvcLinker {
        link_args: vec![
            MSVC_EMBED_FLAG.to_string(),
            format!("{MSVC_INPUT_FLAG_PREFIX}{}", manifest.display()),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn manifest() -> PathBuf {
        PathBuf::from("/tmp/some-dir/rmc.manifest")
    }

    /// 真正的目标：windows-msvc 上两个参数都给、顺序对、路径是传进来的
    /// 那一个。
    ///
    /// 会让它变红的实现改法：少给其中任何一个参数；把两个参数的顺序换过来；
    /// 把清单路径写死成字面量而不是用传进来的 `manifest`。
    #[test]
    fn a_windows_msvc_target_gets_both_linker_flags_pointing_at_the_given_manifest() {
        let m = manifest();
        let ManifestPlan::EmbedWithMsvcLinker { link_args } = plan("windows", "msvc", &m) else {
            panic!(
                "windows-msvc 必须嵌清单，实际 {:?}",
                plan("windows", "msvc", &m)
            );
        };
        assert_eq!(
            link_args,
            vec![
                "/MANIFEST:EMBED".to_string(),
                format!("/MANIFESTINPUT:{}", m.display()),
            ]
        );
    }

    /// 反向自证：参数里那个路径真的跟着入参走，不是一句写死的话。
    ///
    /// 少了这一条，上面那条在「把 `manifest.display()` 换成一个固定字符串」
    /// 时也可能被写成绿的（只要测试里恰好用同一个字面量）——这个项目已经
    /// 抓到 21 个「测试通过但没验证名字声称的事」。
    ///
    /// 会让它变红的实现改法：把 `format!` 里的 `manifest.display()` 换成
    /// 任何常量。
    #[test]
    fn the_manifest_path_in_the_flag_follows_its_argument() {
        let a = plan("windows", "msvc", Path::new("/one/rmc.manifest"));
        let b = plan("windows", "msvc", Path::new("/two/rmc.manifest"));
        assert_ne!(a, b, "换了清单路径，参数却一模一样");
        let ManifestPlan::EmbedWithMsvcLinker { link_args } = a else {
            unreachable!()
        };
        assert!(
            link_args.iter().any(|f| f.ends_with("/one/rmc.manifest")),
            "参数里没有传进来的那个路径：{link_args:?}"
        );
    }

    /// `/MANIFESTINPUT:` 单独给是无效的，MSVC 要求它跟 `/MANIFEST:EMBED`
    /// 成对。这条把「成对」这件事本身钉住。
    ///
    /// 会让它变红的实现改法：只给 `/MANIFESTINPUT:` 那一个参数（产物会
    /// 安静地少一份清单——链接器不报错，exe 里就是没有）。
    #[test]
    fn the_input_flag_never_appears_without_the_embed_flag() {
        let ManifestPlan::EmbedWithMsvcLinker { link_args } = plan("windows", "msvc", &manifest())
        else {
            unreachable!()
        };
        let has_input = link_args
            .iter()
            .any(|f| f.starts_with(MSVC_INPUT_FLAG_PREFIX));
        let has_embed = link_args.iter().any(|f| f == MSVC_EMBED_FLAG);
        assert!(
            has_input,
            "没有 {MSVC_INPUT_FLAG_PREFIX} 参数：{link_args:?}"
        );
        assert!(
            has_embed,
            "给了 {MSVC_INPUT_FLAG_PREFIX} 却没给 {MSVC_EMBED_FLAG}，\
             MSVC 会当它不存在：{link_args:?}"
        );
    }

    /// windows-gnu（闸门 5/6 的交叉编译档）要**带着理由**跳过，不是悄悄
    /// 返回一个空参数表——`build.rs` 拿这个变体打 `cargo:warning`。
    ///
    /// 会让它变红的实现改法：把这一支并进 `NotWindows`（构建日志里就再也
    /// 分不出「这个目标本来就没有清单」与「这个目标该有清单但我们没嵌」），
    /// 或者让它跟 msvc 一样返回那两个参数（gnu 链接器会当场报错）。
    #[test]
    fn a_windows_gnu_target_is_skipped_with_a_reason_not_silently() {
        assert_eq!(
            plan("windows", "gnu", &manifest()),
            ManifestPlan::UnsupportedLinker {
                target_env: "gnu".to_string()
            }
        );
    }

    /// 非 Windows 目标：什么都不做。这条同时钉住**按目标判、不按宿主判**
    /// ——`#[cfg(windows)]` 那版实现在这台 macOS 上对 `windows-msvc` 目标
    /// 也会走进这一支，而那正是 brief 原文的错。
    ///
    /// 会让它变红的实现改法：把 `target_os != "windows"` 写成
    /// `cfg!(windows)`（在这台机器上 `plan("windows", "msvc", ..)` 会退化
    /// 成 `NotWindows`，上面第一条当场红），或者把判断整个删掉。
    #[test]
    fn non_windows_targets_do_nothing() {
        for (os, env) in [("linux", "gnu"), ("macos", ""), ("android", "")] {
            assert_eq!(
                plan(os, env, &manifest()),
                ManifestPlan::NotWindows,
                "{os}-{env} 不该嵌 Windows 清单"
            );
        }
    }
}
