// W12：不用 `#![forbid(unsafe_code)]`。`forbid` 是一条不可被任何子模块的
// `#![allow(...)]` 覆盖的 lint 级别，而下面的 Win32 子模块（single_instance
// 的 `imp`，往后还有 Task 2 的 winhttp、Task 3 的 sspi）恰恰都需要
// `unsafe`。两者放在一起，在 macOS 上完全隐形——`#[cfg(windows)]` 把那些
// 子模块整块切掉，crate 里就再没有 `unsafe` 出现过，forbid 从未真正生效；
// 到 Windows 上编译，五个模块的 `#![allow(unsafe_code)]` 会跟 forbid 同时
// 硬报错。`unsafe_code` 这条 lint 本来就是默认放行（allow-by-default），
// 所以这里不需要一层禁止再一层豁免，只需要 `deny(unsafe_op_in_unsafe_fn)`
// 这条更细的规则：Win32 调用即使写在 `unsafe fn` 内部，每一处具体的不安全
// 操作也必须显式包一层 `unsafe { ... }`，不能靠函数签名的 `unsafe` 一次性
// 免检。（本任务已用 cargo zigbuild 的 windows-gnu 目标实测过，五个
// `#![allow(unsafe_code)]` 子模块不会因此报错——见 task-1-report.md。）
#![deny(unsafe_op_in_unsafe_fn)]
//! Windows 平台适配层。
//!
//! 架构（方案的 Architecture 一节）：每个特性按「取原始数据」与「解析
//! 原始数据」拆成两个子模块——
//!
//! - **纯逻辑子模块**（如 [`proxy::parse`]）不带 `#[cfg(windows)]`、不碰
//!   任何 Win32 符号，在任何平台上都编译、都能跑单元测试。
//! - **Win32 子模块**（如 `single_instance::imp`，往后 Task 2 的
//!   `proxy::winhttp`、Task 3 的 `sspi::imp`）整块 `#[cfg(windows)]`，
//!   模块顶部写 `#![allow(unsafe_code)]` 说明「这里的 unsafe 是故意的」，
//!   职责只到「调 Win32 API、把结果转成普通 Rust 值」为止，一有解析/
//!   判断逻辑立刻转手给同名的纯逻辑子模块。
//!
//! 后续任务往这个 crate 加功能时，新模块请按这个形状拆：不要把纯逻辑
//! （例如某个防抖计时器该不该触发、某个图标该画哪个像素）也关进
//! `#[cfg(windows)]` 里——那样它就只能靠人工验收清单守，没法在这台机器
//! 也没法在 CI 的非 Windows 阶段自动跑到。

pub mod events;
pub mod proxy;
pub mod secret;
pub mod single_instance;
pub mod sspi;
pub mod tray;
