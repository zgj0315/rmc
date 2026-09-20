// W102：`windows_subsystem = "windows"` 让 Windows 上双击启动时不弹黑色
// 控制台窗口——这是发布态必须的。但它是**crate 级**属性，`cargo test`
// 把这个 bin 用 `--test` 再编一遍时同样生效，产出的测试可执行文件也会变成
// GUI 子系统，`running N tests` / `panicked at ...` 全部写进一个没人接的
// stdout。实测（见 task-6-report.md 的 W102 一节）：不加 `not(test)` 时，
// zigbuild 出来的 `rmc-*.exe` 测试程序 PE 头 Subsystem = 2（GUI）；加上
// `not(test)` 后是 3（CONSOLE）。所以这里必须把测试态排除在外。
#![cfg_attr(all(windows, not(test)), windows_subsystem = "windows")]
//! 远程运维客户端的可执行入口。
//!
//! W103：这是一个**薄 bin**——所有逻辑、所有测试都在 `rmc_app` lib 里。
//! 这里只做三件 `main` 才能做的事：初始化日志、抢单实例锁、起 iced 事件
//! 循环。往这个文件加任何判断之前，先看一眼 `lib.rs` 顶部的 crate 级约定。

use rmc_app::wiring::{self, AppPaths, Platform};
#[cfg(windows)]
use rmc_app::SINGLE_INSTANCE_NAME;

fn main() -> iced::Result {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("RMC_LOG")
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    // `SingleInstance` 不是 Send/Sync，只能在主线程持有；iced 的事件循环
    // 也跑在主线程，`_instance` 活到 `main` 结束正好覆盖整个进程生命周期。
    #[cfg(windows)]
    let _instance = match rmc_win::single_instance::SingleInstance::acquire(SINGLE_INSTANCE_NAME) {
        Some(i) => i,
        None => {
            tracing::info!("已有实例在运行，退出");
            return Ok(());
        }
    };

    // 内核跑在**我们自己的** tokio 运行时上。
    //
    // iced 开了 `tokio` feature，自己也会建一个运行时给界面用；两个运行时
    // 并存没有问题（channel 都是 runtime-agnostic 的），而把内核放在自己
    // 的运行时上意味着界面那一侧无论怎么忙，Supervisor 的定时器与重连都
    // 照常走。
    //
    // `enter()` 的守卫**只罩住 `spawn_core` 那一行**：`Supervisor::spawn`
    // 里面是 `tokio::spawn`，需要一个运行时上下文；而把守卫一直拿到
    // `run()` 上，等于让 iced 在一个已经进入的运行时上下文里去建它自己的
    // 运行时。守卫出了作用域运行时照常活着（它有自己的工作线程），
    // `runtime` 这个变量活到 `main` 结束。
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "建不出 tokio 运行时");
            return Ok(());
        }
    };
    let core = {
        let _guard = runtime.enter();
        wiring::spawn_core(AppPaths::resolve(), Platform::detect())
    };
    tracing::info!(paths = ?core.paths, "内核已启动");

    // 装配全部在 `rmc_app::assemble()` 里，那边有测试看得见；这里只负责
    // 把它跑起来。**往这一行加任何东西之前先看 `assemble()` 的文档
    // 注释**——写在 `main()` 里的装配在这台无头机器上一个字都验不了，
    // 实测过 `.title("Gateway")`、绕开 `window_settings()`、删掉
    // `.theme(..)`、挂一棵字面画着 "Gateway" 的控件树、以及 W177 那两枪
    // （忘了登记事件源、根本没把内核接上去），九道闸门全绿。
    //
    // W177 之后那两枪有人接了：`install_event_source` 与
    // `program(Some(core))` 都搬进了 `assemble()`。
    rmc_app::assemble(core).run()
}
