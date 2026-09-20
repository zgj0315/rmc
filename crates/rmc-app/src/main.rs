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

#[cfg(windows)]
use rmc_app::SINGLE_INSTANCE_NAME;
use rmc_app::{window_settings, App, APP_THEME, WINDOW_TITLE};

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

    // iced 0.14 的 `application` 第一个参数是 **boot 函数**（返回初始 state，
    // 或 `(state, Task)`），标题改由 `.title(..)` 设置；0.13 是
    // `application(title, update, view)`。
    iced::application(App::default, App::update, App::view)
        .title(WINDOW_TITLE)
        // iced 0.14 不显式指定主题时会跟随系统深浅色（0.13 关掉
        // `auto-detect-theme` 后恒为 Light）。画板是固定浅色的，必须钉死。
        .theme(APP_THEME)
        .window(window_settings())
        .run()
}
