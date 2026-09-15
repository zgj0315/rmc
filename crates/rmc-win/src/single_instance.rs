//! 单实例互斥量。第二个实例拿不到互斥量就退出；把已有窗口置前是调用方
//! （rmc-app）的事，这个模块只负责「我是不是第二个实例」这一个判断。
//!
//! 这一整块没有可抽出的纯逻辑：CreateMutexW 给回的就是一个二值结果
//! （拿到 / 已经有人拿了），没有中间的原始数据格式需要单独解析，所以不
//! 像 [`crate::proxy`] 那样拆「取数据」/「解析数据」两层。

#[cfg(windows)]
mod imp {
    // W12：crate 根用 `#![deny(unsafe_op_in_unsafe_fn)]` 而不是
    // `#![forbid(unsafe_code)]`——理由写在 lib.rs 顶部。`unsafe_code`
    // 这条 lint 默认就是放行的，这里的 `allow` 不是在绕开什么限制，只是
    // 一句写在代码里、编译器帮着盯住的书面声明：这个模块用 unsafe，且
    // 只有这一个模块的这几处。
    #![allow(unsafe_code)]

    use windows::core::HSTRING;
    use windows::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE};
    use windows::Win32::System::Threading::CreateMutexW;

    /// 持有一个具名互斥量。`Drop` 时释放；释放后同名互斥量才能被下一个
    /// 进程重新拿到。
    pub struct SingleInstance(HANDLE);

    impl SingleInstance {
        /// 尝试拿到名为 `name` 的互斥量。
        ///
        /// 用 `Local\` 前缀（不是 `Global\`）：这是单用户桌面应用，去重
        /// 只需要在当前登录会话内生效，不需要跨会话（比如同一台机器上
        /// 另一个用户的登录会话）互相看见。
        ///
        /// 拿到互斥量（说明没有其它实例在跑）返回 `Some`；`CreateMutexW`
        /// 本身失败，或者已经有实例持有同名互斥量（`GetLastError() ==
        /// ERROR_ALREADY_EXISTS`），都返回 `None`——调用方不需要区分这
        /// 两种失败，两种情况下都应该视为「不能作为本实例继续」而退出。
        ///
        /// 运行期行为（互斥量真的挡住第二个实例、`GetLastError` 真的
        /// 返回 `ERROR_ALREADY_EXISTS`）在这台 macOS 机器上验不了，只能
        /// 靠 Windows 上的人工验收清单——见 task-1-report.md。
        pub fn acquire(name: &str) -> Option<Self> {
            let wide = HSTRING::from(format!("Local\\{name}"));
            // `bInitialOwner = true`：拿到就立刻持有，不用再单独 wait 一次。
            let handle = unsafe { CreateMutexW(None, true, &wide) }.ok()?;
            if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
                // 已经有实例在跑：这次 CreateMutexW 仍然会给回一个有效
                // handle（指向那个已存在的互斥量对象），必须关掉它，
                // 否则泄漏一个句柄。
                unsafe {
                    let _ = CloseHandle(handle);
                }
                return None;
            }
            Some(Self(handle))
        }
    }

    impl Drop for SingleInstance {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

#[cfg(windows)]
pub use imp::SingleInstance;
