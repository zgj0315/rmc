//! 通知区（托盘）图标与气泡通知的 Win32 搬运层。
//!
//! # W192：自己做，不引 `tray-icon`
//!
//! Task 11 的 brief 要用 `tray-icon = "0.19"`。派发前实测过两次：
//!
//! - 直接加：`Cargo.lock` 对本工作区**真新增 48 个包**，里头是整个 GTK3
//!   栈（gtk/gdk/glib/pango/cairo/atk/libappindicator/libxdo/x11…）。那些
//!   是 tray-icon 的 **Linux** 依赖，在我们的 target 上一行都不编译，
//!   **但锁文件不分平台**。`cargo deny` 直接红：licenses 2 条 rejected +
//!   advisories 1 条（`proc-macro-error` unmaintained）。
//! - 加 `default-features = false`：仍然 45 个新包，GTK 仍在，deny 照样
//!   两项红。
//!
//! 换成 Win32 自己做：**零新包、零 deny 事件**，代价是这个文件里多几十行
//! unsafe——而这个 crate 本来就全是这么做的（`CreateMutexW`、WinHTTP、
//! SSPI、DPAPI、`PowerRegisterSuspendResumeNotification`）。
//!
//! # 两层划分（本 crate 的约定，见 `lib.rs` 的模块文档）
//!
//! - **纯逻辑**（本文件上半部分，不带 `#[cfg(windows)]`，macOS 上原生
//!   可测）：[`wide`] 把文本装进 Win32 的定长宽字符缓冲，[`icon_bits`]
//!   把一张 RGBA 图变成 `CreateIcon` 要的两张位图。这两件事都是**最容易
//!   写出缓冲区越界与颜色通道搞反**的地方，所以一个字都不许留在
//!   `#[cfg(windows)]` 里。
//! - **Win32**：只有 `win` 子模块整块 `#[cfg(windows)]`，职责只到「建一个
//!   消息窗口、调 `Shell_NotifyIconW`」为止，**一条判断都没有**。
//!
//! 「画什么颜色、写什么字、要不要弹通知」全在 `rmc_app::tray`——那一层
//! 认识 `Model`，也在这台机器上被测。

/// 通知区图标的边长，像素。16×16 是通知区的标准尺寸。
pub const ICON_SIDE: usize = 16;

/// `NOTIFYICONDATAW::szTip` 的容量，宽字符数（含结尾 NUL）。
pub const TIP_CAP: usize = 128;
/// `NOTIFYICONDATAW::szInfoTitle` 的容量。
pub const INFO_TITLE_CAP: usize = 64;
/// `NOTIFYICONDATAW::szInfo` 的容量。
pub const INFO_CAP: usize = 256;

/// 把一段文本装进 Win32 的定长宽字符缓冲。
///
/// # 为什么这件事必须在纯逻辑层
///
/// `NOTIFYICONDATAW` 的三个字段是三个**定长数组**（128 / 64 / 256 个
/// `u16`）。往里塞一段比缓冲长的文本，最好的结局是画出乱码，最坏的结局
/// 是越界写。而「状态卡副标题」这一路的文本长度来自 rmc-core 的错误
/// 文案，不是我们能预估的。
///
/// 保证三条：
///
/// 1. 结尾**一定**有 NUL（最多放 `N - 1` 个有效宽字符）；
/// 2. 截断**不会把一个代理对切一半**——落单的高代理项是非法 UTF-16，
///    Windows 会把它画成一个问号方块；
/// 3. 不 panic、不越界。
pub fn wide<const N: usize>(text: &str) -> [u16; N] {
    const { assert!(N >= 1, "缓冲至少要放得下一个结尾 NUL") };
    let mut out = [0u16; N];
    let mut n = 0usize;
    for unit in text.encode_utf16() {
        // 留最后一格给 NUL。
        if n + 1 >= N {
            break;
        }
        out[n] = unit;
        n += 1;
    }
    // 截断点落在代理对中间时，把落单的高代理项也去掉。
    if n > 0 && (0xD800..=0xDBFF).contains(&out[n - 1]) {
        out[n - 1] = 0;
    }
    out
}

/// `CreateIcon` 要的两张位图。
///
/// 具名字段，不是一对裸 `Vec<u8>`：两张图的字节数完全不同、含义也完全
/// 不同，写反了 `CreateIcon` 只会返回一个失败的句柄，而托盘图标不显示
/// 这件事在本项目的闸门下没有任何东西看得见。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IconBits {
    /// 颜色位图：32bpp，每像素 **BGRA**（Windows 的字节序），逐行从上
    /// 到下。
    pub color: Vec<u8>,
    /// 单色掩码：1bpp，**位为 1 表示该像素透明**（露出背景）；每行按
    /// WORD（2 字节）对齐，这是 `CreateIcon` 对单色位图的要求。
    pub mask: Vec<u8>,
}

/// 每行掩码占几个字节（按 WORD 对齐）。
fn mask_stride(side: usize) -> usize {
    side.div_ceil(16) * 2
}

/// 把一张 RGBA 图（逐行从上到下，每像素 4 字节）变成 [`IconBits`]。
///
/// 尺寸对不上返回 `None`——**不去猜**：猜出来的图只会让 `CreateIcon`
/// 读到缓冲之外的内存。
///
/// 全透明的像素在颜色位图里一并清零：`CreateIcon` 的 32bpp 颜色位图在
/// 一部分 Windows 版本上会忽略 alpha 通道，只靠掩码抠形状；不清零的话
/// 圆点外面那一圈会画成黑色方块。
pub fn icon_bits(rgba: &[u8], side: usize) -> Option<IconBits> {
    if side == 0 || rgba.len() != side * side * 4 {
        return None;
    }
    let stride = mask_stride(side);
    let mut color = vec![0u8; side * side * 4];
    let mut mask = vec![0u8; stride * side];

    for y in 0..side {
        for x in 0..side {
            let i = (y * side + x) * 4;
            let (r, g, b, a) = (rgba[i], rgba[i + 1], rgba[i + 2], rgba[i + 3]);
            if a == 0 {
                // 透明：掩码置 1，颜色留全零。
                mask[y * stride + x / 8] |= 0x80 >> (x % 8);
            } else {
                color[i] = b;
                color[i + 1] = g;
                color[i + 2] = r;
                color[i + 3] = a;
            }
        }
    }
    Some(IconBits { color, mask })
}

#[cfg(windows)]
mod win {
    //! 一个消息窗口 + `Shell_NotifyIconW`。
    //!
    //! 这个模块在本机（macOS）上整块被 `#[cfg(windows)]` 切掉，一行测试
    //! 都跑不到；两条闸门是 `cargo zigbuild --target
    //! x86_64-pc-windows-gnu` 与同目标的 clippy，**两道都不跑测试**
    //! （Task 5 用八枪实测过这一层的盲区）。所以这里**一条判断都没有**：
    //! 文本怎么截断、颜色通道怎么排、要不要弹通知，全在别处。
    //!
    //! 真实行为只能靠 Windows 上的人工验收，条目记在 task-11-report.md。
    #![allow(unsafe_code)]

    use super::{icon_bits, wide, ICON_SIDE, INFO_CAP, INFO_TITLE_CAP, TIP_CAP};
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::Shell::{
        Shell_NotifyIconW, NIF_ICON, NIF_INFO, NIF_TIP, NIIF_INFO, NIM_ADD, NIM_DELETE, NIM_MODIFY,
        NOTIFYICONDATAW,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateIcon, CreateWindowExW, DestroyIcon, DestroyWindow, HICON, HWND_MESSAGE,
        WINDOW_EX_STYLE, WINDOW_STYLE,
    };

    /// 宿主窗口用的**系统预定义**窗口类。
    ///
    /// 用 `STATIC` 而不是自己 `RegisterClassW` 一个：后者要
    /// `WNDCLASSW`，而 `WNDCLASSW` 在 `windows` 0.62.2 里挂在
    /// `Win32_Graphics_Gdi` feature 后面（闸门 5 实测报的就是这条）。
    /// 预定义类不需要注册、不需要模块句柄、也不需要自己写窗口过程——
    /// 而这个窗口本来就只是 `Shell_NotifyIconW` 要的一个有效 `HWND`，
    /// 不上屏、不收任何回调。
    fn class_name() -> Vec<u16> {
        "STATIC\0".encode_utf16().collect()
    }

    /// 通知区里这个图标的 id。一个进程只有一个托盘图标。
    const ICON_ID: u32 = 1;

    /// 一个通知区图标。
    ///
    /// **不是 `Send`/`Sync`**（`HWND` 是裸指针）：窗口必须由创建它的线程
    /// 销毁，而 iced 的事件循环就跑在主线程上，托盘也建在那里。接线那一层
    /// 因此把它放在 `App` 里（每个界面实例自己一份），不是放在跨线程共享
    /// 的 `Core` 里。
    pub struct Tray {
        hwnd: HWND,
        icon: std::cell::Cell<Option<HICON>>,
    }

    /// 造一张 `HICON`。失败返回 `None`。
    fn make_icon(rgba: &[u8]) -> Option<HICON> {
        let bits = icon_bits(rgba, ICON_SIDE)?;
        // SAFETY: 两个缓冲的长度由 `icon_bits` 按 `ICON_SIDE` 算出，调用
        // 期间都活着；`hinstance` 传 `None`（图标不来自任何模块资源）。
        unsafe {
            CreateIcon(
                None,
                ICON_SIDE as i32,
                ICON_SIDE as i32,
                1,
                32,
                bits.mask.as_ptr(),
                bits.color.as_ptr(),
            )
        }
        .ok()
    }

    /// 一个只用来给通知区当宿主的消息窗口（`HWND_MESSAGE` 父窗口，
    /// 不上屏、不进任务栏）。
    ///
    /// `Shell_NotifyIconW` 要一个有效的 `HWND`，哪怕我们不接任何点击
    /// 回调（`uCallbackMessage` 留 0）。消息由 iced 的事件循环顺带泵掉。
    fn create_host_window() -> Option<HWND> {
        let class = class_name();
        let name = PCWSTR(class.as_ptr());
        // SAFETY: `class` 的存储活到本函数返回，`name` 只在调用期间被读；
        // `STATIC` 是系统预定义类，不需要注册；`HWND_MESSAGE` 作为父窗口
        // 表示只收消息、不显示。失败时 `CreateWindowExW` 返回 `Err`。
        unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE(0),
                name,
                name,
                WINDOW_STYLE(0),
                0,
                0,
                0,
                0,
                Some(HWND_MESSAGE),
                None,
                None,
                None,
            )
        }
        .ok()
    }

    impl Tray {
        /// 建出托盘图标。失败返回 `None`——**没有托盘不是错误**，客户端
        /// 照常工作，只是通知区里没有那个点。
        pub fn open(tooltip: &str, rgba: &[u8]) -> Option<Self> {
            let hwnd = create_host_window()?;
            let tray = Tray {
                hwnd,
                icon: std::cell::Cell::new(make_icon(rgba)),
            };
            let mut data = tray.base();
            data.uFlags = NIF_ICON | NIF_TIP;
            data.hIcon = tray.icon.get().unwrap_or_default();
            data.szTip = wide::<TIP_CAP>(tooltip);
            // SAFETY: `data` 是本函数的局部变量，`cbSize` 是它自己的大小。
            if !unsafe { Shell_NotifyIconW(NIM_ADD, &data) }.as_bool() {
                return None;
            }
            Some(tray)
        }

        fn base(&self) -> NOTIFYICONDATAW {
            NOTIFYICONDATAW {
                cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
                hWnd: self.hwnd,
                uID: ICON_ID,
                ..Default::default()
            }
        }

        /// 换图标颜色与悬停提示。
        ///
        /// # W201：旧图标必须等 `NIM_MODIFY` **返回之后**才能销毁
        ///
        /// 上一版把 `DestroyIcon(old)` 写在 `Shell_NotifyIconW` **之前**，
        /// 而紧挨着的注释写的却是「旧图标要等这一次 `NIM_MODIFY` 之后才
        /// 不再被通知区引用」——**代码跟自己的注释是反的**。
        ///
        /// 后果：在通知区仍然持有旧 `HICON` 的那个窗口期把它销毁了。
        /// 轻则换色的一瞬间托盘图标闪一下空白，重则那个 GDI 句柄号被系统
        /// 复用之后，Explorer 拿着它去画的是**别的对象**。
        ///
        /// **这一层没有任何自动化闸门看得见**（本轮 B7 那一枪已经证明：
        /// 让换状态时永远不换图标，四道语义闸门全绿）。所以顺序只能靠
        /// 这段说明和人工验收守，条目见 task-11-fix-1-report.md。
        pub fn set_status(&self, tooltip: &str, rgba: &[u8]) {
            let mut data = self.base();
            data.uFlags = NIF_TIP;
            data.szTip = wide::<TIP_CAP>(tooltip);
            // 先只是把新图标记进格子，**旧的那张还留着**——通知区在下面
            // 那次调用返回之前仍然引用它。
            let mut replaced = None;
            if let Some(icon) = make_icon(rgba) {
                data.uFlags |= NIF_ICON;
                data.hIcon = icon;
                replaced = self.icon.replace(Some(icon));
            }
            // SAFETY: 同 `open`。
            let _ = unsafe { Shell_NotifyIconW(NIM_MODIFY, &data) };
            // 到这里通知区已经改用新图标，旧的那张才轮得到销毁。
            if let Some(old) = replaced {
                // SAFETY: `old` 是我们自己 `CreateIcon` 出来的，通知区
                // 已经在上面那次 `NIM_MODIFY` 里改用新图标、不再引用它。
                let _ = unsafe { DestroyIcon(old) };
            }
        }

        /// 弹一条气泡通知。
        pub fn notify(&self, title: &str, body: &str) {
            let mut data = self.base();
            data.uFlags = NIF_INFO;
            data.szInfoTitle = wide::<INFO_TITLE_CAP>(title);
            data.szInfo = wide::<INFO_CAP>(body);
            data.dwInfoFlags = NIIF_INFO;
            // SAFETY: 同 `open`。
            let _ = unsafe { Shell_NotifyIconW(NIM_MODIFY, &data) };
        }
    }

    impl Drop for Tray {
        fn drop(&mut self) {
            let data = self.base();
            // SAFETY: 同 `open`。删不掉也只能记一行——`Drop` 里不 panic。
            let _ = unsafe { Shell_NotifyIconW(NIM_DELETE, &data) };
            if let Some(icon) = self.icon.take() {
                // SAFETY: 我们自己建的图标，通知区已经不再引用它。
                let _ = unsafe { DestroyIcon(icon) };
            }
            // SAFETY: 窗口由本线程创建，`Drop` 也在本线程（`Tray` 不是
            // `Send`）。
            let _ = unsafe { DestroyWindow(self.hwnd) };
        }
    }
}

#[cfg(windows)]
pub use win::Tray;

#[cfg(test)]
mod tests {
    use super::*;

    // ================= wide =================

    /// 短文本原样进去，后面全是 NUL。
    #[test]
    fn a_short_text_lands_with_a_trailing_nul() {
        let buf = wide::<8>("abc");
        assert_eq!(&buf[..3], &[b'a' as u16, b'b' as u16, b'c' as u16]);
        assert_eq!(&buf[3..], &[0u16; 5]);
    }

    /// 中文照常。
    #[test]
    fn chinese_text_is_encoded_as_utf16() {
        let buf = wide::<8>("已连接");
        let want: Vec<u16> = "已连接".encode_utf16().collect();
        assert_eq!(&buf[..want.len()], &want[..]);
        assert_eq!(buf[want.len()], 0, "结尾必须是 NUL");
    }

    /// **装不下时截断，而且一定留得下结尾那个 NUL。**
    ///
    /// 改红：把 `if n + 1 >= N` 改成 `if n >= N`——最后一格会被有效字符
    /// 占掉，缓冲里再没有 NUL，Windows 会一直读到数组外面去。这条当场红。
    #[test]
    fn an_overlong_text_is_truncated_and_still_nul_terminated() {
        let long = "啊".repeat(200);
        let buf = wide::<8>(&long);
        assert_eq!(buf[7], 0, "结尾那一格必须是 NUL");
        assert_eq!(
            &buf[..7],
            &"啊".repeat(7).encode_utf16().collect::<Vec<_>>()[..]
        );
        // 反向自证：短一点的确实没被截。
        assert_eq!(wide::<8>("啊")[1], 0);
    }

    /// 截断点落在代理对中间时，落单的高代理项要被去掉。
    ///
    /// 改红：把 `if n > 0 && (0xD800..=0xDBFF).contains(..)` 整段删掉——
    /// `buf[6]` 会是一个落单的高代理项（非法 UTF-16）。
    #[test]
    fn truncation_never_splits_a_surrogate_pair() {
        // U+1F600 在 UTF-16 里是两个码元。7 个有效格子 = 3 个完整表情 +
        // 半个，那半个必须被丢掉。
        let text = "\u{1F600}".repeat(10);
        let buf = wide::<8>(&text);
        assert_eq!(buf[7], 0);
        assert_eq!(buf[6], 0, "落单的高代理项没有被去掉");
        // 前面三个完整的代理对还在。
        let want: Vec<u16> = "\u{1F600}".repeat(3).encode_utf16().collect();
        assert_eq!(&buf[..6], &want[..]);
        // 整段读回来必须是合法 UTF-16。
        let end = buf.iter().position(|&u| u == 0).expect("有 NUL");
        assert_eq!(
            String::from_utf16(&buf[..end]).expect("截断之后不是合法 UTF-16"),
            "\u{1F600}".repeat(3)
        );
    }

    /// 空串也得有 NUL。
    #[test]
    fn an_empty_text_is_still_nul_terminated() {
        assert_eq!(wide::<4>(""), [0u16; 4]);
    }

    /// 三个容量常量必须跟 `NOTIFYICONDATAW` 的三个数组对得上。
    ///
    /// macOS 上没有那个结构体，所以这里只能钉住数值本身；Windows 那一侧
    /// 由 `win` 子模块里 `data.szTip = wide::<TIP_CAP>(..)` 的**类型**
    /// 强制对齐——长度不等直接编译不过（闸门 5）。
    #[test]
    fn the_buffer_capacities_match_the_win32_struct() {
        assert_eq!(TIP_CAP, 128);
        assert_eq!(INFO_TITLE_CAP, 64);
        assert_eq!(INFO_CAP, 256);
    }

    // ================= icon_bits =================

    /// 一张全不透明的纯色图：颜色位图逐像素是 BGRA，掩码全 0（全不透明）。
    ///
    /// 改红：把 `color[i] = b; color[i+1] = g; color[i+2] = r;` 里的 r 与 b
    /// 换回 RGBA 顺序——红点会画成蓝点，而这件事在 Windows 之外没有任何
    /// 东西看得见。这条当场红。
    #[test]
    fn an_opaque_image_keeps_every_pixel_and_swizzles_to_bgra() {
        // 2×2，全是 (r=0xc4, g=0x2b, b=0x1c, a=255)。
        let rgba: Vec<u8> = [0xc4, 0x2b, 0x1c, 0xff].repeat(4);
        let bits = icon_bits(&rgba, 2).expect("2×2 的 RGBA 应当能转");

        assert_eq!(bits.color.len(), 16);
        for px in bits.color.chunks(4) {
            assert_eq!(px, [0x1c, 0x2b, 0xc4, 0xff], "颜色通道没有换成 BGRA");
        }
        // 全不透明 → 掩码一个位都不置。
        assert_eq!(bits.mask, vec![0u8; 2 * 2]);
    }

    /// 透明像素：掩码置位，颜色清零。
    ///
    /// 改红：把 `mask[..] |= 0x80 >> (x % 8)` 改成 `|= 1 << (x % 8)`——
    /// 位序反了，圆点会被抠成一条竖条纹。这条当场红（第 0 列的位是
    /// 最高位 `0x80`，不是最低位 `0x01`）。
    #[test]
    fn a_transparent_pixel_sets_its_mask_bit_and_clears_its_color() {
        // 2×2：只有 (0,0) 不透明。
        let mut rgba = vec![0u8; 2 * 2 * 4];
        rgba[0..4].copy_from_slice(&[0x0f, 0x7b, 0x0f, 0xff]);
        let bits = icon_bits(&rgba, 2).expect("能转");

        assert_eq!(&bits.color[0..4], &[0x0f, 0x7b, 0x0f, 0xff]);
        assert_eq!(&bits.color[4..], &[0u8; 12], "透明像素的颜色没清零");

        let stride = 2; // WORD 对齐，2 字节一行
        assert_eq!(bits.mask.len(), stride * 2);
        // 第 0 行：(0,0) 不透明 → 位 0x80 不置；(0,1) 透明 → 位 0x40 置。
        assert_eq!(bits.mask[0], 0x40, "第 0 行的掩码位序不对");
        // 第 1 行两个像素都透明 → 0x80 | 0x40。
        assert_eq!(bits.mask[stride], 0xc0);
    }

    /// 掩码每行按 WORD 对齐：16 像素宽正好 2 字节，一行不多不少。
    #[test]
    fn the_mask_rows_are_word_aligned() {
        assert_eq!(mask_stride(16), 2);
        assert_eq!(mask_stride(1), 2, "1 像素宽也要凑满一个 WORD");
        assert_eq!(mask_stride(17), 4);

        let rgba = vec![0u8; ICON_SIDE * ICON_SIDE * 4];
        let bits = icon_bits(&rgba, ICON_SIDE).expect("16×16 能转");
        assert_eq!(bits.mask.len(), 2 * ICON_SIDE);
        assert_eq!(bits.color.len(), ICON_SIDE * ICON_SIDE * 4);
        // 全透明 → 每一位都置上。
        assert_eq!(bits.mask, vec![0xffu8; 2 * ICON_SIDE]);
    }

    /// 尺寸对不上就**不猜**。
    ///
    /// 改红：把 `rgba.len() != side * side * 4` 那条判断删掉——
    /// `icon_bits` 会在下一行按越界的下标读缓冲，测试进程当场 panic。
    #[test]
    fn a_buffer_that_does_not_match_the_side_is_refused() {
        assert!(icon_bits(&[0, 0, 0, 0], 2).is_none(), "2×2 要 16 字节");
        assert!(icon_bits(&[0u8; 16], 0).is_none(), "边长 0 不是图");
        // 反向自证：对得上的那一份确实能转。
        assert!(icon_bits(&[0u8; 16], 2).is_some());
    }
}
