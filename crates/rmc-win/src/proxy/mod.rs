//! 系统代理探测与解析。Task 2 会在这里加 `winhttp`（取 WinHTTP/PAC 的
//! 原始数据，`#[cfg(windows)]`）；`parse` 是纯函数，两个平台都编译。

pub mod parse;
