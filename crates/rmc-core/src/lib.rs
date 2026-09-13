#![forbid(unsafe_code)]
//! 远程维护客户端内核。平台无关，不依赖任何 Windows API。

pub mod backoff;
pub mod error;

pub use error::{Error, ErrorClass, Result};
