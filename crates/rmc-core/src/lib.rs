#![forbid(unsafe_code)]
//! 远程维护客户端内核。平台无关，不依赖任何 Windows API。

pub mod addr;
pub mod backoff;
pub mod config;
pub mod error;
pub mod knownhosts;

pub use addr::HostPort;
pub use error::{Error, ErrorClass, Result};
