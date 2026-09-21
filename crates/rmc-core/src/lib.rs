#![forbid(unsafe_code)]
//! 远程维护客户端内核。平台无关，不依赖任何 Windows API。

pub mod addr;
pub mod audit;
pub mod backoff;
pub mod code;
pub mod config;
pub mod diagnostic;
pub mod error;
pub mod knownhosts;
pub mod platform;
pub mod preflight;
pub mod ssh;
pub mod state;
pub mod supervisor;
pub mod transport;
pub mod tunnel;
pub mod wording;

pub use addr::HostPort;
pub use code::{AccountName, CodeError, ConnectionCode, ServerFingerprint};
pub use error::{Error, ErrorClass, Result};
pub use state::{Command, State, TunnelEvent};

pub use wording::{banned_word_in, BANNED_WORDS};
