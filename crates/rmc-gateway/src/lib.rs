#![forbid(unsafe_code)]
//! 运维服务器：一个二进制，只做口令认证与一条反向转发。设计见
//! `docs/superpowers/specs/2026-09-21-rmc-gateway-design.md`。

pub mod accounts;
pub mod cli;
pub mod config;
pub mod datadir;
pub mod identity;
pub mod server;

#[cfg(test)]
mod testing_verifier;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO 错误：{0}")]
    Io(#[from] std::io::Error),
    #[error("配置错误：{0}")]
    Config(String),
    #[error("身份密钥：{0}")]
    Identity(String),
    #[error("账号库：{0}")]
    Accounts(String),
    #[error("TLS：{0}")]
    Tls(String),
    #[error("监听失败：{0}")]
    Listen(String),
}

pub type Result<T> = std::result::Result<T, Error>;
