//! 建立到 Gateway 的字节流：TCP，可选 HTTP CONNECT，TLS。

pub mod connect;
pub mod tls;

use crate::addr::HostPort;
use crate::error::{Error, Result};
use crate::platform::{Conn, ProxyAuthenticator, ProxyResolver};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

pub struct Transport {
    resolver: Arc<dyn ProxyResolver>,
    authenticator: Arc<dyn ProxyAuthenticator>,
    roots: tls::TlsRoots,
}

impl Transport {
    pub fn new(
        resolver: Arc<dyn ProxyResolver>,
        authenticator: Arc<dyn ProxyAuthenticator>,
        roots: tls::TlsRoots,
    ) -> Self {
        Self {
            resolver,
            authenticator,
            roots,
        }
    }

    pub async fn resolve_dns(&self, host: &str) -> Result<Vec<IpAddr>> {
        let host = host.to_string();
        let addrs = tokio::net::lookup_host((host.as_str(), 0u16))
            .await
            .map_err(|e| Error::Dns(format!("{host}：{e}")))?
            .map(|sa| sa.ip())
            .collect::<Vec<_>>();
        if addrs.is_empty() {
            return Err(Error::Dns(format!("{host} 没有解析到任何地址")));
        }
        Ok(addrs)
    }

    /// 纯连通性探测，立即断开，返回握手耗时。
    pub async fn probe_tcp(&self, target: &HostPort, timeout: Duration) -> Result<Duration> {
        let started = Instant::now();
        let stream =
            tokio::time::timeout(timeout, TcpStream::connect((target.host(), target.port())))
                .await
                .map_err(|_| Error::Tcp(format!("连接 {target} 超时")))?
                .map_err(|e| Error::Tcp(format!("连接 {target} 失败：{e}")))?;
        drop(stream);
        Ok(started.elapsed())
    }

    /// 当前生效的代理，None 表示直连。供预检与界面显示使用。
    pub async fn effective_proxy(&self, gateway: &HostPort) -> Option<HostPort> {
        self.resolver.resolve(gateway).await
    }

    /// 建立到 Gateway 的 TLS 通道。经代理时先 CONNECT，再在其上握手。
    pub async fn connect(&self, gateway: &HostPort) -> Result<Conn> {
        let hop = self.effective_proxy(gateway).await;
        let dial = hop.clone().unwrap_or_else(|| gateway.clone());

        let mut stream = TcpStream::connect((dial.host(), dial.port()))
            .await
            .map_err(|e| Error::Tcp(format!("连接 {dial} 失败：{e}")))?;
        stream
            .set_nodelay(true)
            .map_err(|e| Error::Tcp(format!("设置 TCP_NODELAY 失败：{e}")))?;

        if hop.is_some() {
            connect::http_connect(&mut stream, gateway, self.authenticator.as_ref()).await?;
        }

        let tls = tls::wrap_tls(stream, gateway.host(), &self.roots).await?;
        Ok(Box::new(tls))
    }
}
