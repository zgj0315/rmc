//! 建立到 Gateway 的字节流：TCP，可选 HTTP CONNECT，TLS。

pub mod connect;
pub mod tls;

use crate::addr::HostPort;
use crate::code::ServerFingerprint;
use crate::diagnostic::{ConnectOutcome, ProxyObservation};
use crate::error::{Error, Result};
use crate::platform::{Conn, ProxyAuthenticator, ProxyResolver};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

/// 最近一次 [`Transport::connect`] 实际走的那一跳。
///
/// 跟 [`ProxyObservation`] 差一个 `auth`：协商结局不存在这里，它每次从
/// [`ProxyAuthenticator::auth_summary`] 现取——存一份就会有两个真相来源，
/// 而协商器那边还在继续变。
#[derive(Debug, Clone, PartialEq, Eq)]
enum LastHop {
    Direct,
    Via {
        endpoint: HostPort,
        connect: ConnectOutcome,
    },
}

pub struct Transport {
    resolver: Arc<dyn ProxyResolver>,
    authenticator: Arc<dyn ProxyAuthenticator>,
    /// 最近一次 `connect()`/`dial()` 看见的那一跳，`None` 表示这个进程
    /// 还没连过。见 [`Transport::last_proxy`]。
    last_hop: Mutex<Option<LastHop>>,
}

impl Transport {
    /// Task 9：不再收 `TlsRoots`——TLS 侧不再校验一份可复用的信任根，
    /// 每次 `connect()` 核对的指纹随连接码逐次传入（见 [`Self::connect`]），
    /// 没有状态可存。
    pub fn new(
        resolver: Arc<dyn ProxyResolver>,
        authenticator: Arc<dyn ProxyAuthenticator>,
    ) -> Self {
        Self {
            resolver,
            authenticator,
            last_hop: Mutex::new(None),
        }
    }

    /// 最近一次 [`Self::connect`] 实际经过了什么，`None` 表示还没连过。
    ///
    /// # 这个方法存在的理由（W173）
    ///
    /// 界面要在诊断页上画「系统代理 / 代理 CONNECT / 代理认证」三行，
    /// 而它**不许**调用 [`Self::effective_proxy`]：那个方法会真的去问
    /// 一次系统代理配置（企业网络上可能是一整轮 WPAD 发现），还会改写
    /// rmc-win 的 `ProxyEndpointRecorder` 里那一格——界面每重画一帧就查
    /// 一次的话，正在进行的代理认证会被悄悄搅乱，而**没有任何测试会
    /// 因此变红**（rmc-win `ProxyEndpointRecorder` 的文档里写着这件事的
    /// 全部因果）。
    ///
    /// 这个方法**不发起任何解析**：它读的是上一次 `connect()` 留下的
    /// 记录，也就是「这条链路真的走过的那一跳」，比现查一次更准确
    /// （两次解析未必给出同一个答案）。Supervisor 用它拼出
    /// [`crate::state::TunnelEvent::Proxy`] 送给界面。
    pub fn last_proxy(&self) -> Option<ProxyObservation> {
        let hop = lock(&self.last_hop).clone()?;
        Some(match hop {
            LastHop::Direct => ProxyObservation::Direct,
            LastHop::Via { endpoint, connect } => ProxyObservation::Via {
                endpoint,
                connect,
                // 现取，不存：协商器那边还在继续变，存一份就会漂移。
                auth: self.authenticator.auth_summary(),
            },
        })
    }

    fn note_hop(&self, hop: LastHop) {
        *lock(&self.last_hop) = Some(hop);
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

    /// TCP 拨号，经代理时含 CONNECT，不做 TLS。预检的「运维服务器连通」
    /// 那一步用它——它只想知道拨得通、CONNECT 过不过，不关心 TLS。
    pub async fn dial(&self, gateway: &HostPort) -> Result<TcpStream> {
        let hop = self.effective_proxy(gateway).await;
        let dial = hop.clone().unwrap_or_else(|| gateway.clone());

        // 先按"最坏"记一笔：经代理时 CONNECT 还没发生，直连时压根没有
        // CONNECT 这回事。下面 CONNECT 真的拿到 200 才改写成
        // `Established`——反过来写（先记成功再出错时改回去）会在任何一条
        // 提前 `?` 返回的路径上留下一句假话。
        self.note_hop(match &hop {
            Some(p) => LastHop::Via {
                endpoint: p.clone(),
                connect: ConnectOutcome::Failed,
            },
            None => LastHop::Direct,
        });

        let mut stream = TcpStream::connect((dial.host(), dial.port()))
            .await
            .map_err(|e| Error::Tcp(format!("连接 {dial} 失败：{e}")))?;
        stream
            .set_nodelay(true)
            .map_err(|e| Error::Tcp(format!("设置 TCP_NODELAY 失败：{e}")))?;

        if let Some(p) = &hop {
            connect::http_connect(&mut stream, gateway, self.authenticator.as_ref()).await?;
            // 走到这里 CONNECT 一定拿到了 200（上一行的 `?` 把别的出口
            // 都挡住了）。
            self.note_hop(LastHop::Via {
                endpoint: p.clone(),
                connect: ConnectOutcome::Established,
            });
        }

        Ok(stream)
    }

    /// 建立到 Gateway 的 TLS 通道：`dial()` 拿到明文字节流之后，核对证书
    /// 里的公钥是否等于连接码里的 `pin`——见 [`tls::wrap_tls`]。
    pub async fn connect(&self, gateway: &HostPort, pin: &ServerFingerprint) -> Result<Conn> {
        let stream = self.dial(gateway).await?;
        let tls = tls::wrap_tls(stream, gateway, pin).await?;
        Ok(Box::new(tls))
    }
}

/// 中毒了也把里面的值拿出来接着用。
///
/// 这把锁只护着一格 [`LastHop`]，临界区里没有任何会 panic 的东西，所以
/// 中毒只可能来自别处的连带影响。真中毒了也不该让下一次连接跟着崩——
/// 同一条纪律见 rmc-win 的 `events::lock` 与 `sspi::lock`。
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    //! W173：`last_proxy()` 说的必须是「这条链路真的走过的那一跳」。
    //!
    //! 这几条全部跑在 `127.0.0.1` 的临时端口上：不碰 DNS、不碰外网，
    //! 任何一台机器上结果都一样。

    use super::*;
    use crate::diagnostic::ProxyAuthSummary;
    use crate::platform::{NoProxy, NoProxyAuth};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct FixedProxy(Option<HostPort>);

    #[async_trait::async_trait]
    impl ProxyResolver for FixedProxy {
        async fn resolve(&self, _target: &HostPort) -> Option<HostPort> {
            self.0.clone()
        }
    }

    /// 一个绑上就关掉的端口：拨过去必然瞬间被拒。
    async fn closed_port() -> HostPort {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        drop(l);
        addr.parse().unwrap()
    }

    fn transport(proxy: Option<HostPort>) -> Transport {
        Transport::new(Arc::new(FixedProxy(proxy)), Arc::new(NoProxyAuth))
    }

    /// 还没连过的时候没有任何记录。
    ///
    /// 这条是下面几条的反向自证：少了它，那几条的断言可以被一个"恒定
    /// 返回某个默认值"的实现满足。
    #[test]
    fn a_transport_that_never_connected_has_nothing_to_report() {
        let t = Transport::new(Arc::new(NoProxy), Arc::new(NoProxyAuth));
        assert!(t.last_proxy().is_none());
    }

    /// 判定直连时记的是 [`ProxyObservation::Direct`]，**不是**一个
    /// 「代理是谁不知道、CONNECT 失败」的四不像。
    ///
    /// 用 `dial()` 而不是 `connect()`：这条只关心 `note_hop` 记的是什么，
    /// 那份记录完全发生在 `dial()` 内部，TLS 那半段（Task 9 拆出去的）
    /// 跟它无关。
    ///
    /// 改红：把 `dial()` 里 `None => LastHop::Direct` 那一支换成
    /// `Via { endpoint: gateway.clone(), connect: Failed }`——这条当场红，
    /// 而界面上会凭空多出一行「系统代理 ops.example.com:443」。
    #[tokio::test]
    async fn a_direct_connection_is_recorded_as_direct() {
        let gateway = closed_port().await;
        let t = transport(None);
        let _ = t.dial(&gateway).await;
        assert_eq!(t.last_proxy(), Some(ProxyObservation::Direct));
    }

    /// 经代理但**连代理都没拨通**：记的是这台代理 + CONNECT 没建立。
    #[tokio::test]
    async fn a_proxy_that_cannot_even_be_dialled_is_recorded_as_failed() {
        let proxy = closed_port().await;
        let t = transport(Some(proxy.clone()));
        let _ = t.dial(&"ops.example.com:443".parse().unwrap()).await;
        assert_eq!(
            t.last_proxy(),
            Some(ProxyObservation::Via {
                endpoint: proxy,
                connect: ConnectOutcome::Failed,
                auth: ProxyAuthSummary::NotAttempted,
            })
        );
    }

    /// **CONNECT 拿到 200 就算建立，跟后面的 TLS 成不成没关系。**
    ///
    /// 这条是「先记最坏、拿到 200 再改写」那个顺序的全部价值所在：
    /// 假代理老老实实回一个 200，然后什么都不做，TLS 握手必然失败，
    /// `connect()` 返回 `Err`——而诊断页上「代理 CONNECT」那一行必须
    /// 显示「已建立」，因为它确实建立了。把 CONNECT 的失败与 TLS 的
    /// 失败混成一句，现场工程师会去找代理管理员，而问题在证书上。
    ///
    /// 用完整的 `connect()`（不是 `dial()`）：这条要的正是"TLS 那半段
    /// 失败了，但 CONNECT 记录不受影响"这件事本身，指纹随便传一个——
    /// 假代理接上之后什么都不发，TLS 握手连 ServerHello 都等不到，
    /// 传哪个指纹都会在同一处失败。
    ///
    /// 改红：把 `note_hop(... Established)` 那一段挪到 `wrap_tls` 之后
    /// （也就是"整条连接成了才算 CONNECT 成了"）——这条当场红。
    #[tokio::test]
    async fn a_connect_that_returned_200_is_established_even_if_tls_then_fails() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy: HostPort = listener.local_addr().unwrap().to_string().parse().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            // 读到请求头结束为止就够了。
            let _ = s.read(&mut buf).await;
            let _ = s
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await;
            // 之后什么都不发：TLS 握手会在这里失败。
            let _ = s.read(&mut buf).await;
        });

        let t = transport(Some(proxy.clone()));
        let pin = ServerFingerprint::of_ed25519_public(&[0u8; 32]);
        let err = t
            .connect(&"ops.example.com:443".parse().unwrap(), &pin)
            .await;
        assert!(err.is_err(), "对面不是 TLS 服务端，这次连接本该失败");
        assert_eq!(
            t.last_proxy(),
            Some(ProxyObservation::Via {
                endpoint: proxy,
                connect: ConnectOutcome::Established,
                auth: ProxyAuthSummary::NotAttempted,
            })
        );
    }

    /// 上一次经代理、这一次判定直连时，**旧记录必须被抹掉**。
    ///
    /// 改红：把 `dial()` 开头那次 `note_hop` 改成只在
    /// `hop.is_some()` 时才记——这条红，而界面会一直画着一台早就不在
    /// 链路上的代理。
    #[tokio::test]
    async fn switching_to_a_direct_connection_clears_the_old_proxy() {
        let proxy = closed_port().await;
        let gateway = closed_port().await;
        let t = transport(Some(proxy));
        let _ = t.dial(&gateway).await;
        assert!(matches!(t.last_proxy(), Some(ProxyObservation::Via { .. })));

        let t2 = transport(None);
        let _ = t2.dial(&gateway).await;
        assert_eq!(t2.last_proxy(), Some(ProxyObservation::Direct));
    }

    /// 协商结局是**现取**的，不是连接那一刻存下来的。
    ///
    /// 改红：把 `last_proxy()` 里的 `self.authenticator.auth_summary()`
    /// 换成写死的 `ProxyAuthSummary::NotAttempted`——这条红，而诊断页上
    /// 「代理认证」那一行会永远说"代理没有要求认证"。
    #[tokio::test]
    async fn the_negotiation_summary_comes_from_the_authenticator_each_time() {
        struct Speaking;

        #[async_trait::async_trait]
        impl ProxyAuthenticator for Speaking {
            async fn begin_connection(&self) {}
            async fn next_token(
                &self,
                _scheme: &str,
                _challenge: Option<&str>,
            ) -> Option<zeroize::Zeroizing<String>> {
                None
            }
            fn auth_summary(&self) -> ProxyAuthSummary {
                ProxyAuthSummary::ContextUnavailable {
                    package: "Negotiate".into(),
                }
            }
        }

        let proxy = closed_port().await;
        let t = Transport::new(Arc::new(FixedProxy(Some(proxy))), Arc::new(Speaking));
        let _ = t.dial(&"ops.example.com:443".parse().unwrap()).await;
        match t.last_proxy() {
            Some(ProxyObservation::Via { auth, .. }) => assert_eq!(
                auth,
                ProxyAuthSummary::ContextUnavailable {
                    package: "Negotiate".into()
                }
            ),
            other => panic!("{other:?}"),
        }
    }
}
