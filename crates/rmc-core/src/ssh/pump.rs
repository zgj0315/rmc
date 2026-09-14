//! forwarded-tcpip 通道到一体机的双向转发与逐会话流量账目。
//!
//! 一条 `Channel<client::Msg>` 对应工程师那一侧的一次连接（由
//! `ClientHandler::server_channel_open_forwarded_tcpip` accept 出来）；这里
//! 要做的只有两件事：把它和一体机 SSH 端口之间的字节原样搬过去搬回来，
//! 以及记下搬了多少——**转发的内容一个字节都不许进日志**，那是远程工程师
//! 和一体机之间的 SSH 流量，账目只记数量，不记内容。

use crate::addr::HostPort;
use crate::tunnel::TunnelMsg;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

/// 流量上报周期。界面每两秒看到一次增量足够，过密会刷爆事件通道。
pub const BYTES_REPORT_INTERVAL: Duration = Duration::from_secs(2);

/// 关闭某条远程会话的句柄，只存在于 [`SharedChannels`] 账本里。
pub struct Closer(oneshot::Sender<()>);

impl Closer {
    pub fn close(self) {
        let _ = self.0.send(());
    }
}

/// `ClientHandler`（登记新会话）与 `SshTunnel`（响应 `close_remote_session`）
/// 共享的"当前打开的会话"账本。
///
/// 账本里只有**真正打开成功**的会话：插入发生在 `run()` 里一体机拨号成功、
/// 紧跟着 `RemoteSessionOpened` 发出之后；移除发生在 `run()` 结束前，不管
/// 结束的原因是正常 EOF、写失败，还是被 `close_remote_session` 主动关闭。
///
/// 这个设计不是 brief 原始草稿的写法——草稿里 `spawn(...)` 直接返回
/// `Closer`，交给调用方（`ClientHandler`）自己塞进账本，账本从此只增不减：
/// 一条会话自然结束之后，它的 `Closer` 会一直留在表里，直到进程退出。这样
/// `close_remote_session` 没法区分"这个 id 从未存在过"和"这个 id 存在过、
/// 但会话早就自然结束了"——两种情况命中的都是"表里有一个失效的
/// `oneshot::Sender`"，调用 `.close()` 发送失败会被默默吞掉，返回的都是
/// `Ok(())`。把插入和移除都收进 `run()` 自己，账本在任意时刻的内容精确
/// 等于"当前仍然打开的会话"，`close_remote_session` 才谈得上区分"关掉了
/// 一条真会话"与"这个 id 现在压根不在"——后者不区分"从未存在"和"已经
/// 自然结束"，但这两种情况对调用方而言本来就该给出同一个信号："没有什么
/// 好关的"，不是一次静默的、看似成功实则什么都没发生的操作。
pub type SharedChannels = Arc<Mutex<HashMap<u64, Closer>>>;

/// 新建一个空账本，供 `establish_over` 在构造 `ClientHandler`/`SshTunnel`
/// 时共用同一个实例。
pub fn new_shared_channels() -> SharedChannels {
    Arc::new(Mutex::new(HashMap::new()))
}

/// 把 [`run`] 丢进独立的 tokio 任务。调用方（`ClientHandler`）不需要自己
/// `tokio::spawn`，也不需要关心账本的插入/移除时机——这两件事全部收在
/// `run` 内部完成，见 [`SharedChannels`] 上的文档。
pub fn spawn(
    id: u64,
    channel: russh::Channel<russh::client::Msg>,
    appliance: HostPort,
    tx: mpsc::Sender<TunnelMsg>,
    channels: SharedChannels,
) {
    tokio::spawn(run(id, channel, appliance, tx, channels));
}

/// 拨号一体机、登记账本、双向转发，直到通道结束。
///
/// 拨号失败时发送 `ApplianceDialFailed` 并显式 `eof()` + `close()` 这条
/// 通道——只发 `eof()`（brief 原始草稿的写法）不够：`Channel` 本体被 drop
/// 时不会主动发送 channel-close（这一点在这个占位实现被替换之前就已经在
/// 模块文档里写明，见 git 历史），只 `eof()` 会让通道停在"再也不会有数据
/// 但还没关闭"的半开状态，工程师那一侧连的是一条真实 TCP 连接，会一直
/// 挂着等不到任何响应，而不是像"一体机确实拒绝了连接"那样迅速失败。
pub async fn run(
    id: u64,
    channel: russh::Channel<russh::client::Msg>,
    appliance: HostPort,
    tx: mpsc::Sender<TunnelMsg>,
    channels: SharedChannels,
) {
    let upstream = match TcpStream::connect((appliance.host(), appliance.port())).await {
        Ok(s) => s,
        Err(e) => {
            let _ = tx
                .send(TunnelMsg::ApplianceDialFailed {
                    id,
                    reason: format!("连接 {appliance} 失败：{e}"),
                })
                .await;
            let _ = channel.eof().await;
            let _ = channel.close().await;
            return;
        }
    };
    let _ = upstream.set_nodelay(true);

    // 只有拨号成功之后才登记进账本——见 SharedChannels 上的文档：登记的
    // 时机必须晚于"调用方第一次有可能合法地得知这个 id"（也就是
    // RemoteSessionOpened 发出）之后，否则一个抢在通知之前用这个 id 调用
    // close_remote_session 的调用者，会静默命中一个还没真正开始转发的
    // 会话，观察不到任何有意义的效果。
    let (close_tx, mut close_rx) = oneshot::channel();
    channels.lock().unwrap().insert(id, Closer(close_tx));
    let _ = tx.send(TunnelMsg::RemoteSessionOpened { id }).await;

    let to_appliance = Arc::new(AtomicU64::new(0));
    let from_appliance = Arc::new(AtomicU64::new(0));

    // 周期上报累计计数，界面据此显示流量。上报的是累计值不是增量，最后
    // 结束前那次补报（见函数末尾）用的是同一套累计值，跟这里语义一致。
    let reporter = {
        let tx = tx.clone();
        let to = to_appliance.clone();
        let from = from_appliance.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(BYTES_REPORT_INTERVAL);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let msg = TunnelMsg::RemoteSessionBytes {
                    id,
                    to_appliance: to.load(Ordering::Relaxed),
                    from_appliance: from.load(Ordering::Relaxed),
                };
                if tx.send(msg).await.is_err() {
                    return;
                }
            }
        })
    };

    let (mut up_read, mut up_write) = tokio::io::split(upstream);
    let mut ch_stream = channel.into_stream();

    let pump = async {
        let mut ch_buf = vec![0u8; 32 * 1024];
        let mut up_buf = vec![0u8; 32 * 1024];
        loop {
            tokio::select! {
                // 工程师 -> 一体机：从 SSH 通道读，写进一体机的 TCP 连接。
                r = ch_stream.read(&mut ch_buf) => match r {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if up_write.write_all(&ch_buf[..n]).await.is_err() {
                            break;
                        }
                        to_appliance.fetch_add(n as u64, Ordering::Relaxed);
                    }
                },
                // 一体机 -> 工程师：从一体机的 TCP 连接读，写回 SSH 通道。
                r = up_read.read(&mut up_buf) => match r {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if ch_stream.write_all(&up_buf[..n]).await.is_err() {
                            break;
                        }
                        from_appliance.fetch_add(n as u64, Ordering::Relaxed);
                    }
                },
            }
        }
    };

    tokio::select! {
        _ = pump => {}
        _ = &mut close_rx => {}
    }

    reporter.abort();
    // 从账本摘除必须发生在这里，不管上面的 select 是怎么结束的——这是
    // SharedChannels 账本"任意时刻的内容精确等于当前仍打开的会话"这条
    // 不变式的另一半（插入见上文）。摘除之后，任何人再拿这个 id 调用
    // close_remote_session 都会被判定为"不存在"，不会静默命中一个已经
    // 结束的会话。
    channels.lock().unwrap().remove(&id);
    let _ = ch_stream.shutdown().await;
    let _ = up_write.shutdown().await;

    // 结束前补一次最终计数，确保界面看到的最后一条 RemoteSessionBytes
    // 反映的是完整的总量，再报关闭。
    let _ = tx
        .send(TunnelMsg::RemoteSessionBytes {
            id,
            to_appliance: to_appliance.load(Ordering::Relaxed),
            from_appliance: from_appliance.load(Ordering::Relaxed),
        })
        .await;
    let _ = tx.send(TunnelMsg::RemoteSessionClosed { id }).await;
}

#[cfg(test)]
mod tests {
    //! 这里的测试全部跑在 `crate::ssh::test_support` 的进程内假 Gateway
    //! 上——不需要 docker、DNS、`/etc/hosts`，`cargo test -p rmc-core` 任何
    //! 一次都会跑到。"一体机"用测试自己起的一个真实 `TcpListener`
    //! 冒充：pump 从工程师这一侧读到什么字节、真的原样出现在这个监听器
    //! accept 出来的连接上，是这份证据比"能连上"更强的地方——两个方向用
    //! 长度不同、内容不同的payload，一旦读写方向被接反、或者账目的两个
    //! 字段被换标签，测试会直接读到错误的字节或者错误的计数，而不是巧合
    //! 蒙混过关。

    use super::*;
    use crate::ssh::establish_over;
    use crate::ssh::test_support::*;
    use crate::tunnel::{TunnelParams, UnknownSessionId};
    use tokio::net::TcpListener;
    use zeroize::Zeroizing;

    fn params_with_appliance(appliance: HostPort) -> TunnelParams {
        TunnelParams {
            username: TEST_USER.into(),
            password: Zeroizing::new(TEST_PASSWORD.to_string()),
            reverse_port: 22001,
            appliance,
        }
    }

    /// 会让这条测试变红的实现改法：
    /// - 把 `up_write`/`ch_stream` 两个读写分支的读源或写目标对调（方向
    ///   接反）——一体机侧再也读不到 `to_appliance_payload`，或者读到的是
    ///   `from_appliance_payload` 的内容。
    /// - 把 `RemoteSessionBytes` 里 `to_appliance`/`from_appliance` 两个
    ///   字段的赋值对调——两个方向用了不同长度的 payload，标签一旦对调，
    ///   `assert_eq!` 会拿到互相调换过的数字，立刻不等。
    /// - 把上报用的计数器换成某个只在实现内部才看得到的值（例如只报
    ///   "读了几次" 而不是"读了多少字节"）——这里比对的是测试自己在
    ///   两端独立数出来的字节数，不是抄实现内部算出来的数。
    #[tokio::test]
    async fn forwards_bytes_in_both_directions_with_independently_counted_totals() {
        let appliance_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let appliance_addr = appliance_listener.local_addr().unwrap();
        let appliance = HostPort::new("127.0.0.1", appliance_addr.port()).unwrap();

        let (_reads, pending, conn) = spawn_gateway(GatewayConfig::default());
        let known_hosts = Arc::new(tmp_known_hosts());
        let (tx, mut rx) = mpsc::channel(64);
        let handle = with_timeout(
            "establish_over",
            establish_over(
                conn,
                &test_gateway_hostport(),
                &known_hosts,
                params_with_appliance(appliance),
                tx,
            ),
        )
        .await
        .unwrap();
        drain_authenticated_and_forward_registered(&mut rx).await;
        let server_handle = pending.get().await;

        let mut engineer_channel = with_timeout(
            "channel_open_forwarded_tcpip",
            server_handle.channel_open_forwarded_tcpip("127.0.0.1", 22001, "203.0.113.5", 54321),
        )
        .await
        .unwrap();

        let (mut appliance_sock, _peer) =
            with_timeout("一体机 accept 拨入连接", appliance_listener.accept())
                .await
                .unwrap();

        let id = match next_msg(&mut rx).await {
            TunnelMsg::RemoteSessionOpened { id } => id,
            other => panic!("期望 RemoteSessionOpened，实际 {other:?}"),
        };

        // 工程师 -> 一体机：10 万字节。
        let to_appliance_payload = vec![0xABu8; 100_000];
        with_timeout(
            "写入 engineer_channel",
            engineer_channel.data_bytes(to_appliance_payload.clone()),
        )
        .await
        .unwrap();

        let mut got_at_appliance = Vec::new();
        with_timeout("一体机读取工程师数据", async {
            let mut buf = [0u8; 8192];
            while got_at_appliance.len() < to_appliance_payload.len() {
                let n = appliance_sock.read(&mut buf).await.unwrap();
                assert_ne!(n, 0, "一体机侧提前读到 EOF");
                got_at_appliance.extend_from_slice(&buf[..n]);
            }
        })
        .await;
        assert_eq!(
            got_at_appliance, to_appliance_payload,
            "到达一体机的字节与工程师发出的不一致——方向或内容被改动"
        );

        // 一体机 -> 工程师：4 万字节，故意用不同的长度：账目字段一旦被
        // 换标签，这里立刻能数出不一样的数字。
        let from_appliance_payload = vec![0xCDu8; 40_000];
        with_timeout(
            "一体机写回",
            appliance_sock.write_all(&from_appliance_payload),
        )
        .await
        .unwrap();

        let mut got_at_engineer = Vec::new();
        with_timeout("engineer_channel 读取一体机数据", async {
            while got_at_engineer.len() < from_appliance_payload.len() {
                match engineer_channel.wait().await {
                    Some(russh::ChannelMsg::Data { data }) => {
                        got_at_engineer.extend_from_slice(&data);
                    }
                    other => panic!("期望 ChannelMsg::Data，实际 {other:?}"),
                }
            }
        })
        .await;
        assert_eq!(
            got_at_engineer, from_appliance_payload,
            "到达工程师侧的字节与一体机发出的不一致——方向或内容被改动"
        );

        // 关掉一体机侧连接，让 pump 的读循环退出；下面的账目断言比对的是
        // 上面两段测试代码自己独立数出来的长度，不是实现内部算出来的数。
        drop(appliance_sock);
        let mut bytes_report = None;
        loop {
            match next_msg(&mut rx).await {
                TunnelMsg::RemoteSessionBytes {
                    id: bid,
                    to_appliance,
                    from_appliance,
                } => {
                    assert_eq!(bid, id);
                    bytes_report = Some((to_appliance, from_appliance));
                }
                TunnelMsg::RemoteSessionClosed { id: cid } => {
                    assert_eq!(cid, id);
                    break;
                }
                other => panic!("未预期的消息 {other:?}"),
            }
        }
        let (to_appliance, from_appliance) = bytes_report.expect("没有收到 RemoteSessionBytes");
        assert_eq!(
            to_appliance,
            to_appliance_payload.len() as u64,
            "上报的 to_appliance 字节数与独立计数不一致"
        );
        assert_eq!(
            from_appliance,
            from_appliance_payload.len() as u64,
            "上报的 from_appliance 字节数与独立计数不一致"
        );

        handle.shutdown().await;
    }

    /// 会让这条测试变红的实现改法：把 `run()` 里拨号失败分支的
    /// `TcpStream::connect(...).await` 之后那个 `Err(e) => { ... return; }`
    /// 换成继续往下走（例如误把 `Ok`/`Err` 分支写反）——那样这里会等到
    /// `RemoteSessionOpened` 而不是 `ApplianceDialFailed`，直接 panic。
    #[tokio::test]
    async fn unreachable_appliance_reports_dial_failure_and_keeps_the_session_handler_alive() {
        // 绑一个端口再立刻释放：地址合法，但没有人监听，拨号会立即
        // 收到 ECONNREFUSED（回环地址上不需要等超时）。
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = probe.local_addr().unwrap();
        drop(probe);
        let appliance = HostPort::new("127.0.0.1", dead_addr.port()).unwrap();

        let (_reads, pending, conn) = spawn_gateway(GatewayConfig::default());
        let known_hosts = Arc::new(tmp_known_hosts());
        let (tx, mut rx) = mpsc::channel(64);
        let handle = with_timeout(
            "establish_over",
            establish_over(
                conn,
                &test_gateway_hostport(),
                &known_hosts,
                params_with_appliance(appliance),
                tx,
            ),
        )
        .await
        .unwrap();
        drain_authenticated_and_forward_registered(&mut rx).await;
        let server_handle = pending.get().await;

        let mut channel1 = with_timeout(
            "第一次 channel_open_forwarded_tcpip",
            server_handle.channel_open_forwarded_tcpip("127.0.0.1", 22001, "203.0.113.5", 1),
        )
        .await
        .unwrap();
        let id1 = match next_msg(&mut rx).await {
            TunnelMsg::ApplianceDialFailed { id, reason } => {
                assert!(!reason.is_empty(), "拨号失败原因不能为空");
                id
            }
            other => panic!("期望 ApplianceDialFailed，实际 {other:?}"),
        };

        // 正面证据：通道真的被关闭了（eof + close），不是停在"再也不会有
        // 数据但还没关闭"的半开状态——工程师那一侧连的是一条真实 TCP
        // 连接，只 eof 不 close 会让它一直挂着等不到任何响应。
        let mut saw_close = false;
        let deadline_msgs = 4;
        for _ in 0..deadline_msgs {
            match with_timeout("等待通道关闭", channel1.wait()).await {
                Some(russh::ChannelMsg::Eof) => continue,
                Some(russh::ChannelMsg::Close) | None => {
                    saw_close = true;
                    break;
                }
                other => panic!("未预期的通道消息 {other:?}"),
            }
        }
        assert!(saw_close, "拨号失败后通道应该被显式关闭，不能停在半开状态");

        // 隧道必须还活着：能再开一条新通道，还是走同一条失败路径——证明
        // ClientHandler 没有因为这次拨号失败崩掉或者停止处理后续通道，
        // 不是把整条隧道拆了重建。
        let _channel2 = with_timeout(
            "第二次 channel_open_forwarded_tcpip",
            server_handle.channel_open_forwarded_tcpip("127.0.0.1", 22001, "203.0.113.5", 2),
        )
        .await
        .unwrap();
        let id2 = match next_msg(&mut rx).await {
            TunnelMsg::ApplianceDialFailed { id, .. } => id,
            other => panic!("期望第二次 ApplianceDialFailed，实际 {other:?}"),
        };
        assert_ne!(id1, id2, "两次失败的拨号应该分配不同的会话 id");

        // 从未真正打开过的会话 id 不应该出现在账本里——一次失败的拨号
        // 不该留下一个可以被"关闭"的假会话。
        assert_eq!(
            handle.close_remote_session(id1).await,
            Err(UnknownSessionId(id1)),
            "拨号失败的 id 不该出现在账本里"
        );

        handle.shutdown().await;
    }

    /// 会让这条测试变红的实现改法：把"只有拨号成功才插入账本"改回
    /// brief 草稿的写法（`spawn` 一开始就无条件插入、`run` 结束后从不
    /// 移除）——那样对一个从未存在过的 id 调用 `close_remote_session`
    /// 会命中"运气好还是运气不好"的巧合，而对一条已经自然结束的会话
    /// 再关一次会静默返回 `Ok(())`，两种"不存在"都观察不出来。
    #[tokio::test]
    async fn close_remote_session_distinguishes_unknown_id_from_a_real_open_session() {
        let appliance_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let appliance =
            HostPort::new("127.0.0.1", appliance_listener.local_addr().unwrap().port()).unwrap();

        let (_reads, pending, conn) = spawn_gateway(GatewayConfig::default());
        let known_hosts = Arc::new(tmp_known_hosts());
        let (tx, mut rx) = mpsc::channel(64);
        let handle = with_timeout(
            "establish_over",
            establish_over(
                conn,
                &test_gateway_hostport(),
                &known_hosts,
                params_with_appliance(appliance),
                tx,
            ),
        )
        .await
        .unwrap();
        drain_authenticated_and_forward_registered(&mut rx).await;
        let server_handle = pending.get().await;

        // 1) 从未存在过的 id：必须能被区分出来，不能安静地返回 Ok。
        let err = handle.close_remote_session(999_999).await.unwrap_err();
        assert_eq!(err, UnknownSessionId(999_999));

        // 2) 打开一条真实会话。
        let _engineer_channel = with_timeout(
            "channel_open_forwarded_tcpip",
            server_handle.channel_open_forwarded_tcpip("127.0.0.1", 22001, "203.0.113.5", 1),
        )
        .await
        .unwrap();
        let (_appliance_sock, _peer) = with_timeout("一体机 accept", appliance_listener.accept())
            .await
            .unwrap();
        let id = match next_msg(&mut rx).await {
            TunnelMsg::RemoteSessionOpened { id } => id,
            other => panic!("期望 RemoteSessionOpened，实际 {other:?}"),
        };

        // 3) 关掉这条真实存在的会话：必须是 Ok。
        handle.close_remote_session(id).await.unwrap();

        // 等它真正从账本里摘除（RemoteSessionClosed 之后）。
        loop {
            if let TunnelMsg::RemoteSessionClosed { id: cid } = next_msg(&mut rx).await {
                assert_eq!(cid, id);
                break;
            }
        }

        // 4) 同一个 id 再关一次：账本里已经没有它了，这次必须区分成
        // "不存在"，不能又是一次静默的 Ok。
        let err = handle.close_remote_session(id).await.unwrap_err();
        assert_eq!(err, UnknownSessionId(id));

        handle.shutdown().await;
    }

    // --- R52（上一轮评审）：全 crate 没有任何测试锁住"转发内容一个字节
    // 都不许进日志"这条硬约束——本模块顶部文档写了这句承诺，但完全靠
    // 人工看代码里没有哪行 `tracing::` 碰到缓冲区。这条测试用一个最小的
    // `tracing::Subscriber`（`tracing` facade 自带订阅机制，不需要新引入
    // `tracing-subscriber` 这个依赖）捕获事件文本，跑一次带特征字节的
    // 真实转发，断言捕获到的日志里不含那些特征字节。这条约束是产品级
    // 的：那是远程工程师与一体机之间的 SSH 明文。
    //
    // R59（评审）：之前用的是 `tracing::subscriber::set_default`（线程
    // 局部），实测并行跑 `cargo test` 会间歇性失败——真因不是"被别的
    // 测试的 tracing 事件干扰"，是 `tracing-core` 的 callsite `Interest`
    // 缓存被毒化：`set_default` 只在当前线程生效，但 callsite 的
    // `Interest` 缓存是**进程全局**的，且只有一个已注册 dispatcher 时会
    // 走捷径（`Dispatchers::rebuilder()` 返回 `Rebuilder::JustOne`，
    // `for_each` 直接调 `dispatcher::get_default(f)`，用的是"谁第一个
    // 撞到这个 callsite"那条线程的 subscriber）。全 crate 唯一的
    // `tracing::warn!` 在 `handler.rs`——如果本测试 `set_default` 之后、
    // 自己触发这行 `warn!` 之前，另一条会触发同一处 `warn!` 的测试
    // （`forwarded_channel_open_is_rejected_when_port_does_not_match`，
    // 在 `test_support.rs`）先在别的线程撞上这个 callsite，
    // `get_default` 拿到的是那条线程的 `NoSubscriber`，`Interest::
    // never` 就会被**永久缓存**进这个全局 callsite——此后包括本测试在
    // 内的任何线程再触发这一行 `warn!`，都会被这个缓存的 `Interest`
    // 直接短路掉，`CaptureSubscriber::event` 一次都不会被调用。线程数
    // 越多这个竞争窗口越容易被撞上。
    //
    // 换成 `set_global_default`（进程级，只能设置一次——本 crate 的测试
    // 二进制里只有这一处调用，不会跟别的地方冲突）之后，第一个撞上这个
    // callsite 的线程看到的就是这同一个全局 dispatcher，`Interest`
    // 缓存与实际生效的 subscriber 不会再对不上。

    /// 只把 event 的字段格式化进一个字符串，够用来做"包不包含某段文本"
    /// 的判断——不需要时间戳、级别这些 `tracing-subscriber::fmt` 才关心
    /// 的排版。
    struct CaptureVisitor(String);

    impl tracing::field::Visit for CaptureVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            use std::fmt::Write;
            let _ = write!(self.0, " {}={value:?}", field.name());
        }
    }

    /// 只关心 `event`（日志里的一行）本身，span 相关方法全是空实现——这个
    /// crate 目前没有用 `#[instrument]`/`span!`，就算将来加了，我们也只
    /// 关心"最终有没有字节被打进某一行事件"，不需要真的维护 span 树。
    struct CaptureSubscriber(Arc<Mutex<Vec<String>>>);

    impl tracing::Subscriber for CaptureSubscriber {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            let mut visitor = CaptureVisitor(String::new());
            event.record(&mut visitor);
            self.0.lock().unwrap().push(visitor.0);
        }
        fn enter(&self, _span: &tracing::span::Id) {}
        fn exit(&self, _span: &tracing::span::Id) {}
    }

    /// 会让这条测试变红的实现改法：在 `run()` 的读写循环里加一行
    /// `tracing::debug!(?data, ...)`（或者把 `ch_buf`/`up_buf` 的切片
    /// 原样传给任何 `tracing::` 宏）——不管加在哪个方向、哪个级别，这里
    /// 的特征字节断言都会当场抓到。
    ///
    /// 测试本身不是靠"pump.rs 现在没有任何 tracing 调用"这件事空转过
    /// 关：先故意触发 handler.rs 里唯一一处真实存在的
    /// `tracing::warn!`（端口不匹配的 forwarded-tcpip 请求），断言 capture
    /// 机制确实拦到了这一条——证明"日志里没有特征字节"不是在一个从未
    /// 真正捕获过任何事件的空缓冲区上自证。
    #[tokio::test]
    async fn forwarded_payload_bytes_never_reach_a_tracing_event() {
        const TO_APPLIANCE_MARKER: &str = "RMC-TO-APPLIANCE-89f2a1c7-DO-NOT-LOG";
        const FROM_APPLIANCE_MARKER: &str = "RMC-FROM-APPLIANCE-3e5b9d02-DO-NOT-LOG";

        let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        // R59：见上面的说明，必须是 set_global_default，不能是线程局部
        // 的 set_default——callsite 的 Interest 缓存是进程全局的。这是
        // 本 crate 测试二进制里唯一一处调用，预期总能成功；如果失败
        // （意味着别处也调用了 set_global_default），直接 panic 比"悄悄
        // 忽略、然后在一个空缓冲区上得到一条不知所云的失败"更诚实。
        tracing::subscriber::set_global_default(CaptureSubscriber(captured.clone()))
            .expect("这是测试二进制里唯一一次 set_global_default 调用，预期总能成功");

        let appliance_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let appliance_addr = appliance_listener.local_addr().unwrap();
        let appliance = HostPort::new("127.0.0.1", appliance_addr.port()).unwrap();

        let (_reads, pending, conn) = spawn_gateway(GatewayConfig::default());
        let known_hosts = Arc::new(tmp_known_hosts());
        let (tx, mut rx) = mpsc::channel(64);
        let handle = with_timeout(
            "establish_over",
            establish_over(
                conn,
                &test_gateway_hostport(),
                &known_hosts,
                params_with_appliance(appliance),
                tx,
            ),
        )
        .await
        .unwrap();
        drain_authenticated_and_forward_registered(&mut rx).await;
        let server_handle = pending.get().await;

        // 先触发一次真实存在的 tracing::warn!（端口不匹配），证明下面的
        // capture 机制不是在空转——不然"日志里没有特征字节"这句断言在一个
        // 从来没捕获到任何事件的空缓冲区上永远成立，测试名字声称验证的
        // 事情其实一次都没被验证过。
        let rejected = with_timeout(
            "端口不匹配的 channel_open_forwarded_tcpip",
            server_handle.channel_open_forwarded_tcpip("127.0.0.1", 22002, "203.0.113.5", 1),
        )
        .await;
        assert!(rejected.is_err(), "端口不匹配应该被拒绝");

        // 真正的转发：两个方向各推一段带特征字节的 payload。
        let mut engineer_channel = with_timeout(
            "channel_open_forwarded_tcpip",
            server_handle.channel_open_forwarded_tcpip("127.0.0.1", 22001, "203.0.113.5", 2),
        )
        .await
        .unwrap();
        let (mut appliance_sock, _peer) =
            with_timeout("一体机 accept", appliance_listener.accept())
                .await
                .unwrap();
        let _id = match next_msg(&mut rx).await {
            TunnelMsg::RemoteSessionOpened { id } => id,
            other => panic!("期望 RemoteSessionOpened，实际 {other:?}"),
        };

        let to_appliance_payload = TO_APPLIANCE_MARKER.repeat(50).into_bytes();
        with_timeout(
            "写入 engineer_channel",
            engineer_channel.data_bytes(to_appliance_payload.clone()),
        )
        .await
        .unwrap();
        let mut got_at_appliance = vec![0u8; to_appliance_payload.len()];
        with_timeout(
            "一体机读取工程师数据",
            appliance_sock.read_exact(&mut got_at_appliance),
        )
        .await
        .unwrap();
        assert_eq!(got_at_appliance, to_appliance_payload);

        let from_appliance_payload = FROM_APPLIANCE_MARKER.repeat(50).into_bytes();
        with_timeout(
            "一体机写回",
            appliance_sock.write_all(&from_appliance_payload),
        )
        .await
        .unwrap();
        let mut got_at_engineer = Vec::new();
        with_timeout("engineer_channel 读取一体机数据", async {
            while got_at_engineer.len() < from_appliance_payload.len() {
                match engineer_channel.wait().await {
                    Some(russh::ChannelMsg::Data { data }) => {
                        got_at_engineer.extend_from_slice(&data);
                    }
                    other => panic!("期望 ChannelMsg::Data，实际 {other:?}"),
                }
            }
        })
        .await;
        assert_eq!(got_at_engineer, from_appliance_payload);

        drop(appliance_sock);
        loop {
            if let TunnelMsg::RemoteSessionClosed { .. } = next_msg(&mut rx).await {
                break;
            }
        }

        handle.shutdown().await;

        let captured = captured.lock().unwrap();
        // R74（第三轮评审）：只断言"捕获到过至少一行"曾经削弱过——换成
        // `set_global_default` 之后（见上面 R59 的说明），全 crate 唯一
        // 那行 `tracing::warn!` 还有另一条测试
        // （`test_support.rs::forwarded_channel_open_is_rejected_when_
        // port_does_not_match`）也会触发它；如果那条测试先跑、往这个
        // *全局* 缓冲区里塞了一行，而本测试自己触发的那一次因为某种
        // 原因没被捕获到，`!captured.is_empty()` 依然会通过——哨兵只
        // 证明了"这个 callsite 能被捕获"，不能证明"是本测试自己这次
        // 触发被捕获"。改成对内容做匹配：本测试用端口 22002（注册的是
        // 22001）触发拒绝，`handler.rs` 的 `warn!` 把 `connected_port`
        // 当字段记录下来，匹配这个具体端口号才能证明确实是这一次
        // 触发被捕获到，不是蒙对了非空。
        assert!(
            captured.iter().any(|line| line.contains("22002")),
            "capture 机制应该拦到本测试自己触发的那一次 tracing::warn!\
             （端口不匹配，connected_port=22002），不然下面「没有特征\
             字节」的断言证明不了任何事；已捕获：{captured:?}"
        );
        for line in captured.iter() {
            assert!(
                !line.contains(TO_APPLIANCE_MARKER),
                "转发去一体机方向的内容出现在日志里：{line}"
            );
            assert!(
                !line.contains(FROM_APPLIANCE_MARKER),
                "转发回工程师方向的内容出现在日志里：{line}"
            );
        }
    }
}
