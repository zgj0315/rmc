//! 端到端转发：工程师经 Gateway 连到反向端口，字节必须到达一体机。
//! 需要 gateway/test-env 在运行。
//!
//! # 与 task-8-brief.md 原始草稿的两处出入
//!
//! 1. **没有跳板机**。brief 草稿里 `engineer_runs` 用
//!    `ProxyCommand=ssh -i .../engineer-keys/eng_ed25519 ... -W %h:%p -p 2022
//!    eng@127.0.0.1` 先跳一次工程师账号。这一整条路径已经不存在：
//!    `gateway/test-env/docker-compose.yml` 只发布 2322/2422/8443/22001，
//!    镜像里只建了 `tunnel-zhang` 一个账号，没有 `eng` 用户、2022 上没有
//!    sshd、也没有 `engineer-keys/` 目录。产品决策是远程工程师直连反向
//!    端口，在 Gateway 上不需要任何账号——这个跳板机连同"工程师在
//!    Gateway 上有账号"这个设计，在 Gateway 计划的 Task 5 就被删掉了，见
//!    `gateway/tests/test_tunnel_restrictions.py:244`。现在的正确用法见
//!    `gateway/tests/test_tunnel.py` 的
//!    `test_engineer_connects_to_appliance_directly`：没有 `-J`，没有跳板，
//!    也没有 Gateway 账号，直接 `ssh -p 22001 root@127.0.0.1`。
//! 2. **没有 sshpass**。gateway 侧确认过测试容器里装不上 sshpass（这里是
//!    本机跑 `ssh` 客户端连 docker 发布出来的端口，不是在容器里跑，但
//!    统一用同一套口令注入方式，避免这个仓库里同时存在两种连法），改用
//!    OpenSSH 8.4+ 的 `SSH_ASKPASS`/`SSH_ASKPASS_REQUIRE=force`，做法照抄
//!    `gateway/tests/conftest.py` 里的 `askpass_env`。
//!
//! # 上一轮评审的两处小修（R51/R53）
//!
//! - **R51**：`reports_session_open_bytes_and_close` 原来驱动流量的命令是
//!   `head -c 65536 /dev/zero | base64 | wc -c`——整条管道在一体机的 shell
//!   里本地跑完，只有 `wc -c` 数出来的那几个字节真的经过 SSH 通道，评审
//!   实跑两次量出 `from_appliance` 稳定是 3777，在一个完全正确的实现上
//!   这条测试也会红。去掉 `| wc -c`，让 base64 的输出（约 87KB，
//!   `ceil(65536/3)*4` 加上换行）真的推过通道。
//! - **R53**：`unreachable_appliance_reports_dial_failure_and_keeps_the_tunnel`
//!   原来用固定的 `127.0.0.1:9` 模拟不可达，改成跟
//!   `ssh/pump.rs` 里同名进程内测试一样的手法：绑一个端口立刻释放，
//!   保证空置，不依赖某个固定端口号"大概率没人监听"。

use rmc_core::tunnel::{TunnelFactory, TunnelMsg};
use std::io::Write;
use std::process::Stdio;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::sync::mpsc;

mod common;
use common::{factory, next_msg, params, tmp_known_hosts, REVERSE_PORT, TUNNEL_PW};

/// 一体机的动态 root 口令，与 `gateway/tests/conftest.py` 里的
/// `APPLIANCE_PW` 是同一个值。
const APPLIANCE_ROOT_PW: &str = "appliance-dynamic-pw";

/// 生成一个只打印口令的 `SSH_ASKPASS` 脚本，返回脚本路径。
///
/// 只有本文件需要它（`ssh_tunnel.rs` 从不 shell 出去调用 `ssh` 命令行，
/// 全部走 `rmc_core` 库 API），所以不放进 `tests/common`——放过去会在
/// `ssh_tunnel.rs` 那个二进制里变成没人调用的 dead_code。
fn askpass_script(password: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "rmc-core-askpass-{}-{}.sh",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut f = std::fs::File::create(&path).expect("创建 askpass 脚本失败");
    writeln!(f, "#!/bin/sh").unwrap();
    writeln!(f, "printf '%s\\n' '{password}'").unwrap();
    drop(f);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    path
}

/// 以工程师身份直连反向端口，在一体机上执行一条命令——没有 `-J`，没有
/// 跳板，也没有 Gateway 账号，形状与
/// `gateway/tests/test_tunnel.py::test_engineer_connects_to_appliance_directly`
/// 一致。
async fn engineer_runs(cmd: &str) -> std::process::Output {
    let askpass = askpass_script(APPLIANCE_ROOT_PW);
    Command::new("ssh")
        .args(["-o", "StrictHostKeyChecking=no"])
        .args(["-o", "UserKnownHostsFile=/dev/null"])
        .args(["-o", "PreferredAuthentications=password"])
        .args(["-o", "NumberOfPasswordPrompts=1"])
        .args(["-o", "ConnectTimeout=10"])
        .args(["-p", &REVERSE_PORT.to_string(), "root@127.0.0.1", cmd])
        .env("SSH_ASKPASS", &askpass)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env_remove("SSH_AUTH_SOCK")
        .stdin(Stdio::null())
        .output()
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "需要 gateway/test-env 在运行"]
async fn engineer_command_reaches_the_appliance() {
    let (tx, mut rx) = mpsc::channel(64);
    let handle = factory(tmp_known_hosts())
        .establish(params(TUNNEL_PW, REVERSE_PORT), tx)
        .await
        .unwrap();
    while !matches!(next_msg(&mut rx).await, TunnelMsg::ForwardRegistered { .. }) {}

    let out = engineer_runs("cat /etc/appliance-id").await;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "c0001-a1");

    handle.shutdown().await;
}

#[tokio::test]
#[ignore = "需要 gateway/test-env 在运行"]
async fn reports_session_open_bytes_and_close() {
    let (tx, mut rx) = mpsc::channel(64);
    let handle = factory(tmp_known_hosts())
        .establish(params(TUNNEL_PW, REVERSE_PORT), tx)
        .await
        .unwrap();
    while !matches!(next_msg(&mut rx).await, TunnelMsg::ForwardRegistered { .. }) {}

    // 传一段可观测大小的数据，确保两个方向的计数都非零。
    //
    // R51：原来这里还接了 `| wc -c`——整条管道在一体机的 shell 里本地跑
    // 完，只有 `wc -c` 数出来的那几个字节（个位数）真的经过 SSH 通道，
    // `from_appliance > 60_000` 在一个完全正确的实现上也会红。去掉
    // `| wc -c`，让 base64 编码后的输出（约 87KB）真的经过通道被 pump
    // 计入 `from_appliance`。
    let out = engineer_runs("head -c 65536 /dev/zero | base64").await;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut opened = None;
    let mut bytes = None;
    let mut closed = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while tokio::time::Instant::now() < deadline && closed.is_none() {
        match next_msg(&mut rx).await {
            TunnelMsg::RemoteSessionOpened { id } => opened = Some(id),
            TunnelMsg::RemoteSessionBytes {
                id,
                to_appliance,
                from_appliance,
            } => {
                bytes = Some((id, to_appliance, from_appliance));
            }
            TunnelMsg::RemoteSessionClosed { id } => closed = Some(id),
            _ => {}
        }
    }

    let opened = opened.expect("没有收到 RemoteSessionOpened");
    let (bid, to_appliance, from_appliance) = bytes.expect("没有收到 RemoteSessionBytes");
    assert_eq!(bid, opened);
    assert_eq!(closed, Some(opened));
    assert!(to_appliance > 0, "到一体机的字节数为 0");
    assert!(
        from_appliance > 60_000,
        "来自一体机的字节数偏小：{from_appliance}"
    );

    handle.shutdown().await;
}

#[tokio::test]
#[ignore = "需要 gateway/test-env 在运行"]
async fn two_concurrent_sessions_get_distinct_ids() {
    let (tx, mut rx) = mpsc::channel(64);
    let handle = factory(tmp_known_hosts())
        .establish(params(TUNNEL_PW, REVERSE_PORT), tx)
        .await
        .unwrap();
    while !matches!(next_msg(&mut rx).await, TunnelMsg::ForwardRegistered { .. }) {}

    let a = engineer_runs("sleep 3; echo a");
    let b = engineer_runs("sleep 3; echo b");
    let (ra, rb) = tokio::join!(a, b);
    assert!(ra.status.success() && rb.status.success());

    let mut ids = std::collections::HashSet::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < deadline && ids.len() < 2 {
        if let TunnelMsg::RemoteSessionOpened { id } = next_msg(&mut rx).await {
            ids.insert(id);
        }
    }
    assert_eq!(ids.len(), 2, "两条并发会话应有两个不同 id：{ids:?}");

    handle.shutdown().await;
}

#[tokio::test]
#[ignore = "需要 gateway/test-env 在运行"]
async fn unreachable_appliance_reports_dial_failure_and_keeps_the_tunnel() {
    let mut p = params(TUNNEL_PW, REVERSE_PORT);
    // R53：绑一个端口立刻释放，保证空置——比固定端口号 9（赌它"大概率
    // 没人监听"）更可靠，跟 `ssh/pump.rs` 里同名进程内测试的手法一致。
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = probe.local_addr().unwrap();
    drop(probe);
    p.appliance = format!("127.0.0.1:{}", dead_addr.port()).parse().unwrap();

    let (tx, mut rx) = mpsc::channel(64);
    let handle = factory(tmp_known_hosts()).establish(p, tx).await.unwrap();
    while !matches!(next_msg(&mut rx).await, TunnelMsg::ForwardRegistered { .. }) {}

    let out = engineer_runs("true").await;
    assert!(!out.status.success(), "一体机不可达时工程师应连不上");

    let mut saw_failure = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < deadline && !saw_failure {
        if let TunnelMsg::ApplianceDialFailed { reason, .. } = next_msg(&mut rx).await {
            assert!(!reason.is_empty());
            saw_failure = true;
        }
    }
    assert!(saw_failure, "没有收到 ApplianceDialFailed");

    // 隧道本身必须还在：换回正常目标不需要重连整条隧道，这里只断言
    // establish() 返回的 handle 依然能正常走 shutdown，没有中途因为
    // Disconnected 之类的事件被判死。
    handle.shutdown().await;
}

#[tokio::test]
#[ignore = "需要 gateway/test-env 在运行"]
async fn close_remote_session_drops_only_that_session() {
    let (tx, mut rx) = mpsc::channel(64);
    let handle = factory(tmp_known_hosts())
        .establish(params(TUNNEL_PW, REVERSE_PORT), tx)
        .await
        .unwrap();
    while !matches!(next_msg(&mut rx).await, TunnelMsg::ForwardRegistered { .. }) {}

    let long = tokio::spawn(engineer_runs("sleep 30"));
    let mut id = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < deadline && id.is_none() {
        if let TunnelMsg::RemoteSessionOpened { id: got } = next_msg(&mut rx).await {
            id = Some(got);
        }
    }
    let id = id.expect("没有收到 RemoteSessionOpened");

    handle.close_remote_session(id).await.unwrap();

    let out = tokio::time::timeout(Duration::from_secs(20), long)
        .await
        .expect("断开后工程师侧应当立刻结束")
        .unwrap();
    assert!(!out.status.success(), "被断开的会话不该正常结束");

    // 隧道仍在，能接受新会话。
    let again = engineer_runs("cat /etc/appliance-id").await;
    assert!(
        again.status.success(),
        "{}",
        String::from_utf8_lossy(&again.stderr)
    );

    handle.shutdown().await;
}
