from conftest import (
    APPLIANCE_PW, HOST, TUNNEL_PORT, TUNNEL_PW, TUNNEL_SSHD, TUNNEL_USER,
    engineer_proxy_option, gateway_listen_table, parse_listen_table,
    port_listening_in_gateway, run_ssh_password,
)


def test_tunnel_account_authenticates_with_password(harness):
    """认证成功必须有正面证据，不能只断言 stderr 里没有某几个字符串。

    「没有 Permission denied」是假绿的温床：连接被拒、被 reset、超时，或者
    OpenSSH 改了措辞，stderr 里都不会有那两个字符串，用例照样绿。这里的风险是
    真实存在的——wait_port(TUNNEL_SSHD) 连的是 socat 旁路，而 socat 在 2223 上
    照单全收，不管 sshd 到底有没有起来听 2222。

    正面证据用会话本身的输出：账号的 shell 是 nologin、配置里又有
    ForceCommand /bin/false，认证一旦通过、会话一旦建立，nologin 就会打印
    This account is currently not available. 并以 1 退出。这句话只有在认证
    真的过了之后才可能出现，连不上的连接不会有任何 stdout。
    """
    out = run_ssh_password(
        TUNNEL_PW, "-p", str(TUNNEL_SSHD), f"{TUNNEL_USER}@{HOST}", "true")
    assert "This account is currently not available" in out.stdout, (
        f"rc={out.returncode} stdout={out.stdout!r} stderr={out.stderr!r}")
    assert out.returncode == 1, out.stderr


def test_wrong_password_is_rejected(harness):
    out = run_ssh_password(
        "wrong-pw", "-p", str(TUNNEL_SSHD), f"{TUNNEL_USER}@{HOST}", "true")
    assert out.returncode != 0
    assert "Permission denied" in out.stderr


def test_reverse_port_appears_on_gateway_loopback(tunnel):
    assert port_listening_in_gateway(TUNNEL_PORT)


def test_reverse_port_is_not_bound_on_a_wildcard_address(tunnel):
    """GatewayPorts no 必须把监听限制在 loopback。

    别改回「从宿主连 TUNNEL_PORT，断言连不上」：那个断言恒真，证明不了任何事。
    22001 从未在 compose 里发布，宿主无论如何都连不到它——就算 GatewayPorts 改成
    yes、端口真绑到了 0.0.0.0，宿主那一侧的表现也一模一样。要看出区别，只能进
    容器查监听表。

    也别改成匹配地址字面量的子串（`"0.0.0.0:22001" not in table`）：那种写法对
    22001 恰好成立，但不可移植——查 222 会命中 `0.0.0.0:2223`，Task 4 的 443 与
    Task 5 的 22 都会被误判。这里走 parse_listen_table() 的整值比较。
    """
    table = gateway_listen_table()
    entries = parse_listen_table(table)
    assert (HOST, TUNNEL_PORT) in entries, table
    for wildcard in ("0.0.0.0", "*", "[::]"):
        assert (wildcard, TUNNEL_PORT) not in entries, table


def test_engineer_reaches_appliance_through_reverse_port(tunnel):
    out = run_ssh_password(
        APPLIANCE_PW,
        *engineer_proxy_option(),
        "-o", "HostKeyAlias=c0001-a1",
        "-p", str(TUNNEL_PORT), "root@127.0.0.1", "cat /etc/appliance-id",
        timeout=40,
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "c0001-a1"
