from conftest import (
    APPLIANCE_PW, HOST, TUNNEL_PORT, TUNNEL_PW, TUNNEL_SSHD, TUNNEL_USER,
    engineer_proxy_option, gateway_listen_table, port_listening_in_gateway,
    run_ssh_password,
)


def test_tunnel_account_authenticates_with_password(harness):
    out = run_ssh_password(
        TUNNEL_PW, "-p", str(TUNNEL_SSHD), f"{TUNNEL_USER}@{HOST}", "true")
    # ForceCommand /bin/false 会让命令失败，但认证必须通过。
    assert "Permission denied" not in out.stderr
    assert "Authentication failed" not in out.stderr


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
    """
    table = gateway_listen_table()
    assert f"127.0.0.1:{TUNNEL_PORT}" in table, table
    for wildcard in (f"0.0.0.0:{TUNNEL_PORT}", f"*:{TUNNEL_PORT}", f"[::]:{TUNNEL_PORT}"):
        assert wildcard not in table, table


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
