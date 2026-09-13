import socket

import pytest

from conftest import (
    APPLIANCE_PW, HOST, TUNNEL_PORT, TUNNEL_PW, TUNNEL_SSHD, TUNNEL_USER,
    engineer_proxy_option, port_listening_in_gateway, run_ssh_password,
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


def test_reverse_port_is_not_bound_on_external_interface(tunnel):
    """GatewayPorts no 必须把监听限制在 loopback。"""
    with pytest.raises(OSError):
        with socket.create_connection(("127.0.0.1", TUNNEL_PORT), timeout=3):
            pass


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
