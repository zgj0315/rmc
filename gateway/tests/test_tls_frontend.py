import socket
import ssl
import time

import pytest

from conftest import (
    APPLIANCE_SSHD, HAPROXY, HOST, TUNNEL_PORT, TUNNEL_PW, TUNNEL_USER,
    popen_ssh_password, port_listening_in_gateway,
)


def test_tls_handshake_succeeds_and_presents_gateway_test_cert(harness, gateway_tls_cert_pem):
    """握手必须真正校验证书链与主机名，不能只是探测到 443 上有 TLS 在应答。

    证书自签，正好拿它自己当信任锚：`load_verify_locations` 之后打开
    `CERT_REQUIRED` 与 `check_hostname`，握手会真的核验对方出示的证书链是否
    到这张证书为止、以及证书上的名字是否等于 `server_hostname="gateway.test"`。
    验证打开之后 `getpeercert()` 才会被填充，`["subject"]` 才读得出来。

    version 只认 TLSv1.2/TLSv1.3：haproxy.cfg 用 `ssl-min-ver TLSv1.2` 关掉了
    更低版本，这条断言要卡在同一条线上，否则比配置本身还宽松。
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cadata=gateway_tls_cert_pem)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    with socket.create_connection((HOST, HAPROXY), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname="gateway.test") as tls:
            assert tls.version() in ("TLSv1.2", "TLSv1.3")
            cn = dict(x[0] for x in tls.getpeercert(binary_form=False)["subject"])
            assert cn["commonName"] == "gateway.test"


def test_ssh_banner_arrives_through_tls(harness):
    """TLS 之内必须是 sshd-tunnel 的 banner。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((HOST, HAPROXY), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname="gateway.test") as tls:
            tls.settimeout(10)
            assert tls.recv(64).startswith(b"SSH-2.0-")


def test_reverse_tunnel_works_over_tls(tls_wrap):
    proc = popen_ssh_password(
        TUNNEL_PW, "-N", "-T", "-p", str(tls_wrap),
        "-o", "ExitOnForwardFailure=yes",
        # -R 的目标地址由跑在宿主上的 ssh 客户端解析，宿主不在 compose 网络里，
        # 所以只能写一体机已发布到宿主的端口，不能写 compose 服务名。
        "-R", f"127.0.0.1:{TUNNEL_PORT}:{HOST}:{APPLIANCE_SSHD}",
        f"{TUNNEL_USER}@{HOST}",
    )
    try:
        deadline = time.time() + 20
        while time.time() < deadline:
            if port_listening_in_gateway(TUNNEL_PORT):
                break
            time.sleep(0.5)
        else:
            pytest.fail(f"经 TLS 建立的反向端口未出现：{proc.stderr.read()}")
    finally:
        proc.terminate()
        proc.wait(timeout=10)
