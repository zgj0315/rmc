import socket
import ssl
import subprocess
import tempfile
import time

import pytest

from conftest import (
    APPLIANCE_SSHD, HAPROXY, HOST, TUNNEL_PORT, TUNNEL_PW, TUNNEL_USER,
    _stop_tunnel, popen_ssh_password, port_listening_in_gateway,
)


def test_tls_handshake_succeeds_and_presents_gateway_test_cert(harness, gateway_tls_cert_pem):
    """握手必须真正校验证书链与主机名，不能只是探测到 443 上有 TLS 在应答。

    证书自签，正好拿它自己当信任锚：`load_verify_locations` 之后打开
    `CERT_REQUIRED` 与 `check_hostname`，握手会真的核验对方出示的证书链是否
    到这张证书为止、以及证书上的名字是否等于 `server_hostname="gateway.test"`。
    验证打开之后 `getpeercert()` 才会被填充，`["subject"]` 才读得出来。

    version 只认 TLSv1.2/TLSv1.3，但这条断言本身不足以证明 haproxy.cfg 的
    `ssl-min-ver TLSv1.2` 真的在起作用——本机 venv 用的 LibreSSL 客户端最高
    也只谈到 TLSv1.2，删掉那一行配置，这条断言照样绿。

    下面另起一次握手，把客户端能谈的版本摁死在 TLSv1.1，验证「这个前端从不
    接受 TLSv1.2 以下的握手」这条契约本身。**但经过实测确认**：这条负向探针
    在把 `ssl-min-ver TLSv1.2` 从配置里删掉之后仍然通过——这个 haproxy 版本
    （2.6.12，链接 OpenSSL 3.0）在没有该指令时本身就已经拒绝 TLSv1.0/1.1，
    所以它并不能像最初设想的那样，把红绿状态和这一行配置的有无关联起来。
    留着它是因为它仍然验证了一个真实且值得写进契约的属性，只是它验证的是
    「服务端的实际行为」，不是「这一行配置在起作用」。
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

    neg_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    neg_ctx.load_verify_locations(cadata=gateway_tls_cert_pem)
    neg_ctx.verify_mode = ssl.CERT_REQUIRED
    neg_ctx.check_hostname = True
    neg_ctx.minimum_version = ssl.TLSVersion.TLSv1_1
    neg_ctx.maximum_version = ssl.TLSVersion.TLSv1_1
    with socket.create_connection((HOST, HAPROXY), timeout=10) as raw:
        with pytest.raises(ssl.SSLError):
            neg_ctx.wrap_socket(raw, server_hostname="gateway.test")


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
    """经 tls_wrap 建立反向隧道，失败路径与收尾都对齐 `tunnel` 固件的写法。

    输出必须接文件而不是 PIPE：`-N -T` 是常驻进程，没人读的管道写满会把 ssh
    卡死，红色路径里 ssh 还活着时也读不出已有内容，`pytest.fail` 永远到不了，
    整个套件跟着挂住而不是报红。收尾也必须走 `_stop_tunnel`，等 Gateway 上的
    反向端口真的消失，不然它会残留下来把按字母序紧跟其后的 `test_tunnel.py`
    带塌。
    """
    log = tempfile.TemporaryFile()
    proc = popen_ssh_password(
        TUNNEL_PW, "-N", "-T", "-p", str(tls_wrap),
        "-o", "ExitOnForwardFailure=yes",
        # -R 的目标地址由跑在宿主上的 ssh 客户端解析，宿主不在 compose 网络里，
        # 所以只能写一体机已发布到宿主的端口，不能写 compose 服务名。
        "-R", f"127.0.0.1:{TUNNEL_PORT}:{HOST}:{APPLIANCE_SSHD}",
        f"{TUNNEL_USER}@{HOST}",
        stdout=log, stderr=subprocess.STDOUT,
    )

    def output() -> str:
        log.seek(0)
        return log.read().decode("utf-8", "replace").strip()

    try:
        deadline = time.time() + 20
        while time.time() < deadline:
            if proc.poll() is not None:
                pytest.fail(
                    f"隧道进程提前退出（退出码 {proc.returncode}）：{output()}")
            if port_listening_in_gateway(TUNNEL_PORT):
                break
            time.sleep(0.5)
        else:
            pytest.fail(f"经 TLS 建立的反向端口未出现：{output()}")
    finally:
        try:
            _stop_tunnel(proc)
        finally:
            log.close()
