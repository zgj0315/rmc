import signal
import subprocess
import tempfile
import time

import pytest

from conftest import (
    APPLIANCE_SSHD, HOST, TUNNEL_PORT, TUNNEL_PW, TUNNEL_SSHD, TUNNEL_USER,
    _stop_tunnel, popen_ssh_password, reverse_port_registered,
)

# 不是 ClientAliveInterval 10 × CountMax 3 = 30 秒再留余量——那个算法在这套
# OpenSSH（9.2p1）上实测不成立，见 Task 6 报告与 docs/方案设计.md §4.2：
# 实测回收耗时 79.5～80.1 秒（4 次独立测量，含直连与经 haproxy TLS 两条链路，
# 两条链路耗时相差不到 0.1 秒）。110 秒留了约 37% 余量，同时低于客户端「端口
# 占用」重试的 120 秒上限——这条测试必须在产品实际失败之前先失败，而不是等
# 客户端自己先放弃。客户端那个 120 秒上限如果将来改动，这个数字要跟着改。
RECLAIM_BUDGET = 110


def start_tunnel() -> tuple:
    # 输出写临时文件而不是管道：brief 原文给的是裸 popen_ssh_password()，会退回
    # PIPE 默认值。常驻进程的 PIPE 没人读，在 -W error 之下 GC 时会报
    # ResourceWarning: unclosed file，把 pytest.fail() 本该报的失败原因整个盖掉
    # ——诊断阶段实测命中过。改用 tunnel 固件同款的临时文件写法，调用方负责关闭。
    log = tempfile.TemporaryFile()
    proc = popen_ssh_password(
        TUNNEL_PW, "-N", "-T", "-p", str(TUNNEL_SSHD),
        "-o", "ExitOnForwardFailure=yes",
        "-o", "ServerAliveInterval=0",
        # -R 的目标地址由跑在宿主上的 ssh 客户端解析，宿主不在 compose 网络里，
        # 所以只能写一体机已发布到宿主的端口，不能写 compose 服务名。
        "-R", f"127.0.0.1:{TUNNEL_PORT}:{HOST}:{APPLIANCE_SSHD}",
        f"{TUNNEL_USER}@{HOST}",
        stdout=log, stderr=subprocess.STDOUT,
    )
    deadline = time.time() + 20
    while time.time() < deadline:
        if reverse_port_registered(TUNNEL_PORT):
            return proc, log
        time.sleep(0.5)
    proc.kill()
    log.close()
    pytest.fail("反向端口未建立")


def test_frozen_client_port_is_reclaimed_within_budget(harness):
    """SIGSTOP 冻结客户端，模拟静默断线；ClientAlive 必须回收端口。"""
    proc, log = start_tunnel()
    try:
        proc.send_signal(signal.SIGSTOP)
        deadline = time.time() + RECLAIM_BUDGET
        while time.time() < deadline:
            if not reverse_port_registered(TUNNEL_PORT):
                return
            time.sleep(1)
        pytest.fail(f"端口 {TUNNEL_PORT} 在 {RECLAIM_BUDGET} 秒内未被回收")
    finally:
        # 先 SIGCONT 再收尾：进程被 SIGSTOP 冻结时不会处理 SIGTERM，必须先解冻
        # 才能让下面的收尾杀掉它。改用 _stop_tunnel() 而不是裸的
        # terminate()+wait()：它会一直等到端口真的从 Gateway 的监听表里消失
        # 才返回，不然只保证了客户端进程退出，保证不了端口已经放行给下一个
        # 用例——conftest 里 _stop_tunnel() 的文档字符串就是在说这件事。
        proc.send_signal(signal.SIGCONT)
        try:
            _stop_tunnel(proc)
        finally:
            log.close()


def test_port_can_be_rebound_after_reclaim(harness):
    """回收之后同一端口必须能重新注册，这是客户端重连成功的前提。"""
    first, first_log = start_tunnel()
    first.send_signal(signal.SIGSTOP)
    try:
        deadline = time.time() + RECLAIM_BUDGET
        while time.time() < deadline and reverse_port_registered(TUNNEL_PORT):
            time.sleep(1)
        assert not reverse_port_registered(TUNNEL_PORT), "端口未回收，后续断言无意义"
        second, second_log = start_tunnel()
        try:
            _stop_tunnel(second)
        finally:
            second_log.close()
    finally:
        first.send_signal(signal.SIGCONT)
        try:
            _stop_tunnel(first)
        finally:
            first_log.close()
