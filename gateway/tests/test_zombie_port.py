import signal
import subprocess
import tempfile
import time

import pytest

from conftest import (
    APPLIANCE_SSHD, HOST, TUNNEL_PORT, TUNNEL_PW, TUNNEL_SSHD, TUNNEL_USER,
    _stop_tunnel, gateway_listen_table, popen_ssh_password,
    reverse_port_registered,
)

# 实测回收耗时 79.5～81.6 秒（8 次独立测量，覆盖直连与经 haproxy 终止 TLS 两条
# 链路，也包含最终用这个预算跑验证时测得的 81.03/81.54 秒；见 Task 6 报告与
# docs/方案设计.md §4.2）——不是 ClientAliveInterval 10 × CountMax 3 = 30 秒
# 再留余量，那个算法在这套 OpenSSH（9.2p1）上实测不成立。110 秒比测到过的最
# 慢一次（约 81.6 秒）还多出约 28 秒、相当于预算的 26% 左右，同时低于客户端
# 「端口占用」重试的 120 秒上限——这条测试必须在产品实际失败之前先失败，而
# 不是等客户端自己先放弃。客户端那个 120 秒上限如果将来改动，这个数字要跟着改。
RECLAIM_BUDGET = 110


def _log_output(log) -> str:
    log.seek(0)
    return log.read().decode("utf-8", "replace").strip()


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
        if proc.poll() is not None:
            # 与 test_tls_frontend.py 的写法对齐：进程提前退出必须单独报出来，
            # 不能让它跟"20 秒内没等到端口"混成一条消息——分不清是隧道没建起
            # 来，还是根本没有进程在跑。
            output = _log_output(log)
            log.close()
            pytest.fail(
                f"隧道进程在建立反向端口之前就退出（退出码 {proc.returncode}）："
                f"{output}")
        if reverse_port_registered(TUNNEL_PORT):
            return proc, log
        time.sleep(0.5)
    proc.kill()
    # kill() 之后必须 wait()：不 wait，returncode 停在 None，Popen.__del__ 在
    # GC 时会报 ResourceWarning，在 -W error 之下变成一个归到不相干用例头上的
    # 错误，把这里本该报的 pytest.fail() 原因盖掉——跟当初把 stdout/stderr 从
    # PIPE 改成临时文件是同一类问题。
    proc.wait()
    output = _log_output(log)
    log.close()
    pytest.fail(f"反向端口未建立：{output}")


def test_frozen_client_port_is_reclaimed_within_budget(harness):
    """SIGSTOP 冻结客户端，模拟静默断线；ClientAlive 必须回收端口。"""
    proc, log = start_tunnel()
    try:
        # 冻结前的廉价活体检查：send_signal() 对一个已经退出的子进程是静默空
        # 操作（先 poll() 一次，退出码不是 None 就直接返回，不报错），如果客户端
        # 在注册端口之后、这里发 SIGSTOP 之前就已经退出，SIGSTOP 会悄悄打空，
        # 后面量到的其实是一个已经死透的进程，不是被冻结的进程。
        assert proc.poll() is None, (
            f"客户端在注册反向端口之后、冻结之前就已经退出"
            f"（退出码 {proc.returncode}）：{_log_output(log)}；"
            f"没有冻结住的客户端，后面端口是否消失证明不了 ClientAlive 起没起作用。"
        )
        proc.send_signal(signal.SIGSTOP)
        deadline = time.time() + RECLAIM_BUDGET
        while time.time() < deadline:
            if not reverse_port_registered(TUNNEL_PORT):
                # 更重要的一道检查：SIGSTOP 冻结住的进程不可能自己退出——如果
                # 此刻它已经不在了，只能是它在 SIGSTOP 生效之前就已经死了（比如
                # 认证之后、注册端口之后的某个瞬间崩溃），SIGSTOP 打在了一个空
                # 目标上。这种情况下端口消失是客户端自己断线释放的，不是
                # Gateway 的 ClientAlive 机制回收的，用例绿了但什么都没验证到
                # ——这正是本项目反复踩过的"假绿"形状，必须在这里拦住。
                assert proc.poll() is None, (
                    f"端口消失时客户端进程已经退出（退出码 {proc.returncode}）："
                    f"{_log_output(log)}；SIGSTOP 冻结的进程不会自己退出，"
                    f"能看到它退出说明冻结从一开始就没有生效，端口是客户端自己"
                    f"断线释放的，这条用例的绿色状态没有意义。"
                )
                return
            time.sleep(1)
        pytest.fail(
            f"端口 {TUNNEL_PORT} 在 {RECLAIM_BUDGET} 秒内未被回收；"
            f"当前监听表：\n{gateway_listen_table()}"
        )
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
    try:
        # 与另一条用例保持同样的结构：start_tunnel() 之后立刻进 try，SIGSTOP
        # 也在 try 里面发——不把它们留在 try 之外，是因为夹在中间的任何一条
        # 语句只要抛异常，finally 都不会跑，会漏掉收尾、把端口悬在那里占住，
        # 拖累下一条用例。两条用例的写法此前并不对称，这里改成一致。
        assert first.poll() is None, (
            f"客户端在注册反向端口之后、冻结之前就已经退出"
            f"（退出码 {first.returncode}）：{_log_output(first_log)}；"
            f"没有冻结住的客户端，后面端口是否消失证明不了 ClientAlive 起没起作用。"
        )
        first.send_signal(signal.SIGSTOP)
        wait_start = time.time()
        deadline = wait_start + RECLAIM_BUDGET
        while time.time() < deadline and reverse_port_registered(TUNNEL_PORT):
            time.sleep(1)
        waited = time.time() - wait_start
        assert not reverse_port_registered(TUNNEL_PORT), (
            f"端口未回收，后续断言无意义；已经等了 {waited:.0f} 秒"
        )
        assert first.poll() is None, (
            f"端口消失时客户端进程已经退出（退出码 {first.returncode}）："
            f"{_log_output(first_log)}；SIGSTOP 冻结的进程不会自己退出，"
            f"能看到它退出说明冻结从一开始就没有生效，端口是客户端自己断线释放的，"
            f"接下来重新注册的成功与否都跟本用例要验证的性质无关。"
        )
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
