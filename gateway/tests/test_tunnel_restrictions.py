import socket
import subprocess
import tempfile

import pytest

from conftest import (
    APPLIANCE_SSHD, HOST, TUNNEL_PW, TUNNEL_SSHD, TUNNEL_USER,
    compose, popen_ssh_password, run_sftp_password, run_ssh_password, wait_port,
)


def test_no_shell_and_no_command_execution(harness):
    """账号执行不了客户端指定的任意命令。

    正面证据：账号的登录 shell 是 `/usr/sbin/nologin`
    （test-env/gateway/entrypoint.sh 建账号时给的账号属性，不是
    sshd_tunnel_config 里的指令），认证一过、会话一建立，nologin 就会打印
    `This account is currently not available.` 并以 1 退出（同 test_tunnel.py
    里 `test_tunnel_account_authenticates_with_password` 的证据）。这句话只有
    认证真的成功之后才可能出现；如果只断言 stdout 里没有 "uid="、
    returncode != 0，连接失败（错口令、连不上）也会让两条断言一起成立，
    测试就成了假绿。

    这条测试的名字挂的是 ForceCommand，但实测发现这条 behavioral 证据其实是
    nologin 这一层扛的，不是 ForceCommand：有 ForceCommand 时 sshd 跑的是
    `nologin -c /bin/false`；删掉 ForceCommand 后 sshd 会跑
    `nologin -c id`——但 nologin 压根不理会自己收到的参数，两种情况打印的
    横幅、退出码、有没有 "uid=" 完全一样，这三条断言都不会因为单独删掉
    ForceCommand 而变红。这条边界并非没人管：`forcecommand /bin/false` 已经
    进了下面的参数化配置检查表，单独被那条断言钉住；只是钉住它的不是这条
    行为测试，读者不要把两者混为一谈（同样的两层结构见下面
    test_sftp_subsystem_is_unavailable 的说明）。
    """
    out = run_ssh_password(TUNNEL_PW, "-p", str(TUNNEL_SSHD),
                           f"{TUNNEL_USER}@{HOST}", "id")
    assert "This account is currently not available" in out.stdout, (
        f"rc={out.returncode} stdout={out.stdout!r} stderr={out.stderr!r}")
    assert out.returncode != 0
    assert "uid=" not in out.stdout


def test_no_pty(harness):
    out = run_ssh_password(TUNNEL_PW, "-tt", "-p", str(TUNNEL_SSHD),
                           f"{TUNNEL_USER}@{HOST}")
    assert out.returncode != 0
    assert "PTY allocation request failed" in out.stderr


def test_local_forwarding_is_refused(harness):
    """AllowTcpForwarding remote（连同 PermitOpen none）必须禁掉 -L。

    按原样只跑 `ssh -N -T -L ...` 会挂到超时：`-L` 的本地监听由客户端自己在
    本机绑定，这一步永远成功，跟服务端毫无关系；服务端只在真的有连接穿过隧道、
    客户端据此发出 direct-tcpip 通道请求时才会检查 AllowTcpForwarding /
    PermitOpen 并拒绝。`ExitOnForwardFailure=yes` 只覆盖「绑监听失败」这一种
    情况，管不到「通道被服务端拒」，所以光起转发不去用它，进程会一直挂着——
    这正是最初一次运行时两个用例超时的原因。这里改成把 ssh 起成后台进程，
    等本地端口真的开始监听后主动往里连一次，用这次连接触发服务端的拒绝，
    再从常驻进程的日志里读拒绝原因。

    目标写的是 `appliance:61001`：Task 5 已经把 test-env 的 appliance 容器挪到
    一体机真正的默认端口 61001，容器内不再有人听 22（已从 gateway 容器实测：
    连 `appliance:61001` 读得到 SSH 横幅，连 `appliance:22` 是
    Connection refused）。选一个真实开着的端口，是为了
    让 `data == b""` 这条检查本身也有区分度：如果转发被放行，客户端会真的收到
    一段 SSH 版本横幅（已实测：把 AllowTcpForwarding 和 PermitOpen 都放宽后，
    连接到转发端口能读到 `b'SSH-2.0-OpenSSH_9.2p1 ...'`）；如果转发被拒，通道
    在服务端就被关掉，永远收不到任何字节。也已实测过：只放开 AllowTcpForwarding
    （改成 all）而不动 PermitOpen，或者反过来只放开 PermitOpen 而不动
    AllowTcpForwarding，两种情况下服务端都还是报同一句
    "administratively prohibited"、客户端也还是收不到字节。`data == b""` 和
    `"administratively prohibited"` 这两条断言现在各管一层、缺一不可：前者是
    "转发没有把数据带过来"的结构性证据，后者才点出具体是被服务端的策略拒绝，
    不是凑巧对端没监听。

    失败路径也要把 ssh 的日志带出来，不能悄悄吞掉：`wait_port` 超时或者
    `recv` 失败，原因往往就写在这段日志里（比如认证失败的 `Permission
    denied`），不带出来看到的只会是一句「端口没监听」，得自己再猜一遍。
    """
    log = tempfile.TemporaryFile()
    try:
        proc = popen_ssh_password(
            TUNNEL_PW, "-N", "-T", "-p", str(TUNNEL_SSHD),
            "-o", "ExitOnForwardFailure=yes",
            "-L", "127.0.0.1:19099:appliance:61001",
            f"{TUNNEL_USER}@{HOST}",
            stdout=log, stderr=subprocess.STDOUT,
        )

        def output() -> str:
            log.seek(0)
            return log.read().decode("utf-8", "replace").strip()

        try:
            try:
                wait_port(19099, timeout=15)
            except TimeoutError:
                pytest.fail(f"本地转发端口 19099 未监听；ssh 输出：{output()}")
            try:
                with socket.create_connection(("127.0.0.1", 19099), timeout=5) as sock:
                    data = sock.recv(4096)
            except OSError as exc:
                pytest.fail(f"连接本地转发端口失败（{exc!r}）；ssh 输出：{output()}")
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=10)

        log_text = output()
    finally:
        log.close()

    assert data == b"", (
        f"预期通道被服务端拒绝、读不到数据，却收到了 {data!r}；ssh 输出：{log_text}")
    assert "administratively prohibited" in log_text, log_text


def test_reverse_port_outside_permitlisten_is_refused(harness):
    """`PermitListen` 只放行登记过的端口，别的必须被拒。

    Task 5 已经把这条改成裸端口形式（`PermitListen 22001`）、`GatewayPorts` 也
    改成了 `yes`（强制绑通配地址），地址因此不再是 `PermitListen` 判断的一部分：
    请求 22002 被拒的唯一原因就是端口不在放行项里。断言与 Task 5 之前一字未改
    ——"端口被拒"这条性质本来就不受绑定地址那一层的影响。
    """
    # -R 的目标地址由跑在宿主上的 ssh 客户端解析，宿主不在 compose 网络里，
    # 所以只能写一体机已发布到宿主的端口，不能写 compose 服务名。
    out = run_ssh_password(TUNNEL_PW, "-N", "-T", "-p", str(TUNNEL_SSHD),
                           "-o", "ExitOnForwardFailure=yes",
                           "-R", f"127.0.0.1:22002:{HOST}:{APPLIANCE_SSHD}",
                           f"{TUNNEL_USER}@{HOST}")
    assert out.returncode != 0
    assert "remote port forwarding failed" in out.stderr.lower()


def test_reverse_port_outside_permitlisten_is_refused_on_a_wildcard_address_too(harness):
    """换个绑定地址也绕不过端口限制。

    Task 5 落地之后这条用例才真正独立于上面那条。`PermitListen` 现在是裸端口
    形式（`PermitListen 22001`）、`GatewayPorts yes`，地址不再是 `PermitListen`
    判断的一部分，于是这两条用例的唯一差别就是请求里的绑定地址：上面请求
    `127.0.0.1:22002`，这里请求 `0.0.0.0:22002`，两者都只能因为端口 22002 不在
    放行项里而被拒。它多测出来的那条性质是"客户端换一个绑定地址也逃不出端口
    白名单"。

    Task 5 之前它并不比上面那条多测出什么：那时 `PermitListen` 是地址限定形式
    `127.0.0.1:22001`，请求 `0.0.0.0:22002` 地址与端口两个维度都对不上，被拒的
    原因跟上面那条并不是同一件事，但从客户端能看到的现象
    （"remote port forwarding failed"）上分不出区别。当时留着它，是为了那条性质
    一旦生效就立刻有测试盯着，而不是等 Task 5 落地时才想起来要写。
    """
    # 同上：-R 的目标地址由宿主的 ssh 客户端解析，不能写 compose 服务名。
    out = run_ssh_password(TUNNEL_PW, "-N", "-T", "-p", str(TUNNEL_SSHD),
                           "-o", "ExitOnForwardFailure=yes",
                           "-R", f"0.0.0.0:22002:{HOST}:{APPLIANCE_SSHD}",
                           f"{TUNNEL_USER}@{HOST}")
    assert out.returncode != 0
    assert "remote port forwarding failed" in out.stderr.lower()


def test_sftp_subsystem_is_unavailable(harness):
    """sftp 子系统必须不可用。

    只断言 returncode != 0 分不清「认证根本没过」和「认证过了、sftp 被挡」——
    错口令走 sftp 一样会以非零退出。已实测两者的 stderr 完全不同：错口令是
    `Permission denied (password).`；账号真的认证成功、但子系统被顶到
    `/bin/false` 时，sftp 客户端收不到合法的协议握手，报的是
    `Received message too long ...`。断言这条特征文本，才是「认证过了、
    子系统被挡」的正面证据。

    这条报错文本其实还是 nologin 的横幅：`Received message too long
    1416128883` 里的 `1416128883` 换成十六进制是 `0x54686973`，正是 ASCII
    的 `"This"`——也就是 `This account is currently not available.` 这句话
    的头四个字节，被 sftp 客户端当成了协议包的大端长度前缀去解析，自然「too
    long」。这说明本文件里"命令执行被挡"和"sftp 被挡"两条测试，观测到的
    根子其实是同一句 nologin 横幅，只是分别从两种客户端（ssh / sftp）的
    视角去读它。

    另外实测发现：这条防线其实有两层——就算删掉 `Subsystem sftp /bin/false`
    这一行，未声明的子系统请求会被 sshd 直接拒绝（"subsystem request failed"）；
    就算把它换成真正的 `/usr/lib/openssh/sftp-server`，顶层的
    `ForceCommand /bin/false` 也会覆盖掉子系统执行，报的还是这同一条
    "Received message too long"。两层里删掉任何一层单独都不会让 sftp 变得可用，
    所以这个用例事实上同时钉住了 ForceCommand 与 Subsystem 两处配置的组合效果。
    """
    out = run_sftp_password(TUNNEL_PW, "-P", str(TUNNEL_SSHD),
                            f"{TUNNEL_USER}@{HOST}")
    assert out.returncode != 0
    assert "Permission denied" not in out.stderr, out.stderr
    assert "Received message too long" in out.stderr, out.stderr


def test_agent_forwarding_is_refused(tunnel_effective_config):
    """AllowAgentForwarding no 必须生效——但这条在客户端这边看不出来。

    已实测：`-A` 发出的 auth-agent-req@openssh.com 通道请求，OpenSSH 客户端
    发送时 confirm=0（协议里就是 fire-and-forget），服务端准不准都不回任何东西，
    `ssh -vvv` 的日志里也只看得到「Requesting agent forwarding」，看不到任何
    成功/失败的回执。账号又挂着 ForceCommand /bin/false、shell 是 nologin，
    没有远端 shell 能拿来检查转发出来的 agent socket 到底能不能用。原
    Step 1 里 `-A -N -T` 的写法还有另一个问题：`-N` 根本不打开 session 通道，
    agent forwarding 请求依附在 session 通道上发出，于是连请求都不会发，
    ssh 只会一直空等到超时（实测复现）。

    准确地说，不可观测的是「客户端这一侧」：sshd 自己其实会在 debug 级别的
    日志里记下拒绝这件事（`session_auth_agent_req: agent forwarding
    disabled`），只是这份 shipped 配置的 LogLevel 没到能看见它的级别——
    为了让一个用例观测得到而调高生产配置的日志级别不划算，所以没有这么做。
    退而求其次，问 sshd 自己怎么解析配置：`sshd -T -C user=...` 把 Match 块
    解析完之后，这个账号连接时会实际生效的选项打出来，这正是 sshd 在真实
    连接里做判断时查的同一份结果。已用删除 `AllowAgentForwarding no` 这一行
    做过对照：删掉后 `sshd -T` 输出从 `allowagentforwarding no` 变成默认的
    `allowagentforwarding yes`，证明这条断言确实钉住了这一行配置。

    `tunnel_effective_config` 这份 fixture 跟下面参数化测试用的是同一次
    `sshd -T` 结果（module 级缓存，不会为了这一条测试再单起一次
    `docker compose exec`）。
    """
    assert "allowagentforwarding no" in tunnel_effective_config, tunnel_effective_config


def test_pubkey_auth_is_disabled(harness):
    """公钥认证端到端不可用——但这条测试本身分辨不出是哪条指令在管。

    只断言「有 Permission denied」区分不了「pubkey 被服务端整体禁用」和
    「pubkey 本来就允许、只是没有一把授权过的公钥可用」——tunnel-zhang 根本
    没有配置 authorized_keys，即便服务端允许 pubkey，客户端手上现成的公钥
    也不会通过，一样会以 "Permission denied" 收场。

    这里断言的 "(password)" 后缀，最初以为是 `PubkeyAuthentication no` 的
    证据，经复核证明判断错了：`sshd_tunnel_config` 里还有一条
    `AuthenticationMethods password`，单独这一条就会让服务端只广播
    "password" 一种可继续的认证方式——不管 `PubkeyAuthentication` 是 `yes`
    还是 `no`，"(password)" 这个后缀都由 `AuthenticationMethods` 决定。
    当初的对照实验（连 engineer 的 sshd，默认允许 pubkey、也没有
    `AuthenticationMethods`，报的是 "(publickey)"）同时改变了两条指令，
    把两者的差异全记到了其中一条头上——这类"换一个配置整体做对照"的验证，
    只有在两份配置恰好只差被测的那一条指令时才成立，这里不满足。
    （那个 engineer sshd 实例已经在 Task 5 随工程师入口一起删掉了，这个对照
    实验现在也复现不了，留在这里只是为了说明当初的结论是怎么被推翻的。）

    因此删掉 `PubkeyAuthentication no` 并不会让这条断言变红（"(password)"
    后缀不会变成 "(publickey)"，因为 `AuthenticationMethods password` 还在）。
    这条连接测试依然有意义——它端到端证明了公钥确实用不了——但"是哪条指令挡的"
    这件事，改由下面参数化配置检查表里的 `pubkeyauthentication no` 和
    `authenticationmethods password` 两条分别钉住。
    """
    out = subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null",
         "-o", "PreferredAuthentications=publickey",
         "-o", "ConnectTimeout=10",
         "-p", str(TUNNEL_SSHD), f"{TUNNEL_USER}@{HOST}"],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=25,
    )
    assert out.returncode != 0
    assert "Permission denied (password)." in out.stderr, out.stderr


@pytest.fixture(scope="module")
def tunnel_effective_config(harness):
    """tunnel-zhang 在这份配置下、sshd 自己解析出来的有效配置（转小写后按行返回）。

    跟 test_agent_forwarding_is_refused 用的是同一个查法：带 `-C user=...` 让
    Match 块真的被解析，输出反映的是账号连接时 sshd 实际会查到的值，而不是
    源文件里的原始文本。

    返回的是 `splitlines()` 之后的行列表，不是整段字符串——`sshd -T` 每条指令
    正好各占一行，按整段字符串做子串匹配会被一条不相关的指令"顺便"命中：
    `ForceCommand /bin/false; curl evil` 整段文本里依然包含子串
    `"forcecommand /bin/false"`，子串断言会误判通过；按行列表做精确匹配
    （`"forcecommand /bin/false" in lines`）才会因为整行对不上而正确判定失败
    （已用这个具体例子实测过两种写法的差异，见 task-3-report.md）。安全测试
    里这类"看起来在检查、其实只check了子串"的写法尤其危险，不能留。
    """
    out = compose("exec", "-T", "gateway", "sshd", "-T",
                  "-f", "/etc/ssh/sshd_tunnel_config",
                  "-C", f"user={TUNNEL_USER},host=test,addr=127.0.0.1",
                  check=False, timeout=20)
    assert out.returncode == 0, f"sshd -T 失败：{out.stderr}"
    return out.stdout.lower().splitlines()


# 下面这张表钉住的是两类东西，写法一样（在 sshd -T 的有效配置里精确匹配一整
# 行），但各自的成因不同：
#
# 一类是「双重保险」——两条指令二选一在场，行为测试就测不出少了哪一条：
#
# - sftp：`Subsystem sftp /bin/false` 与顶层 `ForceCommand /bin/false` 二选一
#   在场，test_sftp_subsystem_is_unavailable 报的都是同一句
#   "Received message too long"；只删 Subsystem 那一行，未声明的子系统请求会被
#   sshd 直接拒绝（"subsystem request failed"，行为测试的断言依然会因为文本
#   变了而失败，但那是巧合，不是这条测试在把关）；只删 ForceCommand、换成真正
#   的 sftp-server，sftp 会变得可用，行为测试才会失败。
# - 本地转发：`AllowTcpForwarding remote` 与 `PermitOpen none` 二选一在场，
#   test_local_forwarding_is_refused 报的都是同一句 "administratively
#   prohibited"；只放宽其中一条、留着另一条，实测过报错文本完全不变，行为
#   测试会继续通过，看不出少了一层。
#
# 另一类是「归因搞错了」——行为测试的可观察现象其实由另一条指令决定，不是
# 名字上挂的那一条：
#
# - `PubkeyAuthentication no`：test_pubkey_auth_is_disabled 断言的
#   "Permission denied (password)." 后缀实际由 `AuthenticationMethods
#   password` 决定，删掉 `PubkeyAuthentication no` 不会改变这个后缀，行为
#   测试测不出来（详见该测试的 docstring）。
# - `AuthenticationMethods password`：同上，这条才是真正决定后缀的指令，
#   之前完全没有测试盯着它。
#
# 以上六条、加上后来补的四条（X11Forwarding、AllowStreamLocalForwarding、
# LoginGraceTime、MaxAuthTries——这四条目前没有任何行为测试覆盖，是本文件
# 最早的疏漏，不是哪层backstop的问题），已经逐条用 sshd -T 实测过删除效果
# （见 task-3-report.md），确认删掉后 effective config 都会变成默认值，
# 因而都会让参数化测试里对应的那一行断言真的变红——除了 X11Forwarding 一条
# 例外，见它自己的注释。
#
# `nologin` 登录 shell（test_no_shell_and_no_command_execution 的另一层保险）
# 不在这张表里：那是测试环境建账号时给的 `--shell /usr/sbin/nologin`
# （见 test-env/gateway/entrypoint.sh），不是 sshd_tunnel_config 里的指令，
# `sshd -T` 查不到，也不归这份配置管。
#
# `GatewayPorts no` 故意没放进这张表：Task 5 会把它改成 `yes`（强制反向端口
# 绑通配地址），现在写一条「必须是 no」的断言，Task 5 一落地就得立刻删掉，
# 不如现在就不写——这是刻意的取舍，不是漏掉了。
#
# 全分支审查（task-8）又补了下面六条。之前漏掉的不是随便哪六条指令，是这张表
# 里后果最重的六条——少了它们，这张表能钉住"边界能不能绕过"，钉不住"客户已
# 经拍板的取舍是否还在悄悄被推翻"：
#
# - clientaliveinterval 10 / clientalivecountmax 3：唯一挡着「有人把约 80 秒
#   的反向端口回收时间悄悄调回约 30 秒」这件事的两行。方案与手册四处都写着
#   约 80-90 秒是客户在看过"调小间隔换来维护会话可能被中途打断"这个代价之后
#   拍板接受的数字（见 `sshd_tunnel_config` 这两行上方的注释、docs/方案设计.md
#   §4.2）。把 `ClientAliveInterval` 改成 4，回收时间会精确降到约 32 秒——
#   `test_zombie_port.py` 110 秒的预算依然通过，63 个用例依然全绿，这个决定
#   却已经被悄悄推翻。
# - listenaddress 127.0.0.1:2222：唯一挡着「sshd-tunnel 直接监听公网网卡、
#   在 haproxy 旁边裸奔明文 SSH」这件事的一行。改成 `0.0.0.0` 之后，所有端到
#   端用例依然经 127.0.0.1:2222（生产）或 2223（测试环境的 socat 旁路）连接，
#   一个用例都不会变红，却在生产上让 443 之外多出一个不经 TLS 终止的入口，
#   haproxy 的 TLS 终止形同虚设。
# - allowusers tunnel-* / permitrootlogin no：这个 sshd 实例本身「只认
#   tunnel-* 账号、且这些账号不可能是 root」的边界，两条各管一半，缺一条
#   都不完整。
# - permitlisten *:22001（对应 `sshd_tunnel_config` 受管区段里裸端口形式的
#   `PermitListen 22001`）：钉住裸端口写法本身。`sshd -T` 把它规范化成
#   `*:<端口>` 打印，不是原始写法的字面 `22001`，所以这里必须写成 `*:22001`
#   才对得上；已实测删掉这一行后，tunnel-zhang 的有效值回退到 Match 块之外
#   的全局默认 `permitlisten none`。
#
# 逐条用 sshd -T 实测过删除效果（task-8-report.md 有完整表格），六条里五条
# 删除后都会让参数化测试对应的那一行断言真的变红：
#
#   ListenAddress        → listenaddress [::]:22 / listenaddress 0.0.0.0:22
#   PermitRootLogin       → permitrootlogin without-password
#   AllowUsers            → 整行消失，sshd -T 不再打印 allowusers
#   ClientAliveInterval   → clientaliveinterval 0
#   PermitListen（裸端口）→ permitlisten none（回退到全局默认拒绝）
#
# ClientAliveCountMax 是本表继 X11Forwarding 之后第二个例外：OpenSSH 的出厂
# 默认值本来就是 3，删掉这一行之后 `sshd -T` 打出来的仍然是逐字相同的
# `clientalivecountmax 3`——这条断言钉不住「整行被删掉」，只钉得住「被显式
# 改成别的数字」（例如手滑写成 `ClientAliveCountMax 5`，那样才会变红）。如实
# 记录，不假装它跟其余五条一样能防删除；`ClientAliveInterval` 那一条不受这个
# 问题影响，出厂默认是 0，删掉之后一定会变。
_LAYERED_DIRECTIVES = [
    pytest.param("forcecommand /bin/false", id="ForceCommand"),
    pytest.param("subsystem sftp /bin/false", id="Subsystem-sftp"),
    pytest.param("allowtcpforwarding remote", id="AllowTcpForwarding"),
    pytest.param("permitopen none", id="PermitOpen"),
    pytest.param("pubkeyauthentication no", id="PubkeyAuthentication"),
    pytest.param("authenticationmethods password", id="AuthenticationMethods"),
    # 例外：这条 OpenSSH 版本的 X11Forwarding 默认值本来就是 no，删掉这一行
    # 效果不变（已实测：删除后 sshd -T 仍报 "x11forwarding no"）。留着这条
    # 断言只能防"有人把它显式改成 yes"，防不了"整行被删掉"——如实记录，
    # 不假装它跟其他几条一样能防删除。
    pytest.param("x11forwarding no", id="X11Forwarding"),
    pytest.param("allowstreamlocalforwarding no", id="AllowStreamLocalForwarding"),
    pytest.param("logingracetime 20", id="LoginGraceTime"),
    pytest.param("maxauthtries 3", id="MaxAuthTries"),
    pytest.param("listenaddress 127.0.0.1:2222", id="ListenAddress"),
    pytest.param("permitrootlogin no", id="PermitRootLogin"),
    pytest.param("allowusers tunnel-*", id="AllowUsers"),
    pytest.param("clientaliveinterval 10", id="ClientAliveInterval"),
    # 例外（同上 X11Forwarding）：OpenSSH 的出厂默认值本来就是 3，删掉这一行
    # 不会变红，只有显式改成别的数字才会。
    pytest.param("clientalivecountmax 3", id="ClientAliveCountMax"),
    pytest.param("permitlisten *:22001", id="PermitListen-bare-port"),
]


@pytest.mark.parametrize("expected_line", _LAYERED_DIRECTIVES)
def test_layered_directive_is_still_individually_in_effect(
        tunnel_effective_config, expected_line):
    """防止「行为测试测的是端到端现象，测不出具体是哪条指令在管」这一类静默退化。

    这条测试跟上面的行为测试做的是不同的事：行为测试证明边界端到端仍然挡得住，
    这条测试证明挡住它的每一条配置本身还都在——两者都要，缺一个都会漏掉一种
    退化路径。谁把这张表里的某一行从 sshd_tunnel_config 删掉（或者悄悄改了
    值），行为测试可能因为另一层 backstop、或者巧合被别的断言接住、或者
    归因本来就点错了指令，而继续全绿；这条测试会先变红，而且失败信息
    （`expected_line` 是哪一个 `id`）直接就是「哪一条指令出了问题」，不用
    像行为测试那样先去猜是不是 connection 层面出了别的事。
    """
    assert expected_line in tunnel_effective_config, tunnel_effective_config


@pytest.fixture(scope="module")
def tunnel_effective_config_unenrolled(harness):
    """一个不在受管区段里的 tunnel-* 账号，在这份配置下的有效配置。

    与 `tunnel_effective_config` 用的是同一份配置文件、同一条查法，只是
    `-C user=` 换成一个 registry.toml 和受管区段里都不存在的 tunnel-* 用户名
    （`tunnel-ghost`，不需要真实系统账号——`sshd -T -C` 只按 Match 的模式串
    判断，不查 passwd）。sshd 因此不会匹配到 `Match User tunnel-zhang` 那个
    块，看到的正是 Match 块之外的全局默认值——这正是全局默认拒绝
    （`PermitListen none`）要保护的场景：账号已经在 tunnel-* 的命名空间里、
    能连上也能通过认证，但还没有人跑过 enroll-account.sh，此时反向端口必须
    是"什么都转不了"，不能退化成出厂默认的"任意端口绑 0.0.0.0"。
    """
    out = compose("exec", "-T", "gateway", "sshd", "-T",
                  "-f", "/etc/ssh/sshd_tunnel_config",
                  "-C", "user=tunnel-ghost,host=test,addr=127.0.0.1",
                  check=False, timeout=20)
    assert out.returncode == 0, f"sshd -T 失败：{out.stderr}"
    return out.stdout.lower().splitlines()


def test_permitlisten_default_deny_applies_to_unenrolled_tunnel_account(
        tunnel_effective_config_unenrolled):
    """全局默认拒绝（`PermitListen none`）此前只被一条 bats 用例当纯文本盯住
    （在 fixture 或真实文件里 grep 这一行还在不在），从没有人问过 sshd 自己：
    对一个真实会匹配到 `tunnel-*` 但没有专属 Match 块的账号，解析出来的有效
    值是不是真的是 `none`。

    已实测删除 `sshd_tunnel_config` 里 `PermitListen none` 这一行做过对照：
    删掉后这个未登记账号的有效值从 `permitlisten none` 变成出厂默认的
    `permitlisten any`，证明这条断言确实钉住了这一行，不是巧合通过。
    """
    assert "permitlisten none" in tunnel_effective_config_unenrolled, (
        tunnel_effective_config_unenrolled)
