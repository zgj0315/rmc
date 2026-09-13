#!/bin/bash
# 测试环境入口：建隧道账号、起 sshd-tunnel 与 haproxy，并把 loopback 上的
# sshd-tunnel 通过 socat 暴露到容器网卡的 2223，使宿主的测试能直连它。
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "必须以 root 运行：建账号与起 sshd 都需要 root。" >&2
    exit 1
fi

useradd --system --shell /usr/sbin/nologin --no-create-home tunnel-zhang
echo 'tunnel-zhang:tunnel-init-pw' | chpasswd

# -D -e：不 daemonize，日志写 stderr。镜像里没有 syslog 守护进程，少了 -e
# 日志会被直接丢弃，docker logs 里一个字都看不到，认证与转发失败就只能靠猜。
/usr/sbin/sshd -t -f /etc/ssh/sshd_tunnel_config
/usr/sbin/sshd -D -e -f /etc/ssh/sshd_tunnel_config &

# 测试用旁路：把容器网卡 2223 转到 loopback 2222。监听端口必须与 sshd-tunnel
# 的 127.0.0.1:2222 不同，否则 socat 绑 0.0.0.0:2222 会撞上 EADDRINUSE。
# 生产环境没有这一条。
socat TCP-LISTEN:2223,reuseaddr,fork TCP:127.0.0.1:2222 &

exec haproxy -W -db -f /etc/haproxy/haproxy.cfg
