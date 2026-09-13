#!/bin/bash
# 测试环境入口：建账号、起两个 sshd 与 haproxy，并把 loopback 上的
# sshd-tunnel 通过 socat 暴露到容器网卡的 2223，使宿主的测试能直连它。
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "必须以 root 运行：建账号、写 /home/eng 与起 sshd 都需要 root。" >&2
    exit 1
fi

useradd --system --shell /usr/sbin/nologin --no-create-home tunnel-zhang
echo 'tunnel-zhang:tunnel-init-pw' | chpasswd

groupadd engineers
useradd --shell /usr/sbin/nologin --no-create-home --gid engineers eng
mkdir -p /home/eng/.ssh
cp /engineer-keys/authorized_keys /home/eng/.ssh/authorized_keys
chown -R eng:engineers /home/eng
chmod 700 /home/eng/.ssh
chmod 600 /home/eng/.ssh/authorized_keys

# 两个 sshd 都用 -D -e：不 daemonize，日志写 stderr。镜像里没有 syslog 守护进程，
# 少了 -e 两个实例的日志会被直接丢弃，docker logs 里一个字都看不到，
# 认证与转发失败就只能靠猜。
/usr/sbin/sshd -t -f /etc/ssh/sshd_tunnel_config
/usr/sbin/sshd -D -e -f /etc/ssh/sshd_tunnel_config &

/usr/sbin/sshd -t
/usr/sbin/sshd -D -e &

# 测试用旁路：把容器网卡 2223 转到 loopback 2222。监听端口必须与 sshd-tunnel
# 的 127.0.0.1:2222 不同，否则 socat 绑 0.0.0.0:2222 会撞上 EADDRINUSE。
# 生产环境没有这一条。
socat TCP-LISTEN:2223,reuseaddr,fork TCP:127.0.0.1:2222 &

exec haproxy -W -db -f /etc/haproxy/haproxy.cfg
