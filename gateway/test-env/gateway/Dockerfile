FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      openssh-server haproxy socat iproute2 procps openssl python3 \
 && rm -rf /var/lib/apt/lists/*

# 构建上下文是 gateway/（见 compose 的 context: ..），以下路径都相对它书写。
# sshd_tunnel_config 等直接取仓库里的那一份，生产与测试共用同一个配置文件。
COPY sshd_tunnel_config /etc/ssh/sshd_tunnel_config
COPY sshd_engineer.conf /etc/ssh/sshd_config.d/engineer.conf
COPY haproxy.cfg /etc/haproxy/haproxy.cfg
COPY test-env/gateway/entrypoint.sh /usr/local/bin/entrypoint.sh

RUN mkdir -p /run/sshd \
 && ssh-keygen -A \
 && ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/tunnel_host_ed25519_key \
 && chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 22 443 2223
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
