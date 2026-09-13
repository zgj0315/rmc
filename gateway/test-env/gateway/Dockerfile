FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      openssh-server haproxy socat iproute2 procps openssl python3 bats \
 && rm -rf /var/lib/apt/lists/*

# 构建上下文是 gateway/（见 compose 的 context: ..），以下路径都相对它书写。
# sshd_tunnel_config 等直接取仓库里的那一份，生产与测试共用同一个配置文件。
COPY sshd_tunnel_config /etc/ssh/sshd_tunnel_config
COPY haproxy.cfg /etc/haproxy/haproxy.cfg
COPY test-env/gateway/entrypoint.sh /usr/local/bin/entrypoint.sh

RUN mkdir -p /run/sshd \
 && ssh-keygen -A \
 && ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/tunnel_host_ed25519_key \
 && chmod +x /usr/local/bin/entrypoint.sh

# 自签证书，仅测试环境用。生产环境用公共 CA 签发的证书，放在同一路径，不使用自签。
RUN mkdir -p /etc/haproxy/certs \
 && openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -subj "/CN=gateway.test" \
      -addext "subjectAltName=DNS:gateway.test" \
      -keyout /tmp/k.pem -out /tmp/c.pem \
 && cat /tmp/c.pem /tmp/k.pem > /etc/haproxy/certs/gateway.pem \
 && rm /tmp/k.pem /tmp/c.pem \
 && chmod 600 /etc/haproxy/certs/gateway.pem

EXPOSE 443 2223 22001
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
