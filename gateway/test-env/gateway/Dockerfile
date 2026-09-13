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
#
# basicConstraints 与 extendedKeyUsage 这两行不是装饰：`openssl req -x509` 对自签
# 证书默认写的是 CA:TRUE，而 rustls-webpki 严格按 RFC 5280 办事，会以
# CaUsedAsEndEntity 拒绝一张 CA:TRUE 的证书被当作服务端（末端实体）证书使用——
# 无论它是否被信任。OpenSSL 在这一点上宽松，所以 Python 侧的 TLS 用例一直是绿的，
# 而 rmc-core 用 rustls 拨过来时「信任这张证书并握手成功」这半边永远走不通。
# 这是环境无关的，不是本机问题。改成 CA:FALSE 之后它仍然可以作为自己的信任锚
# 被 RootCertStore::add 收下，两侧都能用。
RUN mkdir -p /etc/haproxy/certs \
 && openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -subj "/CN=gateway.test" \
      -addext "subjectAltName=DNS:gateway.test" \
      -addext "basicConstraints=critical,CA:FALSE" \
      -addext "extendedKeyUsage=serverAuth" \
      -keyout /tmp/k.pem -out /tmp/c.pem \
 && cat /tmp/c.pem /tmp/k.pem > /etc/haproxy/certs/gateway.pem \
 && rm /tmp/k.pem /tmp/c.pem \
 && chmod 600 /etc/haproxy/certs/gateway.pem

EXPOSE 443 2223 22001
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
