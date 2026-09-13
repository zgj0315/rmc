FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server \
 && rm -rf /var/lib/apt/lists/*
# 一体机的 SSH 默认端口是 61001，不是 22。harness 必须照这个端口起，否则任何
# 把 22 写死的代码都能全绿通过、到客户现场才炸。别把这里简化回 22。
RUN mkdir -p /run/sshd \
 && echo "root:appliance-dynamic-pw" | chpasswd \
 && echo "c0001-a1" > /etc/appliance-id \
 && printf '%s\n' \
      'Port 61001' \
      'PermitRootLogin yes' \
      'PasswordAuthentication yes' \
      'UsePAM yes' \
    > /etc/ssh/sshd_config.d/appliance.conf \
 && ssh-keygen -A
EXPOSE 61001
CMD ["/usr/sbin/sshd", "-D", "-e"]
