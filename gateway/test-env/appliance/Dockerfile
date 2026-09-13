FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server \
 && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /run/sshd \
 && echo "root:appliance-dynamic-pw" | chpasswd \
 && echo "c0001-a1" > /etc/appliance-id \
 && printf '%s\n' \
      'PermitRootLogin yes' \
      'PasswordAuthentication yes' \
      'UsePAM yes' \
    > /etc/ssh/sshd_config.d/appliance.conf \
 && ssh-keygen -A
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
