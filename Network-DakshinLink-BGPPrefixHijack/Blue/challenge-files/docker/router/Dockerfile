FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      frr frr-pythontools openssh-server iproute2 iputils-ping \
      tcpdump procps netcat-openbsd ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd /run/carrier /var/log/carrier /root/.ssh \
 && chmod 0700 /root/.ssh
COPY start-router.sh /usr/local/sbin/start-router.sh
RUN chmod 0755 /usr/local/sbin/start-router.sh
EXPOSE 22 179
ENTRYPOINT ["/usr/local/sbin/start-router.sh"]
