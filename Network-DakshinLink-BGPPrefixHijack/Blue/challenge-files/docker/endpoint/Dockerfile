FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      vsftpd curl iproute2 ca-certificates openssh-server \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd /var/log/carrier
COPY start-ftp.sh /usr/local/sbin/start-ftp.sh
COPY start-client.sh /usr/local/sbin/start-client.sh
RUN chmod 0755 /usr/local/sbin/start-ftp.sh /usr/local/sbin/start-client.sh
