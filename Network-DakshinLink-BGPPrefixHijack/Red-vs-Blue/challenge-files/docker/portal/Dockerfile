FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      apache2 libapache2-mod-php php-cli openssh-client snmpd procps \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/snmpd /run/carrier /var/log/carrier-portal
COPY apache-carrier.conf /etc/apache2/sites-available/carrier.conf
COPY start-portal.sh /usr/local/sbin/start-portal.sh
COPY serial-mib.sh /usr/local/sbin/serial-mib.sh
RUN chmod 0755 /usr/local/sbin/start-portal.sh /usr/local/sbin/serial-mib.sh \
 && a2dissite 000-default \
 && a2ensite carrier
EXPOSE 80/tcp 161/udp
ENTRYPOINT ["/usr/local/sbin/start-portal.sh"]
