FROM zgrab2_service_base:latest

RUN apt-get install -y ngircd stunnel4 openssl

# Generate self-signed certificate for TLS
RUN mkdir -p /etc/stunnel && \
    openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
      -keyout /etc/stunnel/stunnel.key \
      -out /etc/stunnel/stunnel.crt \
      -subj "/C=US/ST=State/L=City/O=Test/CN=irc-tls.example.com" && \
    cat /etc/stunnel/stunnel.key /etc/stunnel/stunnel.crt > /etc/stunnel/stunnel.pem && \
    chmod 600 /etc/stunnel/stunnel.pem

COPY ngircd.conf /etc/ngircd/ngircd.conf
COPY stunnel.conf /etc/stunnel/stunnel.conf

WORKDIR /
COPY entrypoint.sh .
RUN chmod a+x ./entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
