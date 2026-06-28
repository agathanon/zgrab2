FROM zgrab2_service_base:latest

RUN apt-get install -y inspircd openssl

# Generate a self-signed certificate for STARTTLS.
RUN mkdir -p /etc/inspircd/ssl && \
    openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
      -keyout /etc/inspircd/ssl/key.pem \
      -out /etc/inspircd/ssl/cert.pem \
      -subj "/C=US/ST=State/L=City/O=Test/CN=irc-starttls.example.com" && \
    chmod 600 /etc/inspircd/ssl/key.pem

COPY inspircd.conf /etc/inspircd/inspircd.conf
COPY inspircd.motd /etc/inspircd/inspircd.motd

WORKDIR /
COPY entrypoint.sh .
RUN chmod a+x ./entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
