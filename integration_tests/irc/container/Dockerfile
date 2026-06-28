FROM zgrab2_service_base:latest

RUN apt-get install -y ngircd

COPY ngircd.conf /etc/ngircd/ngircd.conf

WORKDIR /
COPY entrypoint.sh .
RUN chmod a+x ./entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
