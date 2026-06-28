#!/bin/sh

set -x

# Start stunnel for TLS-wrapped IRC on port 6697 (forwarding to plaintext
# ngircd on 6667).
stunnel /etc/stunnel/stunnel.conf

# Run plain ngircd in the foreground.
while true; do
  ngircd --nodaemon --config /etc/ngircd/ngircd.conf
  echo "ngircd exited unexpectedly. Restarting..."
  sleep 1
done
