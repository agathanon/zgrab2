#!/bin/sh

set -x

while true; do
  ngircd --nodaemon --config /etc/ngircd/ngircd.conf
  echo "ngircd exited unexpectedly. Restarting..."
  sleep 1
done
