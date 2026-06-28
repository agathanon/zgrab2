#!/bin/sh

set -x

while true; do
  inspircd --nofork --runasroot --nolog --nopid --config /etc/inspircd/inspircd.conf
  echo "inspircd exited unexpectedly. Restarting..."
  sleep 1
done
