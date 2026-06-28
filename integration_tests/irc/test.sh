#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
ZGRAB_ROOT=$(git rev-parse --show-toplevel)
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

mkdir -p $ZGRAB_OUTPUT/irc

OUTPUT_ROOT="$ZGRAB_OUTPUT/irc"

function dumpDockerLogs() {
  echo "irc/test: BEGIN docker logs from $CONTAINER_NAME [{("
  docker logs --tail all $CONTAINER_NAME
  echo ")}] END docker logs from $CONTAINER_NAME"
}

echo "irc/test: Tests runner for irc"

# Plain IRC registration test (default port 6667), with IRCv3 CAP negotiation.
CONTAINER_NAME=zgrab_irc
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh irc > $OUTPUT_ROOT/irc.json
dumpDockerLogs

# Plain IRC registration without CAP negotiation.
CONTAINER_NAME=zgrab_irc
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh irc --skip-cap > $OUTPUT_ROOT/irc_no_cap.json
dumpDockerLogs

# IRC over TLS (stunnel-wrapped on port 6697).
CONTAINER_NAME=zgrab_irc_tls
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh irc --ircs -p 6697 > $OUTPUT_ROOT/irc_tls.json
dumpDockerLogs

# IRC with IRCv3 STARTTLS (InspIRCd on the default plaintext port 6667).
CONTAINER_NAME=zgrab_irc_starttls
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh irc --starttls > $OUTPUT_ROOT/irc_starttls.json
dumpDockerLogs

# Check that the expected fields are populated in the plaintext result.
FIELDS="welcome isupport motd"
status=0
for field in $FIELDS; do
    echo "check irc.json for $field"
    RESULT=$(jp data.irc.result.$field < $OUTPUT_ROOT/irc.json)
    if [ "$RESULT" = "null" ]; then
        echo "Did not find $field in irc.json [["
        cat $OUTPUT_ROOT/irc.json
        echo "]]"
        status=1
    fi
done

# The TLS result must carry a TLS log.
echo "check irc_tls.json for tls log"
if [ "$(jp data.irc.result.tls < $OUTPUT_ROOT/irc_tls.json)" = "null" ]; then
    echo "Did not find tls log in irc_tls.json [["
    cat $OUTPUT_ROOT/irc_tls.json
    echo "]]"
    status=1
fi

# The STARTTLS result must report success and carry a TLS log.
echo "check irc_starttls.json for starttls success + tls log"
if [ "$(jp data.irc.result.starttls < $OUTPUT_ROOT/irc_starttls.json)" != '"success"' ] \
   || [ "$(jp data.irc.result.tls < $OUTPUT_ROOT/irc_starttls.json)" = "null" ]; then
    echo "STARTTLS did not succeed in irc_starttls.json [["
    cat $OUTPUT_ROOT/irc_starttls.json
    echo "]]"
    status=1
fi

exit $status
