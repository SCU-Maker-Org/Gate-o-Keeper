#!/usr/bin/env bash
set -euo pipefail

export INTERNAL_SECRET="${INTERNAL_MQTT_SECRET:?INTERNAL_MQTT_SECRET must be set}"
API_KEY="${MQTT_BROKER_API_KEY:?MQTT_BROKER_API_KEY must be set}"
API_SECRET="${MQTT_BROKER_API_SECRET:?MQTT_BROKER_API_SECRET must be set}"

perl -pe 's/__INTERNAL_MQTT_SECRET__/$ENV{INTERNAL_SECRET}/g' /etc/emqx-tmpl/emqx.conf.tmpl > /opt/emqx/etc/emqx.conf
printf '%s:%s:administrator\n' "${API_KEY}" "${API_SECRET}" > /opt/emqx/etc/api-keys.txt
chmod 600 /opt/emqx/etc/api-keys.txt /opt/emqx/etc/emqx.conf

exec /usr/bin/docker-entrypoint.sh emqx foreground
