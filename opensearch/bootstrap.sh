#!/bin/sh
# Idempotently configure OpenSearch for the SIP honeypot:
#   1. ip2geo datasource -> downloads GeoLite2-City data (geospatial plugin)
#   2. ingest pipeline   -> geo enrichment (ip2geo) + @timestamp
#   3. ISM policy        -> daily rollover, delete after 90 days (OpenSearch's ILM)
#   4. index template    -> field mappings + wires in the pipeline & ISM rollover
#   5. bootstrap index   -> "sip-honeypot-000001" with write alias "sip-honeypot"
#
# Kamailio POSTs to /sip-honeypot/_doc; the alias routes to the current write index.
set -eu

OS="${OS_HOST:-http://opensearch:9200}"

echo "bootstrap: waiting for OpenSearch at $OS ..."
until curl -sf "$OS/_cluster/health?wait_for_status=yellow&timeout=5s" >/dev/null 2>&1; do
    printf '.'
    sleep 2
done
echo " up."

# put <path> <json> [tolerant]
# tolerant=1 -> a 4xx (e.g. "already exists" on re-run) is logged, not fatal.
put() {
    _tol="${3:-0}"
    code=$(curl -s -o /tmp/os_resp -w '%{http_code}' -X PUT \
        -H 'Content-Type: application/json' "$OS/$1" -d "$2")
    if [ "$code" -ge 300 ]; then
        echo "bootstrap: PUT /$1 -> HTTP $code"
        cat /tmp/os_resp; echo
        [ "$_tol" = "1" ] || exit 1
    else
        echo "bootstrap: PUT /$1 -> HTTP $code (ok)"
    fi
}

# 1. ip2geo datasource. Downloads GeoLite2-City from OpenSearch's public endpoint.
#    Tolerant: it already exists on re-runs.
put "_plugins/geospatial/ip2geo/datasource/city" '{
  "endpoint": "https://geoip.maps.opensearch.org/v1/geolite2-city/manifest.json",
  "update_interval_in_days": 3
}' 1

# Best-effort wait for the datasource to finish its first download so early
# events get geo-enriched. Not fatal if it is slow — the pipeline tolerates it.
echo "bootstrap: waiting for ip2geo datasource to become available ..."
i=0
while [ "$i" -lt 30 ]; do
    state=$(curl -s "$OS/_plugins/geospatial/ip2geo/datasource/city" \
        | sed -n 's/.*"state":"\([A-Z_]*\)".*/\1/p')
    [ "$state" = "AVAILABLE" ] && { echo "bootstrap: datasource AVAILABLE."; break; }
    printf '.'
    sleep 2
    i=$((i + 1))
done
[ "${state:-}" = "AVAILABLE" ] || echo " (not ready yet; geo will fill in once it downloads)"

# 2. Ingest pipeline: stamp @timestamp and geo-locate the attacker IP.
put "_ingest/pipeline/sip-honeypot" '{
  "description": "SIP honeypot enrichment",
  "processors": [
    { "set":    { "field": "@timestamp", "value": "{{{_ingest.timestamp}}}", "override": false } },
    { "ip2geo": { "field": "src_ip", "datasource": "city", "target_field": "src_geo", "ignore_missing": true } }
  ],
  "on_failure": [
    { "set": { "field": "ingest_error", "value": "{{ _ingest.on_failure_message }}" } }
  ]
}'

# 3. ISM policy: roll daily (or at 10gb), delete after 90 days. Auto-attaches to
#    sip-honeypot-* via ism_template.
put "_plugins/_ism/policies/sip-honeypot" '{
  "policy": {
    "description": "SIP honeypot retention",
    "default_state": "hot",
    "states": [
      {
        "name": "hot",
        "actions": [ { "rollover": { "min_index_age": "1d", "min_primary_shard_size": "10gb" } } ],
        "transitions": [ { "state_name": "delete", "conditions": { "min_index_age": "90d" } } ]
      },
      {
        "name": "delete",
        "actions": [ { "delete": {} } ],
        "transitions": []
      }
    ],
    "ism_template": [
      { "index_patterns": ["sip-honeypot-*"], "priority": 100 }
    ]
  }
}' 1

# 4. Index template: mappings + default pipeline + ISM rollover alias.
put "_index_template/sip-honeypot" '{
  "index_patterns": ["sip-honeypot-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "index.default_pipeline": "sip-honeypot",
      "index.plugins.index_state_management.rollover_alias": "sip-honeypot"
    },
    "mappings": {
      "properties": {
        "@timestamp":          { "type": "date" },
        "event_kind":          { "type": "keyword" },
        "method":              { "type": "keyword" },
        "src_ip":              { "type": "ip" },
        "src_port":            { "type": "integer" },
        "transport":           { "type": "keyword" },
        "realm":               { "type": "keyword" },
        "ruri":                { "type": "keyword", "ignore_above": 1024 },
        "from_uri":            { "type": "keyword", "ignore_above": 1024 },
        "from_user":           { "type": "keyword", "ignore_above": 256 },
        "to_uri":              { "type": "keyword", "ignore_above": 1024 },
        "to_user":             { "type": "keyword", "ignore_above": 256 },
        "call_id":             { "type": "keyword", "ignore_above": 256 },
        "cseq":                { "type": "keyword", "ignore_above": 128 },
        "user_agent":          { "type": "keyword", "ignore_above": 512 },
        "contact":             { "type": "keyword", "ignore_above": 1024 },
        "auth_username":       { "type": "keyword", "ignore_above": 256 },
        "authorization":       { "type": "keyword", "ignore_above": 2048 },
        "proxy_authorization": { "type": "keyword", "ignore_above": 2048 },
        "ingest_error":        { "type": "keyword", "ignore_above": 1024 },
        "src_geo": {
          "properties": {
            "location":         { "type": "geo_point" },
            "country_name":     { "type": "keyword" },
            "country_iso_code": { "type": "keyword" },
            "continent_name":   { "type": "keyword" },
            "region_name":      { "type": "keyword" },
            "city_name":        { "type": "keyword" }
          }
        }
      }
    }
  }
}'

# 5. Bootstrap the first backing index with the write alias.
put "sip-honeypot-000001" '{
  "aliases": { "sip-honeypot": { "is_write_index": true } }
}' 1

echo "bootstrap: done."
