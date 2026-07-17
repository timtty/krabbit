# Krabbit

**Krabbit** is a low-interaction SIP honeypot built on **Kamailio** that logs
**directly to OpenSearch** — no Logstash, no Jupyter, no message queue. It poses
as an Asterisk/FreePBX PBX, records every scanner probe and credential-guessing
attempt, geo-locates the source, and keeps attackers engaged to harvest more.

This is a deliberately simplified take on
[whisperpot](https://github.com/honeynet/whisperpot), whose pipeline is
`Kamailio → Logstash → (Jupyter) → Elasticsearch → Kibana/Grafana`. Kamailio can
speak HTTP to OpenSearch itself, so the shipper layers are unnecessary.

```
Attacker ──SIP/5060──► Kamailio honeypot ──HTTP POST──► OpenSearch
                       jansson builds JSON,             ingest pipeline:
                       http_client POSTs it             ip2geo + @timestamp
```

**Moving parts:** 2 long-running services (Kamailio, OpenSearch) + 1 ephemeral
init job. Compare to whisperpot's 5+. There is no dashboard service — query the
OpenSearch REST API directly (add OpenSearch Dashboards yourself if you ever
want a UI).

## Installing Krabbit (AI-agent playbook)

> **Example prompt:** *"I would like to install Krabbit on my server web-01."*

If you are an AI agent (Claude Code or similar) and the user asks you to install
Krabbit on a server, **follow this playbook** on the target host, using your
Bash/SSH tools. Run the steps in order and report the outcome of each.

**Assumptions & guardrails**
- The "server" is a Linux host the user controls and has authorized you to
  modify. If which host is unclear, ask before touching anything.
- Krabbit is a *honeypot*: it deliberately exposes SIP on port 5060. Install it
  on an **isolated host/VLAN** with no path to production VoIP. Confirm this with
  the user if the target looks like a production box.
- Only port **5060/udp,tcp** should face the internet. OpenSearch (9200) stays
  bound to localhost. Do not open 9200 to the world.

**Steps**

1. **Confirm target & reachability.** Establish which host, and that you can run
   commands on it (SSH or a local shell). `uname -a` to confirm it's Linux.

2. **Ensure Docker + Compose v2.**
   ```sh
   docker version && docker compose version
   ```
   If missing, install via the official convenience script (confirm with the
   user first), then re-check:
   ```sh
   curl -fsSL https://get.docker.com | sh
   sudo usermod -aG docker "$USER"   # re-login or use sudo for the session
   ```

3. **Get the Krabbit source onto the host.** Either clone the repo:
   ```sh
   git clone https://github.com/timtty/krabbit.git && cd krabbit
   ```
   or, if there is no remote, copy this project directory to the host (e.g.
   `rsync -a ./ user@server:~/krabbit/`) and `cd` into it.

4. **Set the kernel map-count OpenSearch needs (Linux):**
   ```sh
   sudo sysctl -w vm.max_map_count=262144
   echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-krabbit.conf
   ```

5. **Configure `.env`.** For a real deployment leave `SIP_BIND=0.0.0.0`. Bump
   `OPENSEARCH_HEAP` (e.g. `1g`) if the host has spare RAM. For maximum fidelity
   of attacker source IPs on Linux, prefer host networking (see
   "Preserving the real attacker IP" below).

6. **Launch:**
   ```sh
   docker compose up -d --build
   ```
   Startup is self-sequencing: OpenSearch → `os-init` (creates
   datasource/pipeline/ISM/template/index) → Kamailio. The first run waits
   ~30–60s for the GeoLite2 datasource to download.

7. **Open the firewall for SIP only:**
   ```sh
   sudo ufw allow 5060/udp && sudo ufw allow 5060/tcp     # or firewalld/cloud SG
   ```
   Do **not** expose 9200.

8. **Verify it works** (from the host):
   ```sh
   docker compose ps
   curl -s localhost:9200/_cluster/health | grep -o '"status":"[a-z]*"'
   # send a probe and confirm it lands:
   printf 'OPTIONS sip:100@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5062;branch=z9hG4bKk\r\nFrom: <sip:probe@127.0.0.1>;tag=1\r\nTo: <sip:100@127.0.0.1>\r\nCall-ID: install-check\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n' \
     | nc -u -w1 127.0.0.1 5060
   curl -s 'localhost:9200/sip-honeypot/_count'
   ```
   Expect a `200 OK` from Kamailio and a non-zero document count.

9. **Report back** to the user: which host, container status, the SIP listen
   address, that 9200 is localhost-only, and the OpenSearch query URL
   (`http://127.0.0.1:9200/sip-honeypot/_search`).

Then continue with the reference material below.

## What it does

- Listens on **UDP and TCP 5060** and answers like an Asterisk/FreePBX PBX
  (`Server: FPBX-...`) to attract and keep scanners engaged.
- Turns **every** SIP request into a JSON document and indexes it in
  OpenSearch. Values are serialized with Kamailio's `jansson` module, so a
  hostile `User-Agent`/`From`/`Contact` header **cannot** break the JSON or
  inject fields.
- **Harvests credentials.** REGISTER gets a `401` digest challenge and INVITE a
  `407` — so tools like sipvicious/svcrack keep sending username + digest-response
  guesses, all of which are logged (`auth_username`, `authorization`).
- **Reveals toll-fraud intent.** INVITE `To:` users (the numbers attackers try
  to dial) are captured in `to_user`.
- **Geo-locates attackers** via OpenSearch's `ip2geo` ingest processor
  (`src_geo.location`, `src_geo.country_name`, …).

## Quick start

Requires Docker + Docker Compose.

```sh
cd sip_honeypot
docker compose up -d --build
```

Startup order is handled automatically: OpenSearch comes up → `os-init` creates
the ip2geo datasource / pipeline / ISM policy / template / index → Kamailio
starts logging. (The first `os-init` run waits ~30–60s for the GeoLite2
datasource to download.)

Watch the honeypot:

```sh
docker compose logs -f kamailio
```

## Test it

From another machine (or locally with `SIP_BIND=127.0.0.1`), send a probe with
[sipsak](https://github.com/nils-ohlmeier/sipsak) or sipvicious:

```sh
# OPTIONS ping
sipsak -s sip:100@YOUR_HOST -vv

# Registration/credential probe
svmap YOUR_HOST            # sipvicious scan
svwar -m REGISTER YOUR_HOST
```

Then query what was captured:

```sh
curl -s 'http://127.0.0.1:9200/sip-honeypot/_search?pretty&size=5' \
  -H 'Content-Type: application/json' \
  -d '{"sort":[{"@timestamp":"desc"}]}'

# Top source IPs
curl -s 'http://127.0.0.1:9200/sip-honeypot/_search?pretty' \
  -H 'Content-Type: application/json' \
  -d '{"size":0,"aggs":{"ips":{"terms":{"field":"src_ip","size":10}}}}'
```

## Captured fields

| Field | Description |
|-------|-------------|
| `@timestamp` | Set by the ingest pipeline |
| `method` | SIP method (REGISTER, INVITE, OPTIONS, …) |
| `src_ip` / `src_port` / `transport` | Attacker source |
| `src_geo.*` | ip2geo enrichment of `src_ip` (`location` is a `geo_point`) |
| `from_user` / `from_uri` | Claimed identity |
| `to_user` / `to_uri` / `ruri` | Target (dial target for toll-fraud INVITEs) |
| `user_agent` | Scanner fingerprint (e.g. `friendly-scanner`) |
| `auth_username` | Username in a credential guess |
| `authorization` / `proxy_authorization` | Full digest attempt (crackable offline) |
| `contact` / `call_id` / `cseq` | Protocol details |

## How the direct-to-OpenSearch logging works

`kamailio/kamailio.cfg`:

1. `route(BUILD_DOC)` builds `$var(doc)` field-by-field with `jansson_set()`
   (each value is JSON-escaped, so hostile headers can't corrupt the document).
2. `route(LOG_ES)` POSTs it with `http_client_query()` to
   `http://opensearch:9200/sip-honeypot/_doc`, sending `Content-Type:
   application/json`. The POST is synchronous — fine here because OpenSearch is
   on the same Docker network (~1–5 ms) and honeypot traffic is low volume. A
   failed/rejected POST is logged but never stops the attacker from getting a
   reply.
3. `route(REPLY)` sends a believable SIP response (200 / 401 / 407), using
   `force_rport()` so replies reach the attacker's real source (scanners are
   frequently behind NAT).

`sip-honeypot` is an **ISM rollover alias** (created by
`opensearch/bootstrap.sh`), so the Kamailio config never needs a date in the
URL; indices roll daily and are deleted after 90 days.

## Preserving the real attacker IP (important)

Source IP is the most valuable field a honeypot collects, so make sure Kamailio
sees the *real* one. With Docker's default bridge networking, packets sent from
the **same host** (localhost testing) are NAT'd and arrive with the Docker
gateway's IP — you'll see something like `192.168.65.1` / `172.x.x.x` in
`src_ip`. Real traffic from **external** hosts is DNAT'd and *does* preserve the
client IP, so a normal internet-facing deployment is usually fine.

To be certain on a Linux production box, run Kamailio with host networking so
there is no NAT at all. In `docker-compose.yml`, replace the `kamailio` service's
`ports:` block with:

```yaml
    network_mode: host        # Linux only; sees real source IPs, no NAT
```

and change `ES_URL` in `kamailio/kamailio.cfg` to `http://127.0.0.1:9200/...`
(host networking means "opensearch" no longer resolves via the compose DNS).
OpenSearch already publishes on `127.0.0.1:9200`. Host networking is not
available on Docker Desktop for macOS/Windows — use it on the Linux host where
the honeypot actually runs.

## Security & operational notes

- **Only port 5060 is meant to be internet-facing.** OpenSearch (9200) binds to
  `127.0.0.1` only. Do not expose it.
- OpenSearch's security plugin is disabled (`DISABLE_SECURITY_PLUGIN=true`) for
  simplicity because it's an internal backend. If you put OpenSearch on a shared
  network, enable security and add credentials to the Kamailio POST via
  `http_client_query`'s header argument / an `Authorization` header.
- Run the honeypot on an **isolated host/VLAN** with no access to production
  VoIP. It advertises itself as a PBX; keep it that way — a decoy.
- On Linux hosts you may need `sysctl -w vm.max_map_count=262144` for OpenSearch.
  Docker Desktop (macOS/Windows) handles this for you.
- `ip2geo` downloads GeoLite2-City data on first run (needs outbound internet
  from the OpenSearch container). If offline, docs are still indexed, just
  without `src_geo` (the pipeline `on_failure` records `ingest_error`).

## Tuning

Edit `.env`:

- `OPENSEARCH_HEAP` — OpenSearch JVM heap (default `512m`).
- `SIP_BIND` — `0.0.0.0` for a real deployment, `127.0.0.1` for local testing.
- `OPENSEARCH_VERSION` — OpenSearch image tag.

Retention lives in the ISM policy in `opensearch/bootstrap.sh` (rollover
`min_index_age`, and the `delete` state's `min_index_age`).

