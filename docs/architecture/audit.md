---
title: Audit
description: "Who asked for what, and whether it was allowed: Kayra's audit of every /check decision and every request to its own routes, to a file, an HTTP endpoint or nowhere, and how to feed it to a SIEM: Wazuh, Splunk."
weight: 26
---

# Audit

Kayra writes an audit record for every decision it takes:

- **`stage: check`**: an app's request, decided by `/check`. The record
  says whether it was allowed and why. The app's response is unknown to
  Kayra.
- **`stage: request`**: a request to Kayra's own routes, its
  `system`, `catalog` and `authorization` groups and the authorization
  server's sessions. Kayra serves them, so the record also has the HTTP
  `status`.

The audit is never stored in etcd and never holds a request's body. It is
off until `audit.backend` is set. The examples use
[`infrapi-cli`](https://infrapi.github.io/cli/getting-started/#1-install)
against a Kayra at `https://kayra.example.com`.

## 1. Choose where it goes

```yaml
audit:
  backend: file            # file | api | none (the default)
  reads: false             # get and list too; by default only writes and denials
  file:
    path: /var/log/kayra/audit.log   # "-" for stdout
```

| `backend` | What it does |
|---|---|
| `none` | Nothing. The default. |
| `file` | One JSON line per record, appended to `file.path` (created 0600) and flushed at once. `-` writes to stdout, for a container's log collector. `SIGHUP` reopens the file, for logrotate. |
| `api` | POSTs the records in batches, `{"items": [...]}`, to `api.url`, from a queue: a request never waits on the endpoint. |

**What is audited:**

- **Always:** every write (create, update, patch, delete, an action) and every
  denial, a read included: a `401`, a `403`, or a `/check` that is not
  allowed, or that Kayra refused itself (a namespace that does not exist).
- **With `reads: true`:** allowed `get` and `list` too.
- **Never:** the `-/` routes (health, metrics, docs), the bodies, the token
  endpoints, and an allowed [event](events.md) write.

## 2. The record

```json
{"id": "0193a0c4-…", "time": "2026-11-23T18:42:07.311Z", "stage": "check",
 "request_id": "6f1c…", "user": "jdoe", "groups": ["sandbox-acme-devs"], "kind": "user",
 "client_id": "infrapi-cli", "source_ip": "203.0.113.12", "user_agent": "infrapi-cli/1.2.0",
 "api": "compute.infrapi.io", "namespace": "core", "resource": "vms/reboot", "name": "web-1", "verb": "update",
 "allowed": false, "reason": "your roles in namespace \"core\" grant api \"compute.infrapi.io\", but not \"update\" on \"vms/reboot\""}
```

- **`id`:** a UUIDv7, so the ids sort by time.
- **`kind`:** `user`, `serviceaccount` or `api`: see
  [Service accounts](service-accounts.md) and [API identity](api-identity.md).
- **`request_id`:** the request's `X-Request-Id`. For `stage: check`, it is
  the original request's, with its `source_ip` and `user_agent`: an app on
  infrapi/lib sends them in the check. Otherwise they are the app's own.
  The request's [event](events.md) carries the same `request_id`.
- **`status`:** for `stage: request`, the response's. For `stage: check`, set
  only when Kayra refused the check itself (a `404`).

To see one, refuse yourself something:

**infrapi-cli**

```bash
infrapi-cli auth can-i delete vms.compute.infrapi.io -n core
```

**curl**

```bash
curl -s -X POST https://kayra.example.com/apis/authorization.infrapi.io/v1/check \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"namespace": "core", "api": "compute.infrapi.io", "resource": "vms", "verb": "delete"}'
```

The record is the last line of the file:

```bash
tail -1 /var/log/kayra/audit.log | jq '{stage, user, verb, resource, allowed, reason}'
```

## 3. Send it to an HTTP endpoint

```yaml
audit:
  backend: api
  api:
    url: https://siem.example.com/ingest
    headers:                                     # sent as they are
      Authorization: "Bearer ${SIEM_TOKEN}"      # ${VAR}: read from Kayra's environment at start
    tls:
      cacert: /etc/kayra/siem-ca.pem             # verified against the system's roots otherwise
      cert: /etc/kayra/siem-client.pem           # a client certificate, optional
      key: /etc/kayra/siem-client-key.pem
    timeout: 5s
    batch: {max_events: 100, max_wait: 1s}
    queue: 10000
```

- **A batch** goes out at `max_events` records, or `max_wait` after its
  first.
- **The body** is `{"items": [<record>, ...]}`, `Content-Type:
  application/json`.
- **A failure, a `5xx` or a `429`** is retried 3 times, waiting 0.5, 1 then
  2 seconds. Then the batch is dropped. A `4xx` is not retried.
- **A full queue** drops the record.
- **At shutdown,** Kayra sends what is queued, for up to 10 seconds.
- **An unset `${VAR}`** stops Kayra at start.

Kayra counts it all, at `/apis/system.infrapi.io/v1/-/metrics`:

| Metric | |
|---|---|
| `kayra_audit_records_total{backend}` | records written or sent |
| `kayra_audit_dropped_total{reason}` | records dropped: `queue_full`, `send_failed`, `write_failed` |
| `kayra_audit_send_errors_total` | failed POSTs, retries included |

## Example: Wazuh

A Wazuh agent reads JSON lines from a file, so use the `file` backend. Wazuh's
documented way in is a `<localfile>` block with `log_format json`. Its API has
no generic endpoint for events, so the `api` backend does not fit it.

### 1. Kayra writes the file

```yaml
audit:
  backend: file
  file:
    path: /var/log/kayra/audit.log
```

On Kubernetes or podman, write it to a volume the agent also mounts, or run
the agent as a sidecar.

### 2. The agent reads it

In the agent's `ossec.conf`, on Kayra's host:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/kayra/audit.log</location>
  <label key="@source">kayra-audit</label>
</localfile>
```

Rotate the file with logrotate, sending Kayra a `SIGHUP`:

```text
/var/log/kayra/audit.log {
  daily
  rotate 14
  compress
  delaycompress
  postrotate
    systemctl kill -s HUP kayra.service
  endscript
}
```

### 3. Rules on the manager

Wazuh decodes each line as JSON, and its fields can be matched by name. Put
the rules in the manager's `/var/ossec/etc/rules/local_rules.xml`, with ids
in the custom range:

```xml
<group name="kayra,audit,">
  <!-- every Kayra audit record -->
  <rule id="100200" level="3">
    <decoded_as>json</decoded_as>
    <field name="stage">^check$|^request$</field>
    <field name="verb">\.+</field>
    <description>Kayra: $(user) $(verb) $(resource) on $(api)</description>
  </rule>

  <!-- a denial -->
  <rule id="100201" level="7">
    <if_sid>100200</if_sid>
    <field name="allowed">false</field>
    <description>Kayra: $(user) denied $(verb) $(resource) on $(api): $(reason)</description>
  </rule>

  <!-- a burst of denials from one address -->
  <rule id="100202" level="10" frequency="10" timeframe="60">
    <if_matched_sid>100201</if_matched_sid>
    <same_field>source_ip</same_field>
    <description>Kayra: 10 denials in a minute from $(source_ip)</description>
  </rule>

  <!-- RBAC changed -->
  <rule id="100203" level="8">
    <if_sid>100200</if_sid>
    <field name="api">^authorization\.</field>
    <field name="verb">^create$|^update$|^patch$|^delete$</field>
    <field name="allowed">true</field>
    <description>Kayra: $(user) $(verb) $(resource) $(name)</description>
  </rule>
</group>
```

Restart the manager (`systemctl restart wazuh-manager`) and check a line with
`/var/ossec/bin/wazuh-logtest`: paste one from the file and the rule that
fires is shown.

> [!NOTE]
> These Wazuh files follow Wazuh's documentation for `localfile` and JSON
> rules. Check them against your Wazuh version.

## Example: Splunk

A Splunk Universal Forwarder reads the same file, so use the `file` backend
here too. Splunk's HTTP Event Collector takes events in a format of its own
(`{"event": …}`), not the `api` backend's `{"items": [...]}`.

### 1. Kayra writes the file

```yaml
audit:
  backend: file
  file:
    path: /var/log/kayra/audit.log
```

Rotate it [as for Wazuh](#2-the-agent-reads-it): logrotate, then a `SIGHUP` to Kayra.

### 2. The forwarder reads it

In `inputs.conf` on Kayra's host, in an app of the Universal Forwarder
(`$SPLUNK_HOME/etc/apps/kayra_audit/local/inputs.conf`):

```ini
[monitor:///var/log/kayra/audit.log]
index = kayra
sourcetype = kayra:audit
disabled = false
```

Create the `kayra` index on the indexers first.

### 3. The sourcetype

In `props.conf` on the indexers, for the events' breaking and time, and on
the search heads, for the fields:

```ini
[kayra:audit]
# one JSON object per line
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
# the record's own time, ISO 8601 in UTC
TIME_PREFIX = "time":"
MAX_TIMESTAMP_LOOKAHEAD = 40
TZ = UTC
# the fields at search time: user, verb, api, allowed...
KV_MODE = json
```

No `TIME_FORMAT`: Splunk recognizes ISO 8601, and the record's time has as
many fractional digits as it needs.

### 4. Search it

The denials, by caller:

```text
index=kayra sourcetype=kayra:audit allowed=false
| stats count by user, api, resource, verb, reason
| sort - count
```

A burst of denials from one address, the search behind an alert run every
five minutes:

```text
index=kayra sourcetype=kayra:audit allowed=false earliest=-5m
| stats count by source_ip
| where count >= 10
```

Who changed the RBAC:

```text
index=kayra sourcetype=kayra:audit api="authorization.*" allowed=true
  (verb=create OR verb=update OR verb=patch OR verb=delete)
| table _time, user, verb, resource, name, namespace
```

A request and its [event](events.md) share their `request_id`:
`index=kayra request_id="req-1"`.

> [!NOTE]
> These Splunk files follow Splunk's `inputs.conf` and `props.conf`
> settings. Check them against your Splunk version, and where each setting
> takes effect in your deployment.
