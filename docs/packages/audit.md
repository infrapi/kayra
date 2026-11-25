---
title: audit
description: "Kayra's audit: one Record per /check decision and per request to its own routes, written to a file, POSTed in batches, or nowhere."
weight: 5
---

# audit

```go
import "github.com/infrapi/kayra/internal/audit"
```

Writes Kayra's audit: who asked for what, and whether it was allowed. See
[Audit](../architecture/audit.md) for the configuration and the record.

```go
sink, err := audit.New(cfg.Audit)              // File, API or None
auditor := audit.NewAuditor(sink, cfg.Audit.Reads)
engine, err := apiserver.Build(appCfg, cfg, apiserver.WithAudit(auditor))
defer sink.Close(ctx)                          // the api backend sends what is queued
```

- **`Record`:** `Stage` (`check` or `request`), the caller (`User`,
  `Groups`, `Kind`, `ClientID`), the request (`RequestID`, `SourceIP`,
  `UserAgent`, `API`, `Namespace`, `Resource`, `Name`, `Verb`) and the
  outcome (`Allowed`, `Reason`, `Status`). Its `ID` (a UUIDv7) and `Time`
  are set when written.
- **`Auditor.Record`** writes a record unless it is an allowed read and
  reads are not audited. A nil `Auditor` writes nothing.
- **`Sink`:**
  - `File`: JSON lines, flushed per record, `-` for stdout; `Reopen` on
    `SIGHUP` (`kayra serve`);
  - `API`: a queue and a worker, batches of `{"items": [...]}`, retried on a
    `5xx`, a `429` or a network error;
  - `None`.
- **Where it is written:** `/check` (`rbac.Server.Check`) after
  each decision, and `apiserver`'s middleware on Kayra's own groups and
  `/oauth2/sessions`, once served. The error a denial answered comes from
  `httpapi.Failure` (a gin middleware's) or infrapi/lib's `server.ErrorOf`
  (a generated handler's).
- **Metrics:** `kayra_audit_records_total{backend}`,
  `kayra_audit_dropped_total{reason}`, `kayra_audit_send_errors_total`, in the
  default Prometheus registry that lib's `-/metrics` serves.
