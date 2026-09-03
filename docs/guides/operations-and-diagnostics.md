# Guide: Operations, Diagnostics & Testing Support

Modules: `diagnostics`, `local_audit`, `database`, `testing`.
Reference tests: `tests/test_local_audit.py`, `tests/test_testing_fixtures.py`.

## When to use

Wiring observability into your application, keeping a tamper-evident local
audit trail, running the service-side database runtime, and hardening your
own crash paths with the library's fault-injection harness.

## 1. Diagnostics sinks

Two protocols keep the library free of any specific telemetry backend;
your application supplies implementations:

- `AuditSink.record(name, outcome=..., correlation_id=..., fields=...)` —
  privacy-safe security/audit events with correlation IDs that join with
  transport requests (`X-Correlation-ID`).
- `MetricsSink.increment(name, value=...)` / `.observe(name, value=...)` —
  counters and timings.

Fields are typed (`int | str`) so accidental PII-bearing values fail at the
type level rather than leaking into logs.

## 2. Tamper-evident local audit

`ChainedAppendLog` is a hash-chained append-only log: each record commits to
its predecessor (`previous_sha256`), and `verified_records()` re-verifies the
whole chain on read — a truncated or rewritten history is detected, not
silently trusted (`tests/test_local_audit.py`):

```python
from techflex_cloud_foundation import ChainedAppendLog

log = ChainedAppendLog("audit")
record = log.append({"action": "open", "target": "session-1"})
records = log.verified_records()     # raises if any link in the chain broke
```

Use it for security-relevant local events (session open/close, license
changes, deletion decisions) that must survive later inspection.

## 3. Server-side database runtime

`DatabaseRuntime` owns one server-side connection pool plus a `HealthProbe`;
repositories own SQL and transaction contents (`TransactionScope` protocol).
Requires the `server` extra (`asyncpg`). Client applications do not need this
module.

## 4. Fault-injection harness for your own tests

`techflex_cloud_foundation.testing` is the harness behind the library's
durability guarantees — reuse it to prove your application's crash windows:

- `short_write_os(max_chunk)`, `interrupted_replace(...)`,
  `fsync_failure(...)`, `disk_full(...)` — targeted `FaultInjection`s that
  monkeypatch OS primitives (`install()`/`restore()`).
- `SimulatedPowerLoss` — drops all buffered state mid-operation.
- `KillAndRecoverHarness` — runs a child process, kills it at a chosen point,
  restarts it, and compares the recovered state
  (`tests/test_testing_fixtures.py` shows each in use).

## Invariants

- Telemetry is privacy-safe by construction: typed fields, correlation IDs,
  no raw payloads.
- Audit history is verified on every read; tamper is detected, never
  trusted.
- The fault-injection harness is a supported public surface — your tests may
  depend on it.
