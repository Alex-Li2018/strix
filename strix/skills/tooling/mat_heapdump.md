---
name: mat-heapdump
description: Eclipse MAT headless heapdump analysis — pull Spring /actuator/heapdump, quick strings pass for secrets, ParseHeapDump.sh leak-suspect reports, and OQL to fish live DataSource passwords, Shiro keys, and tokens out of JVM memory.
---

# Heapdump Analysis (Eclipse MAT headless)

A heapdump is a snapshot of the JVM's live memory — every object and field value at capture time. On Spring Boot it is often one request away and is the highest-yield single ask in Java testing: plaintext DB passwords, API keys, JWT signing secrets, and Shiro keys live in memory even when nothing appears in responses or config files.

## Capture

```bash
curl -sf -o /workspace/heap.hprof https://target/actuator/heapdump
file /workspace/heap.hprof    # expect "Java HotSpot(TM) ... HPROF" / "Java heap dump"
```

- Boot 2.x serves an hprof directly. Boot 3.x may need the JMX variant or return JFR — check `file`; if it is not hprof, fall back to `/actuator/env`, `/actuator/configprops`, `/actuator/threaddump` recon.
- Heapdumps are big (hundreds of MB to GB). Keep them in `/workspace` so they ship with run artifacts, and expect MAT to need minutes on large ones.

## Quick Pass First (no MAT)

```bash
strings -n 8 /workspace/heap.hprof \
  | grep -aiE 'jdbc:|password|passwd|secret|api[_-]?key|access[_-]?token|BEGIN (RSA|EC|OPENSSH) PRIVATE' \
  | sort -u | head -80
```

This alone routinely lands credentials. Record hits with enough surrounding context to identify the system they belong to.

## MAT Headless

```bash
# Writes reports next to the dump: heap.hprof_Leak_Suspects.zip, _System_Overview.zip, _Top_Components.zip
mat-parse-heapdump /workspace/heap.hprof \
  org.eclipse.mat.api:suspects org.eclipse.mat.api:overview org.eclipse.mat.api:top_components
# GB-scale dumps: append `-vmargs -Xmx8g` (the image default is 4g)

# Read the suspects report as text
unzip -p /workspace/heap.hprof_Leak_Suspects.zip '*.html' | sed 's/<[^>]*>/ /g' | less
```

The suspects/overview reports show dominator trees and class histograms — use them to find where connection pools, caches, and auth objects live before writing OQL.

## OQL Object Hunting

`mat-parse-heapdump` runs canned reports; for targeted hunting use OQL (`SELECT ... FROM <class>`, `INSTANCEOF <interface>` to include implementors). Field access in WHERE must use real class fields, so prefer class-scoped queries over clever string filters:

```sql
-- Connection pools: inspect user/password fields on each hit
SELECT ds FROM INSTANCEOF javax.sql.DataSource ds

-- In-memory property/config maps (overrides, secrets)
SELECT m.key, m.value FROM java.util.LinkedHashMap m
```

Open each hit's object view; credentials sit in `user`/`password`/`url` fields (HikariCP: `HikariConfig`; Tomcat JDBC: `PoolProperties`). For Shiro rememberMe, hunt `rememberMeCipherKey`/`AbstractRememberMeManager` byte arrays; for JWT, hunt the signing key held by the parser/handler object.

## Reporting Discipline

- A secret in the dump needs its source named to be actionable: which class/field held it, which subsystem it authenticates (DB? third-party API? session signing?).
- Include the literal only when the report requires it (e.g. to prove the credential works); otherwise redact and describe. Mark exposure of the heapdump endpoint itself as a finding — the secrets are a consequence, the endpoint is the root cause.
- Pair with config exposure: `/actuator/env` + heapdump usually corroborate each other; cite both.
