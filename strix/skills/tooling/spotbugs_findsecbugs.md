---
name: spotbugs-findsecbugs
description: SpotBugs with the FindSecBugs plugin — bytecode-level SAST for compiled Java (target/classes, jars, decompiled+rebuilt trees), which bug categories map to real findings, and how to run it in text mode for report ingestion.
---

# SpotBugs + FindSecBugs Playbook

Bytecode analysis sees what regex-over-source misses (taint-informed patterns, configurational crypto misuse). Run it on compiled output; for a plain source tree, compile first: `mvn -q -DskipTests package` (classes land in `target/classes`).

## CLI

```bash
# Text report on compiled classes (effort=max, visitors= all findsecbugs+spotbugs security groups)
spotbugs -textui -effort:max -sortByClass \
  -pluginList /opt/spotbugs-*/plugin/findsecbugs-plugin.jar \
  target/classes

# On a jar
spotbugs -textui -effort:max app.jar

# HTML for manual review alongside the text run
spotbugs -html:out/spotbugs.html -effort:max target/classes
```

Notes:
- The FindSecBugs plugin ships in the image at `/opt/spotbugs-*/plugin/findsecbugs-plugin.jar`; the `-pluginList` flag makes the security detectors explicit.
- FindSecBugs detectors cover 130+ patterns: deserialization (`OBJECT_DESERIALIZATION`), injection (`SQL_INJECTION_*`, `XSS_SERVLET`, `COMMAND_INJECTION`, `LDAP_INJECTION`, `XPath`), crypto (`WEAK_CIPHER`, `ECB_MODE`, `HARD_CODED_KEY`, `HARD_CODED_PASSWORD`, `STATIC_IV`, custom `MessageDigest` use), XXE (`XXE_*`), SSRF (`URLCONNECTION_SSRF`), file handling (`PATH_TRAVERSAL_*`), and per-template SSTI (`TEMPLATE_INJECTION_*`).
- `-onlyAnalyze com.example.*` keeps runs fast on fat dependency sets.

## Reading Results

- **Confidence/priority is a triage hint, not severity.** Map to severity by exploitability in context: `SQL_INJECTION_JDBC` on an unauthenticated endpoint ≠ one behind admin auth.
- Every SpotBugs hit needs a reachability check: open the class (decompile if needed, see `jadx`), find the caller chain to a servlet/controller/MQ listener/CLI entry. Unreachable = hardening note.
- `HARD_CODED_KEY`/`HARD_CODED_PASSWORD`: verify the literal isn't a test fixture or public constant before calling it a finding; then classify as secret exposure with the literal redacted in the report.
- `PREDICTABLE_RANDOM` on a session token or password reset flow is high severity; on logging noise it is informational.

## Combining with Other Tools

- Run **before** manual review; use its class:method list as the itinerary for reading code.
- Cross-check dependency-related hits with `dependency_check` — a vulnerable gadget library plus a deserialization hit is a confirmed chain, report it as one finding with both legs.
- semgrep (source-level) and SpotBugs (bytecode-level) overlap on injection patterns; disagreeing results still deserve a manual look.
