---
name: dependency-check
description: Java dependency CVE scanning — OWASP Dependency-Check CLI against pom.xml/gradle builds and fat jars, NVD_API_KEY handling, and how to merge with trivy results into deduplicated dependency findings.
---

# OWASP Dependency-Check Playbook

Dependency-Check matches `pom.xml`/`build.gradle` coordinates and jar manifests (GAV, pom.properties, jar checksums) against the NVD database. In this image trivy covers the same ground faster; use Dependency-Check when you need NVD detail (exact CVE descriptions, CPE reasoning) or a second opinion on a critical call.

## CLI

```bash
# Source tree (pom.xml / build.gradle)
dependency-check --scan /workspace/repo --format JSON --out /workspace/depcheck.json \
  --enableRetired --failOnCVSS 0

# Fat jar / war (analyzes embedded BOOT-INF/lib jars)
dependency-check --scan app.jar --format JSON --out /workspace/depcheck.json

# Only one CVE source is slow to sync; suppress the experimental analyzers
dependency-check --scan /workspace/repo --format JSON --out /workspace/depcheck.json \
  --disableCentral --noupdate
```

- **NVD API key**: set `NVD_API_KEY` in the environment before running; without it NVD sync is rate-limited to a crawl. With a stale cached DB, `--noupdate` still gives usable results from the cached data.
- First run downloads the NVD cache into `~/.dependency-check` — large. Prefer `--noupdate` + trivy unless deep CVE detail is needed.

## Workflow

1. Collect exact versions first: `ls app/BOOT-INF/lib/`, or `mvn -q dependency:tree -DoutputFile=/workspace/deptree.txt` (works for gradle via `gradle dependencies > /workspace/deptree.txt`).
2. Run trivy on the same input: `trivy fs --scanners vuln /workspace/repo` (fast, no NVD sync).
3. Cross-check only **high/critical** hits with Dependency-Check; the NVD entry settles disputes about affected-version ranges.

## Reporting Discipline

- A dependency CVE is a finding only with an **exploitability leg**: where does the vulnerable code path run? (e.g., log4shell needs the app to log attacker-controlled strings; a vulnerable JSON parser needs an endpoint parsing attacker JSON.) State the leg explicitly — or file it as a hardening note with the upgrade path.
- Deduplicate: trivy + Dependency-Check + nuclei-template hits for the same CVE = **one** finding, cite the strongest evidence.
- Prefer GAV coordinates + fixed version in the recommendation (`org.apache.logging:log4j-core 2.17.1+`), not just "upgrade log4j".
- Use the project's dependency-report tool when available so CVE findings land in the structured report instead of free text.
