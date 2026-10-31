---
name: java
description: Java/JVM application testing strategy — decompile-then-audit workflow for jars/wars/EARs and build files, bytecode SAST, dependency CVE correlation, deserialization and JNDI exploitation, heapdump credential hunting, and framework-specific checks (Spring, Struts, Shiro, fastjson).
---

# Java Applications

Use this skill whenever the target is JVM-based: source trees with `pom.xml`/`build.gradle`, built artifacts (`*.jar`, `*.war`, `*.ear`), Spring Boot fat jars, or a running app whose stack fingerprints as Java.

Pair with `source_aware_sast` for source trees, `jadx` for decompilation, `spotbugs_findsecbugs` for bytecode audits, `dependency_check` for dependency CVEs, `java_deserialization` once a deserialization or JNDI sink is suspected, and `mat_heapdump` when an exposed heapdump or hprof file is in reach.

## Decision Tree

1. **Have source?** (`src/main/java` present) → audit directly: `semgrep` with Java rules + `spotbugs` on `target/classes` after `mvn -q -DskipTests package`. Skip decompilation.
2. **Only build files?** (`pom.xml`/`build.gradle` without sources) → run dependency analysis first (`dependency_check`), fingerprint the framework versions, then decide whether to fetch/audit dependencies' code paths that touch user input.
3. **Only artifacts?** (`*.jar`/`*.war`) → decompile first (`jadx`), then audit the decompiled tree like source. For fat jars, unpack first: `unzip app.jar -d app/` then handle `BOOT-INF/classes/` (application code) and `BOOT-INF/lib/` (dependencies).
4. **Black-box only?** → fingerprint (response headers, `/actuator`, stack traces, error pages), try nuclei Java tags (log4shell, shiro, fastjson, struts), pull `/actuator/heapdump` if exposed (`mat_heapdump`), and probe deserialization endpoints (`java_deserialization`).

## What to Look For (Java-specific)

- **Deserialization sinks**: `ObjectInputStream.readObject`, `XMLDecoder`, `Yaml.load` (SnakeYAML <2.0 unsafe ctor), fastjson `JSON.parseObject` with autoType, XStream, Hessian, Kryo, Java-native session blobs (base64 `rO0AB` magic = serialized object).
- **JNDI injection**: `InitialContext.lookup` with user-controlled input — exploitable on JDK < 8u191/11.0.1 via remote codebase; later JDKs still allow local gadget exfiltration.
- **Expression/Template injection**: Spring EL (`SpelExpressionParser`), OGNL (Struts), Freemarker/Velocity templates from user input.
- **SQLi via string-concatenated JPA/Hibernate** (HQL injection, `createQuery` with concatenation) — check for `PreparedStatement` discipline.
- **XXE**: `DocumentBuilderFactory`, `SAXParser`, `XMLInputFactory` without `setFeature` hardening.
- **Path traversal**: `new File(userInput)`, `Paths.get`, `ZipEntry` extraction without canonical-path checks (zip-slip).
- **Weak crypto**: `DES`, `ECB`, `MD5`/`SHA1` for passwords, hardcoded keys (`SecretKeySpec` with literal).
- **SSRF**: `URL.openConnection`, `HttpURLConnection`, `RestTemplate` with user-controlled URLs.
- **Spring exposure**: actuator endpoints (`/actuator/env`, `/actuator/configprops`, `/actuator/heapdump` — heapdump hands over live in-memory credentials, see `mat_heapdump`), `/actuator/gateway` RCE on Spring Cloud Gateway <3.1.1, misconfigured static routing.
- **Permissive CORS / auth bypass** via Spring Security config (`permitAll`, missing method security).

## Framework Fingerprinting Cheatsheet

| Signal | Framework |
|---|---|
| `/actuator/health` 200 | Spring Boot |
| `JSESSIONID` + `rememberMe=` cookie | Apache Shiro (check Shiro-550 key) |
| `X-Powered-By` or error page | check header value verbatim |
| `struts` tokens / `.action` suffix | Struts2 (check known S2-xx) |
| `fastjson` in stack traces / `@type` accepted in JSON | fastjson autoType |
| `BOOT-INF/lib/*.jar` in fat jar | read exact versions from filenames |

## Boundary Discipline

- Exploit deserialization/JNDI payloads only against the authorized target; DNS/HTTP callbacks (interactsh) confirm the sink without destructive payloads.
- Prefer detection with proof (timed callback, controlled `touch`-equivalent) over destructive gadget chains.
- Record the exact jar/class/method for every finding so the report maps to a patchable unit.
