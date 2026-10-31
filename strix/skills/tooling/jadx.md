---
name: jadx
description: Decompile Java bytecode for source-level review — jadx CLI for jars/APKs/classes, fat-jar unpacking, CFR as a fallback for modern syntax jadx chokes on, and how to grep the decompiled tree efficiently.
---

# jadx / CFR Decompilation Playbook

Decompiled output is *reconstructed* source: line numbers differ from the original, and some constructs (lambdas, switch-on-string, generics) come back odd. Audit it semantically, not literally.

## jadx CLI

```bash
# Whole jar to a source tree
jadx -d /workspace/out app.jar

# Quiet + threads; keep going on decompile errors (default prints per-class)
jadx -q -j 4 -d /workspace/out app.jar

# Single class file or directory of classes
jadx -d /workspace/out com/example/UserService.class

# APK (Java layer only; native .so needs other tooling)
jadx -d /workspace/out mobile.apk
```

- Exit code nonzero with `--no-...`? Check `/workspace/out` anyway: jadx writes what it can and reports the rest as errors.
- `--show-bad-code` keeps classes that fail to decompile cleanly — useful for obfuscated targets, output is rougher.
- Resources (`application.yml`, `web.xml`, `META-INF`) land in `out/resources/` — read them, secrets and config often live there.

## Fat Jars (Spring Boot)

Decompile the app layer only; dependency jars rarely need full decompilation:

```bash
unzip -q app.jar -d app/
jadx -d /workspace/out-app app/BOOT-INF/classes/
ls app/BOOT-INF/lib/ | sort > /workspace/deps.txt   # exact versions for CVE correlation
```

## CFR / procyon Fallbacks

When jadx output for a critical class is broken, retry that class with CFR (often better on newer bytecode):

```bash
cfr app/BOOT-INF/classes/com/example/Svc.class --outputdir /workspace/out-cfr
cfr lib/some-dep.jar --outputdir /workspace/out-cfr
```

If CFR also fails on the class, try procyon — three decompilers reconstruct constructs differently, and one often succeeds where the others give up:

```bash
procyon-decompiler -jar app.jar -o /workspace/out-procyon
```

## Auditing the Decompiled Tree

```bash
# Sink-first greps beat reading everything
rg -n "readObject|XMLDecoder|Yaml\(\)|parseObject" /workspace/out/sources
rg -n "InitialContext|lookup\(" /workspace/out/sources
rg -n "createQuery|createNativeQuery" /workspace/out/sources | rg -v "PreparedStatement|set Parameter|\?"
rg -n "DocumentBuilderFactory|SAXParser|XMLInputFactory" /workspace/out
rg -n "SecretKeySpec|IvParameterSpec|DES|ECB|MD5" /workspace/out/sources
rg -n "URL\(|openConnection|RestTemplate" /workspace/out/sources
```

Then read the surrounding method of each hit (`rg -n -C 20`) to judge reachability from user input — a sink without a taint path is a hardening note, not a vulnerability.

## Output Discipline

- Keep decompiled trees under `/workspace` so they ship with the run artifacts.
- Cite findings as `jar!class#method` (e.g. `app.jar!com.example.Svc#deserialize`) — the original jar path, not the decompiled file path.
