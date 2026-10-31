---
name: deserialization_scan
description: Java 反序列化漏洞白盒扫描——fastjson 全版本 AutoType 绕过、Jackson 多态、Shiro rememberMe、Java 原生 readObject、XStream/XMLDecoder、JNDI 注入、CommonsCollections gadget 链。检测 Java/Spring 源码反序列化 RCE 风险时使用。
---

# Java 反序列化漏洞扫描

工作环境与纪律：目标源码在 `/workspace`；`rg` 预筛后必须读文件确认数据流；只报告实际读过的代码（file:line + 片段）；确认后调 `create_vulnerability_report`，纯依赖版本问题（无代码触发点）走 `create_dependency_report` + `trivy fs /workspace` 佐证。

## 1. 依赖版本风险矩阵（先查，决定后续深挖方向）

```bash
rg -n -g 'pom.xml' -g 'build.gradle' -e 'fastjson' -e 'shiro' -e 'commons-collections' -e 'xstream' -e 'jackson-databind' /workspace
trivy fs --scanners vuln /workspace 2>/dev/null | head -60   # 已知 CVE 对照
```

| 组件 | 高危版本 | 风险 |
|---|---|---|
| fastjson | < 1.2.83 全线 | AutoType 绕过 RCE（见下矩阵） |
| Shiro | < 1.2.4 及后续多处 | rememberMe 默认 AES key → 反序列化 RCE |
| commons-collections | 3.x < 3.2.2, 4.x < 4.1 | InvokerTransformer gadget |
| XStream | < 1.4.18 多处 | 默认反序列化任意类 |
| jackson-databind | 启用 DefaultTyping + 旧版本 | 多态反序列化 gadget |
| SnakeYAML | < 2.0 | `YAML.load()` 任意类构造 |

fastjson 版本细分：< 1.2.25 无限制；1.2.25-1.2.41 L/[ 前缀绕过；1.2.42-1.2.47 双写 `LL...;;` 缓存绕过；1.2.48-1.2.67 特定 gadget；1.2.68-1.2.82 expectClass 绕过；≥ 1.2.83 / 2.x 需开 safeMode 才安全。

## 2. Java 原生反序列化

```bash
rg -n --type java -e 'ObjectInputStream' -e '\.readObject\(\)' -e 'readUnshared' -e 'SerializationUtils\.deserialize' -e 'defineClass\(' /workspace
```

确认要点：`readObject()` 的字节流来源是否用户可控（HTTP 参数、Cookie、Header、消息队列、缓存、文件上传、数据库残留字段）。可控即 Critical；来源内部但可间接影响（如登录用户可写入自己的 session 存储字段）按 High 报告。

有 `ObjectInputFilter`/白名单 resolveClass 重写 → 检查过滤粒度，通配 `*` 等于没有。

## 3. fastjson 专项

```bash
rg -n --type java -e 'JSON\.parse' -e 'JSON\.parseObject' -e 'setAutoTypeSupport' -e 'setSafeMode' -e '@type' /workspace
```

检测点：

1. `JSON.parseObject(userJson)` 且依赖 < 1.2.83 → 结合上面版本矩阵定级
2. `ParserConfig.getGlobalInstance().setAutoTypeSupport(true)` → 显式开启 AutoType，Critical
3. `addAccept("com.myapp.")` 白名单不完整或带通配 → High
4. 未开 safeMode 的 ≥1.2.68 版本：expectClass 绕过向量 `{"@type":"java.lang.AutoCloseable","@type":"<恶意类>"}`

常用 gadget 对照（配合 JNDI/字节码加载 sink 判断可达性）：

| Gadget | 利用方式 | 适用版本 |
|---|---|---|
| JdbcRowSetImpl | JNDI 注入 | < 1.2.25 |
| TemplatesImpl | 字节码执行 | < 1.2.48 |
| BasicDataSource | JNDI/BCEL | 多版本绕过 |
| C3P0 | JNDI | 需 C3P0 依赖 |

## 4. Shiro 专项

```bash
rg -n -g 'pom.xml' -g '*.properties' -g '*.yml' -e 'shiro' -e 'rememberMe' -e 'cipherKey' -e 'setCipherKey' /workspace
rg -n --type java -e 'CookieRememberMeManager' -e 'setCipherKey\(' /workspace
```

检测点：

1. 依赖 < 1.2.4：rememberMe Cookie 使用**硬编码默认 AES key**（`kPH+bIxk5D2deZiIxcaaaA==` 及其变体），攻击者可构造 rememberMe cookie 直接 RCE → Critical
2. 代码中显式 `setCipherKey(硬编码)` → 同样可利用，检查 key 是否在仓库中
3. Shiro 1.x 路径鉴权绕过（CVE-2020-1957 / CVE-2020-11989 系列）：结合 `web_risk_scan` 的 URL 绕过模式检查 `/xxx/..;/admin` 类路径差异，需要 Shiro 版本 + Spring 的路径匹配不一致才成立，报告时写清版本前提

## 5. Jackson / XStream / SnakeYAML

```bash
rg -n --type java -e 'enableDefaultTyping' -e 'activateDefaultTyping' -e 'readValue\(' -e 'new XStream\(' -e 'fromXML\(' -e 'Yaml\(' -e 'yaml\.load\(' /workspace
```

检测点：

1. `objectMapper.enableDefaultTyping()`（或 `activateDefaultTyping`）+ `readValue(userJson)` → 多态反序列化 gadget，Critical；关闭 DefaultTyping 或用 `@JsonTypeInfo` 白名单则安全
2. `new XStream()` 无 `allowTypes` 白名单 + `fromXML(userInput)` → 任意类反序列化
3. `Yaml.load(userInput)`（SnakeYAML < 2.0）→ `!!javax.script.ScriptEngineManager` 类构造 RCE；`load(..., SafeConstructor)` 则安全

## 6. JNDI 注入（反序列化的常见落地路径）

```bash
rg -n --type java -e 'InitialContext\(' -e 'lookup\(' -e 'InitialDirContext' -e 'JndiTemplate' -e 'ldap://' -e 'rmi://' /workspace
rg -n -g 'pom.xml' -e 'log4j-core' /workspace   # log4shell 关联：2.x < 2.15.0 且允许用户输入进日志
```

检测点：

1. `new InitialContext().lookup(userInput)`——lookup 参数用户可控 → 可指向恶意 LDAP/RMI 服务加载类，Critical
2. JDK 缓解上下文：8u191+ 默认 `com.sun.jndi.ldap.object.trustURLCodebase=false`，但 RMI 路径与本地 factory gadget（如 BeanFactory）仍可利用，报告时注明 JDK 版本前提
3. Spring 配置中 `spring.jms.*`/JNDI 数据源 URL 来自配置文件的：若配置可被管理员注入，降级为设计风险

## 输出要求

每个确认发现：漏洞类型 / file:line + 代码片段 / 数据流（输入源 → 反序列化 sink）/ 依赖版本证据（pom 行号 + trivy 输出摘录）/ 利用条件（版本、JDK、网络可达性）/ 修复建议（升级版本、safeMode、白名单、ObjectInputFilter、禁用 DefaultTyping）/ CVSS。仅有危险依赖但无用户可控触发点的，走 `create_dependency_report`，不夸大为 RCE。
