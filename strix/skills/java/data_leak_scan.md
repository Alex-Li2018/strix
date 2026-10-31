---
name: data_leak_scan
description: Java 敏感数据泄漏白盒扫描——源码/配置硬编码(密码、密钥、API Key、数据库凭据)、日志输出敏感信息(密码/身份证/手机号/银行卡)、日志记录完整性缺失(六要素/AOP切面/增删改审计)、公网 IP 硬编码。对 Java/Spring 项目做数据安全合规审计时使用。
---

# Java 敏感数据泄漏扫描

工作环境与纪律：目标源码在 `/workspace`；`rg` 预筛 + 读文件确认；只报实际读过的代码（file:line + 片段）；确认后调 `create_vulnerability_report`。此类问题的定性要点：命中正则 ≠ 漏洞，必须确认值是**真实凭据**（非占位符 `${DB_PASSWORD}`、非示例 `changeme`、非测试值）；日志项必须确认**运行时确实携带敏感值**。

## 1. 硬编码凭据

```bash
rg -n --type java -e 'password\s*=\s*"[^"]{4,}"' -e 'secret\s*=\s*"[^"]{4,}"' -e '([aA]pi[_-]?[kK]ey|[tT]oken)\s*=\s*"[A-Za-z0-9+_/-]{8,}"' /workspace
rg -n -g '*.yml' -g '*.properties' -e 'password:\s*\S+' -e 'secret[-_]?key:\s*\S+' -e 'access[-_]?key' /workspace
rg -n --type java -e 'jdbc:(mysql|oracle|postgresql|sqlserver)://[^"]*"' -e 'Basic\s+[A-Za-z0-9+/=]{8,}' /workspace
```

检测模式与排除规则：

1. **代码内密码/密钥/Token 字面量**：`private static final String PASSWORD = "admin123"`。排除：空串、`${...}` 占位、环境变量读取、明显测试文件（src/test）
2. **配置文件明文凭据**：`application.yml/properties` 中 `spring.datasource.password: 明文`、Redis/MQ 连接密码。生产 profile（application-prod.yml）里的真实值定 High，dev profile 视内容定 Low/信息项
3. **JDBC URL 内嵌凭据**：`jdbc:mysql://user:pass@host`
4. **HTTP Basic 头硬编码**：Base64 解码确认内容后再报告
5. **密钥文件引用**：仓库内存在 `.jks/.p12/.pem/.key` 文件本身 + 引用代码（keystore 密码也常在配置里）
6. **对称密钥特征**：`"A-Za-z0-9+/=]{16,}"` 赋给 key/secret 变量，16/24/32 字节长度是 AES key 的强信号

密钥确认后按高危上报，修复建议：迁移到配置中心/KMS/环境变量，轮换已泄漏密钥（强调：已进 git 历史的密钥必须轮换）。

## 2. 日志输出敏感信息

```bash
rg -n --type java -e 'log(ger)?\.(info|debug|warn|error)\(.*([pP]assword|[pP]wd|idCard|身份证|[pP]hone|手机|bankCard|银行卡|[aA]pi[Kk]ey|[sS]ecret|[tT]oken)' /workspace
rg -n --type java -e 'log(ger)?\.(info|debug|warn|error)\(.*(getParameter|getParameterMap|getInputStream)' /workspace
rg -n --type java -e 'log(ger)?\.(info|debug|warn|error)\(.*toString\(\)' -e 'log(ger)?\..*toJSONString?\(' /workspace
```

检测模式与定性：

1. **显式敏感字段入日志**：`logger.info("登录密码:" + user.getPassword())`——High
2. **隐私数据入日志**：身份证/手机号/银行卡/交易金额——按合规风险（个保法/PCI DSS）High~Medium
3. **整请求参数入日志**：`logger.info("参数:" + request.getParameterMap())`——请求里常有密码字段，Medium
4. **整对象 toString/toJSON 入日志**：确认对象是否含敏感字段再定性
5. **debug 级别输出敏感值**：生产日志级别通常 info，定 Low~Medium 并注明前提

修复建议：脱敏工具类（掩码手机号/卡号）、`@ToString.Exclude`、禁止记录原始请求体。

## 3. 日志记录完整性（审计追溯能力）

这是"缺失类"检查——**没有日志**本身就是风险。检查顺序：

```bash
rg -ln --type java -e '@Aspect' -e 'LogAspect|OperationLog|@interface.*Log' /workspace   # 是否有 AOP 统一日志
rg -ln --type java -e '@(Rest)?Controller' /workspace | head -30                          # Controller 清单
```

1. **统一日志机制**：无 `@Aspect` 切面、无自定义 `@Log/@OperationLog` 注解 → 抽查 5-10 个写操作 Controller，确认是否手工补了日志；普遍缺失即报告"操作审计日志缺失"（Medium，影响安全事件溯源）
2. **日志六要素**（抽查写操作日志语句是否包含）：时间、操作用户 ID（`SecurityUtils`/`Principal`）、来源 IP（`getRemoteAddr`/`X-Forwarded-For`）、事件类型、被操作资源、执行结果（成功/失败）。多项缺失合并为一条发现
3. **增删改操作**：`@DeleteMapping/@PostMapping/@PutMapping` 方法体内无任何日志语句且无切面覆盖 → 逐个列出位置
4. **异常吞没**：`catch (Exception e) { return error; }` 无日志——`rg -n --type java -A 2 'catch\s*\([^)]*Exception' | rg -B1 -A2 'return'` 预筛后确认
5. **登录/登出/鉴权失败**：无记录 → 暴力破解无法检测，单独列一条

注意：此类发现是"可追溯性缺陷"，不是可利用漏洞，统一按 Low~Medium 报告并在描述中写清影响是审计/溯源。

## 4. 公网 IP / 内部架构泄漏

```bash
rg -n --type java -e '\b(12[7-9]|1[3-9][0-9]|[1-9][0-9]|[1-9])\.(1?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.(1?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.(1?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\b' /workspace | head -40
rg -n -g '*.yml' -g '*.properties' -e 'http://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' /workspace | head -40
```

排除私有段（10/8、172.16/12、192.168/16、127/8、169.254/16、组播 224/4）后，剩余公网 IP 确认：是否生产环境地址、是否硬编码在代码/配置。生产公网 IP 硬编码 → Low~Medium（信息泄漏、扩大攻击面）。生产地址应走配置中心/域名。

## 输出要求

每个确认发现：问题类型 / file:line + 片段 / 泄漏内容定性（真实凭据注明长度与用途，**不要在报告里复述完整密钥值**，掩码显示）/ 修复建议（轮换 + 迁移存储）/ CVSS。合规类（日志完整性、隐私入日志）注明对应法规/标准条款。全部命中项先汇总去重（同一配置文件多处同值合并），再上报。
