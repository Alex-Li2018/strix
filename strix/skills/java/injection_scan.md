---
name: injection_scan
description: Java/Spring 注入类漏洞白盒扫描——SQL注入(含MyBatis ${})、命令注入(Runtime.exec/ProcessBuilder)、SpEL/OGNL表达式注入、模板注入(FreeMarker/Velocity/Thymeleaf)。对 Java/Spring Boot 源码做白盒审计、需要检测注入类风险时使用。
---

# Java 注入类漏洞扫描（SQL / 命令 / 表达式 / 模板）

工作环境与纪律（本 skill 所有扫描步骤都必须遵守）：

- 目标源码挂载在沙箱 `/workspace`，命令在 Kali 沙箱内执行
- 用 `rg`（ripgrep）按模式预筛，命中后**必须 Read 文件确认完整数据流**（source → sink）才能定性
- 证据纪律：只报告实际读过代码的位置，引用 `文件路径:行号` + 真实代码片段；宁漏报不误报
- 常见误报先排除：拼接的是常量/枚举而非用户输入；已用参数化占位符；输入经白名单校验
- 确认为真风险后调 `create_vulnerability_report` 上报（含 CVSS、PoC 思路、修复建议）

## 1. SQL 注入

优先 `rg` 预筛（Java 源码 + MyBatis XML）：

```bash
rg -n --type java -e '\+.*\.getParameter\(' -e 'String sql.*=.*\+' -e 'prepareStatement\(".*\+' /workspace
rg -n -g '*Mapper.xml' -e '\$\{' /workspace        # MyBatis ${} 直接拼接
rg -n --type java -e 'createStatement\(\)' -e 'prepareCall\(' /workspace
```

检测模式（命中后逐一确认）：

1. **字符串拼接 SQL**：`"SELECT ... " + userInput` 直接拼接进 `Statement`/`PreparedStatement`（PreparedStatement 里拼接同样无效）
2. **MyBatis `${}`**：`*Mapper.xml` 中 `${param}` 不做预编译转义，应替换 `#{}`。注意区分：`ORDER BY ${column}` 若 column 来自白名单可降级，来自请求参数则为注入
3. **JDBC Statement 直接执行**：`Statement.executeQuery/executeUpdate/execute` + `createStatement()`，SQL 含用户输入即风险
4. **存储过程**：`CallableStatement.prepareCall("... + userInput")`
5. **ORM 动态查询**：Hibernate/JPA `createQuery()`、Criteria 拼接字符串条件
6. **权限拼接特例**：数据权限过滤中 `StringBuilder.append("... OR dept_id IN (SELECT ... role_id = " + roleId)`)` 类内部拼接（若依案例），虽来源内部仍应报告为设计缺陷

典型 sink 示例：

```java
String userInput = request.getParameter("username");
String sql = "SELECT * FROM users WHERE username = '" + userInput + "'";  // 注入
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(sql);
```

```xml
<!-- Mapper.xml：${} 不预编译，存在注入 -->
<select id="findUsers">SELECT * FROM users WHERE username = '${username}'</select>
```

## 2. 命令注入

```bash
rg -n --type java -e 'Runtime\.getRuntime\(\)\.exec\(' -e 'new ProcessBuilder\(' -e 'bash.*-c' -e '"/bin/sh".*-c' /workspace
```

检测模式：

1. `Runtime.getRuntime().exec("cmd " + userInput)`——注意 `exec(String)` 会按空格切分，`exec(String[]{...})` 不经过 shell，但参数注入仍可能
2. `new ProcessBuilder("cmd", userInput)`——参数注入（如以 `-` 开头的选项注入）
3. `bash -c <userInput>` / `sh -c <userInput>`——完整 shell 解释，管道/反引号/`$(...)` 全部生效，最高危
4. 间接路径：用户输入先存库/入配置，后续被取出来执行命令（二次注入），沿数据流多查一步

修复方向：参数化 `ProcessBuilder` 数组形式 + 输入白名单；避免 shell 中间层。

## 3. SpEL / OGNL 表达式注入

```bash
rg -n --type java -e 'parseExpression\(' -e 'SpelExpressionParser' -e 'StandardEvaluationContext' -e 'Ognl\.getValue\(' /workspace
```

检测模式：

1. `parser.parseExpression(userInput).getValue(context)`——直接解析用户输入为 SpEL，可调用任意静态方法 → RCE
2. `StandardEvaluationContext` 允许任意方法调用；若必须动态解析，确认使用 `SimpleEvaluationContext`（只读数据绑定）
3. OGNL：`Ognl.getValue(userInput, context)`，Struts2 时代经典 RCE 向量
4. `@Value("#{...}")` 中拼接外部配置的场景降级处理（非用户直达）

## 4. 模板注入（SSTI）

```bash
rg -n --type java -e 'TemplateEngine\.process\(' -e 'velocityEngine\.evaluate\(' -e 'new Configuration\(' -e '\.process\(' /workspace
rg -n -g '*.ftl' -g '*.vm' -e '\$\{' /workspace | head -50
```

检测模式：

1. **FreeMarker**：`templateEngine.process(userInput, ctx, writer)`——用户输入作为模板内容，`<#assign>`/内建函数可 RCE
2. **Velocity**：`velocityEngine.evaluate(ctx, writer, "tag", userInput)`——`#set` + 反射可 RCE
3. **Thymeleaf**：控制器返回值拼接用户输入（`return "redirect:" + userInput` 或视图名片段），Thymeleaf 表达式 `__${...}____` 预处理可执行
4. 动态模板拼接：`"${user." + userInput + "}"` 后交给引擎渲染

## 输出要求

每个确认发现按模板上报：漏洞类型 / 位置（file:line）/ 漏洞代码片段 / source→sink 数据流说明 / 触发条件与 PoC 请求示例 / 修复建议（参数化、白名单、安全 API）/ CVSS 评分。无法确认数据流可达性的命中项，列入"疑似项"随报告说明，不单独成漏洞。
