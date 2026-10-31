---
name: web_risk_scan
description: Java Web 应用层漏洞白盒扫描——文件上传下载与路径遍历、SSRF、不安全重定向/转发、URL 权限绕过、XSS、CRLF/响应头注入、ReDoS、参数校验缺失 DoS、短信邮箱轰炸。对 Java/Spring 源码做应用层风险审计时使用。
---

# Java Web 应用层风险扫描

工作环境与纪律：目标源码在 `/workspace`；`rg` 预筛 + 读文件确认数据流；只报实际读过的代码（file:line + 片段）；确认后调 `create_vulnerability_report`。定性通用规则：sink 处的变量必须能回溯到 HTTP 入口（`@RequestParam`/`@PathVariable`/`@RequestBody`/`getParameter`/`getHeader`/`getQueryString`/`getRequestURI`）才是漏洞；来自配置文件/常量表/数据库内部字典的值降级或排除。

## 1. 文件上传 / 下载 / 路径遍历

```bash
rg -n --type java -e 'MultipartFile' -e 'getOriginalFilename' -e 'transferTo\(' /workspace
rg -n --type java -e 'new File\(.*getParameter|new File\(.*\+' -e 'Files\.readAllBytes\(' -e 'new FileInputStream\(' -e '\.resolve\(' -e 'getCanonicalPath' /workspace
```

检测模式：

1. **上传文件名未净化**：`new File("/upload/" + multipartFile.getOriginalFilename())` + `transferTo`——`../` 路径遍历写任意位置；修复：服务端重生成文件名（UUID），白名单校验扩展名
2. **扩展名校验缺失/绕过**：只检查 `endsWith(".jpg")` 可被 `1.jpg/`、大小写、`%00`（旧容器）绕过；可上传 `.jsp/.war` 且部署目录可达 → RCE，Critical
3. **任意文件读取**：下载接口 `request.getParameter("file")` 直接拼进 `new FileInputStream(baseDir + fileName)`——绝对路径注入（`/etc/passwd`）、`../` 遍历。修复：`getCanonicalPath().startsWith(baseDir)` 校验 + ID 映射文件名
4. **ZIP 解压炸弹**：`ZipFile` 遍历解压无条目数/解压总大小限制（压缩比 >100 倍检测）
5. **大小限制**：配置缺 `spring.servlet.multipart.max-file-size/max-request-size` 或值过大

## 2. SSRF

```bash
rg -n --type java -e 'RestTemplate' -e 'new URL\(' -e 'openConnection\(' -e 'HttpClient' -e 'HttpGet|HttpPost' -e 'OkHttpClient' -e 'WebClient' -e 'HttpURLConnection' /workspace
```

检测模式：用户可控 URL 进入任一 HTTP 客户端（`getForObject(userUrl, ...)`、`new URL(userInput).openConnection()`、`new HttpGet(userInput)`、`Request.Builder().url(userInput)`）。确认要点：

1. 回溯 URL 来源 → HTTP 入口
2. 是否有校验：域名白名单 / 解析后 IP 黑名单（127.0.0.1、10/8、172.16/12、192.168/16、169.254.169.254 云元数据）
3. 常见绕过（报告 PoC 用）：`http://[::1]/`、十进制 IP `2130706433`、`@` 符号 `http://trusted@evil.com`、DNS rebinding、30x 跳转到内网
4. 修复：协议限制 http/https + 域名白名单 + **解析后 IP 复检**（防 DNS rebinding）+ 禁跟随跨域重定向

## 3. 不安全重定向 / 转发

```bash
rg -n --type java -e 'sendRedirect\(' -e '"redirect:"' -e 'new RedirectView\(' -e 'getRequestDispatcher\(' -e 'setLocation\(' -e 'setHeader\("Location"' -e 'ForwardedHeader' /workspace
```

检测模式（参数用户可控即成立）：

1. `response.sendRedirect(userInput)`——Open Redirect → 钓鱼
2. Spring：`return "redirect:" + userInput`、`new RedirectView(userInput)`、`ModelAndView("redirect:" + ...)`
3. **服务端转发**：`request.getRequestDispatcher(userPath).forward(...)`——可遍历到 WEB-INF 外未授权资源，权限绕过比重定向更严重
4. `HttpHeaders.setLocation(URI.create(userInput))`、`response.setHeader("Location", userInput)`
5. `ForwardedHeaderFilter`/`X-Forwarded-Host` 未校验——外部可操纵生成的重定向/链接域名
6. 修复：目标白名单（域名或相对路径 `/` 开头校验拒绝 `//`、`/\`）

## 4. URL 权限绕过

```bash
rg -n --type java -e '@PreAuthorize' -e '@Secured' -e 'hasRole\(' -e 'antMatchers\(|requestMatchers\(' -e '\.matches\(' -e 'SecurityConfig|WebSecurityConfig' /workspace
rg -n -g '*.java' -e 'excludePathPatterns|addPathPatterns' /workspace
```

检测模式：

1. **鉴权规则遗漏**：`SecurityConfig`/拦截器 `excludePathPatterns` 列表 vs 实际 `@RequestMapping` 路径对照——列出所有 Controller 路径，找出未被鉴权规则覆盖的管理接口
2. **动态权限表达式**：`@PreAuthorize("hasRole('" + userRole + "')")`——角色来自请求参数
3. **正则匹配绕过**：`path.matches("/admin/.*")` 类校验 vs URL 编码（`%2f`）、`..;/`、分号参数、大小写、尾部斜杠、双斜杠的归一化差异（Shiro/Spring 路径匹配不一致是经典组合，结合 Shiro 版本判断）
4. **参数化权限判断**：`request.getParameter("isAdmin")` 直接作为权限依据
5. **水平越权基础面**：按 ID 查询/修改的接口是否校验资源属主（配合 `broken_function_level_authorization` skill 的 IDOR 方法深查）

## 5. XSS

```bash
rg -n --type java -e 'getWriter\(\)\.(print|write)\(' -e 'HtmlUtils\.htmlEscape' -e 'StringEscapeUtils' /workspace | head -30
rg -ln --type java -e '@Controller' /workspace | head; rg -n -g '*.html' -g '*.ftl' -g '*.vm' -e '\$\{[^}]*\}' /workspace | rg -v 'th:|sec:' | head -40
```

检测模式：

1. Servlet 直出：`response.getWriter().print(userInput)` 未过 `HtmlUtils.htmlEscape`
2. 模板未转义输出：FreeMarker `${userInput}`（应 `${userInput?html}`）、Velocity（应 `$!{esc.html($x)}`）、Thymeleaf `th:utext`（应 `th:text`）
3. XSS Filter 覆盖不全：项目有 `XssHttpServletRequestWrapper` 类时，读其过滤实现——替换 `<script>` 黑名单可被 `<img onerror>`、大小写、编码绕过（若依案例）；再确认该 Filter 是否注册到所有路径
4. 存储型：用户输入入库 → 管理后台展示页输出，沿字段追完整链路
5. JSON API 场景 `Content-Type: text/html` 返回用户 JSON → 独立检查

## 6. CRLF / 响应头注入

```bash
rg -n --type java -e 'setHeader\(.*(getParameter|getHeader|getQueryString|getRequestURI)' -e 'addHeader\(.*(getParameter|getHeader)' -e 'new Cookie\(.*(getParameter|getHeader)' -e 'setContentType\(.*\+' /workspace
```

检测模式：用户输入进 `setHeader/addHeader`（Location、Set-Cookie、Content-Disposition 文件名最常见）未过滤 `%0d%0a`——响应拆分/缓存投毒；`new Cookie(name, userInput)`；文件下载 `Content-Disposition: attachment; filename=" + originalFilename`（还可顺带报文件名 UI 欺骗）。现代 Tomcat/Jetty 对 header 中的 CR/LF 有拒绝处理，报告时注明容器与版本对可利用性的影响，仍建议修复（防御纵深）。

## 7. ReDoS 与参数缺失 DoS

```bash
rg -n --type java -e 'Pattern\.compile\(' -e '\.matches\(' -e '\.replaceAll\(' /workspace | head -40
```

检测模式：

1. **危险正则**：嵌套量词 `(a+)+`/`(a|aa)+`、`.*.*.*`、`(.+)+$`——用户输入可触达（校验、搜索、路由匹配）即 Medium~High，给出回溯触发输入示例
2. **用户输入编译正则**：`Pattern.compile(userInput)`——直接控制模式
3. **参数校验缺失**：`@RequestParam String x` 无 `@Size/@Pattern` 校验直接进大循环/正则/集合初始化——超长输入耗 CPU/内存
4. **无界资源操作**：分页参数 `pageSize` 无上限（`pageSize=1000000`）、`@RequestBody` 大对象无限制、循环内逐条查库（N+1 放大）

## 8. 短信 / 邮箱轰炸

```bash
rg -n --type java -e 'sendSms|sendSMS|SmsClient|sendVerificationCode|sendCode|JavaMailSender|sendMail|sendEmail' /workspace
```

检测模式：定位发送接口后 Read 确认四要素——①频率限制（同目标 60s/24h 上限）②图形/滑块验证码 ③IP 限流 ④同一目标日限额。全无 → High（用户骚扰、短信费用损失、通道封禁）。有但只查 IP 未查手机号（或反之）→ Medium（X-Forwarded-For 可伪造的场景注明）。

## 输出要求

每个确认发现：漏洞类型 / file:line + 片段 / source→sink 数据流 / 触发 PoC（HTTP 请求示例或利用步骤）/ 修复建议 / CVSS。路径差异类（URL 绕过）必须注明所依赖组件与版本前提；可利用性存疑的列入"疑似项"附验证思路，不冒充确认漏洞。
