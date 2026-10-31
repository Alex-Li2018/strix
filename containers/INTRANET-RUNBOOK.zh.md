# Strix All-in-One 镜像内网部署与使用手册

一个镜像同时包含 strix 编排器和全套渗透测试工具链（Java 安全工具、浏览器、扫描器、代理等），
无需在目标环境安装任何依赖。镜像双角色：手动 `docker run` 时是编排器；被编排器拉起时
（`STRIX_SANDBOX_ROLE=1`）自动切换为扫描沙箱，复用同一镜像，**内网无镜像仓库也能跑**。

---

## 一、在能联网的机器上：构建与导出

```bash
# 1. 拉最新代码（分支 feat/allinone-docker-image）
git pull

# 2. 构建镜像（需外网：下载 JDK/Maven/MAT 等 + 编译 ysoserial/marshalsec，约 20–40 分钟）
./scripts/docker-allinone.sh <tag>          # 例：javatest2

# 3. 导出为压缩包
docker save strix-allinone:<tag> | gzip > strix-allinone-<tag>.tar.gz
# 有 pigz 更快：docker save strix-allinone:<tag> | pigz > strix-allinone-<tag>.tar.gz

# 4. 传输到内网机
scp strix-allinone-<tag>.tar.gz user@内网机:/data/
```

### 替代：走镜像仓库分发（推荐，断点续传且只同步变化的层）

```bash
# GHCR（Codespace/有 GitHub 的环境）
docker tag strix-allinone:<tag> ghcr.io/<user>/strix-allinone:<tag>
echo "$(gh auth token)" | docker login ghcr.io -u <user> --password-stdin   # 需 write:packages
docker push ghcr.io/<user>/strix-allinone:<tag>
# GHCR 包默认私有：包设置改 Public 免登录拉取，或目标机同样 docker login

# 国内目标机拉 ghcr 慢/超时 → 用阿里云 ACR 个人版
docker login registry.cn-hangzhou.aliyuncs.com --username <阿里云账号>
docker tag strix-allinone:<tag> registry.cn-hangzhou.aliyuncs.com/<命名空间>/strix-allinone:<tag>
docker push registry.cn-hangzhou.aliyuncs.com/<命名空间>/strix-allinone:<tag>
```

目标机拉取后建议 retag 成短名：

```bash
docker pull <registry>/<...>/strix-allinone:<tag>
docker tag <registry>/<...>/strix-allinone:<tag> strix-allinone:<tag>
```

（不 retag 也可：`STRIX_IMAGE` 直接填完整 registry 引用，本地已有同引用镜像时 spawn 不会重新拉。）

> 更新版本 = 联网机重新 build → push → 目标机 pull（同 tag 直接覆盖）。

## 二、内网机：导入镜像

```bash
docker load -i /data/strix-allinone-<tag>.tar.gz     # 自动识别 gzip
docker images strix-allinone                          # 确认 <tag> 存在
```

内网机唯一的前提：**Docker daemon 已运行**，且当前用户能访问 `/var/run/docker.sock`
（见下文 `--group-add`，root 用户可省略）。

## 三、启动扫描

### 3.1 URL 目标（黑盒 / live 扫描）

```bash
mkdir -p strix_runs   # 报告输出目录

docker run --rm -it --network host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --group-add "$(stat -c %g /var/run/docker.sock)" \
  -e STRIX_IMAGE='strix-allinone:<tag>' \
  -e STRIX_LLM='openai/<模型名>' \
  -e LLM_API_BASE='http://<内网LLM地址>:<端口>/v1' \
  -e LLM_API_KEY='<key或任意非空>' \
  -v "$PWD/strix_runs:/workspace/strix_runs" \
  strix-allinone:<tag> \
  -n -t http://<目标地址>:<端口> --scan-mode quick --max-budget 10
```

参数说明：

| 参数 | 作用 |
|---|---|
| `--network host` | 容器共享宿主机网络：编排器可直接访问宿主机可达的一切目标；被拉起的沙箱端口映射也天然可达。**必加** |
| `-v docker.sock` | 编排器通过宿主机 daemon 拉起沙箱容器（DooD 模式） |
| `--group-add $(stat -c %g ...)` | socket 属 root:docker（0660），容器内是非 root 用户，需附加 socket 的 GID 才有权限。root 启动可省 |
| `-e STRIX_IMAGE` | 沙箱复用本镜像。**必须显式指定且与导入的 tag 一致**，否则会尝试拉默认镜像导致 FAILED TO PULL |
| `-e STRIX_LLM` 等 | 见 3.3 |
| `-v strix_runs` | 报告落宿主机，`--rm` 删容器后仍保留 |
| 镜像名之后 | 全部透传给 `strix` CLI：`-n` headless 必加；`-t` 目标；`--scan-mode quick\|deep`；`--max-budget` LLM 花费上限（美元） |

### 3.2 源码目标（白盒审查）

把源码目录挂进容器，`-t` 用**容器内路径**：

```bash
docker run --rm -it --network host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --group-add "$(stat -c %g /var/run/docker.sock)" \
  -e STRIX_IMAGE='strix-allinone:<tag>' \
  -e STRIX_LLM='openai/<模型名>' -e LLM_API_BASE=... -e LLM_API_KEY=... \
  -v "$PWD/strix_runs:/workspace/strix_runs" \
  -v /path/to/项目源码:/workspace/target-src:ro \
  strix-allinone:<tag> \
  -n -t /workspace/target-src --scan-mode quick --max-budget 10
```

（entrypoint 会自动设置 `STRIX_RUNTIME_UPLOAD_SOURCES=1`，源码以文件方式送入沙箱，
不依赖宿主机路径映射，只读挂载即可。）

### 3.3 LLM 配置（内网私服）

扫描完全由 LLM 驱动，必须有一个内网可达的 OpenAI 兼容接口
（vLLM / Xinference / One-API / 内部网关均可）：

```bash
-e STRIX_LLM='openai/glm-5.3'                                  # openai/ 前缀 = 按 OpenAI 协议调用
-e LLM_API_BASE='http://10.x.x.x:8000/v1'                      # 私服地址（宿主机可达即可）
-e LLM_API_KEY='sk-xxx'                                        # 私服不校验时也给任意非空值
# 可选：告知单价，让 run.json 的 cost 准确、预算控制有效
-e STRIX_LLM_INPUT_COST_PER_MTOK=... -e STRIX_LLM_OUTPUT_COST_PER_MTOK=...
```

### 3.4 可选项

```bash
# 报告语言：叙述文字用中文（代码/payload/CVSS 向量保持原样），缺省英文
-e STRIX_REPORT_LANGUAGE='简体中文'

# Java 目标编译走内网 Maven/Gradle 私服（自动生成 ~/.m2/settings.xml 和 ~/.gradle/init.gradle）
-e MAVEN_MIRROR_URL='http://nexus.内网:8081/repository/maven-public/' \
-e MAVEN_MIRROR_USER='...' -e MAVEN_MIRROR_PASS='...'        # 可选凭据
# Gradle 缺省复用 MAVEN_MIRROR_URL，单独指定用 GRADLE_MIRROR_URL
```

### 3.5 后台运行

把 `-it` 换成 `-d`，日志用：

```bash
docker logs -f $(docker ps -q --filter ancestor=strix-allinone:<tag>)
```

## 四、结果与退出码

| 退出码 | 含义 |
|---|---|
| 0 | 未发现漏洞（仅覆盖已分析范围，仍需看 run.json） |
| 1 | 致命错误 |
| 2 | **发现漏洞（对有漏洞目标这是预期结果）** |

artifacts 在 `strix_runs/<run-name>/`：

```bash
RUN=$(ls -td strix_runs/*/ | head -1)
jq '.status, .llm_usage.cost' "$RUN/run.json"        # completed + 预算内
ls "$RUN/vulnerabilities/"                            # 每条漏洞一个 .md
jq '.machine_observed.skills_exercised' "$RUN/coverage.json"   # 实际用到的技能
# penetration_test_report.md 总报告 / vulnerabilities.json / findings.sarif (SARIF 2.1.0)
```

## 五、常见问题

| 现象 | 原因与处理 |
|---|---|
| `permission denied .../docker.sock` | 缺 `--group-add "$(stat -c %g /var/run/docker.sock)"` |
| `FAILED TO PULL ghcr.io/...` | `STRIX_IMAGE` 未设或与导入 tag 不一致 |
| `DOCKER NOT INSTALLED` | 旧版镜像（< eb0f43d8）缺 docker-cli；新版已内置，出现即说明用的是旧 tag |
| 目标连不上 | 编排器已用 host 网络，等价于宿主机直连：先在宿主机 `curl` 目标验证可达性 |
| LLM 超时/401 | 宿主机上 `curl $LLM_API_BASE/models` 验证私服可达与 key 有效 |
| 成本显示异常 | 未设单价 env，或模型 id 与私服不匹配 |
| 需要进容器手工排查 | `docker run --rm -it --network host --entrypoint bash strix-allinone:<tag>` |

## 六、离线限制（纯内网须知）

- **LLM 必须内网可达**——这是硬前提，其余都可降级。
- 联网搜索工具不可用：agent 退回模型内置知识构造 payload。
- 部分扫描器（trivy 漏洞库、nuclei 模板、dependency-check 的 NVD 数据）首次使用会尝试联网更新；
  纯内网下更新失败会跳过或降级。**建议内网首跑后检查 coverage.json 与日志，确认关键工具是否生效。**
- 出网回调验证（interactsh 类 OOB）依赖外部服务器，纯内网不可用；如需该验证手段，
  内网自建 interactsh-server 并配置。响应侧证据（回显、状态码差异）不受影响。

## 七、镜像内容速查

| 组件 | 说明 |
|---|---|
| strix 编排器 | Python venv，独立于沙箱环境的 /app/.venv |
| JDK 17 (Temurin) / Maven 3.9 / Gradle 8.14 | JAVA_HOME=/opt/java-home，支持私服 |
| 反编译 | jadx / CFR / procyon |
| SAST/SCA | SpotBugs+FindSecBugs / OWASP Dependency-Check / semgrep |
| 反序列化 | ysoserial / marshalsec / SerializationDumper |
| 利用 | JNDI-Exploit-Kit；堆分析 Eclipse MAT（mat-parse-heapdump） |
| 沙箱侧 | Kali 工具链、浏览器、Caido 流量代理（沙箱角色自动启用） |
