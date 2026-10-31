---
name: crypto_scan
description: Java 密码学使用安全白盒扫描——证书校验绕过(TrustAll)、不安全算法(DES/MD5/SHA1/RC4)、AES 模式与 IV、随机数(new Random/SHA1PRNG)、密钥生成/长度/硬编码/复用、RSA 填充与长度、DSA 零值、MAC 截短、加密签名顺序、流密码比特反转、TLS 版本。审计 Java 源码密码学实现时使用。
---

# Java 密码学安全扫描

工作环境与纪律：目标源码在 `/workspace`；`rg` 预筛 + 读文件确认；只报实际读过的代码（file:line + 片段）；确认后调 `create_vulnerability_report`。密码学问题定性时要区分"算法缺陷"（一票确认）与"使用方式风险"（需看上下文：Random 用于生成 token/IV/密钥才是漏洞，用于测试数据不是）。

## 1. 证书校验绕过（MITM，最高优先级）

```bash
rg -n --type java -e 'X509TrustManager' -e 'checkServerTrusted' -e 'NoopHostnameVerifier' -e 'setSSLHostnameVerifier' -e 'HostnameVerifier' -e 'trustAllCerts|bypassSSL|ignoreSSL|sslBypass' /workspace
```

检测模式（命中即高危）：

1. `X509TrustManager` 匿名实现中 `checkServerTrusted`/`checkClientTrusted` **空方法体**——信任任意证书
2. `SSLContext.init(null, trustAllCerts, new SecureRandom())`——该 SSLContext 的所有连接失去身份验证
3. `NoopHostnameVerifier.INSTANCE` / 空 `HostnameVerifier`——跳过域名匹配，持他人域名的有效证书即可 MITM
4. `HttpClients.custom().setSSLHostnameVerifier(...)`、OkHttp `.sslSocketFactory(...)` 配套不安全 verifier

示例：

```java
TrustManager[] trustAllCerts = new TrustManager[] {
    new X509TrustManager() {
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}  // 空实现
        ...
    }
};
```

## 2. 不安全算法

```bash
rg -n --type java -e 'Cipher\.getInstance\(' -e 'MessageDigest\.getInstance\(' -e 'Mac\.getInstance\(' -e 'Signature\.getInstance\(' -e 'KeyGenerator\.getInstance\(' /workspace
```

对照表（出现在字符串里即命中）：

| 类别 | 不安全项 | 风险 | 替代 |
|---|---|---|---|
| 对称 | `DES` `3DES/DESede` `RC2` `RC4` `Blowfish` `IDEA` | 短密钥/已知攻击 | AES-256-GCM |
| 哈希 | `MD5` `SHA-1` `SHA` `RIPEMD160` | 碰撞攻击 | SHA-256+（口令存储用 bcrypt/PBKDF2） |
| MAC | `HmacMD5` `HmacSHA1` | 继承哈希缺陷 | HmacSHA256+ |
| 签名 | `SHA1withRSA` `MD5withRSA` `SHA1withDSA` | 碰撞伪造签名 | SHA256withRSA/PSS |
| 模式 | `AES/ECB` | 相同明文→相同密文，无语义安全 | AES/GCM |
| 编码 | Base64"保护"密码/secret | 不是加密，零安全性 | 真实加密 + KMS |

## 3. AES 模式与 IV

```bash
rg -n --type java -e 'AES.*ECB' -e 'AES.*CBC' -e 'AES/CTR' -e 'AES/OFB' -e 'IvParameterSpec' -e 'new byte\[16\]' /workspace
```

检测模式：

1. **ECB**：直接报告（确定性加密）
2. **CBC/CFB + 固定 IV**：`new IvParameterSpec(new byte[16])`（全零）或 `new IvParameterSpec("0102030405060708".getBytes())` 硬编码 IV——IV 可预测 → 重放/已知明文攻击。IV 应随机生成并随密文传输
3. **CTR/OFB 无认证（比特反转）**：流模式密文与明文 XOR 关联，攻击者篡改密文可精确翻转明文比特；解密侧无 MAC/签名校验（`Arrays.copyOf(hmac...)` 不存在）即成立。报告时给出"金额字段 1→9 比特翻转"这类具体利用说明
4. **ChaCha20 不带 Poly1305**：同上

## 4. 随机数

```bash
rg -n --type java -e 'new Random\(' -e 'Math\.random\(' -e 'SHA1PRNG' -e 'SecureRandom' /workspace
```

确认要点（上下文定级）：`java.util.Random`（48-bit seed 可预测）/`Math.random()`/`SHA1PRNG` 出现在以下用途即漏洞——密钥/IV/salt 生成、session token、验证码、密码重置 token、抽奖等安全敏感场景。修复：`SecureRandom`（默认算法，勿显式指定 SHA1PRNG）。

## 5. 密钥生成与管理

```bash
rg -n --type java -e 'SecretKeySpec\(' -e 'KeyGenerator' -e 'KeyPairGenerator' -e 'PBKDF2' -e 'PBEKeySpec' -e 'getEncoded\(\)' /workspace
rg -n --type java -e 'private\s+(static\s+)?final\s+String\s+\w*([Kk]ey|[Ss]ecret|[Pp]assword)\w*\s*=\s*"' /workspace
```

检测模式：

1. **密钥硬编码**：`SecretKeySpec("hardcoded-secret-key".getBytes(), "AES")`、`private static final String SECRET_KEY = "..."`——反编译即失守，Critical
2. **密钥长度**：`KeyGenerator.init(80/96)`（AES<128）、`KeyPairGenerator RSA initialize(512/768/1024)`（<2048 不安全，<3072 建议升级）、EC<256、DH<3072
3. **PBKDF2 参数**：`PBKDF2WithHmacMD5/SHA1` 弱哈希；迭代次数 <10000（口令派生）；salt <16 字节或固定值/非 SecureRandom 生成
4. **密钥复用**：同一 `KeyPair`/密钥既用于加密又用于签名（Cipher.init 与 Signature.initSign 共用对象）——违反密钥隔离，加密密钥泄露会连带伪造签名
5. **密钥用途混用**：同一 key 同时 init 进 Cipher（加密）和 Mac（认证）
6. **密钥组件单点**：根密钥仅一个来源（单个 System.getProperty/env），应为 ≥3 独立组件 XOR 组合 + PBKDF2 派生
7. **密钥字符串化**：`new String(key)` / `Base64.encodeToString(key...)` 后存日志/落盘

## 6. RSA 填充与 DSA 零值

```bash
rg -n --type java -e 'PKCS1' -e 'withRSA' -e 'SHA256withDSA' -e 'Signature\.getInstance' /workspace
```

检测模式：

1. `Cipher.getInstance("RSA/ECB/PKCS1Padding")`——Bleichenbacher padding oracle；加密场景换 OAEP
2. `Signature.getInstance("SHA256withRSA")`——默认 PKCS#1 v1.5 签名填充，理想为 `SHA256withRSA/PSS`（合规项，视验收标准定级 Medium/Low）
3. **DSA r/s 零值**：签名/验签代码未检查 r、s ∈ (0, q)——r 或 s 为 0 的签名应被拒绝；验签入口缺该校验按 Low~Medium 报告
4. **MAC 截短**：`Arrays.copyOf(mac, 12)` 类截短——对照标准长度（SHA-256→32B），截短降低暴力门槛，协议明确要求（如 SSH 96-bit）则不算

## 7. 加密与签名顺序

同一段代码同时出现加密与签名时，读完整流程确认顺序：

- **先签名后加密（Sign-then-Encrypt）✅**；**先加密后签名 ❌**——签名覆盖的是密文，攻击者可替换整段密文+重签或重放
- `rg -n --type java -e 'encrypt' -e '\.sign\(' -e '\.verify\('` 定位后 Read 全方法确认调用序

## 8. TLS 版本

```bash
rg -n --type java -e 'SSLContext\.getInstance\("SSL' -e 'TLSv1\.?[01]' -e 'TLS_1_0|TLS_1_1|SSL_3_0' -e 'setEnabledProtocols' /workspace
rg -n -g '*.yml' -g '*.properties' -g 'server.xml' -e 'ssl.*protocol|enabled-protocols' /workspace
```

检测模式：`SSLContext.getInstance("SSL"/"TLSv1.0"/"TLSv1.1")`、`setEnabledProtocols` 含 SSLv3/TLS1.0/1.1——协议降级与 POODLE/BEAST 风险。修复：TLSv1.2+，理想 1.3。

## 输出要求

每个确认发现：问题类型 / file:line + 代码片段 / 风险说明（具体攻击场景，不要只写"不安全"）/ 修复建议（给出安全替代 API 与参数）/ CVSS。纯合规性偏差（如 PKCS1 签名、RSA-2048）按 Low~Medium 归入"加固建议"，不冒充 High。
