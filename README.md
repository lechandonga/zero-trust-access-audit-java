# 本地零信任接口访问控制与审计（Spring Boot）

一个不依赖外部认证/授权服务的本地零信任最小实现：HMAC 凭证的签发、校验与吊销、
签名密钥轮换与宽限期共存、基于角色与资源属性的默认拒绝授权，以及每次判定必留痕、
读取需权限的审计能力。所有状态更新均为不可变快照原子发布，异常与并发场景下结论
一致、原因可区分。

## 1. 凭证结构

凭证是三段式的不透明 Bearer Token（ASCII，点分，base64url 无填充）：

```
base64url(header) . base64url(payload) . base64url(HMAC_SHA256(header.payload))
header  = {"alg":"HS256","kid":"<签名密钥标识>"}
payload = {"jti":"<凭证唯一标识>", "sub":"<主体>", "roles":["..."],
           "iat":<签发epoch毫秒>, "exp":<过期epoch毫秒>}
```

校验顺序与可区分的拒绝原因（HTTP 401，响应 `error` 字段）：

| 顺序 | 原因码 | 触发条件 |
| --- | --- | --- |
| 1 | `malformed` | 段数错误、Base64/JSON 损坏、`alg` 非 HS256、缺 `kid/jti/sub/roles/iat/exp` |
| 2 | `unknown_key` | `kid` 不存在，或旧密钥已超过轮换宽限期 |
| 3 | `signature_mismatch` | 重算的 HMAC 与签名段不一致（含载荷被篡改），常量时间比较 |
| 4 | `expired` | 当前时间超过 `exp + ztaa.credential.clock-skew-millis`（默认 60s 时钟偏差容忍） |
| 5 | `revoked` | `jti` 在吊销集合中 |

吊销按 `jti` 粒度即时生效（内存 `ConcurrentHashMap.newKeySet()`），
只影响被吊销的那一张凭证，同主体的其他凭证继续有效。

## 2. 密钥轮换流程

- 任意时刻只有一个 **active** 密钥用于签发；轮换时旧密钥变为 **retired**。
- retired 密钥在 `ztaa.key.grace-millis`（默认 10 分钟）内仍可用于**校验**，
  保证轮换前刚签发的凭证平滑过渡；宽限期结束后旧密钥被清除，相关凭证返回
  `unknown_key`。
- `KeyManager` 每次轮换构造一份全新的不可变快照（active 标识 + 不可变 Map），
  单次 volatile 引用发布；并发校验要么看到轮换前、要么看到轮换后的完整状态，
  不存在半更新读取。
- 密钥查询/轮换接口只返回 `keyId`、密钥指纹（SHA-256 前 8 字节的十六进制）、
  启用与退役时间；密钥字节从不出现在任何响应、日志或异常消息中。

## 3. 授权规则

- 默认拒绝：没有任何规则匹配即为 `default-deny`。
- 规则为有序列表，第一条匹配规则决定 `ALLOW`/`DENY`。匹配维度：
  `roles`（任一命中）、`actions`、`resourceTypes`、`environments`（精确匹配）、
  `tags`（任一命中）；空列表表示该维度通配。
- 策略整体替换：`PolicyStore` 先构造并校验完整的新 `Policy`（版本号递增），
  再单次 volatile 发布；单次授权评估只读一次策略快照，读者绝不会读到
  “新旧规则混合”的中间状态。
- 每次判定都写一条审计记录（允许与拒绝都写），内容仅含主体、`jti`、`keyId`、
  角色、资源、判定、原因、命中规则、策略版本与时间戳——**不含凭证、签名或密钥**；
  同样内容以 `ztaa.audit` logger 输出到日志。
- 审计查询需要 `admin` 或 `audit-reader` 角色（权限 `audit:read`），
  越权返回 HTTP 403。

## 4. HTTP 接口

两种认证头：`Authorization: Bearer <凭证>` 或 `Authorization: AdminToken <本地管理令牌>`
（管理令牌具备内置 `admin` 角色，常量时间比较）。

| 方法/路径 | 权限 | 说明 |
| --- | --- | --- |
| `POST /ztaa/credentials` | admin | 签发凭证，body: `{"subject":"alice","roles":["reader"]}`；token 仅本次返回 |
| `POST /ztaa/credentials/revoke` | admin | body: `{"jti":"..."}`，即时吊销 |
| `GET /ztaa/keys` | admin | 当前生效密钥标识与全部密钥元数据（无密钥内容） |
| `POST /ztaa/keys/rotate` | admin | 轮换密钥，返回新的 active keyId |
| `GET /ztaa/policy` | admin | 查询当前策略版本与规则 |
| `PUT /ztaa/policy` | admin | 整体替换规则（原子生效），body 为 `{"rules":[...]}` |
| `POST /api/access/evaluate` | 任意有效凭证 | 对资源请求做授权判定并写审计，返回审计记录 |
| `GET /ztaa/audit?subject=&limit=` | admin / audit-reader | 查询审计（最新在前） |

## 5. 配置（`application.properties`）

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `ztaa.credential.ttl-millis` | 3600000 | 凭证有效期 |
| `ztaa.credential.clock-skew-millis` | 60000 | 过期判定容忍的时钟偏差 |
| `ztaa.key.grace-millis` | 600000 | 旧密钥轮换后的校验宽限期 |
| `ztaa.admin-token` / `ZTAA_ADMIN_TOKEN` | 空 | 本地引导管理令牌；留空时启动生成随机令牌并只在标准输出打印一次 |

## 6. 本地验证方法

要求 JDK 21+、Maven 3.9+。

```bash
# 运行全部单测（控制台会按“业务 → 用例 → 通过/失败”打印覆盖情况）
mvn test

# 启动服务（未配置管理令牌时，注意保存启动时打印的一次性随机令牌）
mvn spring-boot:run

# 1) 签发凭证
TOKEN=$(curl -s -X POST localhost:8080/ztaa/credentials \
  -H 'Authorization: AdminToken <管理令牌>' -H 'Content-Type: application/json' \
  -d '{"subject":"alice","roles":["reader"]}' | jq -r .token)

# 2) 轮换密钥（旧凭证宽限期内仍可用）
curl -s -X POST localhost:8080/ztaa/keys/rotate \
  -H 'Authorization: AdminToken <管理令牌>'

# 3) 授权判定（默认策略为拒绝）
curl -s -X POST localhost:8080/api/access/evaluate \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"action":"read","resourceType":"document","resourceId":"doc-1",
       "environment":"prod","tags":["public"],"attributes":{}}'

# 4) 发布允许策略后再次判定
curl -s -X PUT localhost:8080/ztaa/policy \
  -H 'Authorization: AdminToken <管理令牌>' -H 'Content-Type: application/json' \
  -d '{"rules":[{"name":"readers-read","effect":"ALLOW","roles":["reader"],
       "actions":["read"],"resourceTypes":["document"],
       "environments":["prod"],"tags":["public"]}]}'

# 5) 查询审计（普通凭证调用返回 403）
curl -s 'localhost:8080/ztaa/audit?limit=20' \
  -H 'Authorization: AdminToken <管理令牌>'
```

## 7. 单元测试覆盖

测试通过自定义 JUnit 扩展 `BusinessTestLogger` 在控制台输出
`[业务:xxx] 用例开始/通过/失败: <方法名>`，可直接看出覆盖的业务与每条用例结果。

| 测试类 | 业务 | 关键场景 |
| --- | --- | --- |
| `CredentialServiceTest` | 凭证签发/校验/吊销 | 有效凭证、过期+时钟偏差边界、签名段/载荷篡改、结构损坏、吊销即时且互不影响 |
| `KeyRotationTest` | 密钥轮换与宽限期 | 宽限期精确边界（期内通过/到期 `unknown_key`）、轮换x校验并发无错判、密钥查询不泄密 |
| `AuthorizationPolicyTest` | 授权与审计 | 默认拒绝、角色+资源属性匹配、策略并发更新读不到半更新、审计不含敏感信息 |
| `WebApiTest` | HTTP 接口 | 401 原因区分、非 admin 访问管理接口 403、越权审计查询 403、吊销即时生效、响应不泄密 |
