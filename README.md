# Zero Trust Access Audit (Java / Spring Boot)

本服务在本地实现一套零信任的接口访问控制与审计能力：访问凭证的签发/校验/吊销、
签名密钥轮换与多密钥共存、基于角色与资源属性的授权判定，以及可追溯的审计日志。

## 凭证结构

凭证为紧凑字符串：`base64url(payloadJson) + "." + base64url(hmacSha256)`。

payload JSON 字段：

| 字段 | 含义 |
| --- | --- |
| `jti` | 凭证唯一标识（吊销按此生效） |
| `sub` | 主体 |
| `roles` | 角色集合 |
| `attrs` | 主体属性 |
| `iat` / `exp` | 签发 / 过期时间（epoch 秒） |
| `kid` | 签名密钥标识 |

校验规则与可区分的拒绝原因（`RejectionReason`）：

- `MALFORMED`：结构损坏、字段缺失、非合法 base64/JSON；
- `SIGNATURE_MISMATCH`：负载被篡改或签名不符（常量时间比较）；
- `EXPIRED`：超过 `exp + 时钟偏差`（默认 30s，`zerotrust.credential.clock-skew` 可配）；
- `REVOKED`：jti 已被吊销，吊销立即生效且只影响该凭证；
- `UNKNOWN_KEY`：密钥标识未知或已过轮换宽限期。

## 密钥轮换流程

- `KeyManager` 持有不可变的 `KeyRing` 快照（生效密钥 + 宽限期内旧密钥），保存在
  `volatile` 引用中；轮换在锁内构造新快照后一次性替换，并发校验不会误判。
- 轮换（`POST /api/zt/keys/rotate`）后：新密钥立即用于签发；旧密钥进入宽限期
  （默认 5 分钟，`zerotrust.key.grace-period` 可配），期间其签发的凭证仍可校验；
  宽限期结束后旧密钥被清理，对应凭证以 `UNKNOWN_KEY` 拒绝。
- `GET /api/zt/keys/current` 只返回当前密钥标识 `keyId`，密钥内容从不出现在任何
  响应或日志中。

## 授权规则与审计

- 默认拒绝：无任何匹配规则即拒绝。
- 策略由规则列表组成，规则 = 角色 + 动作 + 资源类型 + 资源属性约束（值支持 `*` 通配）。
- 策略更新是原子的：`AuthorizationService` 先构造完整的新 `Policy`（不可变），再替换
  `AtomicReference`，更新要么整体生效要么完全不生效，并发读不会看到半更新状态。
- 每次判定都写入一条 `AuditRecord`（auditId、时间、主体、动作、资源、结果、原因）。
- 审计查询（`GET /api/zt/audit`）要求凭证具备 `audit:read` 权限（角色匹配
  `audit:read` / `audit` 规则），越权查询返回 403 且该次尝试也会被审计。
- 凭证原文与密钥内容不会出现在任何响应或日志中。

## REST 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/zt/credentials` | 签发凭证 `{subject, roles, attributes, ttlSeconds}` |
| POST | `/api/zt/credentials/verify` | 校验凭证，返回 `valid` 与可区分 `reason` |
| POST | `/api/zt/credentials/revoke` | 吊销凭证 |
| POST | `/api/zt/keys/rotate` | 轮换签名密钥 |
| GET | `/api/zt/keys/current` | 查询当前密钥标识 |
| POST | `/api/zt/authorize` | 授权判定（需 `Authorization: Bearer <credential>`） |
| POST | `/api/zt/policy` | 整体替换授权策略 |
| GET | `/api/zt/audit` | 查询审计日志（需 `audit:read` 权限） |

## 本地验证

```bash
# 运行全部单元测试（日志中会标注各业务覆盖的用例与通过情况）
mvn test

# 本地启动
mvn spring-boot:run

# 签发 -> 校验 -> 授权 -> 审计 示例
TOKEN=$(curl -s -X POST localhost:8080/api/zt/credentials \
  -H 'Content-Type: application/json' \
  -d '{"subject":"alice","roles":["reader"],"attributes":{},"ttlSeconds":600}' \
  | jq -r .credential)
curl -s -X POST localhost:8080/api/zt/credentials/verify \
  -H 'Content-Type: application/json' -d "{\"credential\":\"$TOKEN\"}"
curl -s -X POST localhost:8080/api/zt/policy -H 'Content-Type: application/json' \
  -d '{"rules":[{"role":"reader","action":"read","resourceType":"document","requiredAttrs":{"tenant":"t1"}}]}'
curl -s -X POST localhost:8080/api/zt/authorize -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"action":"read","resourceType":"document","resourceAttrs":{"tenant":"t1"}}'
```

测试覆盖：`CredentialServiceTest`（过期/篡改/损坏/吊销）、`KeyRotationTest`
（宽限期边界、轮换并发）、`AuthorizationConcurrencyTest`（默认拒绝、策略并发更新）、
`AuditAccessTest`（审计留痕、越权审计查询、不泄露秘密）。
