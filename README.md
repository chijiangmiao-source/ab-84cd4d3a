# 隔离维护网 · 设备域密钥轮换授权链

运营员沿**唯一授权链**为远端设备轮换签发密钥：候选轮换必须携带**固定父摘要**，
由**父链头当前成员**用 Ed25519 对**规范 UTF-8 消息**签名；去重后的父成员数达到
**父门限**时，候选才在**同一持久化提交**中激活为新活动检查点。延迟补签、并发
重传与竞争候选最终只收敛为一个活动链头；任何不满足条件的提交都给出拒因且不改变链头。

## 授权链规则

1. 设备域含 **2–5 把 Ed25519 公钥**及门限（1..N）。
2. 待签消息为规范化 JSON（键按码位排序、数组保序）的 UTF-8 字节，字段固定为：
   `label / domainId / rotationId / parentDigest / epoch / nextKeys / nextThreshold`，
   其中 `nextKeys` 为按 `x` 排序后的新公钥集，`epoch = 父代次 + 1`。
3. 服务端对每条签名独立验签，且签名者必须是**当前活动链头**的密钥成员。
4. 去重计数（按父成员公钥）达到父门限 → 在同一临界区内写入新检查点、推进链头、原子落盘。
5. 拒因（均不推进链头，且留审计）：
   - `parent-digest-mismatch`：错误父摘要；
   - `stale-parent`：候选所依据的父检查点已被后继取代；
   - `payload-tampered`：同一轮换标识的载荷与已固定候选不一致；
   - `duplicate-signature`：重复签名 / 重传（幂等，不重复计数）；
   - `bad-signature`：未通过规范 UTF-8 消息验签；
   - `signer-not-parent-member`：签名者不是父链头成员；
   - `rotation-already-activated`：激活后的竞争候选。
6. 状态经互斥锁串行化，落盘采用临时文件 + `rename`；进程重启后活动链头、
   历史检查点与签名证据逐字节一致。

## HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/health` | 健康响应：设备域数、活动检查点数、待签候选数、持久化标志 |
| `GET` | `/api/domains` | 设备域概要列表 |
| `POST` | `/api/domains` | 创建设备域 `{ name, keys: [JWK], threshold }` |
| `GET` | `/api/domains/:id` | 活动链头、历史检查点（含签名证据）、待签、已拒 |
| `POST` | `/api/domains/:id/preview` | 预览规范消息（不写状态） |
| `POST` | `/api/domains/:id/signatures` | 分批提交签名，支持 `{...proposal, signerKey, signature}` |

公钥 JWK 形如 `{"kty":"OKP","crv":"Ed25519","x":"<base64url-32B>"}`，签名为
对规范消息的 Ed25519 签名（64 字节）的 base64url。

页面 `/` 与接口同源，直接渲染接口返回的固定父摘要、下一代次、排序后新公钥集、
新门限及待签 / 已拒 / 已激活检查点（含每份签名证据）。

## 本地运行

```bash
node src/server.js            # 默认 :8080，数据落盘 ./data/state.json
```

## 验收

`verify` 是可执行验收入口，依次执行并以退出码报告结果：

1. 轮换规则代码测试：`node --test test/`（10 个用例，含并发收敛与重启一致性）；
2. 构建检查：全部 JS 语法校验、JSON 校验、模块可加载性、页面 DOM id 一致性；
3. HTTP 冒烟：自启服务，创建**二钥且门限为二**的设备域，分两批补齐两名有效签名，
   通过接口读取已激活链头及两份证据并独立复核，覆盖全部拒因、激活后竞争、
   第二代延伸、健康响应、页面同源检查及进程重启一致性。

```bash
./verify                      # 直接在主机（Node >= 20）运行
```

Docker Compose：

```bash
docker compose up app -d                    # 启动服务
curl http://localhost:8080/health           # 健康响应
docker compose run --rm verify              # 容器内运行完整验收入口
```

`verify` 服务结束即退出，退出码 0 表示全部检查通过，非零表示失败。

## 目录结构

```
src/canonical.js     规范化 JSON / UTF-8 字节
src/crypto-keys.js   Ed25519 JWK、公钥集排序去重、签名验签
src/rotation.js      授权链核心：门限、去重、拒因、互斥、原子持久化
src/server.js        HTTP 服务与静态页面
public/              运营页面
test/rotation.test.js 规则测试（node --test）
scripts/smoke.mjs    HTTP 冒烟验收
scripts/build-check.mjs 构建检查
verify               验收入口
Dockerfile / docker-compose.yml
```
