# Webhook 接收服务

具备**去重、乱序暂存、双密钥验签、失败重试**能力的 webhook 接收服务，附带实时监控页面。

## 能力总览

| 问题 | 机制 |
|---|---|
| 事件重复投递 | 按 `(event_id, version)` 幂等去重，重复投递返回 `duplicate`，不重复处理 |
| 事件乱序到达 | 序号跳空的事件进入**暂存区**；缺口补齐后随**水位**推进按序释放 |
| 事件延迟到达 | 水位已过的迟到事件拒绝为 `stale`；签名时间戳超窗拒绝为 `rejected_timestamp` |
| 旧版本签名 | 密钥轮换后进入**双密钥窗口**：`current` 与 `previous` 均可验签（旧签事件打标 `previous`）；窗口可手动结束，此后旧签拒绝为 `rejected_key_expired` |
| 部分处理失败 | 处理器失败的事件置 `failed`、水位停住、后续事件保持暂存；支持重试与修复后重试 |

## 快速开始

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m webhook_service          # http://127.0.0.1:8000/
.venv/bin/python scripts/demo.py             # 另开终端：跑一遍全部演示场景
.venv/bin/python -m pytest tests/ -q         # 场景验证套件（15 项）
```

配置（环境变量）：`PORT`（默认 8000）、`WEBHOOK_DB`（默认 ./webhook.db）、
`WEBHOOK_INITIAL_SECRET`（初始密钥，默认 `whsec_dev_initial`）、
`WEBHOOK_TOLERANCE_SECONDS`（签名时间戳容差，默认 300）、
`WEBHOOK_ROTATION_GRACE_SECONDS`（双密钥窗口时长，默认 3600）。

## 接收管线

```
POST /webhook
  → 解析签名头  t=<ts>,kid=<key_id>,v1=<hmac>
  → 选钥        kid 命中 current，或窗口期内的 previous
  → 验签        HMAC-SHA256(secret, "{t}.{body}")，常量时间比较
  → 时间戳容差   |now - t| ≤ tolerance，超出判重放
  → 解析事件     {event_id, version, seq, type, payload}
  → 临界区（单锁 + SQLite 事务）
      (event_id, version) 已存在        → duplicate（幂等返回原状态）
      event_id 已有更高 version          → stale_version
      seq ≤ 水位                         → stale
      seq 被其他事件占用                  → rejected_seq_conflict
      seq = 水位+1 → 沿连续序列应用并推进水位；处理器失败 → failed，水位停住
      seq > 水位+1 → staged（暂存区）
  → 投递日志（每次投递一条，含结果、验签密钥、说明）
```

**水位（watermark）**：最大的"已连续应用"序号。只有 `seq = 水位+1` 的事件可被应用；
应用成功后水位推进，并连锁释放暂存区中新的连续序列。任一事件处理失败，
水位停在其前，后续事件留在暂存区，直到失败事件重试成功。

## 事件格式与签名

```json
{
  "event_id": "evt_001",
  "version": 1,
  "seq": 1,
  "type": "ledger.credit",
  "payload": {"account": "alice", "amount": 100}
}
```

```bash
SECRET=whsec_dev_initial
BODY='{"event_id":"evt_001","version":1,"seq":1,"type":"ledger.credit","payload":{"account":"alice","amount":100}}'
T=$(date +%s)
SIG=$(printf '%s.%s' "$T" "$BODY" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $2}')
curl -X POST http://127.0.0.1:8000/webhook \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Signature: t=$T,kid=k_initial,v1=$SIG" \
  -d "$BODY"
```

业务处理器（`handlers.py`）把事件应用到账本投影，演示真实的部分失败：

- `payload.fail_attempts: n` — 前 n 次处理尝试瞬时失败，重试可恢复
- `payload.force_fail: true` — 永久失败，需 `PATCH` 修复后重试
- `ledger.debit` 超余额 — 业务规则失败（余额不足）

## API

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/webhook` | 接收事件（头 `X-Webhook-Signature`，可选 `X-Webhook-Delivery`） |
| GET | `/api/state` | 水位、密钥、计数、接收/暂存/释放/失败记录、投影 |
| GET | `/` | 监控页面（2s 自动刷新） |
| POST | `/admin/keys/rotate` | 轮换密钥：current→previous（进窗口），生成新 current |
| POST | `/admin/keys/expire-previous` | 立即结束双密钥窗口 |
| POST | `/admin/events/{event_id}/{version}/retry` | 重试失败事件；`{"patch": {...}}` 可先修复 payload |
| POST | `/admin/demo/{scenario}` | 触发演示场景（走真实接收管线） |
| POST | `/admin/reset` | 清空数据并恢复初始密钥 |

投递结果：`applied` `staged` `duplicate` `failed` `stale` `stale_version`
`rejected_bad_signature` `rejected_timestamp` `rejected_unknown_key`
`rejected_key_expired` `rejected_seq_conflict` `rejected_invalid_payload`。

## 演示场景（页面按钮 / `/admin/demo/*`）

| 场景 | 验证点 |
|---|---|
| `ordered` | 按序投递，水位连续推进 |
| `duplicate` | 同一签名投递原样重放 → 去重，投影只入账一次 |
| `out_of_order` | 跳空事件暂存，补齐缺口后按序释放（应用日志严格按 seq） |
| `delayed_stale` | 水位已过的迟到事件 → `stale` |
| `key_rotation` | 轮换后旧密钥窗口内可验签（打标"旧密钥"）、新密钥正常 |
| `expired_old_key` | 结束窗口后旧签 → `rejected_key_expired` |
| `bad_signature` | 伪造密钥 → `rejected_bad_signature` |
| `replay_old_timestamp` | 过期时间戳重放 → `rejected_timestamp` |
| `partial_failure` | 批中一笔瞬时失败：水位停住、后续暂存；重试后连锁释放 |

## 验证

`tests/test_scenarios.py`（pytest + TestClient，临时库）覆盖：
按序应用与水位推进、重放去重（投影不重复入账）、乱序暂存与按序释放、
迟到事件 `stale`、旧版本 `stale_version`、序号冲突、伪造签名、过期时间戳、
双密钥窗口（旧签可用并打标）、窗口关闭拒旧签、未知密钥、
部分失败（水位停住 + 暂存保留 + 重放去重 + 重试释放）、
永久失败修复后重试、业务规则失败（余额不足）、重置。

## 结构

```
webhook_service/
  app.py        FastAPI 路由与依赖装配
  core.py       接收管线（验签→去重→定序→应用→释放）、重试、轮换
  store.py      SQLite 持久化（密钥/水位/事件/投递日志/投影）
  crypto.py     HMAC-SHA256 签名与解析
  handlers.py   业务处理器（账本投影，可注入瞬时/永久失败）
  demo.py       演示场景生成器
  static/index.html  监控页面
scripts/demo.py 演示客户端（对运行中的服务跑全部场景）
tests/test_scenarios.py  场景验证套件
```
