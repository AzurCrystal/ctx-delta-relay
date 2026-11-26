# ctx-delta-relay

面向 LLM / Agent 长上下文 API（如 `new-api` / One-API、`/v1/responses`、`/v1/chat/completions`、`/v1/messages`）的**双端透明增量压缩中继**。

在多轮 Agent 编程场景中，虽然上游模型具备服务端 KV Prompt Cache，但客户端每一轮仍需重复上传 100K–200K tokens（几百 KB 至 1 MB+）的历史上下文，造成巨大的跨机房出站流量与延迟。`ctx-delta-relay` 通过 **Zstd Raw Prefix Dictionary (`ref_prefix`) + LDM（长距离匹配）** 与 **严格有界纯内存 TTL LRU 缓存**，在不修改客户端、不解析重构 JSON DOM、100% 保持上游 KV Prompt Cache 字节一致的前提下，将跨机房出站请求体流量压降 **95%–99%**。

## 架构概览

```text
[LLM / Coding Agent 客户端]  (零改造，照常发送全量请求)
            │
            ▼
[本地网关 (如 new-api)] ──(127.0.0.1)──▶ [ctx-delta-relay sender (客户端/发送端)]
                                               │
                         按会话指纹取上轮快照做 zstd ref_prefix + LDM 编码
                         仅传输 1%–5% 新增增量（通常几 KB）+ BLAKE3 校验
                         (携带 X-Delta-Auth 恒定时间鉴权头)
                                               │  HTTPS (TLS)
                                               ▼
                                  [ctx-delta-relay receiver (服务端/接收端)]
                                    - 纯内存有界 LRU（如硬限 256 MiB，0 磁盘）
                                    - 过期 / 重启 / 淘汰 → 返回 409 X-Delta-Miss: 1
                                      (sender 自动透明重发一次独立 zstd 全量，零报错)
                                    - 命中 → 还原字节级完全一致的原始请求并校验 BLAKE3
                                               │
                                               ▼ (127.0.0.1)
                                      [上游 API / new-api]
                                               │
                                               ▼ (零缓冲 SSE 流式透传回客户端)
```

## 核心特性

1. **零 JSON 重序列化，100% 字节级无损**：底层基于 `libzstd` 的 `ZSTD_CCtx_refPrefix` + LDM，直接对原始字节做跨轮增量压缩；上游收到的请求体与客户端发出的完全一致（通过 BLAKE3 强校验），绝不破坏上游 KV Prompt Cache 命中率，也天然兼容任意 API Schema。
2. **零磁盘 + 硬内存上限**：双端 LRU 仅缓存 **zstd 压缩态快照**（1 MB 原始上下文仅占 ~150 KB 内存），严格强制 `current_bytes <= max_cache_bytes`，并内置空闲 TTL 淘汰与每分钟定期清理。
3. **过期 / 重启 100% 透明自愈**：无论会话几天前过期、对端重启还是 LRU 触发淘汰，`receiver` 仅回一个极小的 `409` (`X-Delta-Miss: 1`)，`sender` 立刻自动回退重发一次独立 `zstd` 全量包，客户端完全无感知，且与上游真实 `409` 响应严格隔离。
4. **并发会话防碰撞**：无需客户端配合，优先识别 `x-session-id` → `prompt_cache_key` / `session_id` → `(Authorization 哈希, model, 首条 user 消息切片)` 作为会话指纹，同一用户同时跑多个共享相同 System Prompt 与工具定义的 Agent 也不会互相覆盖。
5. **零缓冲 SSE 流式转发与生产级防护**：响应侧通过 `bytes_stream` 逐块透传并记录中途断流错误；内置并发内存预算背压（`--max-inflight-mb` + `--max-codec-concurrency` 防 OOM）、禁用自动 HTTP 重定向防密钥泄露、`X-Delta-Cached` 显式缓存确认、可选发送端访问鉴权（`--client-auth`），以及 Unix `SIGTERM`/`SIGINT` 优雅停机。*(注：本工具专注 HTTP/SSE 长上下文中继；WebSocket 升级请求会显式返回 `501` 避免静默破坏连接，Responses WebSocket 模式建议直连上游。)*

## 部署文档

完整的生产级**服务端（`receiver`）与客户端（`sender`）部署指南**（包含二进制编译、密钥生成、Nginx/Caddy TLS + SSE 零缓冲反代配置、systemd 单元、NixOS Flake 集成、Kubernetes/Docker Sidecar、`new-api` 接入步骤、验证与排障）请参阅：

👉 **[客户端与服务端完整部署指南 (docs/DEPLOYMENT.md)](./docs/DEPLOYMENT.md)**

## 快速试跑

### 1. 服务端（`receiver`，部署在上游同机）

```bash
export DELTA_SECRET="replace-with-strong-random-hex"
ctx-delta-relay receiver \
  --listen 127.0.0.1:18080 \
  --admin-listen 127.0.0.1:18081 \
  --upstream-url http://127.0.0.1:3000 \
  --max-cache-mb 256 \
  --ttl-secs 1800
```

### 2. 客户端（`sender`，部署在出口侧 / 本地网关旁）

```bash
export DELTA_SECRET="replace-with-strong-random-hex"
ctx-delta-relay sender \
  --listen 127.0.0.1:18080 \
  --admin-listen 127.0.0.1:18081 \
  --receiver-url https://relay.example.com:18443 \
  --max-cache-mb 256 \
  --ttl-secs 1500
```

### 3. 查看实时省流统计

```bash
curl http://127.0.0.1:18081/stats
```

## 构建与实测表现

```bash
cargo test -- --nocapture
cargo clippy --all-targets -- -D warnings
cargo build --release
```

本地端到端集成测试实测数据（含 SSE 流式校验与 BLAKE3 字节级一致性断言）：

* **20 轮长上下文多轮对话（~360 KiB/轮，第 12 轮主动清空 `receiver` 缓存模拟对端重启）**：
  * 原始请求体总计 **7,297 KiB** → 实际跨网传输 **44 KiB**（**节省 99.39%**）
  * 自动触发 1 次 `409 X-Delta-Miss: 1` 透明重试，客户端全程 `200 OK` 无感知；`receiver` 端 LRU 压缩快照内存仅占 **173 KiB**
* **3 个并发会话共享同一份 30 KiB System Prompt 交叉发包（共 18 轮）**：
  * 原始总计 **3,470 KiB** → 实际跨网 **38 KiB**（**节省 98.89%**），零会话碰撞

NixOS 用户可直接通过 [flake.nix](./flake.nix) 构建或导入 `nixosModules.default`。

## License

[MIT](./LICENSE)
