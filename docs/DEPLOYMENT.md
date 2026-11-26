# 客户端（`sender`）与服务端（`receiver`）生产部署指南

`ctx-delta-relay` 采用单一二进制文件提供双端角色：

| 角色 | 子命令 | 部署位置 | 职责 |
| :--- | :--- | :--- | :--- |
| **服务端（接收端 / Hydrator）** | `ctx-delta-relay receiver` | **上游 API 所在机器**（与上游 `new-api` / 推理网关同机或同内网） | 校验 `X-Delta-Auth` → 从内存有界 LRU 还原完整请求体 → 校验 BLAKE3 → 通过 `127.0.0.1` 转发给上游并流式透传 SSE |
| **客户端（发送端 / Encoder）** | `ctx-delta-relay sender` | **发起方机器**（如云端高出站费服务器上的 `new-api` 旁，或本机/局域网网关旁） | 接收明文 LLM API 请求 → 提取会话指纹并做 `zstd ref_prefix` 增量编码 → 发往远端 `receiver` → 遇 `409 X-Delta-Miss` 自动无感重传全量 |

---

## 一、前置准备

### 1. 构建二进制文件

#### 方式 A：Cargo 原生构建（适用于 Debian / Ubuntu / CentOS / macOS / Windows）

```bash
git clone https://github.com/AzurCrystal/ctx-delta-relay.git
cd ctx-delta-relay
cargo build --release
# 产物位置：target/release/ctx-delta-relay
```

#### 方式 B：Nix Flake 构建（适用于 NixOS 或装有 Nix 的 Linux）

```bash
nix build github:AzurCrystal/ctx-delta-relay
# 产物位置：./result/bin/ctx-delta-relay
```

### 2. 生成预共享隧道密钥（两端必须完全一致）

```bash
openssl rand -hex 32
```

请将生成的 64 位随机十六进制字符串妥善保存，下文统一记作 `<YOUR_DELTA_SECRET>`。

> **安全原则**：不要通过命令行 `--secret` 传密钥（会暴露在 `ps aux` 进程列表中），务必通过 `EnvironmentFile`（环境变量 `DELTA_SECRET`）注入，文件权限设为 `0600`。

---

## 二、服务端（`receiver`）部署指南（上游同机）

### 方案 2.1：普通 Linux + systemd + Nginx/Caddy（推荐）

#### 1. 安装二进制与密钥文件

```bash
sudo install -m 0755 target/release/ctx-delta-relay /usr/local/bin/ctx-delta-relay

sudo install -d -m 0750 /etc/ctx-delta-relay
sudo tee /etc/ctx-delta-relay/receiver.env > /dev/null <<'EOF'
DELTA_SECRET=<YOUR_DELTA_SECRET>
EOF
sudo chmod 0600 /etc/ctx-delta-relay/receiver.env
```

#### 2. 创建 systemd 服务单元

假设上游 `new-api` 监听在 `http://127.0.0.1:3000`（若上游是本机 Nginx/Caddy 虚拟主机，可通过 `--upstream-host api.example.com` 指定 `Host` 头）：

```ini
# /etc/systemd/system/ctx-delta-relay-receiver.service
[Unit]
Description=ctx-delta-relay receiver (bounded LRU delta hydrator)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
DynamicUser=yes
EnvironmentFile=/etc/ctx-delta-relay/receiver.env
Environment=RUST_LOG=info
ExecStart=/usr/local/bin/ctx-delta-relay receiver \
  --listen 127.0.0.1:18080 \
  --admin-listen 127.0.0.1:18081 \
  --upstream-url http://127.0.0.1:3000 \
  --max-cache-mb 256 \
  --ttl-secs 1800 \
  --max-body-mb 16 \
  --cache-zstd-level 1 \
  --read-timeout-secs 300
Restart=always
RestartSec=2s
# 系统级硬内存兜底（缓存上限 256M + 运行时富余 192M）
MemoryMax=448M
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

启用并启动服务：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ctx-delta-relay-receiver
sudo systemctl status ctx-delta-relay-receiver
```

#### 3. 配置前置 TLS 反向代理（Nginx 或 Caddy）

> **重要**：`ctx-delta-relay receiver` 监听在 `127.0.0.1:18080`（明文），请使用本机 Nginx 或 Caddy 提供 **HTTPS/TLS 加密**，并**关闭响应缓冲（否则 SSE 会卡顿）**，同时建议在防火墙/反代层**仅放行客户端（`sender`）所在出口 IP**。

**Nginx 示例**（建议开放独立 HTTPS 端口如 `18443` 或专用子域名）：

```nginx
server {
    listen 18443 ssl;
    http2 on;
    server_name relay.example.com;

    ssl_certificate     /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;

    # 强烈建议：仅放行你的 sender 机器出口 IP
    allow 198.51.100.20;
    deny all;

    # 允许单次全量 zstd 包上传（与 --max-body-mb 对应）
    client_max_body_size 32m;

    location / {
        proxy_pass http://127.0.0.1:18080;
        proxy_http_version 1.1;
        proxy_set_header Connection "";

        # 必须关闭缓冲，保证 LLM SSE 流式逐块透传、零额外 TTFT
        proxy_buffering off;
        proxy_cache off;
        chunked_transfer_encoding on;

        # 长思考/长流式响应超时保护
        proxy_connect_timeout 15s;
        proxy_send_timeout 120s;
        proxy_read_timeout 600s;
    }
}
```

**Caddy 示例**（自动管理 TLS 证书，原生流式不缓冲）：

```caddyfile
relay.example.com:18443 {
    @allowed remote_ip 198.51.100.20
    handle @allowed {
        reverse_proxy 127.0.0.1:18080 {
            flush_interval -1
            transport http {
                read_timeout 600s
                write_timeout 120s
            }
        }
    }
    respond 403
}
```

---

### 方案 2.2：NixOS 部署服务端（`receiver`）

在你的 `flake.nix` 中添加输入并启用模块：

```nix
{
  inputs.ctx-delta-relay.url = "github:AzurCrystal/ctx-delta-relay";

  # 在目标主机的 NixOS 配置中：
  imports = [ inputs.ctx-delta-relay.nixosModules.default ];

  services.ctx-delta-relay.receiver = {
    enable = true;
    listen = "127.0.0.1:18080";
    adminListen = "127.0.0.1:18081";
    upstreamUrl = "http://127.0.0.1:3000";
    # 如转发到本地 Nginx/Caddy 虚拟主机则按需设置：
    # upstreamHost = "api.example.com";
    environmentFile = "/run/secrets/ctx-delta-relay.env"; # 内容：DELTA_SECRET=...
    maxCacheMb = 256;
    ttlSecs = 1800;
  };
}
```

---

## 三、客户端（`sender`）部署指南（出口侧 / 本地网关旁）

> **TTL 配比最佳实践**：务必保证 **`sender` 的 `--ttl-secs` 略小于 `receiver` 的 `--ttl-secs`**（例如 `sender = 1500` 秒、`receiver = 1800` 秒）。这样超过 25 分钟的旧会话在 `sender` 侧会主动跳过无意义的 delta 探测，直接走单次独立 `zstd` 全量包，省掉 1 次 `409` RTT 往返。

### 方案 3.1：普通 Linux + systemd

```bash
sudo install -m 0755 target/release/ctx-delta-relay /usr/local/bin/ctx-delta-relay

sudo install -d -m 0750 /etc/ctx-delta-relay
sudo tee /etc/ctx-delta-relay/sender.env > /dev/null <<'EOF'
DELTA_SECRET=<YOUR_DELTA_SECRET>
EOF
sudo chmod 0600 /etc/ctx-delta-relay/sender.env
```

```ini
# /etc/systemd/system/ctx-delta-relay-sender.service
[Unit]
Description=ctx-delta-relay sender (delta + zstd encoder sidecar)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
DynamicUser=yes
EnvironmentFile=/etc/ctx-delta-relay/sender.env
Environment=RUST_LOG=info
ExecStart=/usr/local/bin/ctx-delta-relay sender \
  --listen 127.0.0.1:18080 \
  --admin-listen 127.0.0.1:18081 \
  --receiver-url https://relay.example.com:18443 \
  --max-cache-mb 256 \
  --ttl-secs 1500 \
  --min-delta-bytes 4096 \
  --max-body-mb 16 \
  --zstd-level 3 \
  --read-timeout-secs 300
Restart=always
RestartSec=2s
MemoryMax=448M
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

启用并启动：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ctx-delta-relay-sender
```

### 方案 3.2：NixOS 部署客户端（`sender`）

```nix
{
  imports = [ inputs.ctx-delta-relay.nixosModules.default ];

  services.ctx-delta-relay.sender = {
    enable = true;
    listen = "127.0.0.1:18080";
    adminListen = "127.0.0.1:18081";
    receiverUrl = "https://relay.example.com:18443";
    environmentFile = "/run/secrets/ctx-delta-relay.env"; # 内容：DELTA_SECRET=...
    maxCacheMb = 256;
    ttlSecs = 1500;
    zstdLevel = 3;
  };
}
```

### 方案 3.3：接入 `new-api` / One-API / 下游客户端

无需改动任何终端 Agent 客户端代码，只需修改**发起端网关（如 `new-api`）里的渠道配置**：

1. 打开 `new-api` 管理后台 → **渠道（Channels）** → 编辑目标渠道；
2. 将该渠道的 **代理 / Base URL** 从原公网地址（如 `https://api.example.com`）修改为本地 `sender` 地址：
   * 同宿主机直接部署：`http://127.0.0.1:18080`
   * Kubernetes 同 Pod Sidecar：`http://127.0.0.1:18080`
   * Kubernetes 独立 Service：`http://ctx-delta-sender.<namespace>.svc.cluster.local:18080`
3. 渠道的 **API Key** 保持原样不变（`sender` 与 `receiver` 会原样透传 `Authorization` 等业务请求头）。

---

## 四、上线验收与监控指南

### 1. 健康检查

分别在 `receiver` 和 `sender` 机器本地执行：

```bash
curl -fsS http://127.0.0.1:18081/healthz
# 预期输出：ok
```

### 2. 验证鉴权拒绝（确保不会沦为开放代理）

在 `sender` 机器上直接不带密钥访问 `receiver`：

```bash
curl -i https://relay.example.com:18443/v1/models
# 预期返回：HTTP/2 403 forbidden
```

### 3. 查看实时压缩与省流指标

跑完几轮真实对话后，在 `sender` 机器执行：

```bash
curl -s http://127.0.0.1:18081/stats | jq .
```

正常多轮对话下的输出示例：

```json
{
  "role": "sender",
  "requests_total": 42,
  "mode_pass_total": 2,
  "mode_full_total": 3,
  "mode_delta_total": 37,
  "miss_retries_total": 0,
  "errors_total": 0,
  "raw_bytes_total": 24851200,
  "wire_bytes_total": 412800,
  "saved_bytes_total": 24438400,
  "savings_percent": 98.34,
  "lru_entries": 3,
  "lru_bytes": 195400,
  "lru_max_bytes": 268435456,
  "lru_evictions_total": 0
}
```

### 4. 演练对端重启自愈

在连续对话中途手动重启 `receiver`：

```bash
sudo systemctl restart ctx-delta-relay-receiver
```

紧接着在客户端发下一轮消息：
* 客户端应正常收到 `200 OK` 与完整 SSE 回复（无报错、无断话）；
* 在 `sender` 的 `/stats` 中应看到 `miss_retries_total` 增加 `1`，`mode_full_total` 增加 `1`；
* 再发下一轮时，`mode_delta_total` 自动恢复递增。

---

## 五、参数调优与常见排障

| 现象 | 常见原因 | 解决方法 |
| :--- | :--- | :--- |
| 返回 `403 forbidden` | 两端 `DELTA_SECRET` 不一致，或 Nginx/Caddy IP 白名单未放行 `sender` 出口 IP | 检查两端的 `EnvironmentFile` 是否有多余换行/空格，检查反代 `allow` 规则 |
| 返回 `413 Payload Too Large` | 单次请求体超过 `--max-body-mb`（默认 16 MiB）或 Nginx `client_max_body_size` | 同步调大双端 `--max-body-mb` 与反代 `client_max_body_size` |
| SSE 输出一整段卡住后突然吐出 | 前置 Nginx 开启了响应缓冲 | 在 Nginx `location` 中确认已设 `proxy_buffering off;` 与 `proxy_cache off;` |
| 长思考模型中途断连（504） | Nginx `proxy_read_timeout` 或 `--read-timeout-secs` 过短 | 调大至 `600s` |
| `miss_retries_total` 持续偏高 | `sender` TTL 大于 `receiver` TTL，或 `receiver` 的 `--max-cache-mb` 过小导致活跃会话频繁被淘汰 | 保持 `sender.ttl < receiver.ttl`（如 1500 vs 1800），并将 `receiver` 的 `--max-cache-mb` 设为 `256`–`512` |
| 仅想临时直连自签证书测试 | 尚未给 `receiver` 配正式域名证书 | 测试期可在 `sender` 临时加 `--insecure-tls`（**生产环境请勿开启**，务必使用正式证书） |
