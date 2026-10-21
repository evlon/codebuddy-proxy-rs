# codebuddy-proxy-rs

Rust 实现的 **CodeBuddy → OpenAI 兼容** 代理。读取本机 CodeBuddy / WorkBuddy 桌面端登录态，把 `OpenAI` 协议的 `chat/completions` 请求透传到 CodeBuddy 官方后端，让任意 OpenAI 客户端 / 工具链直接使用 CodeBuddy 订阅。

使用与官方客户端、[codebuddy2openai] 相同的登录文件（`auth/*.info`），**只读 + 按需回写刷新结果**，不替代登录、不存储密码。

[codebuddy2openai]: https://github.com/evlon/codebuddy2openai

## 特性

- OpenAI 兼容 HTTP 面：`/v1/models`（动态）、`/v1/models/{model}`、`/v1/chat/completions`（流式 / 非流式）
- **动态模型列表**：实时调用官方 CLI 同款 `GET /v3/config`，取 `agents["cli"].models`（官方 `/model` 选择器同款可用列表），TTL 缓存 + 失败兜底（上次成功结果 → 内置快照）
- **上下文窗口元数据**：`/v1/models` 每项附 `max_input_tokens` / `context_length` / `max_output_tokens`（`/v1/models/{id}` 再附 vLLM / LM Studio 风格别名与后端原始元数据），客户端可据此做压缩/截断决策、避免上下文溢出
- **官方 CLI 请求指纹**：出站请求头模拟官方客户端（UA / X-Product / X-Request-ID / X-IDE / X-Agent / X-Trace / X-Conversation 族），降低被后端画像为"第三方转换器"的概率（见下方「降低风控识别」）
- 复用 CodeBuddy 桌面登录态，token 临近过期自动刷新并原子回写
- 可选 `--api-key` 鉴权（`Authorization: Bearer` 或 `X-Api-Key`）
- 可选 `--log`：请求 / 原始 SSE 旁路录制，便于排查内容审核拦截
- 可选 `--desensitize`：system 合规词零宽空格脱敏，缓解后端误拦（词表含 `DeepSeek Harness` 竞品签名）
- 可选 `--user-escape`：user 消息敏感术语转义（`[s[<逐字反转>]]` + 自动补解码说明）
- 默认开 `--strip-harness`：清洗 system 里 dsh 三段全局签名（`DeepSeek Harness` 字面量即后端 `11128` 渠道拦截的匹配串）
- `--save-auth` / `--restore-auth`：把本机登录态一键迁移到服务器
- 单一静态二进制，无需运行时

## 工作原理

```
任意 OpenAI 客户端 ──> codebuddy-proxy-rs ──> CodeBuddy 后端
       (127.0.0.1:8787)                    (copilot.tencent.com)
            POST /v2/chat/completions（聊天透传）
            GET  /v3/config（动态模型目录）
```

- 透传时强制 `stream=true`：客户端要流式则逐字节透传 SSE；非流式则在后端流结束后聚合为单个 completion。
- 模型列表来自后端 `/v3/config`（与官方 CLI 登录后拉取产品配置同一接口），`--models-ttl` 控制缓存秒数（默认 600，`0` = 每次实时拉取，`?refresh=1` 强制刷新）。
- 出站请求头为官方 CLI 形态（UA 等，详见下方「降低风控识别」）。
- 登录文件仅本机可写（导入/导出自动 `chmod 600`，非 Windows）。

## 降低风控识别（请求指纹模拟）

早期版本自报 `User-Agent: codebuddy-proxy-rs/0.1.0`，等于在请求头里写明"我是第三方转换器"——后端确实按 UA 做画像与校验（逆向官方客户端 + 实测证实）。现改为**完整模拟官方 CLI（@tencent-ai/codebuddy-code 2.171.0）的请求指纹**（与 codebuddy2openai 的身份面对齐）：

| 出站请求 | 模拟的头 |
|---|---|
| 所有请求 | `User-Agent: CLI/unknown CodeBuddy/2.171.0`、`X-Product: SaaS`、`X-Product-Version`、`X-IDE-Type: CLI`、`X-IDE-Name: CLI`、`X-IDE-Version`、`X-Request-ID`（每请求新生成 32 位 hex）、`X-Private-Data`（默认 `true`，`--private-data false` 对齐官方 SaaS 默认） |
| `POST /v2/chat/completions` | 基础头 + `X-Agent-Intent: craft`、`X-Agent-Runtime: local-agent`、`X-Agent-Type: main`、`X-Model-ID`、`X-Trace-ID`、`X-Conversation-ID` / `X-Conversation-Request-ID` / `X-Conversation-Message-ID`（每请求新 UUID） |
| `GET /v3/config` | 基础头（该接口对 UA 有硬校验：缺 `CodeBuddy/<版本>` 段直接 400 code=12403；缺 `CLI/<x>` 段则 200 但不下发模型数据） |

以上头集合与官方 CLI 的拦截器行为一一对应（UserAgentHttpInterceptor / ProductEndpointHttpInterceptor / CommonHeaderHttpInterceptor / ModelRequestProcessor）。实测后端会把 `X-Trace-ID` 回显为响应消息 id——这些头被真实消费，并非摆设。

身份字段可经 `CLIENT_INFO_*` 环境变量整体覆盖（与官方 IDE 插件声明 VSCode 等身份的通道一致，逐键对齐）：`CLIENT_INFO_*` / `ACC_IDE_TYPE` / `CODEBUDDY2OPENAI_UA`（整条 UA 覆盖）/ `CODEBUDDY2OPENAI_UA_VERSION` / `CODEBUDDY2OPENAI_AGENT_INTENT|RUNTIME|TYPE`。

**仍无法隐藏的行为特征**（知悉后再使用）：

- 使用模式：代理转发的是客户端请求，无官方 CLI 的会话连续性（Conversation-ID 每请求新生成）、无上下文自动压缩、无子代理（subagent）行为特征；
- 网络环境：`--save-auth` 把登录态迁到服务器后，请求 IP 与桌面端登录 IP 不同，且没有 IDE 心跳等配套流量；
- 请求量与模型分布异常依然可能触发风控。

指纹模拟只能降低"按客户端特征识别"的概率，**不能保证不被识别**；请仅在自己拥有合法订阅的前提下使用，并遵守 CodeBuddy 服务条款。

## 内容审核误拦（code 11128 / 敏感词）

后端对**system 消息做字面量关键词拦截**，两类已知特征（详见 codebuddy2openai 仓库的 SECURITY-REVIEW.md）：

1. **竞品签名**：system 里出现字面量 `DeepSeek Harness`（dsh 客户端三段全局段落的签名）→ HTTP 400 `code=11128` "Illegal API invocation from an unapproved channel"。`--strip-harness`（默认开）把三段签名清洗掉：identity 段改写为 `You are CodeBuddy Code.`、source 段删除、web-surface 段替换为中性等效文本，残留变体兜底替换为 `CodeBuddy`；
2. **合规模板词**：客户端合规模板里的"拒绝作恶"词汇（DoS/exploit/credential…）被误判 → `--desensitize` 插零宽空格；
3. **用户措辞**：user 消息里的安全术语被拦 → `--user-escape` 包成 `[s[<逐字反转>]]` 并自动补解码说明，模型自行反转还义。

三层与 [codebuddy2openai]（Python 版）语义一致（`cargo test` 内含与真实 dsh 签名文本的对照用例），可与其共享 dsh CodeBuddy 预设（双层防护互不冲突、幂等）。

## 登录文件位置

| 平台 | 路径 |
|---|---|
| Windows | `%LOCALAPPDATA%\CodeBuddyExtension\Data\Public\auth\*.info` |
| macOS | `~/Library/Application Support/CodeBuddyExtension/Data/Public/auth/*.info` |
| Linux | `${XDG_DATA_HOME:-~/.local/share}/CodeBuddyExtension/Data/Public/auth/*.info` |

代理会扫描该目录下第一个 `*.info`。请先在桌面端登录 CodeBuddy / WorkBuddy。

## 快速开始

### 方式一：下载 Release 二进制

从 [Releases](https://github.com/evlon/codebuddy-proxy-rs/releases) 下载对应平台的 `codebuddy-proxy-rs-<平台>-<架构>[.exe]`。

### 方式二：源码构建

```bash
cargo build --release
# 产物：target/release/codebuddy-proxy-rs(.exe)
```

### 启动

```bash
# 默认监听 http://127.0.0.1:8787
codebuddy-proxy-rs

# 服务器上对外提供（务必配合 --api-key，避免裸奔）
codebuddy-proxy-rs --host 0.0.0.0 --port 8787 --api-key sk-your-key
```

启动时打印登录账号摘要，并预热一次动态模型列表（顺便验证后端连通性）。

## CLI 参数

| 参数 | 说明 |
|---|---|
| `--host <ip>` | 监听地址，默认 `127.0.0.1` |
| `--port <n>` | 监听端口，默认 `8787`（环境变量 `CODEBUDDY2OPENAI_KEY` / `CODEBUDDY2OPENAI_LOG` 可注入 key / log） |
| `--api-key <key>` | 客户端须携带的 API key；空则不校验 |
| `--log <path>` | 请求 / 原始 SSE 日志文件 |
| `--desensitize` | 对 system 合规词插入零宽空格做脱敏（词表含 `DeepSeek Harness`） |
| `--user-escape` | 对 user 消息敏感术语转义（phishing → `[s[gnihsihp]]`），system 尚无解码说明时自动补 `CODEBUDDY_ESCAPE_CODEC` 段 |
| `--strip-harness on\|off` | 清洗 system 里 dsh 三段全局签名（`harness:identity/source`、`app:web-surface`，字面量 `DeepSeek Harness` 即后端 `11128` 渠道拦截匹配串）。**默认 on**；`--strip-harness off` 或环境变量 `CODEBUDDY2OPENAI_STRIP_HARNESS=off` 可关 |
| `--private-data true\|false` | `X-Private-Data` 标头取值，默认 `true`（隐私优先）；`false` 对齐官方 SaaS 默认 |
| `--models-ttl <secs>` | 动态模型列表缓存秒数，默认 `600`；`0` 表示每次 `/v1/models` 都实时拉取（环境变量 `CODEBUDDY2OPENAI_MODELS_TTL`） |
| `--skip-check` | 跳过启动账号预检 |
| `--save-auth <file>` | 一次性导出本机登录文件到指定路径，执行后退出 |
| `--restore-auth <file>` | 一次性把导出的文件安装为本机登录文件，执行后退出 |

## 登录态迁移到服务器（save / restore）

本机导出后经安全通道（scp / rsync）拷到服务器，服务器上安装一次即可：

```bash
# 本机（Windows 等）：导出登录文件
codebuddy-proxy-rs --save-auth codebuddy-auth.info
scp codebuddy-auth.info user@server:~/

# 服务器（首次）：安装登录文件
codebuddy-proxy-rs --restore-auth ~/codebuddy-auth.info

# 启动
codebuddy-proxy-rs --host 0.0.0.0 --port 8787 --api-key sk-your-key
```

注意：

- 导出文件含会话 token，务必走安全通道传输，勿提交到公开仓库；
- `--restore-auth` 检测到目标登录目录已有登录文件时会拒绝安装（防覆盖 / 多账号冲突），请先备份并删除旧文件；
- 服务器上 token 过期后代理会用 refreshToken 自动刷新并回写。

## 客户端接入示例

### curl

```bash
# 模型列表（动态 + 上下文元数据；?refresh=1 强制刷新）
curl http://127.0.0.1:8787/v1/models

# 单个模型详情（附 max_input_tokens / context_length / max_model_len / credits 等）
curl http://127.0.0.1:8787/v1/models/glm-5.3

# 聊天（流式）
curl -N http://127.0.0.1:8787/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-your-key" \
  -d '{
    "model": "glm-5.3",
    "messages": [{"role": "user", "content": "你好"}],
    "stream": true
  }'
```

### OpenAI SDK

```python
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:8787/v1", api_key="sk-your-key")

# 动态模型列表（含每模型的上下文窗口大小）
for m in client.models.list():
    print(m.id, getattr(m, "context_length", None), getattr(m, "max_output_tokens", None))

r = client.chat.completions.create(
    model="auto",
    messages=[{"role": "user", "content": "你好"}],
    stream=True,
)
for chunk in r:
    print(chunk.choices[0].delta.content or "", end="")
```

## 可用模型

`GET /v1/models` **动态返回**你账号当前实际可用的模型（官方 CLI `/model` 选择器同款列表，来自后端 `/v3/config` 的 `agents["cli"].models`），服务端上新/下线模型自动跟进。

截至 2026-06 的实测快照（个人版）：`auto`（默认档位）、`hy4-preview`、`hy3`、`hy3-x`、`step-5-preview`、`space-bunny`、`deepseek-v4.1-flash`、`glm-5.3`、`glm-5.3-flash`、`glm-5.2`、`glm-5.1`、`glm-5v-turbo`、`minimax-m3`、`minimax-m2.7`、`kimi-k3-1`、`kimi-k2.8-preview`、`kimi-k2.7`、`kimi-k2.6`、`deepseek-v4-pro`、`mimo-v2.6-pro`。具体可用性以你的订阅为准。

> 离线兜底：`src/models.rs` 内置上述快照（`FALLBACK_MODEL_IDS`），仅在后端不可达时救急；正常情况一律以动态拉取为准。

## Release（GitHub Actions 自动发布）

打 tag 会自动触发 [`.github/workflows/release.yml`](.github/workflows/release.yml)，在 Ubuntu / Windows / macOS 上分别编译 release 二进制并上传到对应的 GitHub Release：

```bash
git tag v0.2.0
git push origin v0.2.0
```

## 免责声明

非官方项目，仅个人使用；请遵守 CodeBuddy 服务条款。代码仅供学习参考。
