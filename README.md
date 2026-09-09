# codebuddy-proxy-rs

Rust 实现的 **CodeBuddy → OpenAI 兼容** 代理。读取本机 CodeBuddy / WorkBuddy 桌面端登录态，把 `OpenAI` 协议的 `chat/completions` 请求透传到 CodeBuddy 官方后端，让任意 OpenAI 客户端 / 工具链直接使用 CodeBuddy 订阅。

使用与官方客户端、[codebuddy2openai] 相同的登录文件（`auth/*.info`），**只读 + 按需回写刷新结果**，不替代登录、不存储密码。

[codebuddy2openai]: https://github.com/evlon/codebuddy2openai

## 特性

- OpenAI 兼容 HTTP 面：`/v1/models`、`/v1/chat/completions`（流式 / 非流式）
- 复用 CodeBuddy 桌面登录态，token 临近过期自动刷新并原子回写
- 可选 `--api-key` 鉴权（`Authorization: Bearer` 或 `X-Api-Key`）
- 可选 `--log`：请求 / 原始 SSE 旁路录制，便于排查内容审核拦截
- 可选 `--desensitize`：system 合规词零宽空格脱敏，缓解后端误拦
- `--save-auth` / `--restore-auth`：把本机登录态一键迁移到服务器
- 单一静态二进制，无需运行时

## 工作原理

```
任意 OpenAI 客户端 ──> codebuddy-proxy-rs ──> CodeBuddy 后端
       (127.0.0.1:8787)   (copilot.tencent.com)
```

- 透传时强制 `stream=true`：客户端要流式则逐字节透传 SSE；非流式则在后端流结束后聚合为单个 completion。
- 登录文件仅本机可写（导入/导出自动 `chmod 600`，非 Windows）。
- 后端以自报 UA（`codebuddy-proxy-rs/0.1.0`）识别“个人转换器”画像。

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

启动时打印登录账号摘要并自检。

## CLI 参数

| 参数 | 说明 |
|---|---|
| `--host <ip>` | 监听地址，默认 `127.0.0.1` |
| `--port <n>` | 监听端口，默认 `8787`（环境变量 `CODEBUDDY2OPENAI_KEY` / `CODEBUDDY2OPENAI_LOG` 可注入 key / log） |
| `--api-key <key>` | 客户端须携带的 API key；空则不校验 |
| `--log <path>` | 请求 / 原始 SSE 日志文件 |
| `--desensitize` | 对 system 合规词插入零宽空格做脱敏 |
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
curl http://127.0.0.1:8787/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-your-key" \   # 仅当设置了 --api-key
  -d '{
    "model": "deepseek-v4-flash",
    "messages": [{"role": "user", "content": "你好"}],
    "stream": true
  }'
```

### OpenAI SDK

```python
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:8787/v1", api_key="sk-your-key")

r = client.chat.completions.create(
    model="auto",
    messages=[{"role": "user", "content": "你好"}],
    stream=True,
)
for chunk in r:
    print(chunk.choices[0].delta.content or "", end="")
```

## 可用模型

`/v1/models` 返回列表：`auto`、`default`、`deepseek-v4-flash`、`deepseek-v4-pro`、`hy3`、`glm-5v-turbo`、`kimi-k2-instruct-taiji`、`default-1.2`、`hunyuan-turbos-vision`。

## Release（GitHub Actions 自动发布）

打 tag 会自动触发 [`.github/workflows/release.yml`](.github/workflows/release.yml)，在 Ubuntu / Windows / macOS 上分别编译 release 二进制并上传到对应的 GitHub Release：

```bash
git tag v0.1.0
git push origin v0.1.0
```

## 免责声明

非官方项目，仅个人使用；请遵守 CodeBuddy 服务条款。代码仅供学习参考。
