/// 命令行配置：监听地址/端口、可选 API key、日志路径、脱敏/转义/签名清洗开关、
/// X-Private-Data 取值、启动预检开关、动态模型列表缓存秒数、一次性导出/导入动作。

pub struct Args {
    pub host: String,
    pub port: u16,
    /// 客户端须携带的 API key；空表示不校验。
    pub api_key: String,
    /// 日志文件路径；None 表示不记日志。
    pub log: Option<String>,
    /// 对 system 消息做合规词脱敏（零宽空格），缓解后端内容审核误拦。
    pub desensitize: bool,
    /// 对 user 消息做敏感术语转义（[s[<逐字反转>]] + 自动补解码说明）。
    pub user_escape: bool,
    /// 清洗 system 里的 DeepSeek Harness 签名（dsh 三段全局段落，11128 渠道拦截源）。
    /// 默认开；--strip-harness off 可关（与 dsh CodeBuddy 预设的遮蔽幂等）。
    pub strip_harness: bool,
    /// X-Private-Data 标头取值；默认 true（隐私优先），false 对齐官方 SaaS 默认。
    pub private_data: bool,
    /// 跳过启动预检（账号摘要打印）。
    pub skip_check: bool,
    /// 动态模型列表缓存秒数；0 表示每次 /v1/models 都实时拉取。
    pub models_ttl: u64,
    /// 一次性动作：把本机 CodeBuddy 登录文件原样导出到指定路径，执行后退出。
    pub save_auth: Option<String>,
    /// 一次性动作：把指定文件安装为本机 CodeBuddy 登录文件（服务器上运行），执行后退出。
    pub restore_auth: Option<String>,
    /// 日志轮转：日志只保留最近 N 次请求的完整现场；0 = 关闭轮转（保留全部）。
    pub log_keep: usize,
    /// --desensitize-scope all：脱敏扩展到全部角色消息 + tools 描述（渠道风险分降分）。
    pub desensitize_scope_all: bool,
    /// 官方请求形状补齐（默认开）：extra_vars.harnessMetadata 等官方 body 字段。
    pub official_shape: bool,
}

impl Default for Args {
    fn default() -> Self {
        Args {
            host: "127.0.0.1".into(),
            port: 8787,
            api_key: std::env::var("CODEBUDDY2OPENAI_KEY").unwrap_or_default(),
            log: std::env::var("CODEBUDDY2OPENAI_LOG").ok().filter(|s| !s.is_empty()),
            desensitize: false,
            user_escape: env_flag("CODEBUDDY2OPENAI_USER_ESCAPE", false),
            strip_harness: env_switch("CODEBUDDY2OPENAI_STRIP_HARNESS", true),
            private_data: env_switch("CODEBUDDY2OPENAI_PRIVATE_DATA", true),
            skip_check: false,
            models_ttl: std::env::var("CODEBUDDY2OPENAI_MODELS_TTL")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(600),
            save_auth: None,
            restore_auth: None,
            log_keep: std::env::var("CODEBUDDY2OPENAI_LOG_KEEP")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(3),
            desensitize_scope_all: std::env::var("CODEBUDDY2OPENAI_DESENSITIZE_SCOPE")
                .map(|v| v.trim().eq_ignore_ascii_case("all"))
                .unwrap_or(false),
            official_shape: env_switch("CODEBUDDY2OPENAI_OFFICIAL_SHAPE", true),
        }
    }
}

/// 环境变量布尔开关（1/true/yes 为真）。
fn env_flag(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(v) => matches!(v.trim().to_lowercase().as_str(), "1" | "true" | "yes"),
        Err(_) => default,
    }
}

/// 环境变量 on/off 开关（未设置时用 default）。
fn env_switch(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(v) => !v.trim().eq_ignore_ascii_case("off") && !v.trim().eq_ignore_ascii_case("false"),
        Err(_) => default,
    }
}

/// 解析 `--host <ip>` / `--port <n>` / `--api-key <key>` / `--log <path>` /
/// `--desensitize` / `--desensitize-scope system|all` / `--user-escape` /
/// `--strip-harness on|off` / `--official-shape on|off` / `--log-keep <n>` /
/// `--private-data true|false` / `--skip-check` / `--models-ttl <secs>` /
/// `--save-auth <file>` / `--restore-auth <file>`；未知参数忽略。
pub fn parse() -> Args {
    let mut args = Args::default();
    let mut argv = std::env::args().skip(1);
    while let Some(flag) = argv.next() {
        match flag.as_str() {
            "--host" => {
                if let Some(value) = argv.next() {
                    args.host = value;
                }
            }
            "--port" => {
                if let Some(value) = argv.next() {
                    if let Ok(port) = value.parse() {
                        args.port = port;
                    }
                }
            }
            "--api-key" => {
                if let Some(value) = argv.next() {
                    args.api_key = value;
                }
            }
            "--log" => {
                if let Some(value) = argv.next() {
                    args.log = Some(value);
                }
            }
            "--desensitize" => args.desensitize = true,
            "--user-escape" => args.user_escape = true,
            "--strip-harness" => {
                if let Some(value) = argv.next() {
                    args.strip_harness = !value.trim().eq_ignore_ascii_case("off");
                }
            }
            "--private-data" => {
                if let Some(value) = argv.next() {
                    args.private_data = !value.trim().eq_ignore_ascii_case("false");
                }
            }
            "--skip-check" => args.skip_check = true,
            "--models-ttl" => {
                if let Some(value) = argv.next() {
                    if let Ok(ttl) = value.parse() {
                        args.models_ttl = ttl;
                    }
                }
            }
            "--save-auth" => {
                if let Some(value) = argv.next() {
                    args.save_auth = Some(value);
                }
            }
            "--restore-auth" => {
                if let Some(value) = argv.next() {
                    args.restore_auth = Some(value);
                }
            }
            "--log-keep" => {
                if let Some(value) = argv.next() {
                    if let Ok(n) = value.parse() {
                        args.log_keep = n;
                    }
                }
            }
            "--desensitize-scope" => {
                if let Some(value) = argv.next() {
                    args.desensitize_scope_all = value.trim().eq_ignore_ascii_case("all");
                }
            }
            "--official-shape" => {
                if let Some(value) = argv.next() {
                    args.official_shape = !value.trim().eq_ignore_ascii_case("off");
                }
            }
            _ => {}
        }
    }
    args
}
