/// 命令行配置：监听地址/端口、可选 API key、日志路径、脱敏开关、启动预检开关、
/// 动态模型列表缓存秒数。

pub struct Args {
    pub host: String,
    pub port: u16,
    /// 客户端须携带的 API key；空表示不校验。
    pub api_key: String,
    /// 日志文件路径；None 表示不记日志。
    pub log: Option<String>,
    /// 对 system 消息做合规词脱敏（零宽空格），缓解后端内容审核误拦。
    pub desensitize: bool,
    /// 跳过启动预检（账号摘要打印）。
    pub skip_check: bool,
    /// 动态模型列表缓存秒数；0 表示每次 /v1/models 都实时拉取。
    pub models_ttl: u64,
    /// 一次性动作：把本机 CodeBuddy 登录文件原样导出到指定路径，执行后退出。
    pub save_auth: Option<String>,
    /// 一次性动作：把指定文件安装为本机 CodeBuddy 登录文件（服务器上运行），执行后退出。
    pub restore_auth: Option<String>,
}

impl Default for Args {
    fn default() -> Self {
        Args {
            host: "127.0.0.1".into(),
            port: 8787,
            api_key: std::env::var("CODEBUDDY2OPENAI_KEY").unwrap_or_default(),
            log: std::env::var("CODEBUDDY2OPENAI_LOG").ok().filter(|s| !s.is_empty()),
            desensitize: false,
            skip_check: false,
            models_ttl: std::env::var("CODEBUDDY2OPENAI_MODELS_TTL")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(600),
            save_auth: None,
            restore_auth: None,
        }
    }
}

/// 解析 `--host <ip>` / `--port <n>` / `--api-key <key>` / `--log <path>` /
/// `--desensitize` / `--skip-check` / `--models-ttl <secs>` /
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
            _ => {}
        }
    }
    args
}
