/// CodeBuddy 桌面端登录态：定位登录文件、解析会话、token 临近过期自动刷新并原子回写。
///
/// 与官方客户端及 codebuddy2openai 使用同一份 `auth/*.info`，只读 + 按需回写刷新结果，
/// 不做登录、不存密码。
///
/// 请求指纹：出站请求全部模拟官方 CLI（@tencent-ai/codebuddy-code）形态，降低后端
/// 按 UA / 头特征把代理流量画像为"第三方转换器"的概率（详见 README「降低风控识别」）。

use std::{
    env, fs,
    path::PathBuf,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use reqwest::header::{HeaderMap, HeaderName, HeaderValue, ACCEPT, CONTENT_TYPE, USER_AGENT};
use serde_json::{Map, Value, json};

/// 官方聊天后端 origin。
pub const BACKEND: &str = "https://copilot.tencent.com";
/// 兜底域名（登录文件未记录时使用）。
const DEFAULT_DOMAIN: &str = "www.codebuddy.cn";

/// 官方 CLI 形态的 User-Agent（逆向自官方 UserAgentHttpInterceptor 并实测，版本对齐
/// 官方 2.177.0，与 codebuddy2openai 一致）：
///   `{platform}/{platformVersion} {productName}/{productVersion}` + 可选扩展段。
/// 后端校验（实测，见 README「降低风控识别」）：
///   - 须含 "CLI/<x> CodeBuddy/<y>" 两段；缺 "CodeBuddy/<y>" → /v3/config 返回
///     400 code=12403（check ua）；缺 "CLI/<x>" → 200 但不下发 models/agents；
///   - <y> 版本内容不校验（"abc" 亦通过）；"CodeBuddy-Code/2.169.0" 之类连字名不识别。
/// platformVersion 默认 = 官方版本（2026-10-28 官方 2.177.0 抓包：platform 与 product
/// 版本一致，此前空串 → "unknown" 的旧形态已过时）。
/// 环境变量：CODEBUDDY2OPENAI_UA 整条覆盖；CODEBUDDY2OPENAI_UA_VERSION 覆盖版本号；
/// 其余分段走 CLIENT_INFO_* 身份字段通道（见 identity_env）。

/// 与官方 CLI 对齐的版本号（2026-10-28 官方 2.177.0 抓包实测：npm
/// @tencent-ai/codebuddy-code 2.177.0，UA 形态 `CLI/2.177.0 CodeBuddy/2.177.0`；
/// 可用环境变量 CODEBUDDY2OPENAI_UA_VERSION 覆盖）。
pub fn official_version() -> String {
    env::var("CODEBUDDY2OPENAI_UA_VERSION")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "2.177.0".into())
}

pub fn build_user_agent() -> String {
    if let Ok(ua) = env::var("CODEBUDDY2OPENAI_UA") {
        if !ua.trim().is_empty() {
            return ua;
        }
    }
    let platform = identity_env("CLIENT_INFO_PLATFORM").unwrap_or_else(|| "CLI".into());
    let platform_version =
        identity_env("CLIENT_INFO_PLATFORM_VERSION").unwrap_or_else(official_version);
    let product = identity_env("CLIENT_INFO_PRODUCT_NAME").unwrap_or_else(|| "CodeBuddy".into());
    // productVersion：CLIENT_INFO_PRODUCT_VERSION > UA_VERSION > 官方版本
    let product_version = identity_env("CLIENT_INFO_PRODUCT_VERSION").unwrap_or_else(official_version);
    let mut parts = vec![
        format!("{platform}/{platform_version}"),
        format!("{product}/{product_version}"),
    ];
    let extension = env::var("CLIENT_INFO_USER_AGENT_EXTENSION").unwrap_or_default();
    if !extension.trim().is_empty() {
        parts.push(extension);
    }
    parts.join(" ")
}

/// 部署类型（官方 ProductEndpointHttpInterceptor 注入 `X-Product: <deploymentType>`）。
/// 2026-10-28 官方 2.177.0 抓包实测：X-Product="SaaS"（非 productName）；
/// 可用环境变量 CODEBUDDY2OPENAI_X_PRODUCT 覆盖。
fn product() -> String {
    identity_env("CODEBUDDY2OPENAI_X_PRODUCT").unwrap_or_else(|| "SaaS".into())
}

/// 2026-10-28 官方抓包补齐的三个渠道标志头（官方每个请求都带，缺失会推高风险分）；
/// CODEBUDDY2OPENAI_STATIC_EXTRA=off 可整体关闭（排查用）。
fn static_extra_enabled() -> bool {
    match env::var("CODEBUDDY2OPENAI_STATIC_EXTRA") {
        Ok(v) => !v.trim().eq_ignore_ascii_case("off"),
        Err(_) => true,
    }
}

/// trace 头族开关（官方 otel/b3 拦截器形态）；CODEBUDDY2OPENAI_TRACE=off 可整体关闭（排查用）。
fn trace_enabled() -> bool {
    match env::var("CODEBUDDY2OPENAI_TRACE") {
        Ok(v) => !v.trim().eq_ignore_ascii_case("off"),
        Err(_) => true,
    }
}

/// 身份字段环境变量摄取：官方 getProcessEnvInfo 语义——存在且非空则覆盖。
/// 从 bundle module 211504 的 ENV_CLIENT_INFO_KEYS 移植（README §身份面）。
/// 其中 ideType 官方另有 ACC_IDE_TYPE 覆盖（优先级最高）。
fn identity_env(key: &str) -> Option<String> {
    env::var(key).ok().filter(|s| !s.trim().is_empty())
}

fn ide_type() -> String {
    identity_env("ACC_IDE_TYPE")
        .or_else(|| identity_env("CLIENT_INFO_IDE_TYPE"))
        .unwrap_or_else(|| "CLI".into())
}

/// 稳定区身份头（IDE/产品/遥测分段；官方 Ultima 拦截器对所有出站请求带上）：
///   - X-IDE-Type / X-IDE-Name(=platform) / X-IDE-Version(=platformVersion)
///   - X-Product-Version=官方版本、X-Product="SaaS"（抓包实测；非 productName）
///   - X-Private-Data：官方按企业策略/模型优化开关填。true=允许把私有数据用于
///     训练改进/模型优化，能降低"再依据私有头做区间决策"的风控画像特征；
///     false 与官方 SaaS 默认一致。默认 true（--private-data false 可调，隐私优先）。
///   - 渠道标志：X-Requested-With=XMLHttpRequest、X-CodeBuddy-Request=1、
///     X-Agent-Purpose=conversation（官方每个请求都带，缺失会推高风险分；
///     CODEBUDDY2OPENAI_STATIC_EXTRA=off 可整体关闭）。
pub fn static_identity_headers(private_data: bool) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let insert = |headers: &mut HeaderMap, name: &'static str, value: String| {
        if let Ok(v) = HeaderValue::from_str(&value) {
            headers.insert(HeaderName::from_static(name), v);
        }
    };
    let product_version = identity_env("CLIENT_INFO_PRODUCT_VERSION").unwrap_or_else(official_version);
    insert(&mut headers, "x-ide-type", ide_type());
    insert(
        &mut headers,
        "x-ide-name",
        identity_env("CLIENT_INFO_PLATFORM").unwrap_or_else(|| "CLI".into()),
    );
    insert(
        &mut headers,
        "x-ide-version",
        identity_env("CLIENT_INFO_PLATFORM_VERSION").unwrap_or_else(official_version),
    );
    insert(&mut headers, "x-product", product());
    insert(&mut headers, "x-product-version", product_version);
    insert(&mut headers, "x-private-data", private_data.to_string());
    if static_extra_enabled() {
        insert(&mut headers, "x-requested-with", "XMLHttpRequest".into());
        insert(&mut headers, "x-codebuddy-request", "1".into());
        insert(&mut headers, "x-agent-purpose", "conversation".into());
    }
    headers
}

/// token 剩余寿命低于该值即提前刷新。2026-10-28 起：官方 accessToken 28 天 TTL，
/// 但后端渠道风险判定比硬过期更敏感（陈旧 token 直接推高风险分 → 11128，实测）。
/// 官方客户端自己也是常态性刷新，保持令牌新鲜度 = 保持官方形状。
const REFRESH_MARGIN_MS: u128 = 6 * 3600 * 1000;

/// 是否需要刷新（expiresAt 为毫秒时间戳；缺失/为 0 视为已过期，与 Python 语义一致）。
fn needs_refresh(expires_at: u128, now: u128) -> bool {
    expires_at <= now + REFRESH_MARGIN_MS
}

fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

// ---------- 简易伪随机 ID（官方用 UUID；此处无 uuid 依赖，xorshift64* + 时间/进程熵） ----------

pub fn uuid_v4() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut seed = nanos
        ^ (std::process::id() as u64).wrapping_mul(0x9E3779B97F4A7C15)
        ^ n.wrapping_mul(0xBF58476D1CE4E5B9);
    let mut bytes = [0u8; 16];
    for chunk in bytes.chunks_mut(8) {
        seed ^= seed >> 12;
        seed ^= seed << 25;
        seed ^= seed >> 27;
        chunk.copy_from_slice(&seed.wrapping_mul(0x2545F4914F6CDD1D).to_le_bytes());
    }
    bytes[6] = (bytes[6] & 0x0F) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3F) | 0x80; // variant
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..32])
}

/// 官方 injectRequestIdHeader：无 X-Trace-ID 时 X-Request-ID 用无横线 UUID。
fn request_id() -> String {
    uuid_v4().replace('-', "")
}

fn get_str(map: Option<&Map<String, Value>>, key: &str) -> String {
    map.and_then(|m| m.get(key)).and_then(Value::as_str).unwrap_or("").to_string()
}

/// 当前可用的会话事实（聊天鉴权所需的最小集）。
pub struct Session {
    pub access: String,
    pub refresh: String,
    pub expires_at: u128,
    pub domain: String,
    pub uid: String,
    pub enterprise: String,
}

/// 各平台 CodeBuddy 桌面端登录目录（与官方客户端一致）。
pub fn auth_dir() -> PathBuf {
    let home = env::var("USERPROFILE").or_else(|_| env::var("HOME")).unwrap_or_default();
    if cfg!(target_os = "windows") {
        let local = env::var("LOCALAPPDATA").unwrap_or_else(|_| format!("{}\\AppData\\Local", home));
        PathBuf::from(local).join("CodeBuddyExtension/Data/Public/auth")
    } else if cfg!(target_os = "macos") {
        PathBuf::from(&home).join("Library/Application Support/CodeBuddyExtension/Data/Public/auth")
    } else {
        let xdg = env::var("XDG_DATA_HOME").unwrap_or_else(|_| format!("{}/.local/share", home));
        PathBuf::from(xdg).join("CodeBuddyExtension/Data/Public/auth")
    }
}

/// 在候选 auth 目录中找第一个 `*.info`。
pub fn find_auth_file() -> Option<PathBuf> {
    let entries = fs::read_dir(auth_dir()).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().map(|ext| ext == "info").unwrap_or(false) {
            return Some(path);
        }
    }
    None
}

/// 读取登录文件并解析为 `(原始文档, 会话)`。
fn load(path: &PathBuf) -> Result<(Value, Session), String> {
    let bytes = fs::read(path).map_err(|e| format!("读取登录文件失败：{e}"))?;
    let text = String::from_utf8_lossy(&bytes);
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    let info: Value = serde_json::from_str(text).map_err(|e| format!("登录文件不是合法 JSON：{e}"))?;
    let session = parse_session(&info)?;
    Ok((info, session))
}

fn parse_session(info: &Value) -> Result<Session, String> {
    let auth = info.get("auth").and_then(Value::as_object);
    let account = info.get("account").and_then(Value::as_object);
    let access = get_str(auth, "accessToken");
    if access.is_empty() {
        return Err("登录文件缺少 accessToken，请先在桌面端重新登录 CodeBuddy".into());
    }
    let domain = {
        let d = get_str(auth, "domain");
        if d.is_empty() { DEFAULT_DOMAIN.to_string() } else { d }
    };
    let expires_at = auth.and_then(|m| m.get("expiresAt")).and_then(Value::as_u64).unwrap_or(0) as u128;
    Ok(Session {
        access,
        refresh: get_str(auth, "refreshToken"),
        expires_at,
        domain,
        uid: get_str(account, "uid"),
        enterprise: get_str(account, "enterpriseId"),
    })
}

/// 基础鉴权头（官方全局拦截器行为：UA + X-Product + X-Request-ID + 会话鉴权头 +
/// 静态身份头 X-IDE-* / X-Product-Version / X-Private-Data）。
/// 不含 content-type / accept，由调用方按需补充。
pub fn headers_of(session: &Session, private_data: bool) -> HeaderMap {
    let mut headers = static_identity_headers(private_data);
    let ua = build_user_agent();
    headers.insert(
        USER_AGENT,
        HeaderValue::from_str(&ua).unwrap_or_else(|_| HeaderValue::from_static("CLI/unknown CodeBuddy")),
    );
    let set = |headers: &mut HeaderMap, name: &'static str, value: String| {
        if let Ok(v) = HeaderValue::from_str(&value) {
            headers.insert(HeaderName::from_static(name), v);
        }
    };
    set(&mut headers, "x-product", product());
    set(&mut headers, "x-request-id", request_id());
    set(&mut headers, "authorization", format!("Bearer {}", session.access));
    set(&mut headers, "x-user-id", session.uid.clone());
    set(&mut headers, "x-enterprise-id", session.enterprise.clone());
    set(&mut headers, "x-tenant-id", session.enterprise.clone());
    set(&mut headers, "x-domain", session.domain.clone());
    headers
}

/// 聊天请求头：基础鉴权头 + 官方 ModelRequestProcessor 给模型请求注入的内部头。
/// 对照 bundle + 2026-10-28 官方 2.177.0 抓包（与 codebuddy2openai 的
/// _per_request_identity_headers 逐条一致）：
///   - X-Request-ID == X-Conversation-Message-ID == 无连字符 uuid
///   - X-Conversation-Request-ID == X-Root-Request-ID == 独立根 uuid（与消息 ID 分离）
///   - X-Conversation-ID = 会话 id（官方 session.id，带连字符；客户端可透传）
///   - X-Agent-Intent = "craft"；X-Agent-Runtime = "other"（抓包实测主会话即 other）
///   - trace 族（每请求生成，CODEBUDDY2OPENAI_TRACE=off 可关）：
///     traceparent = `00-{trace32hex}-{span16hex}-01`、
///     b3 = `{trace}-{span}-1-{parent16hex}`、X-B3-TraceId/SpanId/ParentSpanId/
///     X-B3-Sampled: 1 / X-Trace-ID、
///     baggage = `codebuddy.session_id={会话id带连字符},codebuddy.conversation_request_id={根id}`
///   - X-Model-ID 标注本次请求的模型档位。
pub fn chat_headers(session: &Session, model: &str, private_data: bool, conversation_id: &str) -> HeaderMap {
    let mut headers = headers_of(session, private_data);
    let message_id = request_id(); // 32 hex 无连字符
    let root_id = request_id(); // 独立根 id，与消息 ID 分离
    let conv_dashed =
        if conversation_id.trim().is_empty() { uuid_v4() } else { conversation_id.trim().to_string() };
    let set = |headers: &mut HeaderMap, name: &'static str, value: String| {
        if let Ok(v) = HeaderValue::from_str(&value) {
            headers.insert(HeaderName::from_static(name), v);
        }
    };
    set(&mut headers, "x-agent-intent",
        env::var("CODEBUDDY2OPENAI_AGENT_INTENT").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "craft".into()));
    set(&mut headers, "x-agent-runtime",
        env::var("CODEBUDDY2OPENAI_AGENT_RUNTIME").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "other".into()));
    set(&mut headers, "x-agent-type",
        env::var("CODEBUDDY2OPENAI_AGENT_TYPE").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "main".into()));
    if !model.is_empty() {
        set(&mut headers, "x-model-id", model.to_string());
    }
    set(&mut headers, "x-request-id", message_id.clone());
    set(&mut headers, "x-conversation-message-id", message_id);
    set(&mut headers, "x-conversation-request-id", root_id.clone());
    set(&mut headers, "x-root-request-id", root_id.clone());
    set(&mut headers, "x-conversation-id", conv_dashed.clone());
    // 链路追踪（官方 otel/b3 拦截器形态）
    if trace_enabled() {
        let trace_id = request_id(); // 32 hex
        let span_id = uuid_hex16();
        let parent_span = uuid_hex16();
        apply_trace_headers(&mut headers, &TraceIds {
            trace_id, span_id, parent_span,
            conv_dashed: conv_dashed.clone(), root_id: root_id.clone(),
        });
    }
    headers
}

/// 一次请求的 trace 头族原料（官方 otel/b3 拦截器形态）。
pub struct TraceIds {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span: String,
    pub conv_dashed: String,
    pub root_id: String,
}

/// 纯函数：按官方形态生成 trace 头族（便于单测，不依赖环境开关）。
///   traceparent = `00-{trace32hex}-{span16hex}-01`
///   b3          = `{trace}-{span}-1-{parent16hex}`
///   X-B3-TraceId / X-B3-SpanId / X-B3-ParentSpanId / X-B3-Sampled: 1 / X-Trace-ID
///   baggage     = `codebuddy.session_id={会话id带连字符},codebuddy.conversation_request_id={根id}`
pub fn trace_header_pairs(ids: &TraceIds) -> Vec<(&'static str, String)> {
    vec![
        ("traceparent", format!("00-{}-{}-01", ids.trace_id, ids.span_id)),
        ("b3", format!("{}-{}-1-{}", ids.trace_id, ids.span_id, ids.parent_span)),
        ("x-b3-traceid", ids.trace_id.clone()),
        ("x-b3-spanid", ids.span_id.clone()),
        ("x-b3-parentspanid", ids.parent_span.clone()),
        ("x-b3-sampled", "1".into()),
        ("x-trace-id", ids.trace_id.clone()),
        ("baggage", format!(
            "codebuddy.session_id={},codebuddy.conversation_request_id={}",
            ids.conv_dashed, ids.root_id
        )),
    ]
}

fn apply_trace_headers(headers: &mut HeaderMap, ids: &TraceIds) {
    for (name, value) in trace_header_pairs(ids) {
        if let Ok(v) = HeaderValue::from_str(&value) {
            headers.insert(HeaderName::from_static(name), v);
        }
    }
}

/// 16 hex 的 span id（官方 otel 形态：trace 32hex、span 16hex）。
fn uuid_hex16() -> String {
    uuid_v4().replace('-', "")[..16].to_string()
}

/// 登录态管理器：读取 → 按需刷新 → 提供会话。
/// 2026-10-28 起：新增 force_refresh 语义——外部信号（后端 11128 渠道拦截）→
/// 下次取头时强制刷新；刷新失败降级沿用现有 token（记日志，不阻塞请求）。
pub struct Auth {
    path: PathBuf,
    client: reqwest::Client,
    /// X-Private-Data 取值（默认 true；--private-data false 对齐官方 SaaS 默认）。
    private_data: bool,
    /// 外部信号：令牌疑似已被后端降级，下次 session() 强制刷新。
    force: AtomicBool,
}

impl Auth {
    pub fn new(path: PathBuf, client: reqwest::Client, private_data: bool) -> Self {
        Auth { path, client, private_data, force: AtomicBool::new(false) }
    }

    /// 当前 X-Private-Data 取值（供 models 拉取头复用）。
    pub fn private_data(&self) -> bool {
        self.private_data
    }

    /// 外部信号：令牌疑似已被后端降级（如 11128 渠道拦截）。下次 session() 强制刷新。
    pub fn force_refresh(&self) {
        self.force.store(true, Ordering::Release);
    }

    /// （测试/诊断用）是否还有未消费的强制刷新信号。
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn force_pending(&self) -> bool {
        self.force.load(Ordering::Acquire)
    }

    /// 当前有效会话；临近过期（剩余 <6h）或收到强制刷新信号时先刷新并回写登录文件。
    /// 刷新失败不阻塞请求：记日志后沿用现有 token（与 codebuddy2openai 语义一致）。
    pub async fn session(&self) -> Result<Session, String> {
        let (info, session) = load(&self.path)?;
        let forced = self.force.swap(false, Ordering::AcqRel);
        if forced || needs_refresh(session.expires_at, now_ms()) {
            match self.refresh(&info, &session).await {
                Ok(next) => return Ok(next),
                Err(e) => eprintln!("── token 刷新失败（沿用现有 token 继续尝试）：{e}"),
            }
        }
        Ok(session)
    }

    /// 启动时打印账号摘要用；失败返回 None。
    pub async fn summary(&self) -> Option<String> {
        self.session().await.ok().map(|s| format!("uid={}", s.uid))
    }

    /// 调用后端刷新并原子写回，随后返回新会话。
    async fn refresh(&self, info: &Value, session: &Session) -> Result<Session, String> {
        let url = format!("{BACKEND}/v2/plugin/auth/token/refresh");
        let mut headers = headers_of(session, self.private_data);
        let set = |headers: &mut HeaderMap, name: &'static str, value: String| {
            if let Ok(v) = HeaderValue::from_str(&value) {
                headers.insert(HeaderName::from_static(name), v);
            }
        };
        set(&mut headers, "x-refresh-token", session.refresh.clone());
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        let response = self
            .client
            .post(&url)
            .headers(headers)
            .body("{}")
            .send()
            .await
            .map_err(|e| format!("刷新 token 网络失败：{e}"))?;
        let body: Value = response
            .json()
            .await
            .map_err(|e| format!("刷新 token 响应异常：{e}"))?;
        let code = body.get("code").and_then(Value::as_i64).unwrap_or(-1);
        let data = body.get("data").cloned().unwrap_or(Value::Null);
        if code != 0 || data.is_null() {
            let msg = body.get("msg").and_then(Value::as_str).unwrap_or("unknown");
            return Err(format!("刷新 CodeBuddy token 失败：{msg}"));
        }
        let mut merged = info.clone();
        let auth_obj = merged.get_mut("auth").and_then(Value::as_object_mut);
        if let Some(auth_obj) = auth_obj {
            if let Value::Object(next) = &data {
                for (k, v) in next {
                    if !v.is_null() {
                        auth_obj.insert(k.clone(), v.clone());
                    }
                }
            }
            auth_obj.insert("domain".into(), Value::String(session.domain.clone()));
        }
        self.write_atomic(&merged)?;
        parse_session(&merged)
    }

    fn write_atomic(&self, value: &Value) -> Result<(), String> {
        let text = serde_json::to_string_pretty(value).map_err(|e| format!("序列化登录文件失败：{e}"))?;
        let tmp = self.path.with_extension("info.tmp");
        fs::write(&tmp, text).map_err(|e| format!("写入临时文件失败：{e}"))?;
        fs::rename(&tmp, &self.path).map_err(|e| format!("回写登录文件失败：{e}"))
    }
}

/// 官方请求形状补齐（--official-shape 默认开；2026-10-28 官方 2.177.0 抓包对齐）：
/// - extra_vars.harnessMetadata：官方客户端必带的 JSON 串（harnessVersion/stepIndex/
///   contextWindowId/agent.depth），缺失属于"非官方客户端"特征，推高渠道风险分；
/// - reasoning_effort/verbosity/cache_retention/reasoning_summary：官方默认值，
///   客户端显式指定时不覆盖。
pub fn apply_official_shape(body: &mut Value) {
    let Some(map) = body.as_object_mut() else { return };
    if !map.contains_key("extra_vars") {
        let harness_metadata = json!({
            "schemaVersion": 1,
            "harnessVersion": official_version(),
            "stepIndex": 0,
            "contextWindowId": uuid_v4(),
            "agent": { "depth": 0 },
        });
        map.insert(
            "extra_vars".into(),
            json!({
                "harnessMetadata": serde_json::to_string(&harness_metadata).unwrap_or_default(),
                "initiator": "user",
            }),
        );
    }
    for (k, v) in [
        ("reasoning_effort", "high"),
        ("verbosity", "high"),
        ("cache_retention", "long"),
        ("reasoning_summary", "auto"),
    ] {
        map.entry(k).or_insert(json!(v));
    }
}

/// 透传时统一携带的静态字段（client 请求若缺省则补上）。
pub fn ensure_stream_fields(body: &mut Value) {
    if let Value::Object(map) = body {
        if map.get("stream").and_then(Value::as_bool) != Some(true) {
            map.insert("stream".into(), Value::Bool(true));
        }
        let has_usage = map
            .get("stream_options")
            .and_then(Value::as_object)
            .and_then(|o| o.get("include_usage"))
            .and_then(Value::as_bool)
            == Some(true);
        if !has_usage {
            map.insert(
                "stream_options".into(),
                json!({ "include_usage": true }),
            );
        }
    }
}

// ---------- 一次性动作：导出 / 导入登录态（--save-auth / --restore-auth） ----------

fn abort(msg: &str) -> ! {
    eprintln!("错误：{msg}");
    std::process::exit(1);
}

/// 非 Windows 下把文件权限收紧为仅当前用户可读写（600）。
#[cfg(unix)]
fn restrict(path: &str) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict(_path: &str) {}

/// 把本机登录文件原样导出到 `out`（供转移到服务器），随后退出。
pub fn save_auth(out: &str) -> ! {
    let Some(src) = find_auth_file() else {
        abort("未找到 CodeBuddy 登录文件；请先在桌面端登录 CodeBuddy / WorkBuddy。");
    };
    if let (Ok(a), Ok(b)) = (src.canonicalize(), PathBuf::from(out).canonicalize()) {
        if a == b {
            abort("导出路径与源登录文件相同，请换一个文件名。");
        }
    }
    if let Err(e) = fs::copy(&src, out) {
        abort(&format!("导出登录文件失败：{e}"));
    }
    restrict(out);
    println!("✅ 已导出登录文件：{}", src.display());
    println!("   -> {out}");
    println!("⚠️  文件含会话 token，请走安全通道传输（scp/rsync），勿公开或提交入库。");
    println!("   在目标机器执行：codebuddy-proxy-rs --restore-auth {out}");
    std::process::exit(0);
}

/// 把 `src`（`--save-auth` 的产物）安装为本机 CodeBuddy 登录文件（服务器上运行），随后退出。
pub fn restore_auth(src: &str) -> ! {
    let info = match load(&PathBuf::from(src)) {
        Ok((info, _)) => info,
        Err(e) => abort(&e),
    };
    let session = match parse_session(&info) {
        Ok(s) => s,
        Err(e) => abort(&e),
    };
    let dir = auth_dir();
    if let Some(existing) = find_auth_file() {
        abort(&format!(
            "目标登录目录已有登录文件：{}；为避免覆盖或多账号冲突，请先备份并删除该文件后重试。",
            existing.display()
        ));
    }
    if let Err(e) = fs::create_dir_all(&dir) {
        abort(&format!("创建登录目录失败（{}）：{e}", dir.display()));
    }
    let file = PathBuf::from(src)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let name = if file.is_empty() {
        "codebuddy-restored.info".to_string()
    } else if file.ends_with(".info") {
        file
    } else {
        format!("{file}.info")
    };
    let dest = dir.join(name);
    if dest.exists() {
        abort(&format!("目标文件已存在：{}", dest.display()));
    }
    let bytes = match fs::read(src) {
        Ok(bytes) => bytes,
        Err(e) => abort(&format!("读取 {src} 失败：{e}")),
    };
    if let Err(e) = fs::write(&dest, bytes) {
        abort(&format!("写入登录文件失败（{}）：{e}", dest.display()));
    }
    restrict(dest.to_string_lossy().as_ref());
    let scope = if session.enterprise.is_empty() {
        "个人"
    } else {
        session.enterprise.as_str()
    };
    println!("✅ 已安装登录文件：{}", dest.display());
    println!("   账号：uid={} domain={}（{scope}）", session.uid, session.domain);
    println!("   现在可直接启动代理：codebuddy-proxy-rs [--host <ip>] [--port <n>]");
    std::process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_session() -> Session {
        Session {
            access: "tok".into(),
            refresh: "ref".into(),
            expires_at: now_ms() + 100_000,
            domain: "Tencent-Cloud.coding-copilot.info".into(),
            uid: "uid-x".into(),
            enterprise: "ent-x".into(),
        }
    }

    /// 官方形状：空 body 补齐全部字段；harnessMetadata 是 JSON 字符串；
    /// 客户端显式指定时不覆盖；已有 extra_vars 不动。
    #[test]
    fn official_shape_fills_and_preserves() {
        let mut body = json!({ "model": "x", "messages": [] });
        apply_official_shape(&mut body);
        let ev = &body["extra_vars"];
        assert_eq!(ev["initiator"], "user");
        let hm: Value = serde_json::from_str(ev["harnessMetadata"].as_str().unwrap())
            .expect("harnessMetadata 应为 JSON 字符串");
        assert_eq!(hm["schemaVersion"], 1);
        assert_eq!(hm["harnessVersion"], official_version());
        assert_eq!(hm["stepIndex"], 0);
        assert_eq!(hm["agent"]["depth"], 0);
        assert!(!hm["contextWindowId"].as_str().unwrap().is_empty());
        assert_eq!(body["reasoning_effort"], "high");
        assert_eq!(body["verbosity"], "high");
        assert_eq!(body["cache_retention"], "long");
        assert_eq!(body["reasoning_summary"], "auto");

        // 客户端显式指定时不覆盖
        let mut body2 = json!({ "reasoning_effort": "low", "extra_vars": { "keep": true } });
        apply_official_shape(&mut body2);
        assert_eq!(body2["reasoning_effort"], "low");
        assert_eq!(body2["extra_vars"]["keep"], true, "已有 extra_vars 不应覆盖");
        assert!(body2["extra_vars"].get("harnessMetadata").is_none());
    }

    /// 身份面头：官方版本号、渠道标志静态头、trace 族、消息/根 ID 分离。
    #[test]
    fn chat_headers_official_face() {
        let s = fake_session();
        let h = chat_headers(&s, "deepseek-v4.1-flash", true, "");
        let get = |name: &str| -> String {
            h.get(name).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string()
        };
        // 静态身份面（2.177.0 抓包对齐）
        assert_eq!(get("X-IDE-Type"), "CLI");
        assert_eq!(get("X-IDE-Version"), official_version());
        assert_eq!(get("X-Product"), "SaaS");
        assert_eq!(get("X-Product-Version"), official_version());
        assert_eq!(get("X-Requested-With"), "XMLHttpRequest");
        assert_eq!(get("X-CodeBuddy-Request"), "1");
        assert_eq!(get("X-Agent-Purpose"), "conversation");
        assert_eq!(get("X-Agent-Runtime"), "other");
        assert_eq!(get("X-Private-Data"), "true");
        assert!(get("User-Agent").contains(&format!("CLI/{} CodeBuddy/{}", official_version(), official_version())));
        // 每 ID：消息 ID 与根 ID 分离（官方形态）
        let msg = get("X-Request-ID");
        let root = get("X-Root-Request-ID");
        assert_eq!(msg.len(), 32, "消息 ID 32 hex 无连字符");
        assert_eq!(root.len(), 32);
        assert_ne!(msg, root, "消息 ID 与根 ID 应分离");
        // trace 族形态
        let tp = get("traceparent");
        let segs: Vec<&str> = tp.split('-').collect();
        assert_eq!(segs.len(), 4);
        assert_eq!(segs[0], "00");
        assert_eq!(segs[1].len(), 32);
        assert_eq!(segs[2].len(), 16);
        assert_eq!(segs[3], "01");
        assert_eq!(get("b3").split('-').count(), 4);
        assert_eq!(get("X-B3-Sampled"), "1");
        assert!(get("baggage").contains("codebuddy.session_id="));
        assert!(get("baggage").contains("codebuddy.conversation_request_id="));
    }

    /// 强制刷新信号：置位 → pending；新实例无信号。
    #[test]
    fn force_refresh_flag_semantics() {
        let auth = Auth::new(
            PathBuf::from("definitely-not-a-real-auth-file.info"),
            reqwest::Client::new(),
            true,
        );
        assert!(!auth.force_pending(), "新实例不应有待消费的刷新信号");
        auth.force_refresh();
        assert!(auth.force_pending(), "置位后应有待消费信号");
    }
}
