/// CodeBuddy 桌面端登录态：定位登录文件、解析会话、token 临近过期自动刷新并原子回写。
///
/// 与官方客户端及 codebuddy2openai 使用同一份 `auth/*.info`，只读 + 按需回写刷新结果，
/// 不做登录、不存密码。

use std::{
    env, fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use reqwest::header::{HeaderMap, HeaderName, HeaderValue, ACCEPT, CONTENT_TYPE, USER_AGENT};
use serde_json::{Map, Value, json};

/// 官方聊天后端 origin。
pub const BACKEND: &str = "https://copilot.tencent.com";
/// 兜底域名（登录文件未记录时使用）。
const DEFAULT_DOMAIN: &str = "www.codebuddy.cn";
/// 本代理的自报 UA（后端以 UA 画像区分“个人转换器”与大厂 agent 框架）。
pub const UA: &str = "codebuddy-proxy-rs/0.1.0";
/// token 剩余寿命低于该值即提前刷新。
const REFRESH_MARGIN_MS: u128 = 60_000;

fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
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

/// 从会话构建鉴权头（不含 content-type / accept，由调用方按需补充）。
pub fn headers_of(session: &Session) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static(UA));
    let mut set = |name: &'static str, value: String| {
        if let Ok(v) = HeaderValue::from_str(&value) {
            headers.insert(HeaderName::from_static(name), v);
        }
    };
    set("authorization", format!("Bearer {}", session.access));
    set("x-user-id", session.uid.clone());
    set("x-enterprise-id", session.enterprise.clone());
    set("x-tenant-id", session.enterprise.clone());
    set("x-domain", session.domain.clone());
    headers
}

/// 登录态管理器：读取 → 按需刷新 → 提供会话。
pub struct Auth {
    path: PathBuf,
    client: reqwest::Client,
}

impl Auth {
    pub fn new(path: PathBuf, client: reqwest::Client) -> Self {
        Auth { path, client }
    }

    /// 当前有效会话；临近过期先刷新并回写登录文件。
    pub async fn session(&self) -> Result<Session, String> {
        let (info, session) = load(&self.path)?;
        if session.expires_at > 0 && session.expires_at <= now_ms() + REFRESH_MARGIN_MS {
            self.refresh(&info, &session).await
        } else {
            Ok(session)
        }
    }

    /// 启动时打印账号摘要用；失败返回 None。
    pub async fn summary(&self) -> Option<String> {
        self.session().await.ok().map(|s| format!("uid={}", s.uid))
    }

    /// 调用后端刷新并原子写回，随后返回新会话。
    async fn refresh(&self, info: &Value, session: &Session) -> Result<Session, String> {
        let url = format!("{BACKEND}/v2/plugin/auth/token/refresh");
        let mut headers = headers_of(session);
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
