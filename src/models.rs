/// 动态模型目录：调用官方 CLI 同款的 `GET /v3/config`，TTL 缓存 + 失败兜底。
///
/// 实测（逆向自 @tencent-ai/codebuddy-code 2.169.0 的 CloudProductProvider）：
///   GET {BACKEND}/v3/config → {"code":0,"data":{
///       "models":[{id,name,credits,maxInputTokens,maxOutputTokens,...}, ...],   // 全量模型元数据
///       "agents":[{"name":"cli","models":["hy3","glm-5.3",...], ...}]           // 当前账号实际可用列表
///   }}
/// - agents 里 name="cli" 的 models 就是官方 CLI `/model` 选择器展示的可用列表；
/// - 请求头与聊天一致（官方 UA + 鉴权头），后端对 UA 有形态校验（见 auth::UA）；
/// - 拉取失败时依次兜底：上次成功结果 → 内置快照（离线救急）。
/// - "auto" 是档位槽位名，其容量元数据对应 /v3/config 里的 "default" 条目。

use std::time::{Duration, Instant};

use reqwest::header::{HeaderValue, CONNECTION};
use serde_json::{Map, Value, json};

use crate::auth::{self, Auth};

/// 离线兜底：/v3/config 里 "cli" agent models 的实测快照（2026-06，服务端持续更新，
/// 正常情况走动态获取，此列表仅在后端不可达时救急）。
pub const FALLBACK_MODEL_IDS: &[&str] = &[
    "auto",
    "hy4-preview", "hy3", "hy3-x", "step-5-preview", "space-bunny",
    "deepseek-v4.1-flash", "glm-5.3", "glm-5.3-flash", "glm-5.2", "glm-5.1",
    "glm-5v-turbo", "minimax-m3", "minimax-m2.7", "kimi-k3-1",
    "kimi-k2.8-preview", "kimi-k2.7", "kimi-k2.6", "deepseek-v4-pro", "mimo-v2.6-pro",
];

struct Cached {
    available: Vec<String>,
    models: Vec<Value>,
    fetched_at: Instant,
}

pub struct ModelCatalog {
    client: reqwest::Client,
    ttl: Duration,
    state: tokio::sync::Mutex<Option<Cached>>,
}

impl ModelCatalog {
    pub fn new(client: reqwest::Client, ttl_secs: u64) -> Self {
        ModelCatalog {
            client,
            ttl: Duration::from_secs(ttl_secs),
            state: tokio::sync::Mutex::new(None),
        }
    }

    /// 返回 (可用模型 id 列表, 模型元数据列表)。TTL 内走缓存（force=true 跳过）；
    /// 重拉失败依次兜底：上次成功结果 → 内置快照（此时元数据为空）。
    pub async fn get(&self, auth: &Auth, force: bool) -> (Vec<String>, Vec<Value>) {
        let mut guard = self.state.lock().await;
        if !force {
            if let Some(c) = guard.as_ref() {
                if c.fetched_at.elapsed() < self.ttl {
                    return (c.available.clone(), c.models.clone());
                }
            }
        }
        match self.fetch(auth).await {
            Ok((available, models)) => {
                *guard = Some(Cached { available: available.clone(), models: models.clone(), fetched_at: Instant::now() });
                (available, models)
            }
            Err(e) => {
                eprintln!("[models] /v3/config 拉取失败（{e}）");
                if let Some(c) = guard.as_ref() {
                    eprintln!("[models] 使用上次成功结果（{} 个）", c.available.len());
                    (c.available.clone(), c.models.clone())
                } else {
                    eprintln!("[models] 使用内置兜底列表（{} 个）", FALLBACK_MODEL_IDS.len());
                    (FALLBACK_MODEL_IDS.iter().map(|s| s.to_string()).collect(), Vec::new())
                }
            }
        }
    }

    async fn fetch(&self, auth: &Auth) -> Result<(Vec<String>, Vec<Value>), String> {
        let session = auth.session().await?;
        let mut headers = auth::headers_of(&session, auth.private_data());
        headers.insert(CONNECTION, HeaderValue::from_static("close"));
        let url = format!("{}/v3/config", auth::BACKEND);
        let response = self
            .client
            .get(&url)
            .headers(headers)
            .timeout(Duration::from_secs(15))
            .send()
            .await
            .map_err(|e| format!("网络错误：{e}"))?;
        let status = response.status().as_u16();
        let body: Value = response
            .json()
            .await
            .map_err(|e| format!("响应不是合法 JSON：{e}"))?;
        if status != 200 || body.get("code").and_then(Value::as_i64) != Some(0) {
            let msg = body.get("msg").and_then(Value::as_str).unwrap_or("");
            return Err(format!(
                "HTTP {status} code={} {msg}",
                body.get("code").and_then(Value::as_i64).unwrap_or(-1)
            ));
        }
        let data = body.get("data").cloned().unwrap_or(Value::Null);
        let models: Vec<Value> = data
            .get("models")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter(|m| m.get("id").is_some()).cloned().collect())
            .unwrap_or_default();
        let cli = data
            .get("agents")
            .and_then(Value::as_array)
            .and_then(|a| a.iter().find(|x| x.get("name").and_then(Value::as_str) == Some("cli")))
            .cloned()
            .unwrap_or(Value::Null);
        let available: Vec<String> = cli
            .get("models")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        if models.is_empty() && available.is_empty() {
            return Err("响应里没有 models/agents".into());
        }
        Ok((available, models))
    }
}

/// "auto" 槽位 → 取 "default" 条目的容量元数据（保守值）。
pub fn meta_model_id(model_id: &str) -> &str {
    if model_id == "auto" { "default" } else { model_id }
}

/// 在元数据列表中查模型。
pub fn meta_for<'a>(models: &'a [Value], model_id: &str) -> Option<&'a Value> {
    models
        .iter()
        .find(|m| m.get("id").and_then(Value::as_str) == Some(model_id))
}

/// 从元数据提取上下文相关字段；`aliases` 附上 vLLM / LM Studio 风格别名（详情端点用）。
pub fn context_fields(meta: &Value, aliases: bool) -> Map<String, Value> {
    let mut out = Map::new();
    let max_in = meta.get("maxInputTokens").and_then(Value::as_u64);
    let max_out = meta.get("maxOutputTokens").and_then(Value::as_u64);
    if let Some(mi) = max_in {
        out.insert("max_input_tokens".into(), json!(mi));
        out.insert("context_length".into(), json!(mi));
        if aliases {
            out.insert("max_model_len".into(), json!(mi));      // vLLM 风格
            out.insert("max_context_length".into(), json!(mi)); // LM Studio 风格
        }
    }
    if let Some(mo) = max_out {
        out.insert("max_output_tokens".into(), json!(mo));
    }
    if aliases {
        if let Some(mas) = meta.get("maxAllowedSize").and_then(Value::as_u64) {
            out.insert("maxAllowedSize".into(), json!(mas));
        }
    }
    out
}

/// /v1/models 列表项（附上下文元数据，便于客户端做压缩/截断决策、避免上下文溢出）。
pub fn list_item(model_id: &str, meta: Option<&Value>) -> Value {
    let mut item = json!({ "id": model_id, "object": "model", "created": 1700000000, "owned_by": "codebuddy" });
    if let Some(m) = meta {
        if let Some(map) = item.as_object_mut() {
            for (k, v) in context_fields(m, false) {
                map.insert(k, v);
            }
        }
    }
    item
}

/// /v1/models/{id} 详情项（上下文别名 + 后端原始元数据）。
pub fn detail_item(model_id: &str, meta: Option<&Value>) -> Value {
    let mut item = json!({ "id": model_id, "object": "model", "created": 1700000000, "owned_by": "codebuddy" });
    if let Some(m) = meta {
        if let Some(map) = item.as_object_mut() {
            for (k, v) in context_fields(m, true) {
                map.insert(k, v);
            }
            for key in ["name", "credits", "vendor", "onlyReasoning", "supportsReasoning",
                        "supportsImages", "supportsToolCall", "reasoning", "descriptionZh"] {
                if let Some(v) = m.get(key) {
                    if !v.is_null() {
                        map.insert(key.into(), v.clone());
                    }
                }
            }
        }
    }
    item
}
