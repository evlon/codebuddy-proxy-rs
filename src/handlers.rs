/// OpenAI 兼容的 HTTP 面：`/health`、`/v1/models`、`/v1/chat/completions`。
///
/// 聊天请求原样透传到 CodeBuddy 后端（仅强制 `stream=true`）；客户端要流式就逐字节
/// 透传 SSE（可选旁路录制到日志），要非流式则在后端流结束后聚合为单个 completion。
/// 可选能力与 codebuddy2openai 对齐：API key 校验、请求日志、system 合规词脱敏。

use std::{path::PathBuf, sync::Arc};

use axum::{
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Response},
};
use futures::StreamExt;
use serde_json::{Value, json};

use crate::{aggregate, auth, desensitize, logging};

const MODEL_IDS: &[&str] = &[
    "auto",
    "default",
    "deepseek-v4-flash",
    "deepseek-v4-pro",
    "hy3",
    "glm-5v-turbo",
    "kimi-k2-instruct-taiji",
    "default-1.2",
    "hunyuan-turbos-vision",
];

/// 应用共享状态。
pub struct AppState {
    pub auth: auth::Auth,
    pub client: reqwest::Client,
    api_key: String,
    logger: Option<logging::Logger>,
    desensitize: bool,
}

impl AppState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client: reqwest::Client,
        auth_file: PathBuf,
        api_key: String,
        logger: Option<logging::Logger>,
        desensitize: bool,
    ) -> Self {
        AppState { auth: auth::Auth::new(auth_file, client.clone()), client, api_key, logger, desensitize }
    }
}

type Shared = Arc<AppState>;

fn json_response(status: u16, value: &Value) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(value).unwrap_or_default()))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

fn error_response(status: u16, message: String) -> Response {
    json_response(status, &json!({ "error": { "message": message, "type": "upstream_error" } }))
}

/// 启用了 --api-key 时校验 Authorization: Bearer <key> 或 X-Api-Key。
fn api_key_allowed(headers: &HeaderMap, key: &str) -> bool {
    if key.is_empty() {
        return true;
    }
    let extract = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string())
    };
    let bearer = extract(header::AUTHORIZATION.as_str())
        .and_then(|value| value.strip_prefix("Bearer ").map(str::to_string));
    let token = bearer.filter(|s| !s.is_empty()).or_else(|| extract("x-api-key"));
    token.as_deref() == Some(key)
}

/// 取最后一条 user 消息的可读摘要（日志用，截断 60 字符）。
fn last_user_text(messages: &Value) -> String {
    let Some(list) = messages.as_array() else { return String::new() };
    for message in list.iter().rev() {
        let Some(map) = message.as_object() else { continue };
        if map.get("role").and_then(Value::as_str) != Some("user") {
            continue;
        }
        let text = match map.get("content") {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Array(blocks)) => blocks
                .iter()
                .filter_map(|b| b.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .concat(),
            _ => continue,
        };
        let trimmed: String = text.chars().filter(|c| !c.is_control()).collect();
        let mut out: String = trimmed.chars().take(60).collect();
        if trimmed.chars().count() > 60 {
            out.push('…');
        }
        return out;
    }
    String::new()
}

/// 后端 SSE 是否带“内容审核拦截”特征（日志标记用）。
fn is_filter_marker(text: &str) -> bool {
    text.contains("content-filter") || text.contains("敏感") || text.contains("审核")
}

pub async fn health() -> impl IntoResponse {
    "ok"
}

pub async fn models(headers: HeaderMap, State(state): State<Shared>) -> Response {
    if !api_key_allowed(&headers, &state.api_key) {
        return error_response(401, "invalid api key".into());
    }
    let data: Vec<Value> = MODEL_IDS
        .iter()
        .map(|id| json!({ "id": id, "object": "model", "created": 1700000000, "owned_by": "codebuddy" }))
        .collect();
    json_response(200, &json!({ "object": "list", "data": data }))
}

pub async fn chat(State(state): State<Shared>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    if !api_key_allowed(&parts.headers, &state.api_key) {
        return error_response(401, "invalid api key".into());
    }

    let bytes = match to_bytes(body, 256 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(e) => return error_response(400, format!("读取请求体失败：{e}")),
    };
    let parsed: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => return error_response(400, format!("请求体不是合法 JSON：{e}")),
    };
    let Value::Object(body_map) = parsed else {
        return error_response(400, "请求体必须是 JSON 对象".into());
    };
    let messages = body_map.get("messages").cloned().unwrap_or(Value::Null);
    if messages.as_array().map(|m| m.is_empty()).unwrap_or(true) {
        return error_response(400, "messages is required".into());
    }
    let model = body_map
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or("auto")
        .to_string();
    let wants_stream = body_map.get("stream").and_then(Value::as_bool).unwrap_or(false);
    let mut up_body = Value::Object(body_map);
    auth::ensure_stream_fields(&mut up_body);
    if state.desensitize {
        desensitize::desensitize_body(&mut up_body);
    }

    // 日志：请求摘要 + 发往后端的完整请求体（脱敏后）。
    let logger = state.logger.clone();
    if let Some(logger) = &logger {
        let last = last_user_text(&messages);
        let tools = messages.as_array().map_or(0, |_| {
            up_body.get("tools").and_then(Value::as_array).map(|t| t.len()).unwrap_or(0)
        });
        logger.line(&format!(
            "▶ REQUEST {model} | stream={wants_stream} | msgs={msgs} | tools={tools} | last_user='{last}'",
            msgs = up_body.get("messages").and_then(Value::as_array).map(|m| m.len()).unwrap_or(0),
        ));
        logger.block("REQUEST BODY", &serde_json::to_string(&up_body).unwrap_or_default());
    }

    // 转发到后端
    let session = match state.auth.session().await {
        Ok(s) => s,
        Err(e) => return error_response(401, e),
    };
    let mut headers = auth::headers_of(&session);
    headers.insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/json"));
    headers.insert(header::ACCEPT, header::HeaderValue::from_static("text/event-stream"));
    let url = format!("{}/v2/chat/completions", auth::BACKEND);
    let upstream = match state
        .client
        .post(&url)
        .headers(headers)
        .body(serde_json::to_vec(&up_body).unwrap_or_default())
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => return error_response(502, format!("请求 CodeBuddy 后端失败：{e}")),
    };
    if !upstream.status().is_success() {
        let status = upstream.status().as_u16();
        let raw = upstream.text().await.unwrap_or_default();
        if let Some(logger) = &logger {
            logger.line(&format!("✗ HTTP {status} | {model} | {}", raw.chars().take(200).collect::<String>()));
        }
        return Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(raw))
            .unwrap_or_else(|_| Response::new(Body::empty()));
    }

    // 流式：逐字节透传 SSE（开启日志时旁路录制完整原始 SSE）
    if wants_stream {
        let mapped = upstream
            .bytes_stream()
            .map(|item| item.map_err(|e| std::io::Error::other(e)));
        let stream = logging::Tee::new(mapped, logger);
        return Response::builder()
            .status(200)
            .header(header::CONTENT_TYPE, "text/event-stream")
            .header(header::CACHE_CONTROL, "no-cache")
            .header("x-accel-buffering", "no")
            .body(Body::from_stream(stream))
            .unwrap_or_else(|_| Response::new(Body::empty()));
    }

    // 非流式：消费完整 SSE 后聚合
    let text = match upstream.text().await {
        Ok(t) => t,
        Err(e) => return error_response(502, format!("读取后端流失败：{e}")),
    };
    let completion = aggregate::aggregate_to_completion(&text, &model);
    if let Some(logger) = &logger {
        let tag = if is_filter_marker(&text) { " ⚠️内容审核拦截" } else { "" };
        logger.line(&format!("◀ RESPONSE {model}{tag}"));
        logger.block("RESPONSE BODY", &serde_json::to_string(&completion).unwrap_or_default());
    }
    json_response(200, &completion)
}
