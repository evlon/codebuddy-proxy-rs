/// OpenAI 兼容的 HTTP 面：`/health`、`/v1/models`（动态）、`/v1/models/{id}`、`/v1/chat/completions`。
///
/// 聊天请求原样透传到 CodeBuddy 后端（仅强制 `stream=true`）；客户端要流式就逐行解析 SSE、
/// 清洗 U+200B（模型回声防护，见 `scrub.rs`）后重序列化转发（可选旁路录制到日志），
/// 要非流式则在后端流结束后聚合为单个 completion。
/// 模型列表动态拉取官方 `/v3/config`（与官方 CLI `/model` 选择器同源），并附上下文
/// 窗口元数据，便于客户端做压缩/截断决策、避免上下文溢出。

use std::{collections::HashMap, path::PathBuf, sync::Arc};

use axum::{
    body::{Body, to_bytes},
    extract::{Path, Query, Request, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Response},
};
use futures::StreamExt;
use serde_json::{Value, json};

use crate::{aggregate, auth, desensitize, logging, models};

/// 应用共享状态。
pub struct AppState {
    pub auth: auth::Auth,
    pub client: reqwest::Client,
    api_key: String,
    logger: Option<logging::Logger>,
    desensitize: bool,
    user_escape: bool,
    strip_harness: bool,
    /// --desensitize-scope all：脱敏扩展到全部角色消息 + tools 描述。
    desensitize_scope_all: bool,
    /// --official-shape（默认开）：补官方 body 形状字段（extra_vars.harnessMetadata 等）。
    official_shape: bool,
    /// 动态模型目录（/v3/config，TTL 缓存 + 失败兜底）。
    pub catalog: models::ModelCatalog,
}

impl AppState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client: reqwest::Client,
        auth_file: PathBuf,
        api_key: String,
        logger: Option<logging::Logger>,
        desensitize: bool,
        user_escape: bool,
        strip_harness: bool,
        private_data: bool,
        models_ttl_secs: u64,
        desensitize_scope_all: bool,
        official_shape: bool,
    ) -> Self {
        let catalog = models::ModelCatalog::new(client.clone(), models_ttl_secs);
        AppState {
            auth: auth::Auth::new(auth_file, client.clone(), private_data),
            client,
            api_key,
            logger,
            desensitize,
            user_escape,
            strip_harness,
            desensitize_scope_all,
            official_shape,
            catalog,
        }
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

fn not_found_response(model_id: &str) -> Response {
    json_response(
        404,
        &json!({ "error": {
            "message": format!("The model '{model_id}' does not exist"),
            "code": "model_not_found",
            "type": "invalid_request_error",
        }}),
    )
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

/// 对外暴露的模型 id 列表：保留 "auto"（代理默认槽位名，后端接受）在首位。
fn ids_with_auto(available: Vec<String>) -> Vec<String> {
    let mut ids = Vec::with_capacity(available.len() + 1);
    if !available.iter().any(|s| s == "auto") {
        ids.push("auto".to_string());
    }
    ids.extend(available);
    ids
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

/// 动态模型列表。默认走缓存（TTL 由 --models-ttl 控制）；?refresh=1 强制重拉。
pub async fn models(
    query: Query<HashMap<String, String>>,
    headers: HeaderMap,
    State(state): State<Shared>,
) -> Response {
    if !api_key_allowed(&headers, &state.api_key) {
        return error_response(401, "invalid api key".into());
    }
    let force = query
        .0
        .get("refresh")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let (available, metas) = state.catalog.get(&state.auth, force).await;
    let ids = ids_with_auto(available);
    let data: Vec<Value> = ids
        .iter()
        .map(|id| {
            let mid = models::meta_model_id(id);
            models::list_item(id, models::meta_for(&metas, mid))
        })
        .collect();
    json_response(200, &json!({ "object": "list", "data": data }))
}

/// 单个模型详情（OpenAI 协议 GET /v1/models/{model}），附上下文别名与后端元数据。
pub async fn model_detail(
    Path(model_id): Path<String>,
    headers: HeaderMap,
    State(state): State<Shared>,
) -> Response {
    if !api_key_allowed(&headers, &state.api_key) {
        return error_response(401, "invalid api key".into());
    }
    let (available, metas) = state.catalog.get(&state.auth, false).await;
    let ids = ids_with_auto(available);
    if !ids.contains(&model_id) {
        return not_found_response(&model_id);
    }
    let mid = models::meta_model_id(&model_id);
    let item = models::detail_item(&model_id, models::meta_for(&metas, mid));
    json_response(200, &item)
}

pub async fn chat(State(state): State<Shared>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    if !api_key_allowed(&parts.headers, &state.api_key) {
        return error_response(401, "invalid api key".into());
    }
    // 优先复用客户端透传的 X-Conversation-ID（多轮客户端与服务端日志按会话关联）；
    // 客户端未携带则 chat_headers 内部每次生成（官方对"新会话"的语义等同）。
    let client_conversation_id = parts
        .headers
        .get("x-conversation-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_string();

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
    // 官方请求形状补齐（--official-shape 默认开；2026-10-28 官方 2.177.0 抓包对齐，
    // 见 auth::apply_official_shape 的字段说明）。
    if state.official_shape {
        auth::apply_official_shape(&mut up_body);
    }
    // 内容审核误拦三层防护（顺序与 codebuddy2openai 一致：先清洗签名，再转义，再脱敏——
    // 后面两层都基于清洗后的 system 文本工作）。
    if state.strip_harness {
        let n = desensitize::strip_harness_body(&mut up_body);
        if n > 0 {
            if let Some(logger) = &state.logger {
                logger.line(&format!("── strip-harness: 清洗 {n} 处签名（含 @-路径段改写）"));
            }
        }
    }
    if state.user_escape {
        let (n, decoder_added) = desensitize::escape_user_body(&mut up_body);
        if n > 0 {
            if let Some(logger) = &state.logger {
                let extra = if decoder_added { "，已补解码说明" } else { "" };
                logger.line(&format!("── user-escape: 转义 {n} 处{extra}"));
            }
        }
    }
    if state.desensitize {
        if state.desensitize_scope_all {
            // dsh 客户端的工具描述/用户笔记里的 dsh/DSH 痕迹是渠道风险分加重因子，
            // scope=all 时全量打散（真实会话 71 处痕迹可打散 68 处）。
            desensitize::desensitize_body(&mut up_body, &["system", "user", "assistant", "tool"]);
            let n = desensitize::desensitize_tools(&mut up_body);
            if n > 0 {
                if let Some(logger) = &state.logger {
                    logger.line(&format!("── desensitize(scope=all): 全角色 + tools 描述改写 {n} 处"));
                }
            }
        } else {
            desensitize::desensitize_body(&mut up_body, &["system"]);
        }
    }

    // 日志：请求摘要 + 发往后端的完整请求体（脱敏后）。
    let logger = state.logger.clone();
    if let Some(logger) = &logger {
        let last = last_user_text(&messages);
        let tools = messages.as_array().map_or(0, |_| {
            up_body.get("tools").and_then(Value::as_array).map(|t| t.len()).unwrap_or(0)
        });
        logger.rotate(); // 记录新请求前先裁掉更早的请求现场（保留最近 log_keep 次）
        logger.line(&format!(
            "▶ REQUEST {model} | stream={wants_stream} | msgs={msgs} | tools={tools} | last_user='{last}'",
            msgs = up_body.get("messages").and_then(Value::as_array).map(|m| m.len()).unwrap_or(0),
        ));
        logger.block("REQUEST BODY", &serde_json::to_string(&up_body).unwrap_or_default());
    }

    // 转发到后端（官方 CLI 形态的请求头，见 auth::chat_headers）。
    // 11128 自愈（对齐 codebuddy2openai）：上游非 200 且响应体含 "11128"（渠道拦截）→
    // 强刷令牌 + 重建身份头，2s 后重试一次。重试轰炸会推高后端渠道热度，故只重试一次；
    // 其余错误原样透传（流式响应不受影响——错误响应体是小 JSON，缓冲判断无副作用）。
    let url = format!("{}/v2/chat/completions", auth::BACKEND);
    let json_bytes = serde_json::to_vec(&up_body).unwrap_or_default();

    async fn fresh_headers(
        state: &AppState,
        model: &str,
        conversation_id: &str,
    ) -> Result<HeaderMap, Response> {
        let session = match state.auth.session().await {
            Ok(s) => s,
            Err(e) => return Err(error_response(401, e)),
        };
        let mut h = auth::chat_headers(&session, model, state.auth.private_data(), conversation_id);
        h.insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/json"));
        h.insert(header::ACCEPT, header::HeaderValue::from_static("text/event-stream"));
        Ok(h)
    }

    let mut headers = match fresh_headers(&state, &model, &client_conversation_id).await {
        Ok(h) => h,
        Err(resp) => return resp,
    };
    let mut retried_11128 = false;
    let upstream = loop {
        let resp = match state
            .client
            .post(&url)
            .headers(headers.clone())
            .body(json_bytes.clone())
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => return error_response(502, format!("请求 CodeBuddy 后端失败：{e}")),
        };
        if resp.status().as_u16() == 200 {
            break resp;
        }
        // 错误响应体较小，缓冲后判断是否渠道拦截 11128。
        let status = resp.status();
        let raw = resp.text().await.unwrap_or_default();
        if let Some(logger) = &logger {
            logger.line(&format!(
                "✗ HTTP {} | {model} | {}",
                status.as_u16(),
                raw.chars().take(200).collect::<String>()
            ));
            logger.block("ERROR BODY", &raw);
        }
        if !retried_11128 && raw.contains("11128") {
            retried_11128 = true;
            if let Some(logger) = &logger {
                logger.line("── 11128 渠道拦截：强刷令牌+换身份头，2s 后重试一次");
            }
            state.auth.force_refresh();
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            headers = match fresh_headers(&state, &model, &client_conversation_id).await {
                Ok(h) => h,
                Err(resp) => return resp,
            };
            continue;
        }
        return Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(raw))
            .unwrap_or_else(|_| Response::new(Body::empty()));
    };

    // 流式：逐字节透传 SSE（开启日志时旁路录制完整原始 SSE）
    if wants_stream {
        let mapped = upstream
            .bytes_stream()
            .map(|item| item.map_err(|e| std::io::Error::other(e)));
        // 响应侧零宽字符清洗：逐行解析-清洗 U+200B-重序列化（模型回声防护，见 scrub.rs）
        let scrubbed = crate::scrub::SseScrubStream::new(mapped);
        let stream = logging::Tee::new(scrubbed, logger);
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
