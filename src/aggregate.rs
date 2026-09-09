/// SSE 聚合：把后端返回的 OpenAI 流式 chunk 合并成单个非流式 `chat.completion`。
///
/// 后端只接受流式；客户端若请求 `stream=false`，则由这里消费完整 SSE 后聚合，
/// 与 codebuddy2openai 的非流式行为一致。

use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

/// 逐行解析 `data: <json>` 事件并聚合到单个 completion 对象。
pub fn aggregate_to_completion(text: &str, model: &str) -> Value {
    let mut id = String::from("cmb-local");
    let mut content = String::new();
    // tool_calls: index -> 累积片段
    let mut tool_calls: BTreeMap<usize, Map<String, Value>> = BTreeMap::new();
    let mut finish_reason: Option<String> = None;
    let mut usage: Option<Value> = None;

    for line in text.lines() {
        let line = line.trim();
        let payload = line.strip_prefix("data:").map(str::trim);
        let Some(payload) = payload else { continue };
        if payload.is_empty() || payload == "[DONE]" {
            continue;
        }
        let Ok(chunk) = serde_json::from_str::<Value>(payload) else { continue };
        if let Some(v) = chunk.get("id").and_then(Value::as_str) {
            id = v.to_string();
        }
        let Some(choice) = chunk.get("choices").and_then(|c| c.get(0)) else { continue };
        if let Some(delta) = choice.get("delta").and_then(Value::as_object) {
            if let Some(text) = delta.get("content").and_then(Value::as_str) {
                content.push_str(text);
            }
            if let Some(calls) = delta.get("tool_calls").and_then(Value::as_array) {
                for call in calls {
                    let index = call.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
                    let entry = tool_calls.entry(index).or_insert_with(|| {
                        let mut m = Map::new();
                        m.insert("type".into(), Value::String("function".into()));
                        m
                    });
                    if let Some(call_id) = call.get("id").and_then(Value::as_str) {
                        entry.insert("id".into(), Value::String(call_id.into()));
                    }
                    if let Some(fn_obj) = call.get("function").and_then(Value::as_object) {
                        let function = entry.entry("function").or_insert_with(|| json!({}));
                        if let Some(map) = function.as_object_mut() {
                            if let Some(name) = fn_obj.get("name").and_then(Value::as_str) {
                                map.insert("name".into(), Value::String(name.into()));
                            }
                            if let Some(args) = fn_obj.get("arguments").and_then(Value::as_str) {
                                let current = map.get("arguments").and_then(Value::as_str).unwrap_or("");
                                map.insert("arguments".into(), Value::String(format!("{current}{args}")));
                            }
                        }
                    }
                }
            }
        }
        if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
            finish_reason = Some(reason.to_string());
        }
        if let Some(u) = chunk.get("usage").cloned() {
            if !u.is_null() {
                usage = Some(u);
            }
        }
    }

    let mut message = Map::new();
    message.insert("role".into(), Value::String("assistant".into()));
    message.insert("content".into(), Value::String(content));
    if !tool_calls.is_empty() {
        message.insert(
            "tool_calls".into(),
            Value::Array(tool_calls.into_values().map(Value::Object).collect()),
        );
    }

    let mut choice = Map::new();
    choice.insert("index".into(), Value::from(0));
    choice.insert("message".into(), Value::Object(message));
    if let Some(reason) = finish_reason {
        choice.insert("finish_reason".into(), Value::String(reason));
    } else {
        choice.insert("finish_reason".into(), Value::String("stop".into()));
    }

    let mut completion = Map::new();
    completion.insert("id".into(), Value::String(id));
    completion.insert("object".into(), Value::String("chat.completion".into()));
    completion.insert("created".into(), Value::from(now_epoch_secs()));
    completion.insert("model".into(), Value::String(model.into()));
    completion.insert("choices".into(), Value::Array(vec![Value::Object(choice)]));
    if let Some(u) = usage {
        completion.insert("usage".into(), u);
    }
    Value::Object(completion)
}

fn now_epoch_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
