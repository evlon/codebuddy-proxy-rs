/// SSE 聚合：把后端返回的 OpenAI 流式 chunk 合并成单个非流式 `chat.completion`。
///
/// 后端只接受流式；客户端若请求 `stream=false`，则由这里消费完整 SSE 后聚合，
/// 与 codebuddy2openai 的非流式行为一致。
///
/// 注意（实测 deepseek-v4.1-flash 2026-10-22）：流式 tool_calls 的第一帧带
/// `function.name`，随后各帧 `name` 是**空串**、`arguments` 逐 token 分发——
/// 因此 name/id 只在非空时写入，否则会被空串覆盖回空（bug：tool_call 的
/// function.name 恒为空）。

use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

/// 逐行解析 `data: <json>` 事件并聚合到单个 completion 对象。
pub fn aggregate_to_completion(text: &str, model: &str) -> Value {
    let mut id = String::from("cmb-local");
    let mut content = String::new();
    let mut reasoning = String::new();
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
        if let Some(u) = chunk.get("usage") {
            if !u.is_null() {
                usage = Some(u.clone());
            }
        }
        let Some(choice) = chunk.get("choices").and_then(|c| c.get(0)) else { continue };
        if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
            finish_reason = Some(reason.to_string());
        }
        let Some(delta) = choice.get("delta").and_then(Value::as_object) else { continue };
        if let Some(text) = delta.get("content").and_then(Value::as_str) {
            content.push_str(text);
        }
        // 思考流（后端非标字段；OpenAI SDK 客户端忽略未知字段，ZCode/Cherry Studio
        // 会作为模型的 thinking 过程展示）——与流式链路透传的形状保持一致。
        if let Some(text) = delta.get("reasoning_content").and_then(Value::as_str) {
            reasoning.push_str(text);
        }
        if let Some(calls) = delta.get("tool_calls").and_then(Value::as_array) {
            for call in calls {
                let index = call.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
                let entry = tool_calls.entry(index).or_insert_with(|| {
                    let mut m = Map::new();
                    m.insert("type".into(), Value::String("function".into()));
                    m
                });
                // 非空才写入：首个 delta 带 id/name，后续 delta 是空串。
                if let Some(call_id) = call.get("id").and_then(Value::as_str) {
                    if !call_id.is_empty() {
                        entry.insert("id".into(), Value::String(call_id.into()));
                    }
                }
                if let Some(fn_obj) = call.get("function").and_then(Value::as_object) {
                    let function = entry.entry("function").or_insert_with(|| json!({}));
                    if let Some(map) = function.as_object_mut() {
                        if let Some(name) = fn_obj.get("name").and_then(Value::as_str) {
                            if !name.is_empty() {
                                map.insert("name".into(), Value::String(name.into()));
                            }
                        }
                        if let Some(args) = fn_obj.get("arguments").and_then(Value::as_str) {
                            if !args.is_empty() {
                                let current =
                                    map.get("arguments").and_then(Value::as_str).unwrap_or("");
                                map.insert("arguments".into(), Value::String(format!("{current}{args}")));
                            }
                        }
                    }
                }
            }
        }
    }

    // 响应侧零宽字符清洗（模型回声防护，见 scrub.rs 模块注释）
    let content = crate::scrub::scrub_zwsp(&content);
    let reasoning = crate::scrub::scrub_zwsp(&reasoning);
    for call in tool_calls.values_mut() {
        if let Some(fn_obj) = call.get_mut("function").and_then(Value::as_object_mut) {
            if let Some(name) = fn_obj.get("name").and_then(Value::as_str) {
                let cleaned = crate::scrub::scrub_zwsp(name);
                fn_obj.insert("name".into(), Value::String(cleaned));
            }
            if let Some(args) = fn_obj.get("arguments").and_then(Value::as_str) {
                let cleaned = crate::scrub::scrub_zwsp(args);
                fn_obj.insert("arguments".into(), Value::String(cleaned));
            }
        }
    }

    let mut message = Map::new();
    message.insert("role".into(), Value::String("assistant".into()));
    // tool_calls-only 的响应 content 用 null（与 codebuddy2openai 一致，客户端更友好）。
    message.insert("content".into(), if content.is_empty() { Value::Null } else { Value::String(content) });
    if !reasoning.is_empty() {
        message.insert("reasoning_content".into(), Value::String(reasoning));
    }
    if !tool_calls.is_empty() {
        finish_reason = Some(finish_reason.filter(|r| r != "stop").unwrap_or_else(|| "tool_calls".into()));
        message.insert(
            "tool_calls".into(),
            Value::Array(tool_calls.into_values().map(Value::Object).collect()),
        );
    }

    let mut choice = Map::new();
    choice.insert("index".into(), Value::from(0));
    choice.insert("message".into(), Value::Object(message));
    choice.insert(
        "finish_reason".into(),
        Value::String(finish_reason.unwrap_or_else(|| "stop".into())),
    );

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

#[cfg(test)]
mod tests {
    use super::*;

    /// 复现实测场景（deepseek-v4.1-flash 2026-10-22）：首帧 tool_call 带 name，
    /// 后续帧 name 为空串、arguments 逐 token；regression：聚合结果 name 不得为空。
    #[test]
    fn tool_call_name_survives_empty_name_frames() {
        let sse = concat!(
            r#"data: {"id":"51d35f08","model":"deepseek-v4.1-flash","object":"chat.completion.chunk","created":1792654706,"choices":[{"index":0,"delta":{"role":"assistant","content":"","reasoning_content":"","function_call":null,"tool_calls":[],"refusal":""}}]}"#,
            "\n",
            r#"data: {"id":"51d35f08","model":"deepseek-v4.1-flash","object":"chat.completion.chunk","created":1792654706,"choices":[{"index":0,"delta":{"content":"","reasoning_content":"","function_call":null,"tool_calls":[{"id":"call_00_GYg0","type":"function","function":{"name":"get_weather","arguments":""},"index":0}],"refusal":""}}]}"#,
            "\n",
            r#"data: {"id":"51d35f08","model":"deepseek-v4.1-flash","object":"chat.completion.chunk","created":1792654706,"choices":[{"index":0,"delta":{"content":"","reasoning_content":"","function_call":null,"tool_calls":[{"function":{"name":"","arguments":"{\"city\": \"Tokyo\"}"},"index":0}],"refusal":""}}]}"#,
            "\n",
            r#"data: {"id":"51d35f08","model":"deepseek-v4.1-flash","object":"chat.completion.chunk","created":1792654706,"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}"#,
            "\n",
            r#"data: [DONE]"#,
            "\n",
        );
        let completion = aggregate_to_completion(sse, "deepseek-v4.1-flash");
        let choice = &completion["choices"][0];
        let tc = &choice["message"]["tool_calls"][0];
        assert_eq!(tc["id"].as_str().unwrap(), "call_00_GYg0");
        assert_eq!(
            tc["function"]["name"].as_str().unwrap(),
            "get_weather",
            "name 被后续空串帧覆盖 = bug 回归"
        );
        assert_eq!(tc["function"]["arguments"].as_str().unwrap(), r#"{"city": "Tokyo"}"#);
        assert_eq!(choice["finish_reason"].as_str().unwrap(), "tool_calls");
        assert!(choice["message"]["content"].is_null(), "tool_calls-only 时 content 应为 null");
        assert!(!choice["message"]["reasoning_content"].is_null() == false);
    }

    /// 普通文本 + 思考流聚合。
    #[test]
    fn text_and_reasoning_aggregated() {
        let sse = concat!(
            r#"data: {"id":"a","choices":[{"index":0,"delta":{"role":"assistant","content":"","reasoning_content":"Let me"}}]}"#,
            "\n",
            r#"data: {"id":"a","choices":[{"index":0,"delta":{"reasoning_content":" think. "}}]}"#,
            "\n",
            r#"data: {"id":"a","choices":[{"index":0,"delta":{"content":"Hi"}}]}"#,
            "\n",
            r#"data: {"id":"a","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2}}"#,
            "\n",
            r#"data: [DONE]"#,
            "\n",
        );
        let completion = aggregate_to_completion(sse, "m");
        let message = &completion["choices"][0]["message"];
        assert_eq!(message["content"].as_str().unwrap(), "Hi");
        assert_eq!(message["reasoning_content"].as_str().unwrap(), "Let me think. ");
        assert!(completion["usage"]["prompt_tokens"].as_i64().unwrap() == 3);
    }

    /// 响应侧零宽字符清洗：模型回声的 U+200B 不得进入聚合结果（content/reasoning/参数）。
    #[test]
    fn zwsp_echo_is_scrubbed() {
        let sse = concat!(
            r#"data: {"choices":[{"index":0,"delta":{"content":"\u5728 d\u200bsh \u76ee\u5f55\u8fd0\u884c"}}]}"#,
            "\n",
            r#"data: {"choices":[{"index":0,"delta":{"reasoning_content":"\u60f3 d\u200bsh"}}]}"#,
            "\n",
            r#"data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c9","function":{"name":"wri\u200bte","arguments":"{\"path\":\"d"}}]}}]}"#,
            "\n",
            r#"data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\u200bsh.txt\"}"}}]}}]}"#,
            "\n",
            r#"data: [DONE]"#,
            "\n",
        );
        let completion = aggregate_to_completion(sse, "m");
        let message = &completion["choices"][0]["message"];
        assert_eq!(message["content"].as_str().unwrap(), "在 dsh 目录运行");
        assert_eq!(message["reasoning_content"].as_str().unwrap(), "想 dsh");
        let tc = &message["tool_calls"][0];
        assert_eq!(tc["function"]["name"].as_str().unwrap(), "write");
        assert_eq!(tc["function"]["arguments"].as_str().unwrap(), r#"{"path":"dsh.txt"}"#);
    }
}
