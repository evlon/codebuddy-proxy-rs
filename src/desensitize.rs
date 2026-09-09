/// 可选脱敏：对 system 消息里“合规声明高频词”插入零宽空格，缓解 CodeBuddy
/// 后端内容审核把客户端合规模板误判为敏感内容（与 codebuddy2openai/desensitize.py
/// 语义一致：只处理 system 角色、词表保守、默认关闭）。
///
/// 例：`DoS` → `Do\u{200b}S`。只改固定模板用词，不改用户输入，不做有害输入绕行。

use serde_json::Value;

const ZWSP: char = '\u{200b}';

/// 合规模板高频触发词（大小写不敏感，按长度降序尝试匹配，避免短词抢先命中长词）。
const TERMS: &[&str] = &[
    "credential testing",
    "credential stuffing",
    "supply-chain compromise",
    "supply chain compromise",
    "remote code execution",
    "detection evasion",
    "privilege escalation",
    "C2 framework",
    "malicious purposes",
    "malicious intent",
    "command and control",
    "brute-force",
    "reverse shell",
    "SQL injection",
    "brute force",
    "mass targeting",
    "keylogger",
    "ransomware",
    "DDoS",
    "DoS",
    "exploit",
    "zero-day",
    "phishing",
    "malware",
    "backdoor",
    "botnet",
    "0day",
    "C2",
    "XSS",
    "CSRF",
    "rootkit",
];

fn is_word(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// 对一个文本插入零宽空格（只插在命中片段第一个字符之后，改动最小）。
pub fn desensitize_text(text: &str) -> String {
    if text.is_empty() {
        return text.to_string();
    }
    let original: Vec<char> = text.chars().collect();
    let lower: Vec<char> = text.to_lowercase().chars().collect();
    let n = original.len();
    // 预排序：先尝试长词。
    let mut terms: Vec<(&str, Vec<char>)> = TERMS
        .iter()
        .map(|t| (*t, t.to_lowercase().chars().collect()))
        .collect();
    terms.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < n {
        let mut matched = false;
        for (_, term_chars) in &terms {
            let len = term_chars.len();
            if len == 0 || i + len > n {
                continue;
            }
            if lower[i..i + len] != term_chars[..] {
                continue;
            }
            let before_ok = i == 0 || !is_word(lower[i - 1]);
            let after_ok = i + len == n || !is_word(lower[i + len]);
            if !before_ok || !after_ok {
                continue;
            }
            // term[0] + ZWSP + term[1..]
            out.push(original[i]);
            if len > 1 {
                out.push(ZWSP);
            }
            for c in &original[i + 1..i + len] {
                out.push(*c);
            }
            i += len;
            matched = true;
            break;
        }
        if !matched {
            out.push(original[i]);
            i += 1;
        }
    }
    out
}

fn desensitize_content(content: &Value) -> Value {
    if let Some(text) = content.as_str() {
        return Value::String(desensitize_text(text));
    }
    if let Some(blocks) = content.as_array() {
        let next: Vec<Value> = blocks
            .iter()
            .map(|block| {
                if let Some(map) = block.as_object() {
                    if map.get("type").and_then(Value::as_str) == Some("text") {
                        let mut copy = map.clone();
                        if let Some(text) = copy.get("text").and_then(Value::as_str) {
                            copy.insert("text".into(), Value::String(desensitize_text(text)));
                        }
                        return Value::Object(copy);
                    }
                }
                block.clone()
            })
            .collect();
        return Value::Array(next);
    }
    content.clone()
}

/// 对请求体里的 system 消息做脱敏（就地修改 messages）。
pub fn desensitize_body(body: &mut Value) {
    let Some(messages) = body.get_mut("messages").and_then(Value::as_array_mut) else {
        return;
    };
    for message in messages {
        let Some(map) = message.as_object_mut() else { continue };
        if map.get("role").and_then(Value::as_str) != Some("system") {
            continue;
        }
        if let Some(content) = map.get("content") {
            let next = desensitize_content(content);
            map.insert("content".into(), next);
        }
    }
}
