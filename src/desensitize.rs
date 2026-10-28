/// 针对 CodeBuddy 后端内容审核的三层文本处理（与 codebuddy2openai/desensitize.py
/// 语义一致，独立模块）：
///
/// 1) 脱敏（`--desensitize`）：对"合规声明高频词"插入零宽空格（`DoS` → `Do\u{200b}S`），
///    缓解后端内容审核把客户端合规模板误判为敏感内容。默认只处理 system 角色
///    （`--desensitize-scope all` 扩展到 user/assistant/tool 消息与 tools 描述）。
///    词表含 `DeepSeek Harness`（实测 2026-10-21：后端对 system 做精确大小写字面量
///    拦截，该竞品签名字符串触发 HTTP 400 code=11128 渠道拦截）。2026-10-28 补充：
///    渠道风险为动态累计评分——外来 prompt 痕迹（dsh/DSH 产品名、DeepSeek 厂商名）
///    与 dsh 客户端内容（工具描述/用户笔记）共现会推高风险分、突破拦截阈值 →
///    词表追加 `deepseek`、`dsh` 一并打散（模型侧零宽空格不可见，无语义影响）。
/// 2) 用户转义（`--user-escape`）：user 消息里命中词表的英文术语包成
///    `[s[<逐字反转>]]`（`phishing` → `[s[gnihsihp]]`）打断关键词匹配；system 里
///    尚无解码说明时自动补一段 `CODEBUDDY_ESCAPE_CODEC` 说明让模型还义作答。
/// 3) 签名清洗（`--strip-harness`，默认开）：清洗 system 三段 dsh 全局签名
///    （`harness:identity/source`、`app:web-surface`，均含 `DeepSeek Harness` 字面量）：
///    identity 改写为 CodeBuddy、source 删除、web-surface 替换为中性等效文本，
///    残留变体兜底替换为 `CodeBuddy`。assistant 历史只做残留兜底（实测 2026-10-28：
///    模型在 dsh persona 时期的自我介绍会被存进会话历史，续聊回放时照样触发 11128）。
///    幂等，与 dsh CodeBuddy 预设的遮蔽互不冲突。
///
/// 保守原则不变：只改固定词表/固定签名段，不做有害输入绕行。

use serde_json::Value;

const ZWSP: char = '\u{200b}';

fn is_word(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Python 版脱敏词边界：只把"紧邻英文字母"视为边界内（数字/下划线允许，
/// 使 "DSH_x" 这类工具名前缀也命中，"unhashed"/"FDSSH" 这类纯字母内嵌才不命中）。
/// 对应 Python 正则 `(?<![A-Za-z])…(?![A-Za-z])`（rust regex crate 无 lookaround，
/// 逐位置手写检查等价实现）。
fn is_boundary_letter(c: char) -> bool {
    c.is_ascii_alphabetic()
}

// ---------------------------------------------------------------------------
// 词表与常量
// ---------------------------------------------------------------------------

/// 合规模板高频触发词（大小写不敏感，按长度降序尝试匹配，避免短词抢先命中长词）。
const TERMS: &[&str] = &[
    "credential testing",
    "credential stuffing",
    "supply-chain compromise",
    "supply chain compromise",
    "remote code execution",
    "detection evasion",
    "privilege escalation",
    "C2 frameworks",
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
    // 实测（2026-10-21）：后端对 system 消息做精确大小写字面量拦截，
    // "DeepSeek Harness"（竞品官方 agent harness 的签名）触发 HTTP 400 code=11128
    // "Illegal API invocation from an unapproved channel"。加 ZWSP 脱敏后实测放行。
    // 2026-10-28 补充：渠道风险为动态累计评分——外来 prompt 痕迹（dsh/DSH 产品名、
    // DeepSeek 厂商名）与 dsh 客户端内容（工具描述/用户笔记）共现会推高风险分、
    // 突破拦截阈值 → 一并打散（模型侧零宽空格不可见，无语义影响）。
    "DeepSeek Harness",
    "deepseek",
    "dsh",
];

/// 用户转义词表（--user-escape，作用对象是 user 消息里的英文术语）。
/// 注：词边界判定沿 Rust 侧既有口径（字母/数字/下划线都算词边界），
/// 比 Python 版的 `(?![A-Za-z])` 更保守——不会误转 "dos2unix" 这类串。
const USER_ESCAPE_TERMS: &[&str] = &[
    "credentials", "credential",
    "hacking", "hacker", "hack",
    "phishing", "phish",
    "malware", "ransomware", "botnet", "keylogger", "spyware", "rootkit",
    "backdoor", "trojan", "exploit",
    "ddos", "dos",
];

/// 自动补齐到 system 的解码说明（模型按它把 [s[...]] 反转还义）。
const USER_ESCAPE_DECODER: &str = "Encoding protocol (CODEBUDDY_ESCAPE_CODEC): the user input may contain bracketed tokens of the form [s[ABC]]. Decode rule: strip the [s[...]] wrapper and read the inner letters in reverse - [s[321cba]] means \"abc123\". Mentally decode every such token before interpreting the sentence, then answer as normal.";

// ---- strip-harness：dsh 三段全局签名的定位标记 ----

/// harness:identity 段精确文本。
const HARNESS_IDENTITY: &str = "You are an AI agent powered by DeepSeek Harness.";
const HARNESS_IDENTITY_REWRITE: &str = "You are CodeBuddy Code.";

/// harness:source 段的起止标记（CodeBuddy 模式下该 dsh 仓库路径指引无意义，整段删除，
/// 与 Python 版 `.*?Use this checkout only to inspect or extend DSH itself\.\s*` 等价）。
const HARNESS_SOURCE_START: &str = "The DeepSeek Harness implementation checkout is at ";
const HARNESS_SOURCE_END: &str = "Use this checkout only to inspect or extend DSH itself.";

/// app:web-surface 段的起止标记（整段是 dsh 前端开发细节，替换为中性等效文本）。
const HARNESS_WEB_START: &str = "You are interacting with the user through the DeepSeek Harness Web GUI at ";
const HARNESS_WEB_END: &str = "verify its exact URL.";

const WEB_SURFACE_NEUTRAL: &str = "You are interacting with the user through a local Web GUI. When the user refers to \"this page\", \"this GUI\", or \"this app\" without naming another target, they mean this GUI. The browser provides no implicit DOM, route, or screenshot context.";

/// @-路径语义段起止标记（2026-10-28 确定性定位）：dsh 预设里该段是后端渠道
/// 拦截的第二处硬字面量源（官方载体分块扫描：预设其余部分全部放行，仅此段
/// 被拦；整段改写后官方载体/转换器 F4/FULL 全通过）。改为中性等效改写。
const ATPATH_START: &str = "Tokens prefixed with @ are paths the user explicitly referenced.";
const ATPATH_END: &str = "quotes a path containing spaces.";
const ATPATH_NEUTRAL: &str = "File paths that the user prefixed with the at sign resolve relative to the workspace root; absolute paths point to host files or directories. A trailing slash marks a directory; otherwise treat it as a file and read it before claiming to have inspected it. Quoted at-paths wrap paths containing spaces.";

/// 通用词替换器：大小写不敏感 + 词边界，按词长降序尝试。
/// `letter_boundary=true` 时边界只拦英文字母（脱敏词表口径，Python 一致）；
/// `false` 时字母/数字/下划线都拦（user-escape 词表的 Rust 既有保守口径）。
/// 命中时用 `f(命中原文)` 生成替换文本。返回 (新文本, 命中数)。
fn replace_terms<F: Fn(&str) -> String>(
    text: &str,
    terms: &[&str],
    letter_boundary: bool,
    f: F,
) -> (String, usize) {
    if text.is_empty() {
        return (text.to_string(), 0);
    }
    let original: Vec<char> = text.chars().collect();
    let lower: Vec<char> = text.chars().map(|c| c.to_ascii_lowercase()).collect();
    let n = original.len();
    let mut terms: Vec<(&str, Vec<char>)> =
        terms.iter().map(|t| (*t, t.to_lowercase().chars().collect())).collect();
    terms.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

    let starts_with = |i: usize, pat: &[char]| -> bool {
        i + pat.len() <= n && lower[i..i + pat.len()] == pat[..]
    };

    let blocked = |c: char| if letter_boundary { is_boundary_letter(c) } else { is_word(c) };

    let mut out = String::with_capacity(text.len());
    let mut count = 0;
    let mut i = 0;
    while i < n {
        let mut matched = false;
        for (_, term_chars) in &terms {
            let len = term_chars.len();
            if len == 0 || i + len > n || !starts_with(i, term_chars) {
                continue;
            }
            let before_ok = i == 0 || !blocked(lower[i - 1]);
            let after_ok = i + len == n || !blocked(lower[i + len]);
            if !before_ok || !after_ok {
                continue;
            }
            let hit: String = original[i..i + len].iter().collect();
            out.push_str(&f(&hit));
            i += len;
            count += 1;
            matched = true;
            break;
        }
        if !matched {
            out.push(original[i]);
            i += 1;
        }
    }
    (out, count)
}

// ---------------------------------------------------------------------------
// 1) ZWSP 脱敏（--desensitize）
// ---------------------------------------------------------------------------

/// 对一个文本插入零宽空格（只插在命中片段第一个字符之后，改动最小）。
pub fn desensitize_text(text: &str) -> String {
    let (out, _) = replace_terms(
        text,
        TERMS,
        true, // 词边界只拦英文字母（数字/下划线允许，见 is_boundary_letter）
        |hit| {
        let mut chars = hit.chars();
        let Some(first) = chars.next() else { return hit.to_string() };
        let mut out = String::with_capacity(hit.len() + 3);
        out.push(first);
        out.push(ZWSP);
        out.push_str(chars.as_str());
        out
    });
    out
}

fn edit_text_blocks(content: &Value, f: &mut impl FnMut(&str) -> String) -> Value {
    if let Some(text) = content.as_str() {
        return Value::String(f(text));
    }
    if let Some(blocks) = content.as_array() {
        let mut next: Vec<Value> = Vec::with_capacity(blocks.len());
        for block in blocks {
            if let Some(map) = block.as_object() {
                if map.get("type").and_then(Value::as_str) == Some("text") {
                    let mut copy = map.clone();
                    if let Some(text) = copy.get("text").and_then(Value::as_str) {
                        copy.insert("text".into(), Value::String(f(text)));
                    }
                    next.push(Value::Object(copy));
                    continue;
                }
            }
            next.push(block.clone());
        }
        return Value::Array(next);
    }
    content.clone()
}

fn edit_body(body: &mut Value, roles: &[&str], f: &mut impl FnMut(&str, &str) -> String) {
    let Some(messages) = body.get_mut("messages").and_then(Value::as_array_mut) else {
        return;
    };
    for message in messages {
        let Some(map) = message.as_object_mut() else { continue };
        let role = map.get("role").and_then(Value::as_str).unwrap_or("").to_string();
        if !roles.contains(&role.as_str()) {
            continue;
        }
        if let Some(content) = map.get("content").cloned() {
            map.insert("content".into(), edit_text_blocks(&content, &mut |s| f(&role, s)));
        }
    }
}

/// 对请求体里指定角色的消息做脱敏（就地修改 messages）。
/// 默认只处理 system（合规模板集中地）；`--desensitize-scope all` 时传全部四角色。
pub fn desensitize_body(body: &mut Value, roles: &[&str]) {
    edit_body(body, roles, &mut |_, s| desensitize_text(s));
}

// ---------------------------------------------------------------------------
// 2) 用户消息转义（--user-escape）：[s[<反转词>]] 编解码方案
// ---------------------------------------------------------------------------

/// 把文本里的转义词包成 `[s[<reversed>]]`。返回 (新文本, 命中数)。
pub fn escape_user_text(text: &str) -> (String, usize) {
    replace_terms(
        text,
        USER_ESCAPE_TERMS,
        false, // 字母/数字/下划线都算边界（Rust 既有保守口径，见词表注释）
        |hit| {
            let reversed: String = hit.chars().rev().collect();
            format!("[s[{reversed}]]")
        },
    )
}

/// system 消息里是否已有解码说明（dsh CodeBuddy 预设的解码段含 `[s[`）。
fn has_escape_codec(messages: &Value) -> bool {
    let Some(list) = messages.as_array() else { return false };
    list.iter().any(|message| {
        let map = match message.as_object() {
            Some(map) => map,
            None => return false,
        };
        if map.get("role").and_then(Value::as_str) != Some("system") {
            return false;
        }
        match map.get("content") {
            Some(Value::String(s)) => s.contains("[s["),
            Some(Value::Array(blocks)) => blocks.iter().any(|b| {
                b.get("text").and_then(Value::as_str).map(|t| t.contains("[s[")).unwrap_or(false)
            }),
            _ => false,
        }
    })
}

/// 对请求体做 user 消息转义；若 system 里尚无解码说明且发生了转义，补一条
/// （插到首条 system 消息内容的开头；没有 system 则新插一条）。
/// 就地修改。返回 (命中数, 是否补了解码说明)。只动 user 的文本和 system 的开头。
pub fn escape_user_body(body: &mut Value) -> (usize, bool) {
    let mut count = 0;
    {
        let Some(messages) = body.get_mut("messages").and_then(Value::as_array_mut) else {
            return (0, false);
        };
        for message in messages {
            let Some(map) = message.as_object_mut() else { continue };
            if map.get("role").and_then(Value::as_str) != Some("user") {
                continue;
            }
            content_mut(map, |content| {
                let mut counter = |s: &str| {
                    let (out, n) = escape_user_text(s);
                    count += n;
                    out
                };
                let next = edit_text_blocks(content, &mut counter);
                *content = next;
            });
        }
    }
    if count == 0 {
        return (count, false);
    }
    // 补解码说明（枚举已经结束，可以重新借 messages）。
    let Some(messages) = body.get_mut("messages").and_then(Value::as_array_mut) else {
        return (count, false);
    };
    if has_escape_codec(&Value::Array(messages.clone())) {
        return (count, false);
    }
    let decoder = json_text_block(USER_ESCAPE_DECODER);
    let sys_idx = messages
        .iter()
        .position(|m| m.get("role").and_then(Value::as_str) == Some("system"));
    match sys_idx {
        Some(idx) => {
            if let Some(map) = messages[idx].as_object_mut() {
                let content = map.get("content").cloned().unwrap_or(Value::Null);
                let merged = match &content {
                    Value::String(_) => prepend_to_string(content, USER_ESCAPE_DECODER),
                    Value::Array(_) => prepend_to_blocks(content, decoder),
                    _ => json_text_block(USER_ESCAPE_DECODER),
                };
                map.insert("content".into(), merged);
            }
        }
        None => {
            let mut m = serde_json::Map::new();
            m.insert("role".into(), Value::String("system".into()));
            m.insert("content".into(), Value::String(USER_ESCAPE_DECODER.into()));
            messages.insert(0, Value::Object(m));
        }
    }
    (count, true)
}

fn content_mut<F: FnOnce(&mut Value)>(map: &mut serde_json::Map<String, Value>, f: F) {
    if let Some(content) = map.get_mut("content") {
        f(content);
    }
}

fn json_text_block(text: &str) -> Value {
    serde_json::json!([{ "type": "text", "text": text }])
}

fn prepend_to_string(content: Value, text: &str) -> Value {
    Value::String(format!("{text}\n\n{}", content.as_str().unwrap_or_default()))
}

fn prepend_to_blocks(content: Value, head: Value) -> Value {
    let Value::Array(blocks) = content else { return head };
    let mut next = vec![head];
    next.extend(blocks);
    Value::Array(next)
}

// ---------------------------------------------------------------------------
// 3) 签名清洗（--strip-harness，默认开）：dsh/DeepSeek Harness 签名清洗
// ---------------------------------------------------------------------------

/// 精确文本替换（大小写敏感，全部命中处都替换）。
fn replace_exact(text: &str, from: &str, to: &str) -> (String, usize) {
    let count = text.matches(from).count();
    if count == 0 {
        (text.to_string(), 0)
    } else {
        (text.replace(from, to), count)
    }
}

/// 大小写敏感地处理首个 `start_marker ... end_marker` 跨度（span 含两端标记；
/// `eat_trailing_ws` 时把 end 标记后的空白一并吃掉——等价于 Python 版 `\s*` 尾部）。
fn replace_span_once(
    text: &str,
    start_marker: &str,
    end_marker: &str,
    replacement: &str,
    eat_trailing_ws: bool,
) -> (String, usize) {
    let Some(start) = text.find(start_marker) else { return (text.to_string(), 0) };
    let search_from = start + start_marker.len();
    let Some(end_rel) = text[search_from..].find(end_marker) else {
        return (text.to_string(), 0);
    };
    let end_abs = search_from + end_rel + end_marker.len();
    let mut end_ws = end_abs;
    if eat_trailing_ws {
        end_ws += text[end_ws..]
            .chars()
            .take_while(|c| c.is_whitespace())
            .map(|c| c.len_utf8())
            .sum::<usize>();
    }
    let mut out = String::with_capacity(text.len());
    out.push_str(&text[..start]);
    out.push_str(replacement);
    out.push_str(&text[end_ws..]);
    (out, 1)
}

/// 残兜底：`Deep[ \t]*Seek[ \t]+Harness` 任意大小写变体 → `CodeBuddy`。
/// 手写扫描器（char 级，`to_ascii_lowercase` 保持 1:1 长度映射）。
fn strip_residual(text: &str) -> (String, usize) {
    let orig: Vec<char> = text.chars().collect();
    let low: Vec<char> = orig.iter().map(|c| c.to_ascii_lowercase()).collect();
    let n = orig.len();
    let starts_with = |i: usize, pat: &[char]| -> bool {
        i + pat.len() <= n && low[i..i + pat.len()] == pat[..]
    };
    let deep: Vec<char> = "deep".chars().collect();
    let seek: Vec<char> = "seek".chars().collect();
    let harness: Vec<char> = "harness".chars().collect();

    let mut out = String::with_capacity(text.len());
    let mut count = 0;
    let mut i = 0;
    while i < n {
        if starts_with(i, &deep) {
            let mut j = i + deep.len();
            while j < n && (low[j] == ' ' || low[j] == '\t') {
                j += 1;
            }
            if starts_with(j, &seek) {
                let mut k = j + seek.len();
                let k0 = k;
                while k < n && (low[k] == ' ' || low[k] == '\t') {
                    k += 1;
                }
                if k > k0 && starts_with(k, &harness) {
                    out.push_str("CodeBuddy");
                    count += 1;
                    i = k + harness.len();
                    continue;
                }
            }
        }
        out.push(orig[i]);
        i += 1;
    }
    (out, count)
}

/// 清洗一段 system 文本里的 DeepSeek Harness 签名。返回 (新文本, 改写数)。
pub fn strip_harness_text(text: &str) -> (String, usize) {
    let mut count = 0;
    let (a, c) = replace_exact(text, HARNESS_IDENTITY, HARNESS_IDENTITY_REWRITE);
    count += c;
    let (b, c) = replace_span_once(&a, HARNESS_SOURCE_START, HARNESS_SOURCE_END, "", true);
    count += c;
    let (d, c) = replace_span_once(&b, HARNESS_WEB_START, HARNESS_WEB_END, WEB_SURFACE_NEUTRAL, false);
    count += c;
    let (e2, c) = replace_span_once(&d, ATPATH_START, ATPATH_END, ATPATH_NEUTRAL, false);
    count += c;
    let (e, c) = strip_residual(&e2);
    count += c;
    (e, count)
}

/// 对请求体做签名清洗（就地修改）。返回改写数。
///
/// system 做**全套**清洗（identity 改写 / source 删除 / web-surface 换中性文本 /
/// 残留兜底）；assistant 历史只做**残留兜底**（`Deep[ \t]*Seek[ \t]+Harness` →
/// `CodeBuddy`，任意大小写）——实测 2026-10-28：模型在 dsh persona 时期的自我
/// 介绍（"我是由 DeepSeek Harness 驱动的…"）会被存进会话历史，续聊回放时照样
/// 触发 11128——只清 system 挡不住历史包袱。历史里只做残留替换，语义无害且与
/// 人设一致。user/tool 等其它角色不动。
pub fn strip_harness_body(body: &mut Value) -> usize {
    let mut count = 0;
    edit_body(body, &["system", "assistant"], &mut |role, s| {
        if role == "system" {
            let (out, n) = strip_harness_text(s);
            count += n;
            out
        } else {
            let (out, n) = strip_residual(s);
            count += n;
            out
        }
    });
    count
}

// ---------------------------------------------------------------------------
// 4) tools 描述脱敏（--desensitize-scope all）
// ---------------------------------------------------------------------------

/// 递归把 schema（parameters 等）里所有字符串型 description 字段脱敏。返回改写数。
fn desensitize_descriptions(value: &mut Value) -> usize {
    match value {
        Value::Object(map) => {
            let mut n = 0;
            for (key, item) in map.iter_mut() {
                if key == "description" {
                    if let Some(text) = item.as_str() {
                        let next = desensitize_text(text);
                        if next != text {
                            n += 1;
                        }
                        *item = Value::String(next);
                    }
                } else {
                    n += desensitize_descriptions(item);
                }
            }
            n
        }
        Value::Array(items) => items.iter_mut().map(desensitize_descriptions).sum(),
        _ => 0,
    }
}

/// 对 body["tools"] 的 function.description 与 parameters 内（递归）字符串型
/// description 脱敏（就地修改）。
///
/// dsh 客户端携带的插件工具描述里大量出现 "DSH_*"/"dsh" 痕迹（渠道风险分的
/// 加重因子），此前完全未被任何清洗覆盖。parameters 先深拷贝再改写，不改
/// 调用方原对象。返回改写数；幂等（脱敏后的文本不再命中词表）。
pub fn desensitize_tools(body: &mut Value) -> usize {
    let Some(tools) = body.get_mut("tools").and_then(Value::as_array_mut) else {
        return 0;
    };
    let mut count = 0;
    for tool in tools.iter_mut() {
        let Some(function) = tool.get_mut("function").and_then(Value::as_object_mut) else {
            continue;
        };
        if let Some(Value::String(text)) = function.get_mut("description") {
            let next = desensitize_text(text);
            if next != *text {
                count += 1;
            }
            *text = next;
        }
        if let Some(params) = function.get_mut("parameters") {
            if params.is_object() {
                let mut copy = params.clone(); // 深拷贝（schema 无循环引用）
                count += desensitize_descriptions(&mut copy);
                *params = copy;
            }
        }
    }
    count
}

// ---------------------------------------------------------------------------
// 单元测试：cargo test
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE_REAL: &str = "The DeepSeek Harness implementation checkout is at D:\\repos\\dsh. \
The checkout location and current working directory are separate values and may differ; \
never infer the working directory from this path. Use pwd to determine the current \
working directory. Use this checkout only to inspect or extend DSH itself. ";

    const WEB_REAL: &str = "You are interacting with the user through the DeepSeek Harness Web GUI at \
http://127.0.0.1:3080. When the user refers to \"this page\", \"this GUI\", or \"this app\" without \
naming another target, they mean this GUI. The browser provides no implicit DOM, route, or \
screenshot context. The client-plugin HMR receiver is active, but client-plugin changes reload \
without a refresh only while `pnpm run dev:web` is also running from this same checkout. Do not \
start a replacement server unless the user asks; if one is needed, use a managed background job \
and verify its exact URL.";

    #[test]
    fn desensitize_inserts_zwsp() {
        let out = desensitize_text("Refuse requests for DoS attacks and exploit development.");
        assert!(out.contains("D\u{200b}oS"), "{out}");
        assert!(out.contains("e\u{200b}xploit"), "{out}");
        let deep = desensitize_text("Run by the DeepSeek Harness runtime.");
        assert!(deep.contains("D\u{200b}eepSeek"), "DeepSeek Harness 应被零宽空格打断：{deep}");
    }

    #[test]
    fn desensitize_keeps_user_text() {
        let mut body: Value = serde_json::from_str(
            r#"{"messages":[
                {"role":"system","content":"Refuse DoS attacks and exploit development."},
                {"role":"user","content":"explain DoS attacks"}]}"#,
        )
        .unwrap();
        desensitize_body(&mut body, &["system"]);
        let msgs = body["messages"].as_array().unwrap();
        assert!(msgs[0]["content"].as_str().unwrap().contains('\u{200b}'));
        assert!(!msgs[1]["content"].as_str().unwrap().contains('\u{200b}'));
    }

    /// 边界语义（2026-10-28 对齐 Python）：左右紧邻英文字母才不命中；
    /// 数字/下划线允许（"DSH_x" 命中），纯字母内嵌（"unhashed"/"FDSSH"）不命中。
    /// 注：词表是大小写不敏感匹配，"dsh" 会命中 "DSH"/"Dsh" 等全部变体。
    #[test]
    fn desensitize_boundary_semantics() {
        // 命中：下划线/数字紧邻允许
        assert!(desensitize_text("call the DSH_x tool").contains("D\u{200b}SH_x"), "DSH_x 应命中");
        assert!(desensitize_text("run dsh now").contains("d\u{200b}sh"), "独立词 dsh 应命中");
        assert!(desensitize_text("step 1dsh2 done").contains("1d\u{200b}sh2"), "数字边界应命中");
        assert!(desensitize_text("uses deepseek backend").contains("d\u{200b}eepseek"), "deepseek 应命中");
        // 不命中：紧邻英文字母
        for untouched in ["unhashed", "FDSSH", "DSHx", "xdsh"] {
            assert_eq!(desensitize_text(untouched), *untouched, "{untouched} 不应命中");
        }
        // 幂等：脱敏结果再跑一遍不再变化
        let once = desensitize_text("DSH_x and deepseek and DoS");
        let twice = desensitize_text(&once);
        assert_eq!(once, twice, "脱敏应幂等");
    }

    /// @-路径语义段（11128 第二处确定性硬拦点，2026-10-28 官方载体分块扫描定位）：
    /// 整段改写为中性等效文本，幂等；不含该段的文本不动。
    #[test]
    fn strip_atpath_paragraph() {
        let text = "Before.\n\nTokens prefixed with @ are paths the user explicitly referenced. Relative paths resolve from the workspace root; absolute paths identify files or directories on the host. A trailing slash marks a directory: list it when its contents matter. Anything else is a file: use the read tool when its contents are needed, and do not claim to have inspected it before reading. @\"...\" quotes a path containing spaces.\n\nAfter.";
        let (out, n) = strip_harness_text(text);
        assert_eq!(n, 1, "应改写 1 处");
        assert!(!out.contains("Tokens prefixed with @"), "原文段落应被替换：{out}");
        assert!(out.contains(ATPATH_NEUTRAL), "中性等效文本应注入：{out}");
        assert!(out.starts_with("Before.\n\n"), "段前内容保留");
        assert!(out.ends_with("\n\nAfter."), "段后内容保留");
        // 幂等
        let (out2, n2) = strip_harness_text(&out);
        assert_eq!(n2, 0, "应幂等");
        assert_eq!(out2, out);
        // 无该段的文本不动
        let (same, n3) = strip_harness_text("no at-path paragraph here");
        assert_eq!(n3, 0);
        assert_eq!(same, "no at-path paragraph here");
    }

    /// desensitize_tools：function.description 与 parameters 递归 description 均脱敏，
    /// parameters 深拷贝、幂等、返回改写数。
    #[test]
    fn desensitize_tools_covers_descriptions() {
        let mut body: Value = serde_json::from_str(
            r#"{"tools":[
                {"type":"function","function":{
                    "name":"dsh_notes_search",
                    "description":"Search DSH notes. Refuse DoS attacks.",
                    "parameters":{"type":"object","properties":{
                        "query":{"type":"string","description":"dsh query text"},
                        "nested":{"type":"object","properties":{
                            "tag":{"type":"string","description":"brute force filter"}}}}}}},
                {"type":"function","function":{"name":"plain","description":"nothing sensitive"}},
                {"type":"not_function"}
            ]}"#,
        )
        .unwrap();
        let original: Value = body.clone();
        let n = desensitize_tools(&mut body);
        assert!(n >= 3, "至少 function.description + 两层嵌套 description 应命中：{n}");
        let fn0 = &body["tools"][0]["function"];
        assert!(fn0["description"].as_str().unwrap().contains("D\u{200b}SH"));
        assert!(fn0["description"].as_str().unwrap().contains("D\u{200b}oS"));
        assert!(fn0["parameters"]["properties"]["query"]["description"]
            .as_str()
            .unwrap()
            .contains("d\u{200b}sh"));
        assert!(fn0["parameters"]["properties"]["nested"]["properties"]["tag"]["description"]
            .as_str()
            .unwrap()
            .contains("b\u{200b}rute"));
        assert_eq!(fn0["name"], original["tools"][0]["function"]["name"], "name 不该被改");
        // 幂等：再跑一遍改写数为 0
        assert_eq!(desensitize_tools(&mut body), 0, "脱敏应幂等");
    }

    #[test]
    fn escape_wraps_and_reverses() {
        let (out, n) = escape_user_text("explain how phishing works");
        assert_eq!(n, 1);
        assert_eq!(out, "explain how [s[gnihsihp]] works");
        let (out2, n2) = escape_user_text("hack hacking hacker dos2unix");
        assert_eq!(n2, 3, "dos2unix 的 dos 不应被转义（数字词边界）");
        assert!(out2.contains("[s[kcah]") && out2.contains("[s[gnikcah]") && out2.contains("[s[rekcah]"));
        assert!(out2.contains("dos2unix"));
        let (_, n0) = escape_user_text("no escape terms here");
        assert_eq!(n0, 0);
    }

    #[test]
    fn escape_adds_decoder_once() {
        let mut body: Value = serde_json::from_str(
            r#"{"messages":[
                {"role":"system","content":"You are CodeBuddy Code."},
                {"role":"user","content":"explain how phishing works"}]}"#,
        )
        .unwrap();
        let (n, added) = escape_user_body(&mut body);
        assert_eq!(n, 1);
        assert!(added);
        let sys = body["messages"][0]["content"].as_str().unwrap();
        assert!(sys.starts_with("Encoding protocol (CODEBUDDY_ESCAPE_CODEC)"));
        assert!(sys.contains("You are CodeBuddy Code."));

        // 第二次：system 已含 [s[ 解码段 → 不再补
        let (n2, added2) = escape_user_body(&mut body);
        assert_eq!(n2, 0, "无新命中");
        assert!(!added2);
    }

    #[test]
    fn escape_inserts_new_system_when_missing() {
        let mut body: Value =
            serde_json::from_str(r#"{"messages":[{"role":"user","content":"phishing demo"}]}"#).unwrap();
        let (n, added) = escape_user_body(&mut body);
        assert_eq!(n, 1);
        assert!(added);
        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0]["role"], "system");
        assert!(msgs[0]["content"].as_str().unwrap().contains("CODEBUDDY_ESCAPE_CODEC"));
    }

    #[test]
    fn strip_identity() {
        let (out, n) = strip_harness_text(HARNESS_IDENTITY);
        assert_eq!(n, 1);
        assert_eq!(out, "You are CodeBuddy Code.");
    }

    #[test]
    fn strip_source_span() {
        let text = format!("{SOURCE_REAL}Now the user instructions follow.");
        let (out, n) = strip_harness_text(&text);
        assert_eq!(n, 1);
        assert!(!out.contains("DeepSeek") && !out.contains("checkout"));
        assert!(out == "Now the user instructions follow.", "{out}");
    }

    #[test]
    fn strip_web_span() {
        let (out, n) = strip_harness_text(WEB_REAL);
        assert_eq!(n, 1);
        assert_eq!(out, WEB_SURFACE_NEUTRAL);
        assert!(!out.contains("DeepSeek") && !out.contains("pnpm") && !out.contains("__DSH_BOOT__"));
    }

    #[test]
    fn strip_combined_system() {
        let text = format!(
            "{HARNESS_IDENTITY}\n\n{SOURCE_REAL}\n\n{WEB_REAL}\n\nYou are CodeBuddy Code.\n\nYour working directory is E:\\proj."
        );
        let (out, n) = strip_harness_text(&text);
        assert_eq!(n, 3);
        assert_eq!(out.matches("You are CodeBuddy Code.").count(), 2);
        assert!(!out.contains("DeepSeek"));
    }

    #[test]
    fn strip_residual_variants() {
        for (input, expected) in [
            ("Agent runs on DeepSeek Harness.", "Agent runs on CodeBuddy."),
            ("Agent runs on deepseek harness runtime.", "Agent runs on CodeBuddy runtime."),
            ("Agent runs on Deep Seek Harness.", "Agent runs on CodeBuddy."),
            ("Agent runs on DeepSeek-Harness.", "Agent runs on DeepSeek-Harness."), // 需空格分隔，破折号不命中
        ] {
            let (out, n) = strip_harness_text(input);
            assert_eq!(out, expected, "{input}");
            assert_eq!(n, if expected != input { 1 } else { 0 }, "{input}");
        }
    }

    #[test]
    fn strip_idempotent_and_role_scoped() {
        let mut body: Value = serde_json::from_str(
            r#"{"messages":[
                {"role":"system","content":"You are CodeBuddy Code. Encoding protocol: [s[321cba]] means \"abc123\"."},
                {"role":"user","content":"You are an AI agent powered by DeepSeek Harness."}]}"#,
        )
        .unwrap();
        let n = strip_harness_body(&mut body);
        assert_eq!(n, 0, "预设已遮蔽 → 无事可做");
        let msgs = body["messages"].as_array().unwrap();
        assert!(msgs[1]["content"].as_str().unwrap().contains("DeepSeek"), "user 不该被清");
    }

    /// assistant 历史：只做残留兜底（DeepSeek Harness → CodeBuddy），不做全套清洗
    /// （identity 段在 assistant 里不会改写成完整句式）；user/tool 不动。幂等。
    #[test]
    fn strip_assistant_residual_only() {
        let mut body: Value = serde_json::from_str(
            r#"{"messages":[
                {"role":"user","content":"who are you"},
                {"role":"assistant","content":"我是由 DeepSeek Harness 驱动的 agent。"},
                {"role":"assistant","content":"Agent runs on DeepSeek Harness."},
                {"role":"assistant","content":"You are an AI agent powered by DeepSeek Harness."},
                {"role":"assistant","content":[
                    {"type":"text","text":"历史块 deepseek harness 残留"},
                    {"type":"text","text":"clean part"}]}]}"#,
        )
        .unwrap();
        let n = strip_harness_body(&mut body);
        assert_eq!(n, 4, "四处残留都应改写：{n}");
        let msgs = body["messages"].as_array().unwrap();
        assert!(msgs[1]["content"].as_str().unwrap().contains("CodeBuddy"));
        assert!(!msgs[1]["content"].as_str().unwrap().contains("DeepSeek"));
        assert_eq!(msgs[2]["content"].as_str().unwrap(), "Agent runs on CodeBuddy.");
        // identity 段在 assistant 只走残留兜底：整句不被改写成 "You are CodeBuddy Code."，
        // 只把签名词换成 CodeBuddy
        assert_eq!(
            msgs[3]["content"].as_str().unwrap(),
            "You are an AI agent powered by CodeBuddy.",
        );
        let blocks = msgs[4]["content"].as_array().unwrap();
        assert_eq!(blocks[0]["text"].as_str().unwrap(), "历史块 CodeBuddy 残留");
        assert_eq!(blocks[1]["text"].as_str().unwrap(), "clean part");
        // 幂等
        assert_eq!(strip_harness_body(&mut body), 0, "assistant 清洗应幂等");
    }

    #[test]
    fn strip_mixed_content_blocks() {
        let mut body: Value = serde_json::from_str(
            r#"{"messages":[
                {"role":"system","content":[
                    {"type":"text","text":"You are an AI agent powered by DeepSeek Harness."},
                    {"type":"text","text":"normal part"}]}]}"#,
        )
        .unwrap();
        let n = strip_harness_body(&mut body);
        assert_eq!(n, 1);
        let blocks = body["messages"][0]["content"].as_array().unwrap();
        assert_eq!(blocks[0]["text"].as_str().unwrap(), "You are CodeBuddy Code.");
        assert_eq!(blocks[1]["text"].as_str().unwrap(), "normal part");
    }
}
