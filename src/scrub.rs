//! 响应侧 U+200B 零宽空格清洗（模型回声防护）。
//!
//! 背景：请求侧 `--desensitize` 打码会把敏感词变成 `d\u{200b}sh` 这种带零宽
//! 空格的拼写发给模型；模型会照抄这种"长得像原词"的拼写进自己的输出——实测
//! （2026-10-29）回声出现在正文、todos、shell 命令（`npm i d\u{200b}sh-pkg`）、
//! 甚至标识符（`d\u{200b}shHome`）里，零宽字符随之落进 UI/终端/文件。
//!
//! 对策：发给客户端的一切（流式 SSE / 非流式聚合）先递归清洗掉 U+200B。
//! 流式转发改成逐行解析 → 清洗 → 重序列化；一个 data 行内的 JSON 是完整值，
//! 因此 ZWSP 不会跨行漏洗。注意 serde_json 无 preserve_order，重序列化后
//! 对象键序会字母化——OpenAI 客户端按键名取值，不受影响。
//!
//! 对齐 python 侧 converter.py 的 `_scrub_zwsp` / `_SSEScrubber`（同日实现）。

use bytes::{Buf, Bytes, BytesMut};
use futures::Stream;
use serde_json::Value;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

/// 零宽空格 U+200B。
pub const ZWSP: char = '\u{200b}';

/// 去掉字符串里的零宽空格。
pub fn scrub_zwsp(s: &str) -> String {
    s.replace(ZWSP, "")
}

/// 递归清洗 serde_json 值内所有字符串里的 U+200B（就地修改）。
pub fn scrub_strings_deep(value: &mut Value) {
    match value {
        Value::String(s) => {
            if s.contains(ZWSP) {
                *s = s.replace(ZWSP, "");
            }
        }
        Value::Array(items) => {
            for v in items {
                scrub_strings_deep(v);
            }
        }
        Value::Object(map) => {
            for (_k, v) in map.iter_mut() {
                scrub_strings_deep(v);
            }
        }
        _ => {}
    }
}

/// 单行处理：data: 行解出 JSON → 清洗 → 重序列化；[DONE] 与非数据行原样透传；
/// 结构异常的 data 行原样透传（保证流连续性）。
fn process_line(line: &[u8]) -> Vec<u8> {
    if line.starts_with(b"data:") {
        let payload = trim_ascii(&line[5..]);
        if payload == b"[DONE]" {
            return b"data: [DONE]\n".to_vec();
        }
        match serde_json::from_slice::<Value>(payload) {
            Ok(mut obj) => {
                scrub_strings_deep(&mut obj);
                let mut out = Vec::with_capacity(payload.len() + 8);
                out.extend_from_slice(b"data: ");
                out.extend_from_slice(serde_json::to_string(&obj).unwrap_or_default().as_bytes());
                out.push(b'\n');
                out
            }
            Err(_) => {
                let mut out = line.to_vec();
                out.push(b'\n');
                out
            }
        }
    } else {
        let mut out = line.to_vec();
        out.push(b'\n');
        out
    }
}

fn trim_ascii(buf: &[u8]) -> &[u8] {
    let is_ws = |b: u8| matches!(b, b' ' | b'\t' | b'\r' | b'\x0c');
    let start = buf.iter().position(|b| !is_ws(*b)).unwrap_or(buf.len());
    let end = buf.iter().rposition(|b| !is_ws(*b)).map(|i| i + 1).unwrap_or(start);
    &buf[start..end]
}

/// 流式增量清洗器：把上游 SSE 字节流按行缓冲 → 清洗 → 重排给客户端。
///
/// 用法：`upstream.bytes_stream().map(...).` 之后接 `SseScrubStream::new(...)`
/// 再接 `logging::Tee`（日志记录到的即为清洗后的输出，与客户端一致）。
pub struct SseScrubStream<S> {
    inner: S,
    buf: BytesMut,
    finished: bool,
}

impl<S> SseScrubStream<S> {
    pub fn new(inner: S) -> Self {
        Self { inner, buf: BytesMut::new(), finished: false }
    }
}

impl<S> Stream for SseScrubStream<S>
where
    S: Stream<Item = Result<Bytes, io::Error>> + Unpin,
{
    type Item = Result<Bytes, io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.finished {
            return Poll::Ready(None);
        }
        loop {
            match Pin::new(&mut this.inner).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(bytes))) => {
                    this.buf.extend_from_slice(&bytes);
                    let drained = drain_lines(&mut this.buf);
                    if !drained.is_empty() {
                        return Poll::Ready(Some(Ok(Bytes::from(drained))));
                    }
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(None) => {
                    // 流末尾冲洗缓冲里没有换行结尾的残余行（空缓冲则直接结束）
                    this.finished = true;
                    let rest = std::mem::take(&mut this.buf);
                    if rest.is_empty() {
                        return Poll::Ready(None);
                    }
                    let out = process_line(&rest);
                    if out.is_empty() {
                        return Poll::Ready(None);
                    }
                    return Poll::Ready(Some(Ok(Bytes::from(out))));
                }
            }
        }
    }
}

/// 把缓冲中所有完整行清洗后取出，未完成行留在 buf。
fn drain_lines(buf: &mut BytesMut) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(pos) = buf.iter().position(|b| *b == b'\n') {
        let line: Vec<u8> = buf[..pos].to_vec();
        buf.advance(pos + 1);
        out.extend_from_slice(&process_line(&line));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::task::Poll;

    fn feed_all(input: &[u8]) -> Vec<u8> {
        // 模拟上游：按 1 字节半逐段喂，覆盖跨 chunk 的边界
        let mut s = SseScrubStream::new(Dup::new(input));
        let mut out = Vec::new();
        futures::executor::block_on(async {
            use futures::StreamExt;
            while let Some(item) = s.next().await {
                if let Ok(bytes) = item {
                    out.extend_from_slice(&bytes);
                }
            }
        });
        out
    }

    /// 单元辅助：把静态字节当作流，每次吐 2 字节。
    struct Dup {
        data: Vec<u8>,
        pos: usize,
    }
    impl Dup {
        fn new(data: &[u8]) -> Self {
            Self { data: data.to_vec(), pos: 0 }
        }
    }
    impl Stream for Dup {
        type Item = Result<Bytes, io::Error>;
        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let this = self.get_mut();
            if this.pos >= this.data.len() {
                return Poll::Ready(None);
            }
            let end = (this.pos + 2).min(this.data.len());
            let chunk = Bytes::copy_from_slice(&this.data[this.pos..end]);
            this.pos = end;
            Poll::Ready(Some(Ok(chunk)))
        }
    }

    #[test]
    fn scrub_basics() {
        assert_eq!(scrub_zwsp("d\u{200b}sh"), "dsh");
        assert_eq!(scrub_zwsp("普通文本"), "普通文本");
        let mut v = json!({"a": "x\u{200b}y", "b": ["m\u{200b}n", {"c": "k\u{200b}l"}], "n": 1});
        scrub_strings_deep(&mut v);
        assert_eq!(v, json!({"a": "xy", "b": ["mn", {"c": "kl"}], "n": 1}));
    }

    #[test]
    fn stream_end_to_end() {
        // 完整 SSE：content 增量、tool_calls 增量、finish、[DONE]
        let chunk = |v: Value| {
            format!("data: {}\n\n", serde_json::to_string(&v).unwrap()).into_bytes()
        };
        let mut raw = Vec::new();
        raw.extend(chunk(json!({"id":"c1","choices":[{"index":0,"delta":{"content":"\u{524d}\u{6587} d\u{200b}sh"}}]})));
        raw.extend(chunk(json!({"id":"c1","choices":[{"index":0,"delta":{"tool_calls":[
            {"index":0,"function":{"name":"run_cmd","arguments":"{\"command\":\"npm i d"}}]}}]})));
        raw.extend(chunk(json!({"id":"c1","choices":[{"index":0,"delta":{"tool_calls":[
            {"index":0,"function":{"arguments":"\u{200b}sh-pkg\"}"}}]}}]})));
        raw.extend(chunk(json!({"id":"c1","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}],"usage":{"total_tokens":99}})));
        raw.extend(b"data: [DONE]\n\n".to_vec());

        let out = feed_all(&raw);
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains('\u{200b}'), "流里不允许残留 U+200B");
        assert!(text.contains("data: [DONE]\n"));
        // 重新解析验证 content 与拼接后的 arguments
        let mut content = String::new();
        let mut args = String::new();
        for line in text.lines() {
            if let Some(payload) = line.strip_prefix("data: ") {
                if payload == "[DONE]" { continue; }
                let v: Value = serde_json::from_str(payload).unwrap();
                for ch in v["choices"].as_array().unwrap() {
                    if let Some(c) = ch["delta"]["content"].as_str() { content.push_str(c); }
                    if let Some(calls) = ch["delta"]["tool_calls"].as_array() {
                        for t in calls {
                            if let Some(a) = t["function"]["arguments"].as_str() { args.push_str(a); }
                        }
                    }
                }
            }
        }
        assert_eq!(content, "\u{524d}\u{6587} dsh");
        assert_eq!(args, "{\"command\":\"npm i dsh-pkg\"}");
    }

    #[test]
    fn non_data_and_malformed_lines_pass_through() {
        let raw = b"event: ping\ndata: {bad json\n\ndata: {\"choices\":[{\"delta\":{\"content\":\"a\xe2\x80\x8bb\"}}]}\n\ndata: [DONE]\n\n";
        let out = feed_all(raw);
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("event: ping\n"));
        assert!(text.contains("data: {bad json\n"));
        assert!(!text.contains('\u{200b}'));
        assert!(text.ends_with("data: [DONE]\n\n"));
    }

    #[test]
    fn flush_without_trailing_newline() {
        let raw = b"data: {\"choices\":[{\"delta\":{\"content\":\"tail\xe2\x80\x8bZ\"}}]}";
        let out = feed_all(raw);
        let text = String::from_utf8(out).unwrap();
        let v: Value = serde_json::from_str(text.trim_start_matches("data: ")).unwrap();
        assert_eq!(v["choices"][0]["delta"]["content"], "tailZ");
    }
}
