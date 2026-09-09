/// 可选日志与流式“旁路录制”：在 --log 开启时把每次请求的关键报文落到文件，
/// 便于排查“内容审核拦截 / 异常响应”（对应 codebuddy2openai 的 --log）。

use std::{
    fs::OpenOptions,
    io::Write,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{SystemTime, UNIX_EPOCH},
};

use futures::Stream;
use std::fmt::Write as _;

#[derive(Clone)]
pub struct Logger {
    path: PathBuf,
}

impl Logger {
    pub fn new(path: PathBuf) -> Self {
        Logger { path }
    }

    /// 追加一行文本（带 UTC 时间戳）；写失败静默忽略。
    pub fn line(&self, text: &str) {
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&self.path) {
            let _ = writeln!(file, "[{}] {}", stamp(), text);
        }
    }

    /// 追加一段多行报文（正文不加时间戳前缀）。
    pub fn block(&self, title: &str, body: &str) {
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&self.path) {
            let _ = writeln!(file, "[{}] ── {} ──\n{}", stamp(), title, body);
        }
    }
}

fn stamp() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let h = secs / 3600 % 24;
    let m = secs / 60 % 60;
    let s = secs % 60;
    let mut out = String::new();
    let _ = write!(out, "{h:02}:{m:02}:{s:02} (utc)");
    out
}

/// 流式旁路：一边把字节继续转发给客户端，一边把完整 SSE 原文收进日志缓冲，
/// 流结束（poll 返回 None）时统一落盘。
pub struct Tee<S> {
    inner: Pin<Box<S>>,
    buffer: Arc<Mutex<Vec<u8>>>,
    logger: Option<Logger>,
    ended: bool,
}

impl<S> Tee<S>
where
    S: Stream + Send + 'static,
{
    pub fn new(stream: S, logger: Option<Logger>) -> Self {
        Tee { inner: Box::pin(stream), buffer: Arc::new(Mutex::new(Vec::new())), logger, ended: false }
    }
}

impl<S> Stream for Tee<S>
where
    S: Stream<Item = Result<bytes::Bytes, std::io::Error>> + Send + 'static,
{
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let ready = self.inner.as_mut().poll_next(cx);
        match &ready {
            Poll::Ready(Some(Ok(bytes))) => {
                if let Ok(mut buffer) = self.buffer.lock() {
                    buffer.extend_from_slice(bytes);
                }
            }
            Poll::Ready(None) => {
                if !self.ended {
                    self.ended = true;
                    if let Some(logger) = &self.logger {
                        if let Ok(buffer) = self.buffer.lock() {
                            let text = String::from_utf8_lossy(&buffer);
                            logger.block("RESPONSE RAW SSE", &text);
                        }
                    }
                }
            }
            _ => {}
        }
        ready
    }
}
