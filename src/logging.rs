/// 可选日志与流式“旁路录制”：在 --log 开启时把每次请求的关键报文落到文件，
/// 便于排查“内容审核拦截 / 异常响应”（对应 codebuddy2openai 的 --log）。

use std::{
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{SystemTime, UNIX_EPOCH},
};

use futures::Stream;
use std::fmt::Write as _;

/// 请求现场标记（logger.line 写入的 "▶ REQUEST ..." 行内子串），
/// 轮转按它定位请求块边界（跨 chunk 扫描时带 overlap 防切分）。
const REQ_MARKER: &[u8] = "▶ REQUEST".as_bytes();
/// 小于该尺寸不值得重写文件。
const ROTATE_MIN_SIZE: u64 = 256 * 1024;

#[derive(Clone)]
pub struct Logger {
    path: PathBuf,
    /// 日志轮转：只保留最近 N 次请求的完整现场；0 = 不轮转。
    log_keep: usize,
    /// 轮转互斥（并发请求同时触发轮转时避免双写 tmp）。
    rotate_lock: Arc<Mutex<()>>,
}

impl Logger {
    pub fn new(path: PathBuf, log_keep: usize) -> Self {
        Logger { path, log_keep, rotate_lock: Arc::new(Mutex::new(())) }
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

    /// 日志轮转：只保留最近 N 次请求的现场（log_keep；0 = 不轮转）。
    ///
    /// 在记录新请求前调用。从文件尾部反向扫描第 N 个 `▶ REQUEST` 标记，
    /// 把它之前的所有内容裁掉——文件里始终只有最近 N 次请求（含进行中的这次），
    /// 避免日志无限膨胀。采用尾部分块扫描 + 临时文件替换，不整读大文件。
    pub fn rotate(&self) {
        let keep = self.log_keep;
        if keep == 0 {
            return;
        }
        let _guard = self.rotate_lock.lock().unwrap_or_else(|e| e.into_inner());
        let Ok(meta) = std::fs::metadata(&self.path) else { return };
        let size = meta.len();
        if size < ROTATE_MIN_SIZE {
            return;
        }
        let Ok(mut file) = std::fs::File::open(&self.path) else { return };
        // 从尾部倒着分块找 marker，凑够 keep 个即停（绝对偏移，升序）。
        let overlap = REQ_MARKER.len() - 1;
        let chunk = 4 * 1024 * 1024;
        let mut found: Vec<usize> = Vec::new();
        let mut pos = size as usize;
        while pos > 0 && found.len() < keep {
            let step = chunk.min(pos);
            let start = pos - step;
            if file.seek(SeekFrom::Start(start as u64)).is_err() {
                return;
            }
            let mut data = vec![0u8; step + if start > 0 { overlap } else { 0 }];
            let Ok(n) = file.read(&mut data) else { return };
            data.truncate(n);
            let mut hits: Vec<usize> = data
                .windows(REQ_MARKER.len())
                .enumerate()
                .filter(|(_, w)| *w == REQ_MARKER)
                .map(|(i, _)| i + start)
                .collect();
            hits.append(&mut found);
            found = hits;
            pos = start;
        }
        found.sort_unstable();
        found.dedup(); // 重叠区可能重复命中同一 marker
        if found.len() < keep {
            return; // 还不够 keep 个请求块，无需裁剪
        }
        // 保留最近 keep-1 个完整块 + 即将写入的当前块（合计 keep）：
        // 裁到倒数第 keep-1 个 marker 处；keep=1 时清空（文件只剩当前请求）。
        let mut cut = if keep > 1 { found[found.len() - (keep - 1)] } else { size as usize };
        // 回退到 marker 所在行的行首（保住 "[ts] " 前缀，行首便于回查）
        let back = cut.saturating_sub(64);
        let mut prefix = vec![0u8; cut - back];
        if file.seek(SeekFrom::Start(back as u64)).is_err() {
            return;
        }
        if file.read_exact(&mut prefix).is_err() {
            return;
        }
        if let Some(nl) = prefix.iter().rposition(|&b| b == b'\n') {
            cut = back + nl + 1;
        }
        if file.seek(SeekFrom::Start(cut as u64)).is_err() {
            return;
        }
        let tmp = PathBuf::from(format!("{}.tmp", self.path.display()));
        let Ok(mut out) = std::fs::File::create(&tmp) else { return };
        let mut buf = [0u8; 1024 * 1024];
        loop {
            match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if out.write_all(&buf[..n]).is_err() {
                        let _ = std::fs::remove_file(&tmp);
                        return;
                    }
                }
                Err(_) => {
                    let _ = std::fs::remove_file(&tmp);
                    return;
                }
            }
        }
        // 原子替换（Windows 上 std::fs::rename 即 MoveFileEx+REPLACE_EXISTING）
        if std::fs::rename(&tmp, &self.path).is_err() {
            let _ = std::fs::remove_file(&tmp);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn write_request_scene(path: &std::path::Path, idx: usize, body: &str) {
        let mut f = OpenOptions::new().create(true).append(true).open(path).unwrap();
        let _ = writeln!(f, "[2026-10-28 1{:02}:00:00] ▶ REQUEST model-x | stream=false | last_user='{idx}'", idx);
        let _ = writeln!(f, "[2026-10-28 1{:02}:00:00] ── REQUEST BODY ──\n{body}", idx);
        let _ = writeln!(f, "[2026-10-28 1{:02}:00:01] ◀ RESPONSE model-x | 0.5s", idx);
    }

    fn count_markers(path: &std::path::Path) -> usize {
        std::fs::read(path).unwrap().windows(REQ_MARKER.len()).filter(|w| *w == REQ_MARKER).count()
    }

    #[test]
    fn rotate_keeps_last_n_scenes() {
        let dir = std::env::temp_dir().join(format!("rs_log_rotate_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test.log");
        let _ = std::fs::remove_file(&path);
        let logger = Logger::new(path.clone(), 3);
        for i in 0..6 {
            if i >= 3 {
                logger.rotate(); // 记录新请求前轮转
            }
            // 场景要足够大：每块 ~100KB，6 块 600KB 超过 ROTATE_MIN_SIZE
            let body = "x".repeat(100 * 1024);
            write_request_scene(&path, i, &body);
        }
        assert_eq!(count_markers(&path), 3, "应只保留最近 3 个请求现场");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("last_user='5'"), "最新请求应保留");
        assert!(content.contains("last_user='4'"), "次新请求应保留");
        assert!(content.contains("last_user='3'"), "第三新请求应保留");
        assert!(!content.contains("last_user='2'"), "更早请求应被裁掉");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn rotate_disabled_or_small_file() {
        let dir = std::env::temp_dir().join(format!("rs_log_rotate0_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        // log_keep = 0：不轮转
        let path = dir.join("a.log");
        let _ = std::fs::remove_file(&path);
        let logger = Logger::new(path.clone(), 0);
        for i in 0..8 {
            write_request_scene(&path, i, &"x".repeat(100 * 1024));
        }
        logger.rotate();
        assert_eq!(count_markers(&path), 8, "log_keep=0 应保留全部");
        // 文件小于 256KB：不轮转
        let path2 = dir.join("b.log");
        let _ = std::fs::remove_file(&path2);
        let logger2 = Logger::new(path2.clone(), 1);
        for i in 0..5 {
            write_request_scene(&path2, i, "small body");
        }
        logger2.rotate();
        assert_eq!(count_markers(&path2), 5, "小文件不应轮转");
        // 块数少于 keep：不轮转
        let path3 = dir.join("c.log");
        let _ = std::fs::remove_file(&path3);
        let logger3 = Logger::new(path3.clone(), 10);
        for i in 0..5 {
            write_request_scene(&path3, i, &"y".repeat(100 * 1024));
        }
        logger3.rotate();
        assert_eq!(count_markers(&path3), 5, "块数不足 keep 不应轮转");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&path2);
        let _ = std::fs::remove_file(&path3);
        let _ = std::fs::remove_dir(&dir);
    }
}
