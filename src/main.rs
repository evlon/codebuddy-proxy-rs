mod aggregate;
mod auth;
mod config;
mod desensitize;
mod handlers;
mod logging;

use std::sync::Arc;

use axum::{Router, routing::{get, post}};
use tokio::net::TcpListener;

use handlers::AppState;

#[tokio::main]
async fn main() {
    let args = config::parse();

    // 一次性动作：导出 / 导入登录态，执行后退出（不再启动服务）。
    if args.save_auth.is_some() && args.restore_auth.is_some() {
        eprintln!("错误：--save-auth 与 --restore-auth 只能同时使用一个。");
        std::process::exit(2);
    }
    if let Some(out) = &args.save_auth {
        auth::save_auth(out);
    }
    if let Some(src) = &args.restore_auth {
        auth::restore_auth(src);
    }

    let auth_file = auth::find_auth_file().expect(
        "未找到 CodeBuddy 登录文件；请先在桌面端登录 CodeBuddy / WorkBuddy。",
    );
    let client = reqwest::Client::new();
    let logger = args.log.as_ref().map(|path| logging::Logger::new(path.into()));
    let state = Arc::new(AppState::new(
        client,
        auth_file,
        args.api_key.clone(),
        logger,
        args.desensitize,
    ));

    if args.skip_check {
        println!("已跳过启动预检（--skip-check）");
    } else if let Some(summary) = state.auth.summary().await {
        println!("登录账号：{summary}");
    } else {
        println!("⚠️ 启动预检未读到登录信息；仍将启动，请求会失败直到登录态可用");
    }

    let app = Router::new()
        .route("/health", get(handlers::health))
        .route("/v1/models", get(handlers::models))
        .route("/v1/chat/completions", post(handlers::chat))
        .with_state(state);

    let addr = format!("{}:{}", args.host, args.port);
    let listener = TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("监听 {addr} 失败：{e}"));
    println!("✅ 监听 http://{addr}  （CodeBuddy → OpenAI 兼容代理）");
    if !args.api_key.is_empty() {
        println!("   鉴权已启用（API key 已设置）");
    }
    if let Some(path) = &args.log {
        println!("   日志      : {path}");
    }
    if args.desensitize {
        println!("   脱敏已启用（system 合规词插入零宽空格）");
    }
    axum::serve(listener, app).await.expect("server 退出异常");
}
