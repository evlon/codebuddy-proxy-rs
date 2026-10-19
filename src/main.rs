mod aggregate;
mod auth;
mod config;
mod desensitize;
mod handlers;
mod logging;
mod models;

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
        args.models_ttl,
    ));

    if args.skip_check {
        println!("已跳过启动预检（--skip-check）");
    } else if let Some(summary) = state.auth.summary().await {
        println!("登录账号：{summary}");
        // 预热动态模型目录（失败不阻塞启动；/v1/models 会重试并兜底）
        let (available, metas) = state.catalog.get(&state.auth, true).await;
        let n = if available.iter().any(|s| s == "auto") { available.len() } else { available.len() + 1 };
        if metas.is_empty() {
            println!("⚠️ 模型列表：/v3/config 不可达，将使用内置兜底列表（{n} 个）");
        } else {
            let preview: Vec<&str> = available.iter().take(6).map(String::as_str).collect();
            println!("模型列表：动态获取成功，{n} 个（{}…）", preview.join(", "));
        }
    } else {
        println!("⚠️ 启动预检未读到登录信息；仍将启动，请求会失败直到登录态可用");
    }

    let app = Router::new()
        .route("/health", get(handlers::health))
        .route("/v1/models", get(handlers::models))
        .route("/v1/models/{model_id}", get(handlers::model_detail))
        .route("/v1/chat/completions", post(handlers::chat))
        .with_state(state);

    let addr = format!("{}:{}", args.host, args.port);
    let listener = TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("监听 {addr} 失败：{e}"));
    println!("✅ 监听 http://{addr}  （CodeBuddy → OpenAI 兼容代理）");
    println!("   GET  /v1/models              （动态获取，带缓存；?refresh=1 强制刷新）");
    println!("   GET  /v1/models/{{model}}    （单个模型详情，附上下文窗口元数据）");
    println!("   POST /v1/chat/completions     （流式 / 非流式）");
    if !args.api_key.is_empty() {
        println!("   鉴权已启用（API key 已设置）");
    }
    if let Some(path) = &args.log {
        println!("   日志      : {path}");
    }
    if args.desensitize {
        println!("   脱敏已启用（system 合规词插入零宽空格）");
    }
    println!("   模型缓存  : {} 秒（--models-ttl 可调）", args.models_ttl);
    axum::serve(listener, app).await.expect("server 退出异常");
}
