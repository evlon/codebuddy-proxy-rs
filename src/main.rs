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
    let logger = args
        .log
        .as_ref()
        .map(|path| logging::Logger::new(path.into(), args.log_keep));
    let state = Arc::new(AppState::new(
        client,
        auth_file,
        args.api_key.clone(),
        logger,
        args.desensitize,
        args.user_escape,
        args.strip_harness,
        args.private_data,
        args.models_ttl,
        args.desensitize_scope_all,
        args.official_shape,
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
        println!("   日志      : {path}（轮转保留最近 {} 次请求；--log-keep 可调，0=不轮转）", args.log_keep);
    }
    if args.desensitize {
        if args.desensitize_scope_all {
            println!("   脱敏      : 已启用（scope=all：全角色 + tools 描述，渠道风险降分）");
        } else {
            println!("   脱敏      : 已启用（system 合规词插入零宽空格；--desensitize-scope all 可扩展）");
        }
    }
    if args.user_escape {
        println!("   用户转义  : 已启用（[s[...]] 反转编码 + 解码说明）");
    }
    if !args.strip_harness {
        println!("   签名清洗  : 已关闭（--strip-harness off）");
    }
    if !args.official_shape {
        println!("   官方形状  : 已关闭（--official-shape off）");
    }
    println!("   身份面    : 官方 {}（UA/身份头/trace 族/官方 body 形状 + 令牌保鲜 + 11128 自愈）", auth::official_version());
    println!("   隐私标志  : X-Private-Data={}（--private-data 可调）", args.private_data);
    println!("   模型缓存  : {} 秒（--models-ttl 可调）", args.models_ttl);
    axum::serve(listener, app).await.expect("server 退出异常");
}
