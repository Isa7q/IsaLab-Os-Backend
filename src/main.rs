use axum::{
    routing::{get, post, put},
    Router,
};
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;

mod handlers;
mod casaos;
mod npm;
mod pihole;

use handlers::AppState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Carregar variáveis de ambiente
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://homelab.db".to_string());
    let jwt_secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "isa-secret-token-key-123".to_string());
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "3001".to_string())
        .parse::<u16>()
        .unwrap_or(3001);

    println!("[IsaLab] Iniciando Homelab Governance API...");
    println!("[IsaLab] Banco de dados: {}", db_url);
    println!("[IsaLab] Porta da API: {}", port);

    // Garantir criação do arquivo SQLite local se for o default
    if db_url.starts_with("sqlite://") {
        let clean_path = if db_url.starts_with("sqlite:///") {
            db_url.trim_start_matches("sqlite://") // Mantém a barra inicial: "/app/data/homelab.db"
        } else {
            db_url.trim_start_matches("sqlite://") // Caso seja relativo, ex: "homelab.db"
        };
        if !clean_path.is_empty() && !std::path::Path::new(clean_path).exists() {
            println!("[IsaLab] Criando arquivo de banco de dados SQLite vazio: {}", clean_path);
            if let Some(parent) = std::path::Path::new(clean_path).parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            std::fs::File::create(clean_path)?;
        }
    }

    // 2. Pooling do banco de dados SQLite
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .map_err(|e| format!("Falha ao conectar no SQLite: {}", e))?;

    // 3. Executar as migrações (se a pasta migrations existir)
    println!("[IsaLab] Rodando migrações sqlx...");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .map_err(|e| format!("Falha ao executar migrações: {}", e))?;

    // 4. Estruturar tabelas adicionais e estender a tabela services
    setup_extra_db_structures(&pool).await?;

    // 5. Rodar Seeding Inicial (se o banco estiver recém-criado/vazio)
    seed_database_if_empty(&pool).await?;

    // 6. Configurar Estado Compartilhado
    let state = Arc::new(AppState {
        db: pool,
        jwt_secret,
    });

    // 7. Habilitar CORS
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // 8. Construir as Rotas do Axum
    let api_routes = Router::new()
        .route("/status", get(handlers::get_status))
        .route("/onboard", post(handlers::post_onboard))
        .route("/setup", post(handlers::post_onboard)) // Compatibilidade dupla
        .route("/auth/login", post(handlers::post_login))
        .route("/system-stats", get(handlers::get_system_stats))
        .route("/services", get(handlers::get_services).post(handlers::post_add_service))
        .route("/services/add", post(handlers::post_add_service))
        .route("/services/:id/toggle-pin", post(handlers::post_toggle_pin))
        .route("/services/:id", put(handlers::put_edit_service))
        .route("/containers", get(handlers::get_containers))
        .route("/containers/:id/toggle", post(handlers::post_toggle_container))
        .route("/npm-hosts", get(handlers::get_npm_hosts).post(handlers::post_npm_hosts))
        .route("/npm-hosts/:id", put(handlers::put_npm_host).delete(handlers::delete_npm_host))
        .route("/npm-hosts/:id/toggle-ssl", post(handlers::post_toggle_npm_ssl))
        .route("/dns-entries", get(handlers::get_dns_entries).post(handlers::post_dns_entries))
        .route("/dns-entries/:id", put(handlers::put_dns_entry).delete(handlers::delete_dns_entry))
        .route("/config", get(handlers::get_config).put(handlers::put_config))
        .route("/config/servers", post(handlers::post_server))
        .route("/config/servers/:id", put(handlers::put_server).delete(handlers::delete_server))
        .route("/config/servers/:id/activate", post(handlers::post_activate_server))
        .route("/pipelines", get(handlers::get_pipelines))
        .route("/pipelines/run", post(handlers::post_run_pipeline))
        .with_state(state);

    // Servir arquivos estáticos do frontend em modo de produção
    // Tenta ler o diretório dist se existir, caso contrário foca apenas na API
    let app = Router::new().nest("/api", api_routes).layer(cors);

    let frontend_dist_path = std::path::Path::new("../frontend/dist");
    let app = if frontend_dist_path.exists() {
        println!("[IsaLab] Frontend compilado encontrado em '../frontend/dist'. Servindo arquivos estáticos.");
        app.fallback_service(ServeDir::new(frontend_dist_path))
    } else {
        println!("[IsaLab] Frontend compilado não encontrado. Servindo apenas a API REST.");
        app
    };

    // 9. Inicializar o servidor
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("[IsaLab] Servidor nativo em Rust rodando em http://0.0.0.0:{}", port);
    
    axum::serve(listener, app).await?;

    Ok(())
}

async fn setup_extra_db_structures(pool: &SqlitePool) -> Result<(), Box<dyn std::error::Error>> {
    // Adicionar colunas extras na tabela services se não existirem
    let queries = vec![
        "ALTER TABLE services ADD COLUMN name TEXT;",
        "ALTER TABLE services ADD COLUMN pinned INTEGER DEFAULT 0;",
        "ALTER TABLE services ADD COLUMN status TEXT DEFAULT 'online';",
        "ALTER TABLE services ADD COLUMN docker_container_id TEXT;",
        "ALTER TABLE services ADD COLUMN npm_host_id TEXT;",
        "ALTER TABLE services ADD COLUMN dns_entry_id TEXT;",
        "ALTER TABLE servers ADD COLUMN admin_password_hash TEXT;",
    ];

    for q in queries {
        let _ = sqlx::query(q).execute(pool).await; // Ignora erros se a coluna já existir
    }

    Ok(())
}

async fn seed_database_if_empty(pool: &SqlitePool) -> Result<(), Box<dyn std::error::Error>> {
    use sqlx::Row;
    
    // Verificar se a tabela servers está vazia
    let servers_count: i32 = sqlx::query("SELECT COUNT(*) FROM servers")
        .fetch_one(pool)
        .await?
        .get(0);

    if servers_count == 0 {
        // Tentar obter a configuração ativa de system_config
        let local_ip_res = sqlx::query("SELECT value FROM system_config WHERE key = 'local_ip'")
            .fetch_optional(pool)
            .await;
        
        if let Ok(Some(row)) = local_ip_res {
            let local_ip = row.get::<String, _>(0);
            if !local_ip.is_empty() {
                let pihole_path = sqlx::query("SELECT value FROM system_config WHERE key = 'pihole_path'")
                    .fetch_optional(pool)
                    .await
                    .ok()
                    .flatten()
                    .map(|r| r.get::<String, _>(0))
                    .unwrap_or_default();
                let npm_email = sqlx::query("SELECT value FROM system_config WHERE key = 'npm_email'")
                    .fetch_optional(pool)
                    .await
                    .ok()
                    .flatten()
                    .map(|r| r.get::<String, _>(0))
                    .unwrap_or_else(|| "admin@example.com".to_string());
                let npm_password = sqlx::query("SELECT value FROM system_config WHERE key = 'npm_password'")
                    .fetch_optional(pool)
                    .await
                    .ok()
                    .flatten()
                    .map(|r| r.get::<String, _>(0))
                    .unwrap_or_default();
                
                println!("[IsaLab] Migrando configuracoes ativas para o perfil de servidor padrao...");
                let _ = sqlx::query("INSERT INTO servers (id, name, local_ip, pihole_path, npm_email, npm_password, active) VALUES ('default', 'Servidor Principal', ?, ?, ?, ?, 1)")
                    .bind(local_ip)
                    .bind(pihole_path)
                    .bind(npm_email)
                    .bind(npm_password)
                    .execute(pool)
                    .await;
            }
        }
    }
    Ok(())
}
