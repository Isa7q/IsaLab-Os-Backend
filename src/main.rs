use axum::{
    routing::{get, post, put, delete},
    Router,
};
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool, Row};
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
        let path_str = db_url.trim_start_matches("sqlite://");
        // Se for caminhos como "sqlite://homelab.db" ou "sqlite:///app/homelab.db"
        let clean_path = path_str.trim_start_matches('/');
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
        .route("/services", get(handlers::get_services))
        .route("/services/:id/toggle-pin", post(handlers::post_toggle_pin))
        .route("/services/:id", put(handlers::put_edit_service))
        .route("/containers", get(handlers::get_containers))
        .route("/containers/:id/toggle", post(handlers::post_toggle_container))
        .route("/npm-hosts", get(handlers::get_npm_hosts).post(handlers::post_npm_hosts))
        .route("/npm-hosts/:id/toggle-ssl", post(handlers::post_toggle_npm_ssl))
        .route("/dns-entries", get(handlers::get_dns_entries).post(handlers::post_dns_entries))
        .route("/dns-entries/:id", delete(handlers::delete_dns_entry))
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
    // Criar tabelas extras
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS containers (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            image TEXT NOT NULL,
            status TEXT NOT NULL,
            created TEXT NOT NULL,
            ports TEXT NOT NULL,
            cpu REAL NOT NULL,
            memory TEXT NOT NULL,
            labels TEXT NOT NULL
        );"
    ).execute(pool).await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS npm_hosts (
            id TEXT PRIMARY KEY,
            domain_names TEXT NOT NULL,
            forward_scheme TEXT NOT NULL,
            forward_host TEXT NOT NULL,
            forward_port INTEGER NOT NULL,
            ssl_active INTEGER NOT NULL,
            ssl_provider TEXT NOT NULL,
            status TEXT NOT NULL
        );"
    ).execute(pool).await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS dns_entries (
            id TEXT PRIMARY KEY,
            ip TEXT NOT NULL,
            domain TEXT NOT NULL UNIQUE,
            active INTEGER NOT NULL,
            source TEXT NOT NULL
        );"
    ).execute(pool).await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS pipelines (
            id TEXT PRIMARY KEY,
            service_name TEXT NOT NULL,
            subdomain TEXT NOT NULL,
            ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            description TEXT,
            category TEXT NOT NULL,
            register_npm INTEGER NOT NULL,
            register_pihole INTEGER NOT NULL,
            create_docker INTEGER NOT NULL,
            status TEXT NOT NULL,
            current_step TEXT NOT NULL,
            logs TEXT NOT NULL
        );"
    ).execute(pool).await?;

    // Adicionar colunas extras na tabela services se não existirem
    let queries = vec![
        "ALTER TABLE services ADD COLUMN name TEXT;",
        "ALTER TABLE services ADD COLUMN pinned INTEGER DEFAULT 0;",
        "ALTER TABLE services ADD COLUMN status TEXT DEFAULT 'online';",
        "ALTER TABLE services ADD COLUMN docker_container_id TEXT;",
        "ALTER TABLE services ADD COLUMN npm_host_id TEXT;",
        "ALTER TABLE services ADD COLUMN dns_entry_id TEXT;",
    ];

    for q in queries {
        let _ = sqlx::query(q).execute(pool).await; // Ignora erros se a coluna já existir
    }

    Ok(())
}

async fn seed_database_if_empty(pool: &SqlitePool) -> Result<(), Box<dyn std::error::Error>> {
    // Checar se a tabela services está vazia
    let count: i32 = sqlx::query("SELECT COUNT(*) FROM services")
        .fetch_one(pool)
        .await?
        .get(0);

    if count > 0 {
        return Ok(());
    }

    println!("[IsaLab] Banco de dados vazio. Rodando Seeding dos dados padrão...");

    // Seeding Containers
    let containers = vec![
        ("komga", "komga", "gotson/komga:latest", "running", "2026-05-10T14:22:11Z", r#"["8080:8080"]"#, 1.2, "214MB", r#"{"homelab.description":"Servidor de quadrinhos, mangás e ebooks","homelab.category":"Media","homelab.domain":"komga.isa7q.uk"}"#),
        ("gitea", "gitea", "gitea/gitea:latest", "running", "2026-06-01T09:30:00Z", r#"["3000:3000","222:22"]"#, 0.8, "155MB", r#"{"homelab.description":"Servidor do Git para repositórios locais","homelab.category":"DevOps","homelab.domain":"git.isa7q.uk"}"#),
        ("pihole", "pihole", "pihole/pihole:latest", "running", "2026-04-12T10:15:22Z", r#"["80:80","53:53/udp"]"#, 1.8, "95MB", r#"{"homelab.description":"DNS local e bloqueador de anúncios e rastros","homelab.category":"Network","homelab.domain":"dns.isa7q.uk"}"#),
        ("jellyfin", "jellyfin", "jellyfin/jellyfin:latest", "stopped", "2026-06-02T18:00:15Z", r#"["8096:8096"]"#, 0.0, "0MB", r#"{"homelab.description":"Servidor de streaming de filmes e músicas","homelab.category":"Media","homelab.domain":"jellyfin.isa7q.uk"}"#),
        ("nginx-proxy-manager", "nginx-proxy-manager", "jc21/nginx-proxy-manager:latest", "running", "2026-04-12T10:20:01Z", r#"["81:81","443:443","80:80"]"#, 0.5, "78MB", r#"{"homelab.description":"Proxy reverso central com geração de certificados SSL Let's Encrypt","homelab.category":"Network","homelab.domain":"npm.isa7q.uk"}"#),
        ("casaos-gateway", "casaos-gateway", "icewhalebenson/casaos-gateway:latest", "running", "2026-04-12T10:10:00Z", r#"["88:80"]"#, 0.4, "42MB", r#"{"homelab.description":"Portal CasaOS e gerenciador simplificado de aplicativos","homelab.category":"Utilities","homelab.domain":"casa.isa7q.uk"}"#),
    ];

    for c in containers {
        sqlx::query("INSERT INTO containers (id, name, image, status, created, ports, cpu, memory, labels) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(c.0).bind(c.1).bind(c.2).bind(c.3).bind(c.4).bind(c.5).bind(c.6).bind(c.7).bind(c.8)
            .execute(pool).await?;
    }

    // Seeding NPM Hosts
    let npm_hosts = vec![
        ("npm-1", r#"["komga.isa7q.uk"]"#, "http", "192.168.1.50", 8080, 1, "Let's Encrypt", "active"),
        ("npm-2", r#"["git.isa7q.uk"]"#, "http", "192.168.1.100", 3000, 1, "Let's Encrypt", "active"),
        ("npm-3", r#"["casa.isa7q.uk"]"#, "http", "192.168.1.50", 88, 1, "Let's Encrypt", "active"),
        ("npm-4", r#"["dns.isa7q.uk"]"#, "http", "192.168.1.50", 80, 1, "Let's Encrypt", "active"),
    ];

    for n in npm_hosts {
        sqlx::query("INSERT INTO npm_hosts (id, domain_names, forward_scheme, forward_host, forward_port, ssl_active, ssl_provider, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(n.0).bind(n.1).bind(n.2).bind(n.3).bind(n.4).bind(n.5).bind(n.6).bind(n.7)
            .execute(pool).await?;
    }

    // Seeding DNS Entries
    let dns_entries = vec![
        ("dns-1", "192.168.1.50", "komga.isa7q.uk", 1, "hosts"),
        ("dns-2", "192.168.1.100", "git.isa7q.uk", 1, "hosts"),
        ("dns-3", "192.168.1.50", "casa.isa7q.uk", 1, "dnsmasq"),
        ("dns-4", "192.168.1.50", "dns.isa7q.uk", 1, "hosts"),
        ("dns-5", "192.168.1.50", "npm.isa7q.uk", 1, "dnsmasq"),
    ];

    for d in dns_entries {
        sqlx::query("INSERT INTO dns_entries (id, ip, domain, active, source) VALUES (?, ?, ?, ?, ?)")
            .bind(d.0).bind(d.1).bind(d.2).bind(d.3).bind(d.4)
            .execute(pool).await?;
    }

    // Seeding Services (precisa casar com os IDs do schema INTEGER do SQLite, id será gerado serializado)
    let services = vec![
        ("komga.isa7q.uk", "192.168.1.50", 8080, "Servidor de quadrinhos, mangás e ebooks", "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/komga.png", "Media", "Komga Comics", 1, "online", "komga", "npm-1", "dns-1"),
        ("git.isa7q.uk", "192.168.1.100", 3000, "Servidor do Git para repositórios locais", "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/gitea.png", "DevOps", "Gitea Server", 1, "online", "gitea", "npm-2", "dns-2"),
        ("jellyfin.isa7q.uk", "192.168.1.50", 8096, "Servidor de streaming de filmes e músicas", "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/jellyfin.png", "Media", "Jellyfin Library", 0, "offline", "jellyfin", "", ""),
        ("npm.isa7q.uk", "192.168.1.50", 81, "Gerenciador de proxies e certificados SSL", "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/nginx-proxy-manager.png", "Network", "Nginx Proxy Manager", 1, "online", "nginx-proxy-manager", "", "dns-5"),
        ("dns.isa7q.uk", "192.168.1.50", 80, "Bloqueador de anúncios e DNS recursivo local", "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/pi-hole.png", "Network", "Pi-hole DNS", 0, "online", "pihole", "npm-4", "dns-4"),
        ("casa.isa7q.uk", "192.168.1.50", 88, "Portal CasaOS e gerenciador simplificado de aplicativos", "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/casaos.png", "Utilities", "CasaOS Portal", 1, "online", "casaos-gateway", "npm-3", "dns-3"),
    ];

    for s in services {
        sqlx::query("INSERT INTO services (subdomain, target_ip, target_port, description, icon_url, category, name, pinned, status, docker_container_id, npm_host_id, dns_entry_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(s.0).bind(s.1).bind(s.2).bind(s.3).bind(s.4).bind(s.5).bind(s.6).bind(s.7).bind(s.8).bind(s.9).bind(s.10).bind(s.11)
            .execute(pool).await?;
    }

    println!("[IsaLab] Seeding concluído com sucesso!");

    Ok(())
}
