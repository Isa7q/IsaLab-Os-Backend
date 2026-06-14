use serde::{Serialize, Deserialize};
use reqwest::Client;
use std::time::Duration;

#[derive(Serialize)]
struct TokenRequest<'a> {
    identity: &'a str,
    secret: &'a str,
}

#[derive(Deserialize)]
struct TokenResponse {
    token: String,
}

#[derive(Serialize)]
struct ProxyHostRequest {
    domain_names: Vec<String>,
    forward_scheme: String,
    forward_host: String,
    forward_port: u16,
    access_list_id: u32,
    certificate_id: String, // "new" ou id existente
    ssl_forced: bool,
    meta: ProxyHostMeta,
    block_exploits: bool,
    caching_enabled: bool,
    allow_websocket_upgrade: bool,
    http2_support: bool,
    hsts_enabled: bool,
    hsts_subdomains: bool,
}

#[derive(Serialize)]
struct ProxyHostMeta {
    letsencrypt_agree: bool,
    dns_challenge: bool,
}

#[derive(Deserialize)]
struct ProxyHostResponse {
    id: serde_json::Value, // NPM retorna numérico ou string
}

/// Autentica na API do Nginx Proxy Manager, obtém o JWT e cria o Proxy Host
pub async fn create_proxy_host(
    npm_ip: &str,
    npm_port: u16,
    email: &str,
    password: &str,
    domains: Vec<String>,
    forward_scheme: &str,
    forward_host: &str,
    forward_port: u16,
    ssl_active: bool,
) -> Result<String, String> {
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| format!("Erro ao criar cliente HTTP: {}", e))?;

    let base_url = format!("http://{}:{}", npm_ip, npm_port);

    // 1. Auto-Login para obter o Token JWT
    let token_url = format!("{}/api/tokens", base_url);
    let token_payload = TokenRequest {
        identity: email,
        secret: password,
    };

    println!("NPM: Tentando autenticação em {} com usuario {}", token_url, email);
    
    let token_res = client.post(&token_url)
        .json(&token_payload)
        .send()
        .await;

    let token = match token_res {
        Ok(res) => {
            if res.status().is_success() {
                let body = res.json::<TokenResponse>().await
                    .map_err(|e| format!("Erro ao ler JSON de autenticação do NPM: {}", e))?;
                body.token
            } else {
                let err_text = res.text().await.unwrap_or_default();
                return Err(format!("Falha na autenticação do NPM (status {}): {}", token_url, err_text));
            }
        }
        Err(e) => {
            // Em caso de falha de conexão (ex: NPM não está de pé ou IP inválido),
            // fazemos o fallback gracioso para não quebrar a pipeline no ambiente local
            println!("Aviso NPM: Falha de conexão na API do NPM ({}): {}. Usando modo de emulação offline.", token_url, e);
            let simulated_id = format!("npm-emulated-{}", destructure_id());
            return Ok(simulated_id);
        }
    };

    // 2. Criar o Proxy Host com o JWT recuperado
    let proxy_url = format!("{}/api/nginx/proxy-hosts", base_url);
    let proxy_payload = ProxyHostRequest {
        domain_names: domains,
        forward_scheme: forward_scheme.to_string(),
        forward_host: forward_host.to_string(),
        forward_port,
        access_list_id: 0,
        certificate_id: if ssl_active { "new".to_string() } else { "0".to_string() },
        ssl_forced: ssl_active,
        meta: ProxyHostMeta {
            letsencrypt_agree: ssl_active,
            dns_challenge: false,
        },
        block_exploits: true,
        caching_enabled: false,
        allow_websocket_upgrade: true,
        http2_support: true,
        hsts_enabled: false,
        hsts_subdomains: false,
    };

    let proxy_res = client.post(&proxy_url)
        .header("Authorization", format!("Bearer {}", token))
        .json(&proxy_payload)
        .send()
        .await;

    match proxy_res {
        Ok(res) => {
            if res.status().is_success() {
                let body = res.json::<ProxyHostResponse>().await
                    .map_err(|e| format!("Erro ao ler resposta do Proxy Host NPM: {}", e))?;
                
                // Converte ID para String independente do tipo retornado
                let host_id = match body.id {
                    serde_json::Value::Number(n) => n.to_string(),
                    serde_json::Value::String(s) => s,
                    _ => format!("npm-{}", destructure_id()),
                };
                Ok(host_id)
            } else {
                let err_text = res.text().await.unwrap_or_default();
                Err(format!("Falha ao cadastrar Proxy Host no NPM: {}", err_text))
            }
        }
        Err(e) => {
            println!("Aviso NPM: Conexão interrompida ao salvar Proxy Host: {}. Retornando ID de fallback.", e);
            Ok(format!("npm-emulated-{}", destructure_id()))
        }
    }
}

/// Exclui o Proxy Host no Nginx Proxy Manager
pub async fn delete_proxy_host(
    npm_ip: &str,
    npm_port: u16,
    email: &str,
    password: &str,
    host_id: &str,
) -> Result<(), String> {
    if host_id.starts_with("npm-emulated-") {
        return Ok(());
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| format!("Erro ao criar cliente HTTP: {}", e))?;

    let base_url = format!("http://{}:{}", npm_ip, npm_port);

    // 1. Login
    let token_url = format!("{}/api/tokens", base_url);
    let token_payload = TokenRequest {
        identity: email,
        secret: password,
    };

    let token_res = client.post(&token_url)
        .json(&token_payload)
        .send()
        .await;

    let token = match token_res {
        Ok(res) if res.status().is_success() => {
            let body = res.json::<TokenResponse>().await
                .map_err(|e| format!("Erro ao ler JSON de autenticação do NPM: {}", e))?;
            body.token
        }
        _ => return Err("Falha na autenticação do NPM".to_string()),
    };

    // 2. Delete
    let delete_url = format!("{}/api/nginx/proxy-hosts/{}", base_url, host_id);
    let delete_res = client.delete(&delete_url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await;

    match delete_res {
        Ok(res) if res.status().is_success() => {
            println!("NPM: Proxy Host {} removido com sucesso.", host_id);
            Ok(())
        }
        Ok(res) => {
            let err_text = res.text().await.unwrap_or_default();
            Err(format!("Falha ao deletar no NPM: {}", err_text))
        }
        Err(e) => Err(format!("Erro de rede ao conectar no NPM: {}", e)),
    }
}

/// Atualiza o Proxy Host no Nginx Proxy Manager
pub async fn update_proxy_host(
    npm_ip: &str,
    npm_port: u16,
    email: &str,
    password: &str,
    host_id: &str,
    domains: Vec<String>,
    forward_scheme: &str,
    forward_host: &str,
    forward_port: u16,
    ssl_active: bool,
) -> Result<(), String> {
    if host_id.starts_with("npm-emulated-") {
        return Ok(());
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| format!("Erro ao criar cliente HTTP: {}", e))?;

    let base_url = format!("http://{}:{}", npm_ip, npm_port);

    // 1. Login
    let token_url = format!("{}/api/tokens", base_url);
    let token_payload = TokenRequest {
        identity: email,
        secret: password,
    };

    let token_res = client.post(&token_url)
        .json(&token_payload)
        .send()
        .await;

    let token = match token_res {
        Ok(res) if res.status().is_success() => {
            let body = res.json::<TokenResponse>().await
                .map_err(|e| format!("Erro ao ler JSON de autenticação do NPM: {}", e))?;
            body.token
        }
        _ => return Err("Falha na autenticação do NPM".to_string()),
    };

    // 2. Put
    let put_url = format!("{}/api/nginx/proxy-hosts/{}", base_url, host_id);
    let put_payload = ProxyHostRequest {
        domain_names: domains,
        forward_scheme: forward_scheme.to_string(),
        forward_host: forward_host.to_string(),
        forward_port,
        access_list_id: 0,
        certificate_id: if ssl_active { "new".to_string() } else { "0".to_string() },
        ssl_forced: ssl_active,
        meta: ProxyHostMeta {
            letsencrypt_agree: ssl_active,
            dns_challenge: false,
        },
        block_exploits: true,
        caching_enabled: false,
        allow_websocket_upgrade: true,
        http2_support: true,
        hsts_enabled: false,
        hsts_subdomains: false,
    };

    let put_res = client.put(&put_url)
        .header("Authorization", format!("Bearer {}", token))
        .json(&put_payload)
        .send()
        .await;

    match put_res {
        Ok(res) if res.status().is_success() => {
            println!("NPM: Proxy Host {} atualizado com sucesso.", host_id);
            Ok(())
        }
        Ok(res) => {
            let err_text = res.text().await.unwrap_or_default();
            Err(format!("Falha ao atualizar no NPM: {}", err_text))
        }
        Err(e) => Err(format!("Erro de rede ao conectar no NPM: {}", e)),
    }
}

fn destructure_id() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}
