use serde::Deserialize;
use reqwest::Client;
use std::time::Duration;

#[derive(Deserialize, Debug)]
pub struct CasaOsResponse {
    pub data: CasaOsData,
}

#[derive(Deserialize, Debug)]
pub struct CasaOsData {
    pub installed: Vec<CasaOsApp>,
}

#[derive(Deserialize, Debug, Clone)]
#[allow(dead_code)]
pub struct CasaOsApp {
    pub id: String,
    pub icon: String, // Contém a URL direta do ícone (ex: jsdelivr / selfhst icons)
    pub status: String,
}

/// Consulta a API local do CasaOS para recuperar a URL direta do ícone de um aplicativo.
/// Caso falhe ou não encontre, fornece uma URL de fallback do repositório 'walkxcode/dashboard-icons'.
pub async fn get_icon_url(casaos_url: &str, app_id: &str) -> String {
    let client = match Client::builder().timeout(Duration::from_secs(3)).build() {
        Ok(c) => c,
        Err(_) => return get_fallback_icon(app_id),
    };

    // Formata a URL (ex: http://192.168.1.50:88/v2/app-management/apps)
    let url = format!("{}/v2/app-management/apps", casaos_url.trim_end_matches('/'));

    println!("CasaOS: Consultando API de aplicativos em {}", url);

    let res = client.get(&url).send().await;

    match res {
        Ok(resp) => {
            if resp.status().is_success() {
                if let Ok(body) = resp.json::<CasaOsResponse>().await {
                    // Procura o aplicativo pelo ID
                    if let Some(app) = body.data.installed.into_iter().find(|a| a.id == app_id) {
                        if !app.icon.is_empty() {
                            println!("CasaOS: Ícone oficial encontrado para '{}': {}", app_id, app.icon);
                            return app.icon;
                        }
                    }
                }
            }
            println!("CasaOS: Aplicativo '{}' não encontrado ou não tem ícone. Usando fallback.", app_id);
            get_fallback_icon(app_id)
        }
        Err(e) => {
            println!("Aviso CasaOS: Falha ao conectar na API ({}): {}. Usando fallback.", url, e);
            get_fallback_icon(app_id)
        }
    }
}

/// Gera uma URL de fallback baseada na convenção do painel do walkxcode no GitHub
fn get_fallback_icon(app_id: &str) -> String {
    let clean_id = app_id.to_lowercase().replace('_', "-");
    format!("https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/{}.png", clean_id)
}
