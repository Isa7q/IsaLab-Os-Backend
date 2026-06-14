use serde::{Serialize, Deserialize};
use std::path::Path;
use tokio::fs;
use tokio::process::Command;

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct PiholeConfig {
    pub dns: Option<DnsSection>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct DnsSection {
    pub hosts: Option<Vec<String>>,
}

/// Lê e adiciona um host no pihole.toml
pub async fn add_dns_host(path_str: &str, ip: &str, domain: &str) -> Result<(), String> {
    let path = Path::new(path_str);
    
    // 1. Ler o arquivo ou inicializar se não existir
    let mut config = if path.exists() {
        let content = fs::read_to_string(path)
            .await
            .map_err(|e| format!("Falha ao ler o arquivo pihole.toml: {}", e))?;
        toml::from_str::<PiholeConfig>(&content)
            .map_err(|e| format!("Falha ao parsear pihole.toml: {}", e))?
    } else {
        // Se a pasta pai não existir, criar
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| format!("Falha ao criar diretório do pihole.toml: {}", e))?;
        }
        PiholeConfig::default()
    };

    // Garantir que a seção dns existe
    if config.dns.is_none() {
        config.dns = Some(DnsSection::default());
    }
    
    let dns_sec = config.dns.as_mut().unwrap();
    if dns_sec.hosts.is_none() {
        dns_sec.hosts = Some(Vec::new());
    }

    let hosts = dns_sec.hosts.as_mut().unwrap();
    let entry = format!("{} {}", ip, domain);

    // Prevenir duplicatas de domínio
    hosts.retain(|h| {
        let parts: Vec<&str> = h.split_whitespace().collect();
        if parts.len() >= 2 {
            parts[1] != domain
        } else {
            true
        }
    });

    hosts.push(entry);

    // 2. Serializar e salvar de volta
    let updated_content = toml::to_string_pretty(&config)
        .map_err(|e| format!("Falha ao serializar pihole.toml: {}", e))?;

    fs::write(path, updated_content)
        .await
        .map_err(|e| format!("Falha ao escrever no pihole.toml: {}", e))?;

    // 3. Executar o comando pihole restartdns de forma assíncrona
    let output = Command::new("pihole")
        .arg("restartdns")
        .output()
        .await;

    match output {
        Ok(out) => {
            if out.status.success() {
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                Err(format!("pihole restartdns retornou erro: {}", stderr))
            }
        }
        Err(e) => {
            // Em ambientes locais onde pihole não está instalado globalmente,
            // logamos um aviso no console e prosseguimos com sucesso (graceful degrad).
            println!("Aviso: Comando 'pihole' não encontrado no sistema: {}. Mapeamento DNS salvo no arquivo.", e);
            Ok(())
        }
    }
}

/// Lê e remove um host do pihole.toml
pub async fn remove_dns_host(path_str: &str, domain: &str) -> Result<(), String> {
    let path = Path::new(path_str);
    if !path.exists() {
        return Ok(());
    }

    let content = fs::read_to_string(path)
        .await
        .map_err(|e| format!("Falha ao ler o arquivo pihole.toml: {}", e))?;
    
    let mut config = toml::from_str::<PiholeConfig>(&content)
        .map_err(|e| format!("Falha ao parsear pihole.toml: {}", e))?;

    if let Some(dns_sec) = config.dns.as_mut() {
        if let Some(hosts) = dns_sec.hosts.as_mut() {
            hosts.retain(|h| {
                let parts: Vec<&str> = h.split_whitespace().collect();
                if parts.len() >= 2 {
                    parts[1] != domain
                } else {
                    true
                }
            });
        }
    }

    let updated_content = toml::to_string_pretty(&config)
        .map_err(|e| format!("Falha ao serializar pihole.toml: {}", e))?;

    fs::write(path, updated_content)
        .await
        .map_err(|e| format!("Falha ao escrever no pihole.toml: {}", e))?;

    let output = Command::new("pihole")
        .arg("restartdns")
        .output()
        .await;

    match output {
        Ok(out) => {
            if out.status.success() {
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                Err(format!("pihole restartdns retornou erro: {}", stderr))
            }
        }
        Err(e) => {
            println!("Aviso: Comando 'pihole' não encontrado no sistema ao remover host: {}.", e);
            Ok(())
        }
    }
}

