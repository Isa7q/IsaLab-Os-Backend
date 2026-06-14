# 🗺️ Guia de Integração e APIs do Backend - IsaLab Homelab OS

Este guia detalha o comportamento, endpoints, payloads e o fluxo lógico da API do backend em Rust para guiar a integração com o frontend.

---

## 🔌 Especificação dos Endpoints REST

A API responde sob o prefixo `/api` e todas as rotas de mutação/leitura complexa possuem suporte a CORS habilitado nativamente.

### 📌 1. Auditoria e Primeiro Acesso (Onboarding Wizard)

#### `GET /api/status`
Verifica se o sistema já passou pelo setup inicial e recolhe os metadados de governança.
* **Payload da Resposta (JSON):**
  ```json
  {
    "onboarded": false,
    "localIp": "",
    "piholePath": "",
    "hasNpmToken": false
  }
  ```

#### `POST /api/onboard` (ou `/api/setup`)
Submete as configurações de primeiro acesso, grava no banco e define a senha mestre criptografada com Bcrypt.
* **Payload da Requisição (JSON):**
  ```json
  {
    "localIp": "192.168.1.50",
    "piholePath": "/app/big-bear-pihole/etc/pihole.toml",
    "npmToken": "token-opcional-npm",
    "adminPassword": "minha_senha_mestra"
  }
  ```
* **Payload da Resposta (200 OK):**
  ```json
  {
    "success": true,
    "message": "Onboarding realizado com sucesso!"
  }
  ```
* **Payload de Erro (400 Bad Request):**
  ```json
  {
    "error": "IP local, caminho do Pi-hole e senha de administrador são obrigatórios."
  }
  ```

---

### 🔑 2. Autenticação Administrativa

#### `POST /api/auth/login`
Valida a senha digitada no painel contra o hash Bcrypt armazenado na tabela `users`.
* **Payload da Requisição (JSON):**
  ```json
  {
    "password": "senha_digitada"
  }
  ```
* **Payload da Resposta (200 OK):**
  ```json
  {
    "success": true,
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
  ```
* **Payload de Erro (401 Unauthorized):**
  ```json
  {
    "error": "Senha de administrador inválida."
  }
  ```

---

### 📦 3. Diretório de Serviços

#### `GET /api/services`
Retorna a lista completa de ferramentas cadastradas no banco de dados SQLite.
* **Payload da Resposta (JSON):**
  ```json
  [
    {
      "id": "srv-1",
      "name": "Komga Comics",
      "domain": "komga.isa7q.uk",
      "ip": "192.168.1.50",
      "port": 8080,
      "description": "Servidor de quadrinhos, mangás e ebooks",
      "category": "Media",
      "status": "online",
      "pinned": true,
      "iconUrl": "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/komga.png",
      "dockerContainerId": "komga",
      "npmHostId": "npm-1",
      "dnsEntryId": "dns-1"
    }
  ]
  ```

#### `POST /api/services/:id/toggle-pin`
Inverte a propriedade `pinned` (fixado no topo) de um determinado serviço.
* **Payload da Resposta (200 OK):**
  ```json
  {
    "success": true,
    "service": {
      "id": "srv-1",
      "pinned": false,
      "...": "..."
    }
  }
  ```

#### `PUT /api/services/:id`
Atualiza persistente os metadados do serviço no SQLite.
* **Payload da Requisição (JSON):**
  ```json
  {
    "name": "Komga Comics Atualizado",
    "domain": "komga.isa7q.uk",
    "ip": "192.168.1.50",
    "port": 8080,
    "description": "Nova descrição",
    "category": "Media",
    "pinned": true,
    "iconUrl": "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/komga.png"
  }
  ```
* **Payload da Resposta (200 OK):**
  ```json
  {
    "success": true,
    "service": {
      "id": "srv-1",
      "name": "Komga Comics Atualizado",
      "...": "..."
    }
  }
  ```

---

### 🐳 4. Gerenciamento de Contêineres Docker

#### `GET /api/containers`
Lista todos os contêineres gerenciados e suas estatísticas.
* **Payload da Resposta (JSON):**
  ```json
  [
    {
      "id": "komga",
      "name": "komga",
      "image": "gotson/komga:latest",
      "status": "running",
      "created": "2026-05-10T14:22:11Z",
      "ports": ["8080:8080"],
      "cpu": 1.2,
      "memory": "214MB",
      "labels": {
        "homelab.description": "Servidor de quadrinhos, mangás e ebooks",
        "homelab.category": "Media",
        "homelab.domain": "komga.isa7q.uk"
      }
    }
  ]
  ```

#### `POST /api/containers/:id/toggle`
Liga/desliga um container de forma virtualizada no SQLite. Atualiza o status do container (`running` <-> `stopped`) e sincroniza o status do serviço associado (`online` <-> `offline`).
* **Payload da Resposta (200 OK):**
  ```json
  {
    "success": true,
    "container": {
      "id": "komga",
      "status": "stopped",
      "cpu": 0.0,
      "memory": "0MB",
      "...": "..."
    }
  }
  ```

---

### 🌐 5. Gerenciador de Proxy Hosts (Nginx Proxy Manager)

#### `GET /api/npm-hosts`
Retorna as rotas de proxy cadastrados.
* **Payload da Resposta (JSON):** Array de objetos `NpmProxyHost`.

#### `POST /api/npm-hosts`
Cadastra manualmente uma rota proxy.
* **Payload da Requisição (JSON):**
  ```json
  {
    "domainNames": ["komga.isa7q.uk"],
    "forwardScheme": "http",
    "forwardHost": "192.168.1.50",
    "forwardPort": 8080,
    "sslActive": true
  }
  ```

#### `POST /api/npm-hosts/:id/toggle-ssl`
Inverte a flag `sslActive` e atualiza o `sslProvider` para "Let's Encrypt".

---

### 🗺️ 6. Gerenciador de DNS (Pi-hole)

#### `GET /api/dns-entries`
Lista todos os mapeamentos locais de IP -> Domínio.

#### `POST /api/dns-entries`
Cria um novo registro local de DNS e dispara a gravação física no arquivo `pihole.toml`.
* **Payload da Requisição (JSON):**
  ```json
  {
    "ip": "192.168.1.50",
    "domain": "komga.isa7q.uk",
    "source": "hosts"
  }
  ```

#### `DELETE /api/dns-entries/:id`
Exclui um mapeamento DNS local do SQLite.

---

### ⚡ 7. Nova Implantação (Pipeline Jobs)

O frontend interage com o Wizard de implantação de novos serviços disparando uma pipeline assíncrona robusta.

#### `GET /api/pipelines`
Lista todos os históricos e status de execução de pipelines.

#### `POST /api/pipelines/run`
Cria um pipeline e dispara de forma assíncrona (`tokio::spawn`) o fluxo completo em background.
* **Payload da Requisição (JSON):**
  ```json
  {
    "serviceName": "Jellyfin Library",
    "subdomain": "jellyfin.isa7q.uk",
    "ip": "192.168.1.50",
    "port": 8096,
    "description": "Servidor de streaming de filmes",
    "category": "Media",
    "registerNPM": true,
    "registerPihole": true,
    "createDocker": true
  }
  ```
* **Payload da Resposta (200 OK):**
  ```json
  {
    "success": true,
    "pipelineId": "pipe-1718361000000"
  }
  ```

#### 🛡️ Fluxo em Background da Pipeline:
1. **Estágio 1 (Metadados):** Criação das estruturas iniciais.
2. **Estágio 2 (DNS Pi-hole):** Lê o `pihole.toml`, insere a linha `"IP DOMÍNIO"` evitando duplicatas, escreve e simula o reinício do DNSmasq.
3. **Estágio 3 (NPM):** Autentica na API do NPM, obtém o JWT e cria o Proxy Host via HTTP, realizando desafio SSL Let's Encrypt.
4. **Estágio 4 (Docker):** Cria o container no SQLite com as labels de governança.
5. **Estágio 5 (CasaOS):** Conecta na API do CasaOS para obter a imagem de ícone oficial do aplicativo. Se offline, usa fallback automático.
6. **Finalização:** Registra o serviço final como `online` e atualiza a pipeline para `completed`.
