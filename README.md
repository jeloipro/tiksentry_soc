# 🛡️ TikSentry SOC — Sistema de Monitoramento Syslog & IDS/IPS para MikroTik

> **TikSentry** (sugestões de nomes adicionais: *MikroSentry SOC*, *TikDefend*, *NetTik Guard*, *AegisTik*).  
> Sistema de inteligência de ameaças, monitoramento de logs de firewall (Syslog) em tempo real, IDS/IPS automatizado e mapa de calor geográfico de ataques desenvolvido em **Node.js** para ser extremamente leve, rápido e estável no Docker.

---

## 🚀 Por que este sistema substitui o anterior em Python?

| Característica | Sistema Anterior (Python) | Novo TikSentry (Node.js) |
|---|---|---|
| **Arquitetura Docker** | 6 containers (Postgres, Redis, Celery, App, Front, Nginx) | **1 único container autocontido** |
| **Erros de Build** | Falhas com wheels, psycopg2, alembic, gcc | **Zero dependências C++ nativas pesadas** |
| **Consumo de Memória** | ~1.5 GB a 2 GB RAM | **~80 MB a 120 MB RAM** |
| **Tempo para Subir** | 3 a 5 minutos (com migrations) | **Menos de 3 segundos** |
| **Banco de Dados** | Postgres externo exigindo migrations manuais | **SQLite embutido com modo WAL** de altíssima performance |
| **GeoIP** | Dependente de chamadas externas de API com rate limit | **GeoIP local em memória offline** com resolução imediata (<0.1ms) |

---

## 🎯 Principais Funcionalidades

1. **Coletor Syslog UDP em Tempo Real**:
   - Escuta na porta UDP 514 (e porta alternativa 1514).
   - Ingestão assíncrona sem travamento de threads com `dgram` nativo.
   - Parser inteligente para MikroTik RouterOS v6 e v7 (identifica `chain`, `action`, `protocol`, `src_ip`, `dst_port`, `tcp_flags`, tentativas de invasão Winbox, SSH, etc.).

2. **Motor IDS / IPS com Auto-Block**:
   - **Varredura de Portas (Port Scan TCP SYN / UDP)**: detecta quando um IP sonda múltiplas portas na rede.
   - **Força Bruta Winbox (Porta 8291)**: identifica ataques à porta de gerenciamento MikroTik.
   - **Força Bruta SSH (Porta 22) e Telnet (Porta 23)**.
   - **Sondas Web (Portas 80, 443, 8080)**.
   - **Varredura da API RouterOS (Portas 8728 e 8729)**.
   - **Ataques de Negação de Serviço (DoS Flood)**.
   - **Auto-Block Integrado**: adiciona o atacante imediatamente à `Address-List` do roteador (`TIKSENTRY_BLOCKED`) com expiração configurável (ex: 60m, 120m ou permanente).

3. **Mapa de Ataques GeoIP Interativo**:
   - Distribuição geográfica mundial com mapa escuro de cibersegurança (Leaflet + CartoDB Dark Matter).
   - Marcadores de intensidade com raio proporcional ao volume do ataque.
   - Linhas de vetor e pulsos animados conectando o atacante ao seu roteador MikroTik.
   - Filtros dinâmicos: **País**, **Cidade**, **Endereço IP**, **Porta**, **Protocolo** e **Período de Tempo**.
   - Ação rápida no popup: **"Bloquear no MikroTik"** com 1 clique.

4. **Aba de Configuração do MikroTik via API**:
   - Suporte duplo: **REST API** (RouterOS v7) e **Socket API** (porta 8728 para RouterOS v6 e v7).
   - Botão **"Testar Conexão"** em tempo real: exibe modelo da RouterBOARD, versão do RouterOS, uptime, uso de CPU e memória livre.
   - Gerador de script MikroTik com 1 clique para copiar e colar no terminal do Winbox.

5. **Threat Network (Inteligência de Rede)**:
   - Agrupamento de atacantes por sub-redes `/24 CIDR`.
   - Mapeamento das portas e serviços mais visados.

6. **Relatórios Completos e Formatados**:
   - Resumo Executivo (Total de eventos, ameaças bloqueadas, taxa de mitigação).
   - Top 10 países e cidades atacantes.
   - Top 15 portas alvo e serviços identificados.
   - Top 20 IPs maliciosos com data, motivos e status de bloqueio.
   - Botão **"Imprimir / Salvar PDF"** com estilização profissional para impressão (`@media print`).
   - Exportação para **CSV de Logs**, **CSV de Atacantes** e **JSON**.

---

## ⚡ Como Rodar o Sistema

### Opção 1: Com Docker (Recomendado)

Na pasta `WORKAPP`, basta executar:

```bash
docker compose up -d --build
```

O container irá compilar em menos de 30 segundos e estará disponível em:
- **Painel Web**: `http://localhost:3000`
- **Coletor Syslog**: `udp://localhost:514`

Para verificar os logs do container:
```bash
docker compose logs -f
```

---

### Opção 2: Localmente com Node.js

Certifique-se de ter o Node.js v18+ instalado.

1. Instale as dependências:
   ```bash
   cd WORKAPP
   npm install
   ```

2. Inicie o sistema:
   ```bash
   npm start
   ```

3. Acesse no navegador:
   ```
   http://localhost:3000
   ```

---

## 🧪 Testando com o Simulador de Tráfego

Para testar o mapa, os alertas de IDS e os relatórios sem precisar de um MikroTik físico no momento, execute:

```bash
# Enviar um lote de 30 ataques simulados:
npm run simulate

# Ou enviar pacotes contínuos em tempo real:
node scripts/test-syslog-generator.js --stream
```

Você verá instantaneamente os pontos surgindo no mapa e os alertas no painel!

---

## 🔧 Configuração no MikroTik RouterOS

Abra o **Winbox** > **New Terminal** e cole o seguinte script (ajustando o IP do servidor onde o TikSentry está rodando):

```routeros
# 1. Configurar servidor Syslog remoto apontando para o TikSentry
/system logging action
add name=tiksentry-remote target=remote remote=IP_DO_SEU_SERVIDOR remote-port=514 bsd-syslog=yes syslog-facility=daemon

# 2. Enviar logs de Firewall e Tentativas de Login para o TikSentry
/system logging
add topics=firewall action=tiksentry-remote
add topics=system,error,critical action=tiksentry-remote

# 3. Regra de Firewall para Bloqueio Automático da Address-List
/ip firewall filter
add chain=input src-address-list=TIKSENTRY_BLOCKED action=drop comment="[TikSentry] Bloqueio Automatico de Atacantes" place-before=0
add chain=forward src-address-list=TIKSENTRY_BLOCKED action=drop comment="[TikSentry] Bloqueio Forward de Atacantes" place-before=1

# 4. Regra para logar pacotes descartados (para o TikSentry analisar)
add chain=input action=drop log=yes log-prefix="[TIKSENTRY-DROP]" comment="[TikSentry] Log de Descarte Input"
```

---

## 📁 Estrutura de Arquivos

```
WORKAPP/
├── Dockerfile                  # Dockerfile ultra-leve baseado em node:20-slim
├── docker-compose.yml          # Definição simples de 1 container
├── package.json                # Apenas 7 dependências essenciais
├── .env.example                # Exemplo de variáveis de ambiente
├── .env                        # Variáveis ativas
├── data/                       # Armazenamento SQLite persistente (WAL mode)
├── scripts/
│   └── test-syslog-generator.js # Simulador de tráfego de ataques MikroTik
├── src/
│   ├── config.js               # Carregador de configurações
│   ├── index.js                # Ponto de entrada do sistema
│   ├── storage/
│   │   └── db.js               # Camada SQLite com tabelas, índices e WAL
│   ├── syslog/
│   │   ├── parser.js           # Parser regex avançado de logs do RouterOS
│   │   └── server.js           # Servidor UDP não-bloqueante
│   ├── geoip/
│   │   └── resolver.js         # Resolução offline GeoIP rápida com cache
│   ├── ids/
│   │   └── engine.js           # Motor de detecção e regras de IDS/IPS
│   ├── mikrotik/
│   │   ├── client.js           # Cliente API RouterOS (REST v7 e Socket v6/v7)
│   │   └── addressList.js      # Gerenciador de Address-List com auto-expiração
│   ├── reports/
│   │   └── generator.js        # Gerador de relatórios e exportadores CSV/JSON
│   └── web/
│       ├── server.js           # Express Web Server e WebSockets
│       └── routes/             # Rotas da API REST
└── public/
    ├── index.html              # Interface do SOC com abas e modal
    ├── css/
    │   ├── styles.css          # Tema escuro SOC Cyberpunk
    │   └── print.css           # Estilo limpo para impressão e PDF
    └── js/
        ├── app.js              # Controlador principal da aplicação
        ├── map.js              # Mapa interativo Leaflet
        ├── charts.js           # Gráficos Chart.js
        ├── ids.js              # Regras IDS e lista de bloqueados
        ├── mikrotik.js         # Aba de conexão MikroTik
        └── reports.js          # Relatórios e exportação
```
# tiksentry_soc
