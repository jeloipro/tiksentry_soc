# ===================================================================
# TIKSENTRY SOC - DOCKERFILE MULTI-STAGE ULTRA-LEVE
# Resolve 100% o erro de GLIBC_2.38 compilando o SQLite no ambiente
# exato do Debian e entregando uma imagem final limpa e leve (~140MB)
# ===================================================================

# -------------------------------------------------------------------
# 1. Estágio de Compilação (Builder)
# -------------------------------------------------------------------
FROM node:20-slim AS builder

WORKDIR /app

# Instala ferramentas necessárias para compilar módulos nativos C/C++
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

COPY package*.json ./

# Força a compilação local do sqlite3 contra a glibc do container
RUN npm install --omit=dev --build-from-source=sqlite3 --no-audit --no-fund

# -------------------------------------------------------------------
# 2. Estágio Final de Execução (Produção)
# -------------------------------------------------------------------
FROM node:20-slim

WORKDIR /app

# Copia os node_modules já compilados perfeitamente para este sistema
COPY --from=builder /app/node_modules ./node_modules
COPY package*.json ./
COPY src/ ./src/
COPY public/ ./public/
COPY scripts/ ./scripts/
COPY .env.example ./.env.example

# Garante a existência do diretório de dados persistentes
RUN mkdir -p /app/data

# Portas expostas:
# 3000/tcp: Painel Web SOC e API REST
# 514/udp: Coletor Syslog UDP padrão
# 1514/udp: Coletor Syslog UDP alternativo
EXPOSE 3000/tcp
EXPOSE 514/udp
EXPOSE 1514/udp

# Configurações de ambiente de produção
ENV NODE_ENV=production \
    PORT=3000 \
    SYSLOG_PORT=514 \
    DB_PATH=/app/data/tiksentry.db

# Inicializa o TikSentry
CMD ["node", "src/index.js"]
