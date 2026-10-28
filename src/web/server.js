const express = require('express');
const http = require('http');
const path = require('path');
const cors = require('cors');
const { WebSocketServer, WebSocket } = require('ws');
const config = require('../config');

const logsRouter = require('./routes/logs');
const idsRouter = require('./routes/ids');
const geoipRouter = require('./routes/geoip');
const mikrotikRouter = require('./routes/mikrotik');
const reportsRouter = require('./routes/reports');
const backupsRouter = require('./routes/backups');

function createWebServer() {
  const app = express();
  const server = http.createServer(app);

  // Middlewares essenciais
  app.use(cors());
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Arquivos estáticos da interface web
  const publicDir = path.resolve(__dirname, '../../public');
  app.use(express.static(publicDir));

  // Rotas da API REST
  app.use('/api/logs', logsRouter);
  app.use('/api/ids', idsRouter);
  app.use('/api/geoip', geoipRouter);
  app.use('/api/mikrotik', mikrotikRouter);
  app.use('/api/reports', reportsRouter);
  app.use('/api/backups', backupsRouter);

  // Fallback para SPA (Single Page Application)
  app.use((req, res, next) => {
    if (req.path.startsWith('/api')) return next();
    res.sendFile(path.join(publicDir, 'index.html'));
  });

  // WebSocket Server para transmissão de logs e alertas em tempo real
  const wss = new WebSocketServer({ server, path: '/ws' });

  const broadcast = (data) => {
    const payload = typeof data === 'string' ? data : JSON.stringify(data);
    wss.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        try {
          client.send(payload);
        } catch (err) {
          // Erro silencioso se socket fechar durante o envio
        }
      }
    });
  };

  wss.on('connection', (ws) => {
    // Envia mensagem de boas-vindas e confirmação de conexão
    ws.send(JSON.stringify({
      type: 'CONNECTED',
      message: 'Conectado ao TikSentry SOC WebSocket em tempo real.',
      timestamp: new Date().toISOString()
    }));

    ws.on('message', (msg) => {
      try {
        const parsed = JSON.parse(msg);
        if (parsed.type === 'PING') {
          ws.send(JSON.stringify({ type: 'PONG', time: Date.now() }));
        }
      } catch {}
    });
  });

  return {
    app,
    server,
    wss,
    broadcast
  };
}

module.exports = {
  createWebServer
};
