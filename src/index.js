const config = require('./config');
const db = require('./storage/db');
const idsEngine = require('./ids/engine');
const addressListManager = require('./mikrotik/addressList');
const autoPruneManager = require('./storage/cleaner');
const syslogServer = require('./syslog/server');
const { createWebServer } = require('./web/server');

async function main() {
  console.log('================================================================');
  console.log('       TIKSENTRY - NEXT-GEN MIKROTIK SYSLOG IDS/IPS SOC         ');
  console.log('   Lightweight Network Threat Intelligence & Attack GeoMap      ');
  console.log('================================================================');

  try {
    // 1. Inicializa o banco de dados SQLite e tabelas
    await db.initDb();

    // 2. Inicializa o gerenciador de Address-List do MikroTik
    addressListManager.start();

    // 3. Inicializa o agendador de limpeza e arquivamento de logs
    autoPruneManager.start();

    // 4. Inicializa o motor de IDS com regras ativas
    await idsEngine.init();

    // 4. Inicializa o Servidor Web Express e WebSockets
    const { server, broadcast } = createWebServer();

    // 5. Conecta o Broadcaster de WebSockets ao Servidor Syslog e IDS Engine
    syslogServer.setBroadcaster(broadcast);
    idsEngine.setBroadcaster(broadcast);

    // 6. Inicia o Servidor Syslog UDP
    syslogServer.start();

    // 7. Inicia o Servidor HTTP
    server.listen(config.port, config.host, () => {
      console.log('----------------------------------------------------------------');
      console.log(`[HTTP] Painel Web SOC rodando em: http://${config.host === '0.0.0.0' ? 'localhost' : config.host}:${config.port}`);
      console.log(`[Syslog] Coletor UDP ativo na porta: ${syslogServer.activePort}`);
      console.log(`[Storage] Armazenamento SQLite WAL: ${config.dbPath}`);
      console.log(`[MikroTik] Roteador Alvo: ${config.mikrotik.host} (${config.mikrotik.protocol.toUpperCase()})`);
      console.log('================================================================');
    });

    // Tratamento de encerramento seguro (Graceful Shutdown)
    const shutdown = async () => {
      console.log('\n[TikSentry] Encerrando serviços com segurança...');
      syslogServer.stop();
      addressListManager.stop();
      server.close(() => {
        console.log('[TikSentry] Servidor HTTP e WebSockets encerrados.');
        db.db.close(() => {
          console.log('[TikSentry] Banco de dados fechado. Até logo!');
          process.exit(0);
        });
      });
    };

    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);

  } catch (err) {
    console.error('[TikSentry] Erro fatal durante a inicialização:', err);
    process.exit(1);
  }
}

main();
