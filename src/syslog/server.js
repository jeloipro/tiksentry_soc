const dgram = require('dgram');
const config = require('../config');
const db = require('../storage/db');
const { parseMikroTikLog } = require('./parser');
const { resolveGeoIp } = require('../geoip/resolver');
const idsEngine = require('../ids/engine');

class SyslogServer {
  constructor() {
    this.socket = null;
    this.fallbackSocket = null;
    this.writeQueue = [];
    this.batchTimer = null;
    this.broadcastCallback = null;
    this.activePort = config.syslogPort;
  }

  setBroadcaster(fn) {
    this.broadcastCallback = fn;
  }

  start() {
    this.startBatchFlusher();
    this.initSocket(config.syslogPort, false);
  }

  initSocket(port, isFallback = false) {
    const socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });

    socket.on('error', (err) => {
      console.warn(`[Syslog UDP] Erro na porta ${port}: ${err.message}`);
      socket.close();

      if (!isFallback && config.syslogFallbackPort && config.syslogFallbackPort !== port) {
        console.log(`[Syslog UDP] Tentando porta alternativa unprivileged: ${config.syslogFallbackPort}...`);
        this.activePort = config.syslogFallbackPort;
        this.initSocket(config.syslogFallbackPort, true);
      }
    });

    socket.on('message', async (msg, rinfo) => {
      try {
        await this.handleIncomingPacket(msg, rinfo);
      } catch (err) {
        console.error('[Syslog UDP] Erro ao processar pacote:', err.message);
      }
    });

    socket.on('listening', () => {
      const address = socket.address();
      this.activePort = address.port;
      console.log(`[Syslog UDP] Servidor de logs ouvindo em UDP ${address.address}:${address.port}`);
    });

    try {
      socket.bind(port, config.syslogHost);
      if (!isFallback) this.socket = socket;
      else this.fallbackSocket = socket;
    } catch (err) {
      console.error(`[Syslog UDP] Falha ao vincular porta ${port}:`, err.message);
    }
  }

  async handleIncomingPacket(msgBuffer, rinfo) {
    const parsed = parseMikroTikLog(msgBuffer);
    if (!parsed) return;

    // Se o src_ip for genérico ou ausente, usa o IP da origem do pacote
    if (!parsed.src_ip || parsed.src_ip === '-') {
      parsed.src_ip = rinfo.address;
    }

    // Enriquece com informações GeoIP
    const geo = resolveGeoIp(parsed.src_ip);
    parsed.country = geo.country;
    parsed.city = geo.city;
    parsed.country_code = geo.country_code;
    parsed.latitude = geo.latitude;
    parsed.longitude = geo.longitude;

    // Processa no IDS para detecção de anomalias/ataques
    const processed = await idsEngine.processLog(parsed);

    // Enfileira para gravação no banco SQLite em lotes
    this.writeQueue.push(processed);

    // Envia em tempo real para os clientes conectados no WebSocket
    if (this.broadcastCallback) {
      this.broadcastCallback({
        type: 'FIREWALL_LOG',
        log: processed
      });
    }

    // Se a fila atingir 50 itens, descarrega imediatamente
    if (this.writeQueue.length >= 50) {
      this.flushQueue();
    }
  }

  startBatchFlusher() {
    this.batchTimer = setInterval(() => {
      this.flushQueue();
    }, 500); // Flush a cada 500ms
  }

  async flushQueue() {
    if (this.writeQueue.length === 0) return;

    const itemsToSave = this.writeQueue.splice(0, 100);
    const operations = itemsToSave.map(log => ({
      sql: `
        INSERT INTO firewall_logs (
          timestamp, chain, action, protocol, src_ip, src_port, dst_ip, dst_port,
          in_interface, out_interface, packet_size, tcp_flags, connection_state,
          src_mac, country, city, country_code, latitude, longitude,
          is_threat, threat_reason, raw_message
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      params: [
        log.timestamp,
        log.chain,
        log.action,
        log.protocol,
        log.src_ip,
        log.src_port,
        log.dst_ip,
        log.dst_port,
        log.in_interface,
        log.out_interface,
        log.packet_size,
        log.tcp_flags,
        log.connection_state,
        log.src_mac,
        log.country,
        log.city,
        log.country_code,
        log.latitude,
        log.longitude,
        log.is_threat ? 1 : 0,
        log.threat_reason,
        log.raw_message
      ]
    }));

    try {
      await db.transaction(operations);
    } catch (err) {
      console.error('[Syslog UDP] Erro ao gravar lote de logs no SQLite:', err.message);
    }
  }

  stop() {
    if (this.batchTimer) clearInterval(this.batchTimer);
    if (this.socket) {
      try { this.socket.close(); } catch {}
    }
    if (this.fallbackSocket) {
      try { this.fallbackSocket.close(); } catch {}
    }
  }
}

const syslogServer = new SyslogServer();
module.exports = syslogServer;
