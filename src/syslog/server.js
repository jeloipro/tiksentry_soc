const dgram = require('dgram');
const config = require('../config');
const db = require('../storage/db');
const { parseMikroTikLog } = require('./parser');
const { resolveGeoIp, isPrivateIp } = require('../geoip/resolver');
const idsEngine = require('../ids/engine');

class SyslogServer {
  constructor() {
    this.socket = null;
    this.fallbackSocket = null;
    this.writeQueue = [];
    this.batchTimer = null;
    this.broadcastCallback = null;
    this.activePort = config.syslogPort;
    this.cachedWanInterfaces = ['ether1', 'pppoe-out1', 'wan', 'sfp-sfpplus1', 'internet'];
    this.cachedLanInterfaces = ['bridge', 'lan', 'bridge1', 'ether2', 'ether3', 'ether4', 'ether5'];
    this.lastCacheRefresh = 0;
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

  async refreshInterfacesCache() {
    const now = Date.now();
    if (now - this.lastCacheRefresh < 30000) return;
    this.lastCacheRefresh = now;
    try {
      const wanStr = await db.getSetting('wan_interfaces', 'ether1,pppoe-out1,wan,sfp-sfpplus1,internet');
      const lanStr = await db.getSetting('lan_interfaces', 'bridge,lan,bridge1,ether2,ether3,ether4,ether5');
      this.cachedWanInterfaces = wanStr.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
      this.cachedLanInterfaces = lanStr.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
    } catch {}
  }

  determineZone(parsed) {
    const raw = (parsed.raw_message || '').toUpperCase();
    const inIf = (parsed.in_interface || '').toLowerCase();

    // 1. Prefixo explícito nos logs gerados pelas regras MikroTik
    if (raw.includes('[TIKSENTRY-WAN') || raw.includes('WAN-DROP') || raw.includes('WAN_DROP')) {
      return 'WAN';
    }
    if (raw.includes('[TIKSENTRY-LAN') || raw.includes('LAN-DROP') || raw.includes('LAN_DROP')) {
      return 'LAN';
    }

    // 2. Compara interface de entrada com as interfaces identificadas na rota 0.0.0.0/0
    if (inIf && inIf !== '-' && inIf !== 'unknown') {
      for (const w of this.cachedWanInterfaces) {
        if (inIf === w || inIf.includes(w)) return 'WAN';
      }
      for (const l of this.cachedLanInterfaces) {
        if (inIf === l || inIf.includes(l)) return 'LAN';
      }
    }

    // 3. Verificação por endereço IP (RFC 1918)
    const isPrivate = isPrivateIp(parsed.src_ip);
    if (!isPrivate) {
      // IP público vindo da internet (WAN / rota default)
      return 'WAN';
    } else {
      // IP privado de dispositivo na rede local (LAN)
      return 'LAN';
    }
  }

  async handleIncomingPacket(msgBuffer, rinfo) {
    const parsed = parseMikroTikLog(msgBuffer);
    if (!parsed) return;

    // Se o src_ip for genérico ou ausente, usa o IP da origem do pacote
    if (!parsed.src_ip || parsed.src_ip === '-') {
      parsed.src_ip = rinfo.address;
    }

    // Atualiza cache de interfaces se necessário
    await this.refreshInterfacesCache();

    // Determina a Zona (WAN: Internet 0.0.0.0/0 vs LAN: Rede Interna)
    parsed.zone = this.determineZone(parsed);

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
          is_threat, threat_reason, zone, raw_message
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        log.zone || 'WAN',
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
