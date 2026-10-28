const db = require('../storage/db');
const addressListManager = require('../mikrotik/addressList');

class IdsEngine {
  constructor() {
    this.rules = [];
    this.rulesLastLoaded = 0;
    // Map de rastreamento de IP: ip -> { hits: [{ time, port, proto, action }], ports: Set, lastSeen }
    this.ipTrackers = new Map();
    // Cache de bloqueados recentes em memória para evitar re-bloqueio repetido a cada segundo
    this.recentlyBlocked = new Map();
    this.cleanerInterval = null;
    this.broadcastCallback = null;
  }

  setBroadcaster(fn) {
    this.broadcastCallback = fn;
  }

  async init() {
    await this.reloadRules();
    if (!this.cleanerInterval) {
      // Limpeza de rastreadores antigos a cada 60s
      this.cleanerInterval = setInterval(() => this.pruneTrackers(), 60000);
    }
    console.log(`[IDS] Engine inicializado com ${this.rules.length} regras ativas.`);
  }

  async reloadRules() {
    try {
      this.rules = await db.all('SELECT * FROM ids_rules WHERE enabled = 1');
      this.rulesLastLoaded = Date.now();
    } catch (err) {
      console.error('[IDS] Erro ao carregar regras:', err.message);
    }
  }

  /**
   * Processa cada log em tempo real
   */
  async processLog(log) {
    // Apenas analisa conexões com IP de origem válido e não-vazio
    if (!log || !log.src_ip) return log;

    // Se o monitoramento da rede interna (LAN) estiver desativado, ignora avaliacao no IDS
    const zone = log.zone || 'WAN';
    if (zone === 'LAN') {
      const monitorLan = await db.getSetting('monitor_lan_threats', 'false');
      if (monitorLan !== 'true') {
        log.is_threat = 0;
        log.threat_reason = null;
        return log;
      }
    }

    // Se a regra de recarga tiver mais de 30 segundos, recarrega assincronamente
    if (Date.now() - this.rulesLastLoaded > 30000) {
      this.reloadRules().catch(() => {});
    }

    const now = Date.now();
    const srcIp = log.src_ip;

    // Obtém ou inicializa rastreador para este IP
    let tracker = this.ipTrackers.get(srcIp);
    if (!tracker) {
      tracker = {
        hits: [],
        ports: new Set(),
        lastSeen: now
      };
      this.ipTrackers.set(srcIp, tracker);
    }

    tracker.lastSeen = now;
    tracker.hits.push({
      time: now,
      port: log.dst_port,
      proto: log.protocol,
      action: log.action,
      flags: log.tcp_flags
    });
    if (log.dst_port) {
      tracker.ports.add(log.dst_port);
    }

    // Se já é uma ameaça identificada (ex: falha de login)
    if (log.is_threat && log.threat_reason) {
      await this.handleThreatMatch(log, {
        id: 'rule-login-fail',
        name: log.threat_reason,
        severity: 'critical',
        auto_block: 1,
        block_duration_minutes: 120
      });
      return log;
    }

    // Avalia regras configuradas para pacotes bloqueados (drop/reject)
    if (log.action === 'drop' || log.action === 'reject') {
      for (const rule of this.rules) {
        if (this.evaluateRule(rule, tracker, log, now)) {
          log.is_threat = 1;
          log.threat_reason = rule.name;
          await this.handleThreatMatch(log, rule);
          break; // Aciona a primeira regra coincidente de maior prioridade
        }
      }
    }

    return log;
  }

  /**
   * Avalia uma regra contra o histórico recente do IP
   */
  evaluateRule(rule, tracker, currentLog, now) {
    const windowMs = (rule.threshold_window_seconds || 60) * 1000;
    const cutoff = now - windowMs;

    // Filtra histórico dentro da janela de tempo da regra
    const recentHits = tracker.hits.filter(h => h.time >= cutoff);

    // 1. Regra baseada em portas alvo específicas (ex: Winbox 8291, SSH 22)
    if (rule.target_ports) {
      const allowedPorts = rule.target_ports.split(',').map(p => parseInt(p.trim(), 10)).filter(Boolean);
      const portHits = recentHits.filter(h => allowedPorts.includes(h.port));

      if (rule.protocol) {
        const protoHits = portHits.filter(h => h.proto === rule.protocol);
        return protoHits.length >= rule.threshold_count;
      }
      return portHits.length >= rule.threshold_count;
    }

    // 2. Regra de Port Scan horizontal (múltiplas portas distintas)
    if (rule.category === 'scan') {
      const distinctPorts = new Set();
      for (const h of recentHits) {
        if (rule.protocol && h.proto !== rule.protocol) continue;
        if (h.port) distinctPorts.add(h.port);
      }
      return distinctPorts.size >= rule.threshold_count;
    }

    // 3. Regra de DoS / Inundação de pacotes
    if (rule.category === 'dos') {
      return recentHits.length >= rule.threshold_count;
    }

    return false;
  }

  /**
   * Aciona alerta de ameaça e auto-bloqueio se configurado
   */
  async handleThreatMatch(log, rule) {
    const zone = log.zone || 'WAN';
    if (zone === 'LAN') {
      const monitorLan = await db.getSetting('monitor_lan_threats', 'false');
      if (monitorLan !== 'true') return;
    }

    const srcIp = log.src_ip;
    const now = Date.now();
    const nowIso = new Date(now).toISOString();

    // Evita disparar auto-bloqueio repetidamente se já foi bloqueado nos últimos 60 segundos
    const lastBlockedAt = this.recentlyBlocked.get(srcIp);
    const alreadyBlockedRecently = lastBlockedAt && (now - lastBlockedAt < 60000);

    let autoBlocked = 0;

    if (!alreadyBlockedRecently) {
      this.recentlyBlocked.set(srcIp, now);

      // Proteção de infraestrutura: nunca auto-bloquear o IP do próprio gateway local ou loopback
      const isGatewayOrLoopback = srcIp === '127.0.0.1' || srcIp === '::1' || srcIp === '192.168.88.1' || srcIp.endsWith('.255');

      // Verifica se o auto-bloqueio da regra e global estão ativos
      const autoBlockGlobal = await db.getSetting('mikrotik_auto_block', 'true');
      const shouldBlock = rule.auto_block === 1 && autoBlockGlobal === 'true' && !isGatewayOrLoopback;

      const lanQuarantineList = await db.getSetting('lan_quarantine_list', 'TIKSENTRY_LAN_QUARANTINE');
      const targetList = zone === 'LAN' ? lanQuarantineList : null;

      const ruleDisplayName = zone === 'LAN' 
        ? `[Ameaça Interna / LAN] ${rule.name}`
        : `[Ataque Internet / WAN] ${rule.name}`;

      if (shouldBlock) {
        autoBlocked = 1;
        const duration = rule.block_duration_minutes || 60;
        addressListManager.blockIp({
          ip: srcIp,
          reason: `IDS: ${ruleDisplayName}`,
          durationMinutes: duration,
          ruleId: rule.id,
          ruleName: ruleDisplayName,
          zone: zone,
          customList: targetList,
          geoData: {
            country: log.country,
            city: log.city,
            country_code: log.country_code,
            latitude: log.latitude,
            longitude: log.longitude
          }
        }).catch(err => {
          console.error(`[IDS] Falha no auto-bloqueio de ${srcIp}:`, err.message);
        });
      }

      // Registra evento de segurança no banco
      await db.run(`
        INSERT INTO ids_events (timestamp, src_ip, rule_id, rule_name, severity, details, auto_blocked, country, city, zone)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, [
        nowIso,
        srcIp,
        rule.id,
        ruleDisplayName,
        rule.severity || 'high',
        `${ruleDisplayName}. Origem: ${zone}. Porta destino: ${log.dst_port || 'múltiplas'}. Protocolo: ${log.protocol}. Interface: ${log.in_interface || '-'}`,
        autoBlocked,
        log.country,
        log.city,
        zone
      ]).catch(() => {});

      // Notifica via WebSocket para o mapa e dashboard apenas se alertas estiverem ativos
      if (this.broadcastCallback) {
        const alertsEnabled = await db.getSetting('alerts_enabled', 'true');
        if (alertsEnabled === 'true') {
          this.broadcastCallback({
            type: 'IDS_ALERT',
            alert: {
              id: Date.now(),
              timestamp: nowIso,
              src_ip: srcIp,
              dst_port: log.dst_port,
              protocol: log.protocol,
              rule_name: ruleDisplayName,
              severity: rule.severity,
              zone: zone,
              auto_blocked: autoBlocked === 1,
              country: log.country,
              city: log.city,
              country_code: log.country_code,
              latitude: log.latitude,
              longitude: log.longitude
            }
          });
        }
      }
    }
  }

  /**
   * Limpa rastreadores inativos da memória para manter o consumo ultra-baixo
   */
  pruneTrackers() {
    const cutoff = Date.now() - 300000; // 5 minutos sem atividade
    for (const [ip, tracker] of this.ipTrackers.entries()) {
      if (tracker.lastSeen < cutoff) {
        this.ipTrackers.delete(ip);
      } else {
        // Limpa hits mais velhos que 3 minutos no próprio tracker
        tracker.hits = tracker.hits.filter(h => h.time >= cutoff);
      }
    }

    // Limpa cache de bloqueados recentes
    const blockCutoff = Date.now() - 300000;
    for (const [ip, time] of this.recentlyBlocked.entries()) {
      if (time < blockCutoff) {
        this.recentlyBlocked.delete(ip);
      }
    }
  }
}

const idsEngine = new IdsEngine();
module.exports = idsEngine;
