const db = require('../storage/db');

// Dicionário de serviços comuns para portas
const PORT_SERVICES = {
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  80: 'HTTP (Web)',
  110: 'POP3',
  143: 'IMAP',
  443: 'HTTPS (Web SSL)',
  445: 'SMB / Windows',
  1433: 'MS SQL Server',
  3306: 'MySQL',
  3389: 'RDP (Remote Desktop)',
  5060: 'SIP (VoIP)',
  5432: 'PostgreSQL',
  8080: 'HTTP-Proxy / Web Alt',
  8291: 'MikroTik Winbox',
  8728: 'MikroTik API',
  8729: 'MikroTik API SSL'
};

class ReportGenerator {
  /**
   * Converte uma faixa de tempo para timestamp ISO de corte
   */
  getCutoffDate(range = '24h') {
    const now = Date.now();
    let ms = 24 * 60 * 60 * 1000;

    if (range === '1h') ms = 60 * 60 * 1000;
    else if (range === '6h') ms = 6 * 60 * 60 * 1000;
    else if (range === '12h') ms = 12 * 60 * 60 * 1000;
    else if (range === '24h') ms = 24 * 60 * 60 * 1000;
    else if (range === '7d') ms = 7 * 24 * 60 * 60 * 1000;
    else if (range === '30d') ms = 30 * 24 * 60 * 60 * 1000;

    return new Date(now - ms).toISOString();
  }

  /**
   * Gera relatório executivo e técnico completo
   */
  async generateFullReport(range = '24h') {
    const cutoff = this.getCutoffDate(range);

    // 1. Métricas Globais
    const totalRow = await db.get(`
      SELECT 
        COUNT(*) as total_events,
        SUM(CASE WHEN is_threat = 1 THEN 1 ELSE 0 END) as total_threats,
        SUM(CASE WHEN action IN ('drop', 'reject') THEN 1 ELSE 0 END) as total_blocked_drops,
        COUNT(DISTINCT src_ip) as unique_sources,
        COUNT(DISTINCT CASE WHEN is_threat = 1 THEN src_ip END) as unique_attackers
      FROM firewall_logs 
      WHERE timestamp >= ?
    `, [cutoff]);

    const blockedCountRow = await db.get('SELECT COUNT(*) as count FROM blocked_ips');

    // 2. Distribuição por Ação
    const actionsRows = await db.all(`
      SELECT action, COUNT(*) as count 
      FROM firewall_logs 
      WHERE timestamp >= ? 
      GROUP BY action 
      ORDER BY count DESC
    `, [cutoff]);

    // 3. Distribuição por Protocolo
    const protoRows = await db.all(`
      SELECT protocol, COUNT(*) as count 
      FROM firewall_logs 
      WHERE timestamp >= ? 
      GROUP BY protocol 
      ORDER BY count DESC 
      LIMIT 8
    `, [cutoff]);

    // 4. Top 10 Países de Origem dos Ataques
    const countriesRows = await db.all(`
      SELECT 
        country, country_code, 
        COUNT(*) as count,
        SUM(CASE WHEN is_threat = 1 THEN 1 ELSE 0 END) as threats
      FROM firewall_logs 
      WHERE timestamp >= ? AND country_code NOT IN ('LAN', 'XX')
      GROUP BY country_code 
      ORDER BY count DESC 
      LIMIT 10
    `, [cutoff]);

    // 5. Top 10 Cidades de Origem
    const citiesRows = await db.all(`
      SELECT 
        city, country, country_code,
        COUNT(*) as count 
      FROM firewall_logs 
      WHERE timestamp >= ? AND city != 'Desconhecido' AND city != 'Privado'
      GROUP BY city, country 
      ORDER BY count DESC 
      LIMIT 10
    `, [cutoff]);

    // 6. Top 15 Portas Alvo
    const portsRows = await db.all(`
      SELECT 
        dst_port, protocol,
        COUNT(*) as count 
      FROM firewall_logs 
      WHERE timestamp >= ? AND dst_port > 0
      GROUP BY dst_port 
      ORDER BY count DESC 
      LIMIT 15
    `, [cutoff]);

    const formattedPorts = portsRows.map(p => ({
      port: p.dst_port,
      protocol: p.protocol ? p.protocol.toUpperCase() : 'TCP',
      service: PORT_SERVICES[p.dst_port] || 'Outro / Não registrado',
      count: p.count
    }));

    // 7. Top 20 IPs Atacantes
    const attackersRows = await db.all(`
      SELECT 
        l.src_ip, l.country, l.city, l.country_code,
        COUNT(*) as hits,
        SUM(CASE WHEN l.is_threat = 1 THEN 1 ELSE 0 END) as threat_hits,
        MAX(l.timestamp) as last_seen,
        MIN(l.timestamp) as first_seen,
        GROUP_CONCAT(DISTINCT l.threat_reason) as reasons,
        b.blocked_at,
        b.expires_at,
        b.is_permanent
      FROM firewall_logs l
      LEFT JOIN blocked_ips b ON l.src_ip = b.ip
      WHERE l.timestamp >= ?
      GROUP BY l.src_ip
      ORDER BY hits DESC
      LIMIT 20
    `, [cutoff]);

    // 8. Eventos de IDS registrados no período
    const idsEvents = await db.all(`
      SELECT * FROM ids_events 
      WHERE timestamp >= ? 
      ORDER BY id DESC 
      LIMIT 50
    `, [cutoff]);

    // 9. Agrupamento por Sub-redes (/24) para Threat Network
    const subnetsRows = await db.all(`
      SELECT 
        substr(src_ip, 1, instr(substr(src_ip, instr(src_ip, '.') + 1), '.') + instr(src_ip, '.')) as prefix,
        country, country_code,
        COUNT(*) as count,
        COUNT(DISTINCT src_ip) as unique_ips
      FROM firewall_logs 
      WHERE timestamp >= ? AND country_code != 'LAN'
      GROUP BY prefix 
      ORDER BY count DESC 
      LIMIT 12
    `, [cutoff]);

    const formattedSubnets = subnetsRows.filter(s => s.prefix).map(s => {
      const parts = s.prefix.split('.').filter(Boolean);
      const subnetCidr = parts.length >= 3 ? `${parts[0]}.${parts[1]}.${parts[2]}.0/24` : s.prefix;
      return {
        subnet: subnetCidr,
        country: s.country,
        country_code: s.country_code,
        count: s.count,
        unique_ips: s.unique_ips
      };
    });

    const totalEvents = totalRow?.total_events || 0;
    const totalThreats = totalRow?.total_threats || 0;
    const totalDrops = totalRow?.total_blocked_drops || 0;

    return {
      generatedAt: new Date().toISOString(),
      timeframe: range,
      summary: {
        totalEvents,
        totalThreats,
        totalDrops,
        uniqueSources: totalRow?.unique_sources || 0,
        uniqueAttackers: totalRow?.unique_attackers || 0,
        activeBlockedIps: blockedCountRow?.count || 0,
        threatRate: totalEvents > 0 ? ((totalThreats / totalEvents) * 100).toFixed(1) : 0,
        mitigationRate: totalEvents > 0 ? ((totalDrops / totalEvents) * 100).toFixed(1) : 0
      },
      actions: actionsRows,
      protocols: protoRows,
      topCountries: countriesRows,
      topCities: citiesRows,
      topPorts: formattedPorts,
      topAttackers: attackersRows,
      threatSubnets: formattedSubnets,
      recentAlerts: idsEvents
    };
  }

  /**
   * Gera exportação CSV de logs recentes
   */
  async generateLogsCsv(range = '24h') {
    const cutoff = this.getCutoffDate(range);
    const rows = await db.all(`
      SELECT timestamp, action, chain, protocol, src_ip, src_port, dst_ip, dst_port, country, city, is_threat, threat_reason
      FROM firewall_logs 
      WHERE timestamp >= ? 
      ORDER BY id DESC 
      LIMIT 5000
    `, [cutoff]);

    const headers = ['Timestamp', 'Acao', 'Chain', 'Protocolo', 'IP Origem', 'Porta Origem', 'IP Destino', 'Porta Destino', 'Pais', 'Cidade', 'Ameaca', 'Motivo Ameaca'];
    const lines = [headers.join(',')];

    for (const r of rows) {
      lines.push([
        `"${r.timestamp}"`,
        `"${r.action || ''}"`,
        `"${r.chain || ''}"`,
        `"${r.protocol || ''}"`,
        `"${r.src_ip || ''}"`,
        r.src_port || 0,
        `"${r.dst_ip || ''}"`,
        r.dst_port || 0,
        `"${r.country || ''}"`,
        `"${r.city || ''}"`,
        r.is_threat ? 'SIM' : 'NAO',
        `"${(r.threat_reason || '').replace(/"/g, '""')}"`
      ].join(','));
    }

    return lines.join('\n');
  }

  /**
   * Gera exportação CSV dos atacantes
   */
  async generateAttackersCsv(range = '24h') {
    const cutoff = this.getCutoffDate(range);
    const rows = await db.all(`
      SELECT 
        l.src_ip, l.country, l.city, l.country_code,
        COUNT(*) as hits,
        SUM(CASE WHEN l.is_threat = 1 THEN 1 ELSE 0 END) as threat_hits,
        MAX(l.timestamp) as last_seen,
        MIN(l.timestamp) as first_seen,
        GROUP_CONCAT(DISTINCT l.threat_reason) as reasons,
        CASE WHEN b.ip IS NOT NULL THEN 'BLOQUEADO' ELSE 'ATIVO' END as status
      FROM firewall_logs l
      LEFT JOIN blocked_ips b ON l.src_ip = b.ip
      WHERE l.timestamp >= ?
      GROUP BY l.src_ip
      ORDER BY hits DESC
      LIMIT 1000
    `, [cutoff]);

    const headers = ['IP Atacante', 'Pais', 'Cidade', 'Total Bloqueios/Hits', 'Hits de Ameaca', 'Primeira Ocorrencia', 'Ultima Ocorrencia', 'Motivos Detectados', 'Status IPS'];
    const lines = [headers.join(',')];

    for (const r of rows) {
      lines.push([
        `"${r.src_ip}"`,
        `"${r.country || ''}"`,
        `"${r.city || ''}"`,
        r.hits,
        r.threat_hits,
        `"${r.first_seen}"`,
        `"${r.last_seen}"`,
        `"${(r.reasons || '').replace(/"/g, '""')}"`,
        `"${r.status}"`
      ].join(','));
    }

    return lines.join('\n');
  }
}

const reportGenerator = new ReportGenerator();
module.exports = reportGenerator;
