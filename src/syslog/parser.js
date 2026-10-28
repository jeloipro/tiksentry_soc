/**
 * Parser de Logs do Firewall e Sistema MikroTik (RouterOS v6 e v7)
 */

// Regex para logs padrão de firewall MikroTik
// Exemplo: firewall,info forward: in:ether1 out:bridge1, proto TCP (SYN), 185.120.34.12:44123->192.168.88.1:8291, len 52
const FIREWALL_PATTERN = /(?:(?:firewall,(\w+))|([A-Za-z0-9_\-\[\]]+))\s+(?:(\w+):)?\s*(?:in:([^\s,]+))?\s*(?:out:([^\s,]+))?,?\s*(?:src-mac\s+([0-9a-fA-F:]+),?)?\s*(?:proto\s+(\w+)(?:\s*\(([^)]+)\))?,?)?\s*([0-9a-fA-F.:]+)(?::(\d+))?\s*->\s*([0-9a-fA-F.:]+)(?::(\d+))?,?\s*(?:len\s+(\d+))?/;

// Regex para falhas de login do sistema
// Exemplo: system,error,critical login failure for user admin from 185.220.101.5 via winbox
const LOGIN_FAILURE_PATTERN = /login failure for user\s+(\S+)\s+from\s+([0-9a-fA-F.:]+)\s+via\s+(\S+)/i;

// Regex para connection-state
const CONN_STATE_PATTERN = /connection-state=([a-zA-Z0-9_\-]+)/;

function parseMikroTikLog(rawBufferOrString) {
  let raw = '';
  if (Buffer.isBuffer(rawBufferOrString)) {
    raw = rawBufferOrString.toString('utf8');
  } else {
    raw = String(rawBufferOrString || '');
  }

  raw = raw.trim();
  if (!raw) return null;

  // Remove cabeçalhos Syslog comuns se houver (ex: <134>1 2026-10-27T17:00:00Z MikroTik ...)
  let cleanMsg = raw;
  const syslogHeaderMatch = cleanMsg.match(/^<\d+>(?:\d\s+)?(?:\d{4}-\S+|\w{3}\s+\d+\s+[\d:]+)?\s*(?:[A-Za-z0-9_\-.:]+)?\s*(.*)$/);
  if (syslogHeaderMatch && syslogHeaderMatch[1]) {
    cleanMsg = syslogHeaderMatch[1].trim();
  }

  const now = new Date().toISOString();

  // 1. Tenta identificar evento de falha de login (Brute Force no próprio RouterOS)
  const loginMatch = cleanMsg.match(LOGIN_FAILURE_PATTERN);
  if (loginMatch) {
    const username = loginMatch[1];
    const srcIp = loginMatch[2];
    const service = loginMatch[3].toLowerCase();

    let dstPort = 8291;
    if (service === 'ssh') dstPort = 22;
    else if (service === 'telnet') dstPort = 23;
    else if (service === 'www' || service === 'web' || service === 'http') dstPort = 80;
    else if (service === 'api') dstPort = 8728;

    return {
      timestamp: now,
      chain: 'input',
      action: 'drop',
      protocol: 'tcp',
      src_ip: normalizeIp(srcIp),
      src_port: 0,
      dst_ip: '192.168.88.1',
      dst_port: dstPort,
      in_interface: 'wan',
      out_interface: 'local',
      packet_size: 64,
      tcp_flags: 'LOGIN_FAIL',
      connection_state: 'new',
      src_mac: null,
      is_threat: 1,
      threat_reason: `Tentativa de login inválida: ${username} via ${service}`,
      raw_message: raw
    };
  }

  // 2. Tenta parsear log de firewall padrão
  const match = cleanMsg.match(FIREWALL_PATTERN);
  if (match) {
    const logLevel = (match[1] || '').toLowerCase();
    const prefixOrLevel = match[2] || '';
    const chain = match[3] || 'forward';
    const inIf = match[4] || '-';
    const outIf = match[5] || '-';
    const srcMac = match[6] || null;
    const protocol = (match[7] || 'ip').toLowerCase();
    const tcpFlags = match[8] || null;
    const srcIp = match[9] || '';
    const srcPort = match[10] ? parseInt(match[10], 10) : 0;
    const dstIp = match[11] || '';
    const dstPort = match[12] ? parseInt(match[12], 10) : 0;
    const packetLen = match[13] ? parseInt(match[13], 10) : 0;

    if (!srcIp || !dstIp) return null;

    // Determina a ação do firewall
    let action = 'unknown';
    const combinedMsg = (logLevel + ' ' + prefixOrLevel + ' ' + cleanMsg).toLowerCase();

    if (combinedMsg.includes('drop') || logLevel === 'warning' || logLevel === 'critical' || logLevel === 'error') {
      action = 'drop';
    } else if (combinedMsg.includes('reject')) {
      action = 'reject';
    } else if (combinedMsg.includes('accept') || logLevel === 'info') {
      action = 'accept';
    }

    // Se o prefixo contiver DROP, REJECT ou BLOCK
    if (/drop|block|reject|defend|ids/i.test(prefixOrLevel)) {
      action = 'drop';
    }

    const connMatch = cleanMsg.match(CONN_STATE_PATTERN);
    const connState = connMatch ? connMatch[1] : (tcpFlags && tcpFlags.includes('SYN') ? 'new' : null);

    return {
      timestamp: now,
      chain: chain.toLowerCase(),
      action: action,
      protocol: protocol,
      src_ip: normalizeIp(srcIp),
      src_port: srcPort,
      dst_ip: normalizeIp(dstIp),
      dst_port: dstPort,
      in_interface: inIf,
      out_interface: outIf,
      packet_size: packetLen,
      tcp_flags: tcpFlags,
      connection_state: connState,
      src_mac: srcMac,
      is_threat: 0,
      threat_reason: null,
      raw_message: raw
    };
  }

  // Fallback genérico para logs com formato de IP e portas: 1.2.3.4:1234 -> 5.6.7.8:80
  const genericIpPattern = /([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(?::(\d+))?\s*(?:->|>)\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(?::(\d+))?/;
  const genMatch = cleanMsg.match(genericIpPattern);
  if (genMatch) {
    const srcIp = genMatch[1];
    const srcPort = genMatch[2] ? parseInt(genMatch[2], 10) : 0;
    const dstIp = genMatch[3];
    const dstPort = genMatch[4] ? parseInt(genMatch[4], 10) : 0;

    let proto = 'tcp';
    if (/udp/i.test(cleanMsg)) proto = 'udp';
    else if (/icmp/i.test(cleanMsg)) proto = 'icmp';

    let action = 'drop';
    if (/accept/i.test(cleanMsg)) action = 'accept';

    return {
      timestamp: now,
      chain: 'forward',
      action: action,
      protocol: proto,
      src_ip: normalizeIp(srcIp),
      src_port: srcPort,
      dst_ip: normalizeIp(dstIp),
      dst_port: dstPort,
      in_interface: '-',
      out_interface: '-',
      packet_size: 0,
      tcp_flags: null,
      connection_state: null,
      src_mac: null,
      is_threat: 0,
      threat_reason: null,
      raw_message: raw
    };
  }

  return null;
}

function normalizeIp(ip) {
  if (!ip) return '';
  return ip.trim();
}

module.exports = {
  parseMikroTikLog
};
