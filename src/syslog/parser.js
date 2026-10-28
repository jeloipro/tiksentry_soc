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

  // 2. Extração de IP de Origem e Destino do Firewall
  // Formato: 1.2.3.4:1234 -> 5.6.7.8:80 ou sem portas: 1.2.3.4 -> 5.6.7.8
  const ipMatch = cleanMsg.match(/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(?::(\d+))?\s*(?:->|>)\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(?::(\d+))?/);
  if (!ipMatch) return null;

  const srcIp = normalizeIp(ipMatch[1]);
  const srcPort = ipMatch[2] ? parseInt(ipMatch[2], 10) : 0;
  const dstIp = normalizeIp(ipMatch[3]);
  const dstPort = ipMatch[4] ? parseInt(ipMatch[4], 10) : 0;

  // Cadeia do firewall (input, forward, output)
  const chainMatch = cleanMsg.match(/\b(input|forward|output):/i);
  const chain = chainMatch ? chainMatch[1].toLowerCase() : 'forward';

  // Interfaces de entrada e saída
  const inMatch = cleanMsg.match(/\bin:([^\s,]+)/);
  const inIf = inMatch ? inMatch[1].replace(/[(),]/g, '').trim() : '-';

  const outMatch = cleanMsg.match(/\bout:(\([^)]+\)|[^\s,]+)/);
  let outIf = '-';
  if (outMatch) {
    outIf = outMatch[1].replace(/[(),]/g, '').trim();
    if (!outIf || outIf === 'unknown 0' || outIf === 'unknown') outIf = '-';
  }

  // MAC de origem
  const macMatch = cleanMsg.match(/src-mac\s+([0-9a-fA-F:]+)/);
  const srcMac = macMatch ? macMatch[1] : null;

  // Protocolo e flags TCP
  const protoMatch = cleanMsg.match(/proto\s+(\w+)(?:\s*\(([^)]+)\))?/i);
  let protocol = protoMatch ? protoMatch[1].toLowerCase() : 'ip';
  const tcpFlags = protoMatch && protoMatch[2] ? protoMatch[2] : null;

  if (protocol === 'ip') {
    if (/udp/i.test(cleanMsg)) protocol = 'udp';
    else if (/icmp/i.test(cleanMsg)) protocol = 'icmp';
    else if (/tcp/i.test(cleanMsg)) protocol = 'tcp';
  }

  // Tamanho do pacote
  const lenMatch = cleanMsg.match(/\blen\s+(\d+)/);
  const packetLen = lenMatch ? parseInt(lenMatch[1], 10) : 0;

  // Connection-state
  const connMatch = cleanMsg.match(/connection-state=([a-zA-Z0-9_\-]+)/);
  const connState = connMatch ? connMatch[1] : (tcpFlags && tcpFlags.includes('SYN') ? 'new' : null);

  // Ação (drop, reject, accept)
  let action = 'drop';
  const lowerMsg = cleanMsg.toLowerCase();
  if (lowerMsg.includes('accept')) action = 'accept';
  else if (lowerMsg.includes('reject')) action = 'reject';
  else if (lowerMsg.includes('drop') || lowerMsg.includes('block') || lowerMsg.includes('defend')) action = 'drop';

  return {
    timestamp: now,
    chain: chain,
    action: action,
    protocol: protocol,
    src_ip: srcIp,
    src_port: srcPort,
    dst_ip: dstIp,
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

function normalizeIp(ip) {
  if (!ip) return '';
  return ip.trim();
}

module.exports = {
  parseMikroTikLog
};
