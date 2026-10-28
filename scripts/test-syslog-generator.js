const dgram = require('dgram');

const TARGET_HOST = process.env.SYSLOG_HOST || '127.0.0.1';
const TARGET_PORT = parseInt(process.env.SYSLOG_PORT, 10) || 514;

const client = dgram.createSocket('udp4');

// Amostra de IPs globais conhecidos por scanners e ataques
const ATTACK_PROFILES = [
  { ip: '185.220.101.5', country: 'RU', type: 'winbox', ports: [8291], proto: 'TCP', flags: 'SYN' },
  { ip: '114.119.160.10', country: 'CN', type: 'ssh', ports: [22], proto: 'TCP', flags: 'SYN' },
  { ip: '45.33.32.156', country: 'US', type: 'scan', ports: [21, 22, 23, 25, 80, 443, 3389, 8080, 8291, 8728], proto: 'TCP', flags: 'SYN' },
  { ip: '195.201.20.50', country: 'DE', type: 'udp', ports: [53, 123, 5060, 161, 51820], proto: 'UDP', flags: '' },
  { ip: '194.26.29.100', country: 'NL', type: 'web', ports: [80, 443, 8080, 8443], proto: 'TCP', flags: 'SYN,ACK' },
  { ip: '187.18.200.45', country: 'BR', type: 'rdp', ports: [3389], proto: 'TCP', flags: 'SYN' },
  { ip: '177.67.80.12', country: 'BR', type: 'mikrotik_api', ports: [8728, 8729], proto: 'TCP', flags: 'SYN' },
  { ip: '80.82.77.33', country: 'NL', type: 'telnet', ports: [23], proto: 'TCP', flags: 'SYN' },
  { ip: '103.251.167.20', country: 'VN', type: 'dos', ports: [80], proto: 'TCP', flags: 'SYN' }
];

function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function generateMikroTikLog() {
  const profile = ATTACK_PROFILES[Math.floor(Math.random() * ATTACK_PROFILES.length)];
  const srcPort = getRandomInt(40000, 65000);
  const dstPort = profile.ports[Math.floor(Math.random() * profile.ports.length)];
  const dstIp = '192.168.88.1';
  const len = getRandomInt(40, 128);

  const flagsStr = profile.flags ? `(${profile.flags})` : '';

  // Formato padrão MikroTik Firewall Drop
  return `firewall,warning forward: in:ether1-wan out:bridge1, src-mac 00:0c:42:ff:ee:01, proto ${profile.proto} ${flagsStr}, ${profile.ip}:${srcPort}->${dstIp}:${dstPort}, len ${len}`;
}

function generateLoginFailLog() {
  const users = ['admin', 'root', 'support', 'mikrotik', 'cisco'];
  const user = users[Math.floor(Math.random() * users.length)];
  const profile = ATTACK_PROFILES[Math.floor(Math.random() * ATTACK_PROFILES.length)];
  const services = ['winbox', 'ssh', 'web', 'api'];
  const srv = services[Math.floor(Math.random() * services.length)];

  return `system,error,critical login failure for user ${user} from ${profile.ip} via ${srv}`;
}

function sendPacket(msg) {
  const buffer = Buffer.from(msg, 'utf8');
  client.send(buffer, 0, buffer.length, TARGET_PORT, TARGET_HOST, (err) => {
    if (err) {
      console.error(`[Simulador] Erro ao enviar pacote para ${TARGET_HOST}:${TARGET_PORT}:`, err.message);
    }
  });
}

// Execução
const isStream = process.argv.includes('--stream');
const countArgIndex = process.argv.indexOf('--batch');
const batchCount = countArgIndex !== -1 && process.argv[countArgIndex + 1] ? parseInt(process.argv[countArgIndex + 1], 10) : 25;

console.log(`[Simulador TikSentry] Enviando pacotes syslog para ${TARGET_HOST}:${TARGET_PORT}...`);

if (isStream) {
  console.log('[Simulador] Modo Stream contínuo ativo (Pressione Ctrl+C para parar)...');
  setInterval(() => {
    const isLogin = Math.random() < 0.2;
    const log = isLogin ? generateLoginFailLog() : generateMikroTikLog();
    sendPacket(log);
    console.log(`[TX] ${log}`);
  }, 1200);
} else {
  console.log(`[Simulador] Disparando lote de ${batchCount} logs de ataque para teste...`);
  for (let i = 0; i < batchCount; i++) {
    setTimeout(() => {
      const isLogin = Math.random() < 0.2;
      const log = isLogin ? generateLoginFailLog() : generateMikroTikLog();
      sendPacket(log);
      console.log(`[TX #${i + 1}] ${log}`);
      if (i === batchCount - 1) {
        setTimeout(() => {
          console.log('[Simulador] Lote enviado com sucesso!');
          client.close();
          process.exit(0);
        }, 500);
      }
    }, i * 80);
  }
}
