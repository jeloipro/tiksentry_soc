const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const config = require('../config');

// Garante que o diretório do banco exista
const dbDir = path.dirname(config.dbPath);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const db = new sqlite3.Database(config.dbPath, (err) => {
  if (err) {
    console.error('[DB] Erro fatal ao abrir banco SQLite:', err.message);
  } else {
    console.log(`[DB] Banco de dados SQLite conectado em: ${config.dbPath}`);
  }
});

// Promisify auxiliares
const run = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
};

const get = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
};

const all = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows || []);
    });
  });
};

// Fila de execução estritamente sequencial para transações SQLite (mutex contra concorrência assíncrona)
let transactionQueue = Promise.resolve();

// Executa um lote de comandos dentro de uma transação serializada
const transaction = (operations) => {
  const execute = async () => {
    if (!operations || operations.length === 0) return;

    let inTransaction = false;
    try {
      await run('BEGIN IMMEDIATE TRANSACTION');
      inTransaction = true;

      for (const op of operations) {
        await run(op.sql, op.params);
      }

      await run('COMMIT');
      inTransaction = false;
    } catch (err) {
      if (inTransaction) {
        try {
          await run('ROLLBACK');
        } catch (_) {}
      }
      throw err;
    }
  };

  // Garante ordem estrita FIFO e que transações nunca colidam
  const next = transactionQueue.then(execute, execute);
  transactionQueue = next.catch(() => {});
  return next;
};

// Inicialização de Tabelas
const initDb = async () => {
  try {
    await run('PRAGMA journal_mode = WAL;');
    await run('PRAGMA synchronous = NORMAL;');

    // 1. Tabela de Configurações
    await run(`
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
    `);

    // 2. Tabela de Logs de Firewall
    await run(`
      CREATE TABLE IF NOT EXISTS firewall_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        chain TEXT,
        action TEXT,
        protocol TEXT,
        src_ip TEXT NOT NULL,
        src_port INTEGER,
        dst_ip TEXT,
        dst_port INTEGER,
        in_interface TEXT,
        out_interface TEXT,
        packet_size INTEGER,
        tcp_flags TEXT,
        connection_state TEXT,
        src_mac TEXT,
        country TEXT,
        city TEXT,
        country_code TEXT,
        latitude REAL,
        longitude REAL,
        is_threat INTEGER DEFAULT 0,
        threat_reason TEXT,
        zone TEXT DEFAULT 'WAN',
        raw_message TEXT
      );
    `);

    // Migração de schema caso as tabelas já existam sem a coluna zone
    await migrateColumns();

    // Índices para consultas ultra-rápidas no Dashboard e Mapa
    await run('CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON firewall_logs(timestamp);');
    await run('CREATE INDEX IF NOT EXISTS idx_logs_src_ip ON firewall_logs(src_ip);');
    await run('CREATE INDEX IF NOT EXISTS idx_logs_dst_port ON firewall_logs(dst_port);');
    await run('CREATE INDEX IF NOT EXISTS idx_logs_is_threat ON firewall_logs(is_threat);');
    await run('CREATE INDEX IF NOT EXISTS idx_logs_country_code ON firewall_logs(country_code);');
    await run('CREATE INDEX IF NOT EXISTS idx_logs_city ON firewall_logs(city);');
    await run('CREATE INDEX IF NOT EXISTS idx_logs_zone ON firewall_logs(zone);');

    // 3. Tabela de Regras IDS
    await run(`
      CREATE TABLE IF NOT EXISTS ids_rules (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        enabled INTEGER DEFAULT 1,
        auto_block INTEGER DEFAULT 1,
        block_duration_minutes INTEGER DEFAULT 60,
        threshold_count INTEGER DEFAULT 15,
        threshold_window_seconds INTEGER DEFAULT 60,
        target_ports TEXT,
        protocol TEXT
      );
    `);

    // 4. Tabela de IPs Bloqueados (IPS)
    await run(`
      CREATE TABLE IF NOT EXISTS blocked_ips (
        ip TEXT PRIMARY KEY,
        reason TEXT NOT NULL,
        rule_id TEXT,
        rule_name TEXT,
        blocked_at TEXT NOT NULL,
        expires_at TEXT,
        is_permanent INTEGER DEFAULT 0,
        synced_to_mikrotik INTEGER DEFAULT 0,
        mikrotik_list_name TEXT DEFAULT 'TIKSENTRY_BLOCKED',
        country TEXT,
        city TEXT,
        country_code TEXT,
        latitude REAL,
        longitude REAL,
        zone TEXT DEFAULT 'WAN',
        hit_count INTEGER DEFAULT 1,
        last_hit_at TEXT NOT NULL
      );
    `);

    await run('CREATE INDEX IF NOT EXISTS idx_blocked_expires ON blocked_ips(expires_at);');

    // 5. Tabela de Eventos e Alertas IDS
    await run(`
      CREATE TABLE IF NOT EXISTS ids_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        src_ip TEXT NOT NULL,
        rule_id TEXT,
        rule_name TEXT NOT NULL,
        severity TEXT NOT NULL,
        details TEXT,
        auto_blocked INTEGER DEFAULT 0,
        country TEXT,
        city TEXT,
        zone TEXT DEFAULT 'WAN'
      );
    `);

    await run('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON ids_events(timestamp);');

    // Popular regras padrão caso a tabela esteja vazia
    await seedDefaultRules();

    // Carregar configurações padrão no settings se não existirem
    await seedDefaultSettings();

    console.log('[DB] Tabelas e índices do TikSentry inicializados com sucesso.');
  } catch (err) {
    console.error('[DB] Erro ao inicializar esquema do banco:', err);
  }
};

const migrateColumns = async () => {
  try {
    const ensureColumn = async (table, column, definition) => {
      const cols = await all(`PRAGMA table_info(${table})`);
      if (cols && !cols.some(c => c.name === column)) {
        await run(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
        console.log(`[DB Migration] Coluna '${column}' adicionada à tabela '${table}'.`);
      }
    };

    await ensureColumn('firewall_logs', 'zone', "TEXT DEFAULT 'WAN'");
    await ensureColumn('ids_events', 'zone', "TEXT DEFAULT 'WAN'");
    await ensureColumn('blocked_ips', 'zone', "TEXT DEFAULT 'WAN'");
  } catch (err) {
    console.error('[DB Migration] Erro ao verificar/migrar colunas:', err.message);
  }
};

const seedDefaultRules = async () => {
  const defaultRules = [
    {
      id: 'rule-winbox-bruteforce',
      name: 'Winbox Port Scan / Brute Force',
      description: 'Ataques repetidos à porta de gerenciamento MikroTik Winbox (8291)',
      category: 'bruteforce',
      severity: 'critical',
      enabled: 1,
      auto_block: 1,
      block_duration_minutes: 120,
      threshold_count: 5,
      threshold_window_seconds: 60,
      target_ports: '8291',
      protocol: 'tcp'
    },
    {
      id: 'rule-ssh-bruteforce',
      name: 'SSH Brute Force',
      description: 'Tentativas repetidas de varredura ou força bruta na porta SSH (22)',
      category: 'bruteforce',
      severity: 'high',
      enabled: 1,
      auto_block: 1,
      block_duration_minutes: 60,
      threshold_count: 8,
      threshold_window_seconds: 60,
      target_ports: '22',
      protocol: 'tcp'
    },
    {
      id: 'rule-portscan-syn',
      name: 'TCP SYN Port Scan',
      description: 'Varredura horizontal de múltiplas portas TCP a partir da mesma origem',
      category: 'scan',
      severity: 'high',
      enabled: 1,
      auto_block: 1,
      block_duration_minutes: 60,
      threshold_count: 10,
      threshold_window_seconds: 45,
      target_ports: null,
      protocol: 'tcp'
    },
    {
      id: 'rule-udp-scan',
      name: 'UDP Port Scan / Flood',
      description: 'Varredura rápida ou inundação em portas UDP',
      category: 'scan',
      severity: 'medium',
      enabled: 1,
      auto_block: 1,
      block_duration_minutes: 30,
      threshold_count: 20,
      threshold_window_seconds: 60,
      target_ports: null,
      protocol: 'udp'
    },
    {
      id: 'rule-web-bruteforce',
      name: 'Web Interface Scan (HTTP/HTTPS)',
      description: 'Ataques às portas de gerenciamento web (80, 443, 8080)',
      category: 'web',
      severity: 'high',
      enabled: 1,
      auto_block: 1,
      block_duration_minutes: 60,
      threshold_count: 12,
      threshold_window_seconds: 60,
      target_ports: '80,443,8080',
      protocol: 'tcp'
    },
    {
      id: 'rule-mikrotik-api',
      name: 'MikroTik API Port Scan',
      description: 'Tentativas de acesso às portas da API RouterOS (8728, 8729)',
      category: 'bruteforce',
      severity: 'critical',
      enabled: 1,
      auto_block: 1,
      block_duration_minutes: 180,
      threshold_count: 4,
      threshold_window_seconds: 60,
      target_ports: '8728,8729',
      protocol: 'tcp'
    },
    {
      id: 'rule-telnet-bruteforce',
      name: 'Telnet Brute Force',
      description: 'Varredura na porta legada Telnet (23)',
      category: 'bruteforce',
      severity: 'high',
      enabled: 1,
      auto_block: 1,
      block_duration_minutes: 60,
      threshold_count: 5,
      threshold_window_seconds: 60,
      target_ports: '23',
      protocol: 'tcp'
    },
    {
      id: 'rule-rdp-scan',
      name: 'RDP Remote Desktop Scan',
      description: 'Varredura e ataques à porta de desktop remoto RDP (3389)',
      category: 'scan',
      severity: 'medium',
      enabled: 1,
      auto_block: 1,
      block_duration_minutes: 60,
      threshold_count: 8,
      threshold_window_seconds: 60,
      target_ports: '3389',
      protocol: 'tcp'
    },
    {
      id: 'rule-dos-flood',
      name: 'High Packet Drop / DoS Flood',
      description: 'Volume extremo de pacotes bloqueados no firewall em curto período',
      category: 'dos',
      severity: 'critical',
      enabled: 1,
      auto_block: 1,
      block_duration_minutes: 120,
      threshold_count: 40,
      threshold_window_seconds: 30,
      target_ports: null,
      protocol: null
    },
    {
      id: 'rule-lan-smb-ransomware',
      name: 'Ransomware / SMB Outbound Leak',
      description: 'Dispositivo interno tentando espalhar SMB/Ransomware (portas 445/139) para a Internet',
      category: 'trojan',
      severity: 'critical',
      enabled: 1,
      auto_block: 1,
      block_duration_minutes: 180,
      threshold_count: 2,
      threshold_window_seconds: 60,
      target_ports: '445,139',
      protocol: 'tcp'
    },
    {
      id: 'rule-lan-spambot',
      name: 'Spam Botnet Outbound (SMTP 25)',
      description: 'Máquina interna infectada disparando conexões massivas na porta SMTP (25) para envio de spam',
      category: 'botnet',
      severity: 'high',
      enabled: 1,
      auto_block: 1,
      block_duration_minutes: 120,
      threshold_count: 3,
      threshold_window_seconds: 60,
      target_ports: '25',
      protocol: 'tcp'
    },
    {
      id: 'rule-lan-c2-mining',
      name: 'Malware C2 / Cryptomining Outbound',
      description: 'Tráfego outbound suspeito para pools de mineração de cripto ou servidores C2 (portas 3333, 4444, 5555, etc.)',
      category: 'malware',
      severity: 'high',
      enabled: 1,
      auto_block: 1,
      block_duration_minutes: 120,
      threshold_count: 3,
      threshold_window_seconds: 60,
      target_ports: '3333,4444,5555,6666,7777,8888,9999',
      protocol: 'tcp'
    }
  ];

  for (const r of defaultRules) {
    const existing = await get('SELECT id FROM ids_rules WHERE id = ?', [r.id]);
    if (!existing) {
      await run(`
        INSERT INTO ids_rules (id, name, description, category, severity, enabled, auto_block, block_duration_minutes, threshold_count, threshold_window_seconds, target_ports, protocol)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, [r.id, r.name, r.description, r.category, r.severity, r.enabled, r.auto_block, r.block_duration_minutes, r.threshold_count, r.threshold_window_seconds, r.target_ports, r.protocol]);
    }
  }
  console.log(`[DB] ${defaultRules.length} regras IDS padrão registradas.`);
};

const seedDefaultSettings = async () => {
  const defaults = {
    'system_name': config.systemName,
    'mikrotik_protocol': config.mikrotik.protocol,
    'mikrotik_host': config.mikrotik.host,
    'mikrotik_port': config.mikrotik.port.toString(),
    'mikrotik_username': config.mikrotik.username,
    'mikrotik_password': config.mikrotik.password,
    'mikrotik_use_tls': config.mikrotik.useTls ? 'true' : 'false',
    'mikrotik_block_list': config.mikrotik.blockListName,
    'mikrotik_auto_block': config.mikrotik.autoBlock ? 'true' : 'false',
    'wan_interfaces': 'ether1,pppoe-out1,wan,sfp-sfpplus1,internet',
    'lan_interfaces': 'bridge,lan,bridge1,ether2,ether3,ether4,ether5',
    'lan_quarantine_list': 'TIKSENTRY_LAN_QUARANTINE',
    'auto_detect_wan': 'true',
    'router_lat': config.router.lat.toString(),
    'router_lng': config.router.lng.toString(),
    'router_name': config.router.name
  };

  const now = new Date().toISOString();
  for (const [key, value] of Object.entries(defaults)) {
    const existing = await get('SELECT key FROM settings WHERE key = ?', [key]);
    if (!existing) {
      await run('INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)', [key, value, now]);
    }
  }
};

// Funções de Settings
const getSetting = async (key, fallback = null) => {
  const row = await get('SELECT value FROM settings WHERE key = ?', [key]);
  return row ? row.value : fallback;
};

const getAllSettings = async () => {
  const rows = await all('SELECT key, value, updated_at FROM settings');
  const res = {};
  for (const r of rows) res[r.key] = r.value;
  return res;
};

const setSetting = async (key, value) => {
  const now = new Date().toISOString();
  await run(`
    INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
  `, [key, String(value), now]);
};

// Limpeza de logs antigos
const cleanupOldLogs = async (days = config.logRetentionDays) => {
  const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
  const res = await run('DELETE FROM firewall_logs WHERE timestamp < ?', [cutoff]);
  console.log(`[DB] Limpeza de logs concluída: registros anteriores a ${cutoff} removidos.`);
  return res.changes;
};

module.exports = {
  db,
  run,
  get,
  all,
  transaction,
  initDb,
  getSetting,
  getAllSettings,
  setSetting,
  cleanupOldLogs
};
