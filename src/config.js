require('dotenv').config();
const path = require('path');

const config = {
  systemName: process.env.SYSTEM_NAME || 'TikSentry SOC',
  port: parseInt(process.env.PORT, 10) || 3000,
  host: process.env.HOST || '0.0.0.0',

  syslogPort: parseInt(process.env.SYSLOG_PORT, 10) || 514,
  syslogFallbackPort: parseInt(process.env.SYSLOG_FALLBACK_PORT, 10) || 1514,
  syslogHost: process.env.SYSLOG_HOST || '0.0.0.0',

  dbPath: path.resolve(process.env.DB_PATH || './data/tiksentry.db'),
  logRetentionDays: parseInt(process.env.LOG_RETENTION_DAYS, 10) || 14,

  router: {
    lat: parseFloat(process.env.ROUTER_LAT) || -23.5505,
    lng: parseFloat(process.env.ROUTER_LNG) || -46.6333,
    name: process.env.ROUTER_NAME || 'MikroTik Gateway'
  },

  mikrotik: {
    protocol: process.env.MIKROTIK_PROTOCOL || 'rest', // 'rest' ou 'api'
    host: process.env.MIKROTIK_HOST || '192.168.88.1',
    port: parseInt(process.env.MIKROTIK_PORT, 10) || 443,
    username: process.env.MIKROTIK_USER || 'admin',
    password: process.env.MIKROTIK_PASSWORD || '',
    useTls: process.env.MIKROTIK_USE_TLS === 'true',
    blockListName: process.env.MIKROTIK_BLOCK_LIST || 'TIKSENTRY_BLOCKED',
    autoBlock: process.env.MIKROTIK_AUTO_BLOCK_ENABLED !== 'false',
    defaultBlockMinutes: parseInt(process.env.MIKROTIK_DEFAULT_BLOCK_MINUTES, 10) || 60
  }
};

module.exports = config;
