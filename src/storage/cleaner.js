const fs = require('fs');
const path = require('path');
const db = require('./db');
const config = require('../config');

class AutoPruneManager {
  constructor() {
    this.backupDir = path.resolve(path.dirname(config.dbPath), 'backups');
    this.intervalId = null;
    this.ensureBackupDir();
  }

  ensureBackupDir() {
    if (!fs.existsSync(this.backupDir)) {
      fs.mkdirSync(this.backupDir, { recursive: true });
    }
  }

  start() {
    this.ensureBackupDir();
    // Verifica agendamento a cada 30 minutos
    if (!this.intervalId) {
      this.intervalId = setInterval(() => {
        this.checkScheduledRun().catch(err => {
          console.error('[AutoPrune] Erro na verificação agendada:', err.message);
        });
      }, 30 * 60 * 1000);
      console.log('[AutoPrune] Agendador de limpeza e arquivamento de logs ativo.');
    }
  }

  stop() {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
  }

  async getConfig() {
    const settings = await db.getAllSettings();
    return {
      enabled: settings['prune_enabled'] !== 'false', // default true
      frequency: settings['prune_frequency'] || 'weekly', // 'daily', 'weekly', 'monthly'
      retentionDays: parseInt(settings['prune_retention_days'] || config.logRetentionDays || 14, 10),
      saveFormat: settings['prune_format'] || 'csv', // 'csv'
      lastRun: settings['prune_last_run'] || null
    };
  }

  async setConfig({ enabled, frequency, retentionDays, saveFormat }) {
    if (enabled !== undefined) await db.setSetting('prune_enabled', enabled ? 'true' : 'false');
    if (frequency !== undefined) await db.setSetting('prune_frequency', frequency);
    if (retentionDays !== undefined) await db.setSetting('prune_retention_days', String(retentionDays));
    if (saveFormat !== undefined) await db.setSetting('prune_format', saveFormat);
    return await this.getConfig();
  }

  async checkScheduledRun() {
    const cfg = await this.getConfig();
    if (!cfg.enabled) return;

    const now = new Date();
    const lastRunDate = cfg.lastRun ? new Date(cfg.lastRun) : null;

    let shouldRun = false;

    if (!lastRunDate) {
      // Primeira execução
      shouldRun = true;
    } else {
      const diffMs = now.getTime() - lastRunDate.getTime();
      const diffDays = diffMs / (1000 * 60 * 60 * 24);

      if (cfg.frequency === 'daily' && diffDays >= 1) {
        shouldRun = true;
      } else if (cfg.frequency === 'weekly' && diffDays >= 7) {
        shouldRun = true;
      } else if (cfg.frequency === 'monthly' && diffDays >= 30) {
        shouldRun = true;
      }
    }

    if (shouldRun) {
      console.log(`[AutoPrune] Executando rotina agendada de limpeza (${cfg.frequency})...`);
      await this.performBackupAndCleanup('agendado');
    }
  }

  /**
   * Executa o backup em CSV/JSON dos logs antigos e depois remove do SQLite
   */
  async performBackupAndCleanup(trigger = 'manual') {
    this.ensureBackupDir();
    const cfg = await this.getConfig();
    const days = (cfg.retentionDays !== undefined && cfg.retentionDays !== null && !isNaN(cfg.retentionDays)) ? cfg.retentionDays : 14;
    const cutoffDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();

    console.log(`[AutoPrune] Iniciando arquivamento de logs anteriores a ${cutoffDate} (${days} dias)...`);

    // Busca os logs que serão removidos para fazer o backup
    const logsToArchive = await db.all(`
      SELECT timestamp, action, chain, protocol, src_ip, src_port, dst_ip, dst_port,
             country, city, country_code, is_threat, threat_reason, raw_message
      FROM firewall_logs
      WHERE timestamp < ?
      ORDER BY id ASC
    `, [cutoffDate]);

    const count = logsToArchive.length;
    let backupFileName = null;
    let backupFilePath = null;

    if (count > 0) {
      const nowStr = new Date().toISOString().replace(/[:.]/g, '-');
      backupFileName = `tiksentry-logs-backup-${nowStr}.csv`;
      backupFilePath = path.join(this.backupDir, backupFileName);

      // Converte para formato CSV
      const headers = ['Timestamp', 'Acao', 'Chain', 'Protocolo', 'IP_Origem', 'Porta_Origem', 'IP_Destino', 'Porta_Destino', 'Pais', 'Cidade', 'Pais_Code', 'Ameaca', 'Motivo', 'Raw_Log'];
      const lines = [headers.join(',')];

      for (const r of logsToArchive) {
        lines.push([
          `"${r.timestamp}"`,
          `"${r.action || ''}"`,
          `"${r.chain || ''}"`,
          `"${r.protocol || ''}"`,
          `"${r.src_ip || ''}"`,
          r.src_port || 0,
          `"${r.dst_ip || ''}"`,
          r.dst_port || 0,
          `"${(r.country || '').replace(/"/g, '""')}"`,
          `"${(r.city || '').replace(/"/g, '""')}"`,
          `"${r.country_code || ''}"`,
          r.is_threat ? 'SIM' : 'NAO',
          `"${(r.threat_reason || '').replace(/"/g, '""')}"`,
          `"${(r.raw_message || '').replace(/"/g, '""')}"`
        ].join(','));
      }

      fs.writeFileSync(backupFilePath, lines.join('\n'), 'utf8');
      console.log(`[AutoPrune] Backup de ${count} registros salvo em: ${backupFileName}`);

      // Remove os logs do SQLite
      await db.run('DELETE FROM firewall_logs WHERE timestamp < ?', [cutoffDate]);

      // Executa PRAGMA para reorganizar e liberar espaço em disco
      try {
        await db.run('PRAGMA incremental_vacuum;');
      } catch {}
    } else {
      console.log(`[AutoPrune] Nenhum log anterior a ${days} dias para arquivar.`);
    }

    const nowIso = new Date().toISOString();
    await db.setSetting('prune_last_run', nowIso);

    return {
      success: true,
      trigger,
      archivedCount: count,
      cutoffDate,
      retentionDays: days,
      backupFile: backupFileName,
      timestamp: nowIso
    };
  }

  /**
   * Lista todos os backups já gerados disponíveis para download
   */
  listBackups() {
    this.ensureBackupDir();
    try {
      const files = fs.readdirSync(this.backupDir);
      const backups = [];

      for (const f of files) {
        if (!f.endsWith('.csv') && !f.endsWith('.json')) continue;
        const fullPath = path.join(this.backupDir, f);
        const stats = fs.statSync(fullPath);

        backups.push({
          filename: f,
          sizeBytes: stats.size,
          sizeFormatted: this.formatBytes(stats.size),
          createdAt: stats.mtime.toISOString(),
          downloadUrl: `/api/backups/download/${encodeURIComponent(f)}`
        });
      }

      // Ordena pelos mais recentes
      return backups.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    } catch (err) {
      console.error('[AutoPrune] Erro ao listar backups:', err.message);
      return [];
    }
  }

  getBackupFilePath(filename) {
    // Sanitiza para evitar directory traversal
    const safeName = path.basename(filename);
    const fullPath = path.join(this.backupDir, safeName);
    if (fs.existsSync(fullPath)) {
      return fullPath;
    }
    return null;
  }

  deleteBackup(filename) {
    const safeName = path.basename(filename);
    const fullPath = path.join(this.backupDir, safeName);
    if (fs.existsSync(fullPath)) {
      fs.unlinkSync(fullPath);
      return true;
    }
    return false;
  }

  formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }
}

const autoPruneManager = new AutoPruneManager();
module.exports = autoPruneManager;
