const express = require('express');
const router = express.Router();
const autoPruneManager = require('../../storage/cleaner');

/**
 * GET /api/backups
 * Lista os arquivos de backup gerados
 */
router.get('/', (req, res) => {
  try {
    const list = autoPruneManager.listBackups();
    res.json({ success: true, data: list });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/backups/config
 * Retorna configurações do agendamento
 */
router.get('/config', async (req, res) => {
  try {
    const cfg = await autoPruneManager.getConfig();
    res.json({ success: true, data: cfg });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/backups/config
 * Atualiza configurações de agendamento (frequência, retenção)
 */
router.post('/config', async (req, res) => {
  try {
    const { enabled, frequency, retention_days, save_format } = req.body;
    const updated = await autoPruneManager.setConfig({
      enabled: enabled !== undefined ? (enabled === true || enabled === 'true') : undefined,
      frequency: frequency,
      retentionDays: retention_days ? parseInt(retention_days, 10) : undefined,
      saveFormat: save_format
    });
    res.json({ success: true, data: updated, message: 'Configurações de limpeza agendada atualizadas!' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/backups/run-now
 * Executa a limpeza e exportação imediatamente
 */
router.post('/run-now', async (req, res) => {
  try {
    const result = await autoPruneManager.performBackupAndCleanup('manual_force');
    res.json(result);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/backups/download/:filename
 * Download de um arquivo de backup
 */
router.get('/download/:filename', (req, res) => {
  try {
    const filePath = autoPruneManager.getBackupFilePath(req.params.filename);
    if (!filePath) {
      return res.status(404).json({ success: false, error: 'Arquivo de backup não encontrado.' });
    }
    res.download(filePath, req.params.filename);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * DELETE /api/backups/:filename
 * Remove um arquivo de backup
 */
router.delete('/:filename', (req, res) => {
  try {
    const ok = autoPruneManager.deleteBackup(req.params.filename);
    if (ok) {
      res.json({ success: true, message: 'Backup excluído com sucesso.' });
    } else {
      res.status(404).json({ success: false, error: 'Arquivo não encontrado.' });
    }
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
