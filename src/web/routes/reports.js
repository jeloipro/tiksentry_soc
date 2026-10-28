const express = require('express');
const router = express.Router();
const reportGenerator = require('../../reports/generator');

/**
 * GET /api/reports/full
 * Retorna dados completos do relatório formatado
 */
router.get('/full', async (req, res) => {
  try {
    const range = req.query.range || '24h';
    const report = await reportGenerator.generateFullReport(range);
    res.json({ success: true, data: report });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/reports/csv/logs
 * Download de CSV com histórico de logs
 */
router.get('/csv/logs', async (req, res) => {
  try {
    const range = req.query.range || '24h';
    const csvContent = await reportGenerator.generateLogsCsv(range);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="tiksentry-logs-${range}.csv"`);
    res.send(csvContent);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/reports/csv/attackers
 * Download de CSV com lista de atacantes
 */
router.get('/csv/attackers', async (req, res) => {
  try {
    const range = req.query.range || '24h';
    const csvContent = await reportGenerator.generateAttackersCsv(range);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="tiksentry-attackers-${range}.csv"`);
    res.send(csvContent);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
