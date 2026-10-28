const express = require('express');
const router = express.Router();
const db = require('../../storage/db');

/**
 * GET /api/logs
 * Retorna logs de firewall com suporte a paginação e filtros
 */
router.get('/', async (req, res) => {
  try {
    const page = parseInt(req.query.page, 10) || 1;
    const limit = Math.min(parseInt(req.query.limit, 10) || 50, 200);
    const offset = (page - 1) * limit;

    const whereClauses = [];
    const params = [];

    if (req.query.search) {
      const s = `%${req.query.search.trim()}%`;
      whereClauses.push('(src_ip LIKE ? OR dst_ip LIKE ? OR threat_reason LIKE ? OR raw_message LIKE ?)');
      params.push(s, s, s, s);
    }

    if (req.query.action && req.query.action !== 'all') {
      whereClauses.push('action = ?');
      params.push(req.query.action.toLowerCase());
    }

    if (req.query.chain && req.query.chain !== 'all') {
      whereClauses.push('chain = ?');
      params.push(req.query.chain.toLowerCase());
    }

    if (req.query.protocol && req.query.protocol !== 'all') {
      whereClauses.push('protocol = ?');
      params.push(req.query.protocol.toLowerCase());
    }

    if (req.query.threats_only === 'true') {
      whereClauses.push('is_threat = 1');
    }

    if (req.query.country && req.query.country !== 'all') {
      whereClauses.push('country_code = ?');
      params.push(req.query.country.toUpperCase());
    }

    const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

    const countRow = await db.get(`SELECT COUNT(*) as total FROM firewall_logs ${whereSql}`, params);
    const total = countRow ? countRow.total : 0;

    const rows = await db.all(
      `SELECT * FROM firewall_logs ${whereSql} ORDER BY id DESC LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );

    res.json({
      success: true,
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
      data: rows
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/logs/stats
 * Estatísticas rápidas para cards do Dashboard
 */
router.get('/stats', async (req, res) => {
  try {
    const cutoff24h = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const cutoff1h = new Date(Date.now() - 60 * 60 * 1000).toISOString();

    const [stats24h, stats1h, blockedCount] = await Promise.all([
      db.get(`
        SELECT 
          COUNT(*) as total_events,
          SUM(CASE WHEN is_threat = 1 THEN 1 ELSE 0 END) as threats,
          SUM(CASE WHEN action IN ('drop', 'reject') THEN 1 ELSE 0 END) as dropped,
          COUNT(DISTINCT src_ip) as unique_sources,
          COUNT(DISTINCT CASE WHEN is_threat = 1 THEN src_ip END) as unique_attackers
        FROM firewall_logs 
        WHERE timestamp >= ?
      `, [cutoff24h]),

      db.get(`
        SELECT COUNT(*) as events_last_hour 
        FROM firewall_logs 
        WHERE timestamp >= ?
      `, [cutoff1h]),

      db.get('SELECT COUNT(*) as count FROM blocked_ips')
    ]);

    const totalEvents = stats24h?.total_events || 0;
    const threats = stats24h?.threats || 0;
    const dropped = stats24h?.dropped || 0;

    res.json({
      success: true,
      data: {
        totalEvents,
        threats,
        dropped,
        uniqueSources: stats24h?.unique_sources || 0,
        uniqueAttackers: stats24h?.unique_attackers || 0,
        activeBlockedIps: blockedCount?.count || 0,
        eventsLastHour: stats1h?.events_last_hour || 0,
        eventsPerMinute: Math.round((stats1h?.events_last_hour || 0) / 60)
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * DELETE /api/logs
 * Limpa logs
 */
router.delete('/', async (req, res) => {
  try {
    const days = parseInt(req.query.older_than_days, 10);
    if (days && days > 0) {
      const removed = await db.cleanupOldLogs(days);
      return res.json({ success: true, message: `${removed} logs antigos removidos.` });
    }

    await db.run('DELETE FROM firewall_logs');
    res.json({ success: true, message: 'Todos os logs foram limpos com sucesso.' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
