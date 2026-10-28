const express = require('express');
const router = express.Router();
const db = require('../../storage/db');
const addressListManager = require('../../mikrotik/addressList');
const idsEngine = require('../../ids/engine');

/**
 * GET /api/ids/rules
 * Lista todas as regras de detecção IDS
 */
router.get('/rules', async (req, res) => {
  try {
    const rules = await db.all('SELECT * FROM ids_rules ORDER BY severity DESC, name ASC');
    res.json({ success: true, data: rules });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * PUT /api/ids/rules/:id
 * Atualiza parâmetros de uma regra IDS
 */
router.put('/rules/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const {
      enabled,
      auto_block,
      block_duration_minutes,
      threshold_count,
      threshold_window_seconds
    } = req.body;

    await db.run(`
      UPDATE ids_rules SET
        enabled = COALESCE(?, enabled),
        auto_block = COALESCE(?, auto_block),
        block_duration_minutes = COALESCE(?, block_duration_minutes),
        threshold_count = COALESCE(?, threshold_count),
        threshold_window_seconds = COALESCE(?, threshold_window_seconds)
      WHERE id = ?
    `, [
      enabled !== undefined ? (enabled ? 1 : 0) : null,
      auto_block !== undefined ? (auto_block ? 1 : 0) : null,
      block_duration_minutes !== undefined ? parseInt(block_duration_minutes, 10) : null,
      threshold_count !== undefined ? parseInt(threshold_count, 10) : null,
      threshold_window_seconds !== undefined ? parseInt(threshold_window_seconds, 10) : null,
      id
    ]);

    // Recarrega as regras no engine em memória
    await idsEngine.reloadRules();

    const updated = await db.get('SELECT * FROM ids_rules WHERE id = ?', [id]);
    res.json({ success: true, data: updated });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/ids/blocked
 * Lista todos os IPs bloqueados (IPS)
 */
router.get('/blocked', async (req, res) => {
  try {
    const rows = await db.all('SELECT * FROM blocked_ips ORDER BY blocked_at DESC');
    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/ids/blocked
 * Bloqueia um IP manualmente
 */
router.post('/blocked', async (req, res) => {
  try {
    const { ip, reason, duration_minutes, is_permanent } = req.body;
    if (!ip || !ip.trim()) {
      return res.status(400).json({ success: false, error: 'Endereço IP é obrigatório.' });
    }

    const duration = parseInt(duration_minutes, 10) || 60;
    const perm = is_permanent === true || is_permanent === 'true' || duration <= 0;

    const result = await addressListManager.blockIp({
      ip: ip.trim(),
      reason: reason || 'Bloqueio Manual via TikSentry',
      durationMinutes: duration,
      isPermanent: perm
    });

    res.json({ success: true, data: result });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * DELETE /api/ids/blocked/:ip
 * Desbloqueia um IP manualmente
 */
router.delete('/blocked/:ip', async (req, res) => {
  try {
    const { ip } = req.params;
    const result = await addressListManager.unblockIp(ip);
    res.json({ success: true, data: result });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/ids/sync
 * Sincroniza a lista de bloqueados com o MikroTik
 */
router.post('/sync', async (req, res) => {
  try {
    const result = await addressListManager.syncWithRouter();
    res.json({ success: true, data: result });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/ids/events
 * Retorna os últimos eventos de alerta detectados
 */
router.get('/events', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 30, 100);
    const events = await db.all('SELECT * FROM ids_events ORDER BY id DESC LIMIT ?', [limit]);
    res.json({ success: true, data: events });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
