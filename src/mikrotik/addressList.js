const db = require('../storage/db');
const mikrotikClient = require('./client');
const { resolveGeoIp } = require('../geoip/resolver');

class AddressListManager {
  constructor() {
    this.expirationInterval = null;
  }

  start() {
    // Verifica expirações a cada 60 segundos
    if (!this.expirationInterval) {
      this.expirationInterval = setInterval(() => {
        this.checkExpiredBlocks().catch(err => {
          console.error('[AddressList] Erro ao verificar expiração de IPs:', err.message);
        });
      }, 60000);
      console.log('[AddressList] Gerenciador de expiração de IPs bloqueados ativo (intervalo 60s).');
    }
  }

  stop() {
    if (this.expirationInterval) {
      clearInterval(this.expirationInterval);
      this.expirationInterval = null;
    }
  }

  /**
   * Bloqueia um IP no sistema e sincroniza com o MikroTik
   */
  async blockIp({
    ip,
    reason = 'TikSentry Auto-Block',
    durationMinutes = 60,
    ruleId = null,
    ruleName = null,
    isPermanent = false,
    geoData = null
  }) {
    if (!ip) return { success: false, error: 'IP inválido' };

    const now = new Date();
    const blockedAt = now.toISOString();

    let expiresAt = null;
    if (!isPermanent && durationMinutes > 0) {
      expiresAt = new Date(now.getTime() + durationMinutes * 60 * 1000).toISOString();
    }

    const geo = geoData || resolveGeoIp(ip);
    const params = await mikrotikClient.getParams();
    const listName = params.blockListName || 'TIKSENTRY_BLOCKED';

    // 1. Tenta enviar o bloqueio para o MikroTik via API
    let mikrotikSynced = 0;
    try {
      const blockRes = await mikrotikClient.addIpToAddressList(
        ip,
        reason,
        isPermanent ? 0 : durationMinutes,
        listName
      );
      if (blockRes.success) {
        mikrotikSynced = 1;
      }
    } catch (err) {
      console.warn(`[AddressList] Aviso: Falha ao sincronizar bloqueio de ${ip} no MikroTik: ${err.message}`);
    }

    // 2. Registra ou atualiza no banco SQLite local
    await db.run(`
      INSERT INTO blocked_ips (
        ip, reason, rule_id, rule_name, blocked_at, expires_at,
        is_permanent, synced_to_mikrotik, mikrotik_list_name,
        country, city, country_code, latitude, longitude, hit_count, last_hit_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
      ON CONFLICT(ip) DO UPDATE SET
        reason = excluded.reason,
        rule_id = excluded.rule_id,
        rule_name = excluded.rule_name,
        expires_at = excluded.expires_at,
        is_permanent = excluded.is_permanent,
        synced_to_mikrotik = excluded.synced_to_mikrotik,
        hit_count = blocked_ips.hit_count + 1,
        last_hit_at = excluded.last_hit_at
    `, [
      ip,
      reason,
      ruleId,
      ruleName,
      blockedAt,
      expiresAt,
      isPermanent ? 1 : 0,
      mikrotikSynced,
      listName,
      geo.country,
      geo.city,
      geo.country_code,
      geo.latitude,
      geo.longitude,
      blockedAt
    ]);

    return {
      success: true,
      ip,
      syncedToMikrotik: mikrotikSynced === 1,
      expiresAt
    };
  }

  /**
   * Desbloqueia manualmente um IP
   */
  async unblockIp(ip) {
    if (!ip) return { success: false, error: 'IP inválido' };

    const params = await mikrotikClient.getParams();
    const listName = params.blockListName || 'TIKSENTRY_BLOCKED';

    // Remove do MikroTik
    try {
      await mikrotikClient.removeIpFromAddressList(ip, listName);
    } catch (err) {
      console.warn(`[AddressList] Falha ao remover ${ip} do MikroTik: ${err.message}`);
    }

    // Remove do banco local
    await db.run('DELETE FROM blocked_ips WHERE ip = ?', [ip]);

    return { success: true, ip };
  }

  /**
   * Verifica e remove automaticamente IPs com tempo de bloqueio expirado
   */
  async checkExpiredBlocks() {
    const nowIso = new Date().toISOString();
    const expiredList = await db.all(
      'SELECT ip, mikrotik_list_name FROM blocked_ips WHERE is_permanent = 0 AND expires_at IS NOT NULL AND expires_at <= ?',
      [nowIso]
    );

    if (!expiredList || expiredList.length === 0) return;

    for (const item of expiredList) {
      console.log(`[AddressList] Desbloqueando IP expirado: ${item.ip}`);
      try {
        await mikrotikClient.removeIpFromAddressList(item.ip, item.mikrotik_list_name);
      } catch (err) {
        console.warn(`[AddressList] Falha ao remover ${item.ip} do router:`, err.message);
      }
      await db.run('DELETE FROM blocked_ips WHERE ip = ?', [item.ip]);
    }
  }

  /**
   * Sincroniza a lista do MikroTik com a lista local
   */
  async syncWithRouter() {
    const params = await mikrotikClient.getParams();
    const listName = params.blockListName || 'TIKSENTRY_BLOCKED';

    const routerEntries = await mikrotikClient.getBlockedListFromMikroTik(listName);
    const localEntries = await db.all('SELECT ip, synced_to_mikrotik FROM blocked_ips');

    const routerIpSet = new Set(routerEntries.map(e => e.address).filter(Boolean));

    // Atualiza status dos locais
    for (const local of localEntries) {
      const isPresentOnRouter = routerIpSet.has(local.ip);
      if (isPresentOnRouter && local.synced_to_mikrotik === 0) {
        await db.run('UPDATE blocked_ips SET synced_to_mikrotik = 1 WHERE ip = ?', [local.ip]);
      } else if (!isPresentOnRouter && local.synced_to_mikrotik === 1) {
        // Envia para o roteador se deveria estar lá
        await mikrotikClient.addIpToAddressList(local.ip, 'TikSentry Re-Sync', 60, listName);
      }
    }

    // Registra novos IPs encontrados no roteador que não estavam no banco
    const now = new Date().toISOString();
    for (const rEntry of routerEntries) {
      const ip = rEntry.address;
      if (!ip) continue;

      const exists = await db.get('SELECT ip FROM blocked_ips WHERE ip = ?', [ip]);
      if (!exists) {
        const geo = resolveGeoIp(ip);
        await db.run(`
          INSERT INTO blocked_ips (
            ip, reason, rule_name, blocked_at, is_permanent, synced_to_mikrotik, mikrotik_list_name,
            country, city, country_code, latitude, longitude, hit_count, last_hit_at
          ) VALUES (?, ?, ?, ?, 1, 1, ?, ?, ?, ?, ?, ?, 1, ?)
        `, [
          ip,
          rEntry.comment || 'Importado do MikroTik',
          'MikroTik Existing',
          now,
          listName,
          geo.country,
          geo.city,
          geo.country_code,
          geo.latitude,
          geo.longitude,
          now
        ]);
      }
    }

    return {
      success: true,
      routerTotal: routerEntries.length,
      syncedAt: now
    };
  }
}

const addressListManager = new AddressListManager();
module.exports = addressListManager;
