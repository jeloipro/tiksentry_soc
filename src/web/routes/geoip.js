const express = require('express');
const router = express.Router();
const db = require('../../storage/db');
const config = require('../../config');
const reportGenerator = require('../../reports/generator');

/**
 * GET /api/geoip/attacks
 * Retorna clusters de ataques para o mapa interativo
 */
router.get('/attacks', async (req, res) => {
  try {
    const range = req.query.range || '24h';
    const cutoff = reportGenerator.getCutoffDate(range);

    const whereClauses = ['timestamp >= ?', 'latitude != 0', "country_code NOT IN ('LAN', 'XX')"];
    const params = [cutoff];

    if (req.query.country && req.query.country !== 'all') {
      whereClauses.push('country_code = ?');
      params.push(req.query.country.toUpperCase());
    }

    if (req.query.city && req.query.city !== 'all') {
      whereClauses.push('city = ?');
      params.push(req.query.city);
    }

    if (req.query.ip) {
      whereClauses.push('src_ip LIKE ?');
      params.push(`%${req.query.ip.trim()}%`);
    }

    if (req.query.port) {
      whereClauses.push('dst_port = ?');
      params.push(parseInt(req.query.port, 10));
    }

    if (req.query.protocol && req.query.protocol !== 'all') {
      whereClauses.push('protocol = ?');
      params.push(req.query.protocol.toLowerCase());
    }

    const whereSql = `WHERE ${whereClauses.join(' AND ')}`;

    // Agrupa por Cidade/Coordenadas para desenhar os marcadores com contagem e intensidade
    const points = await db.all(`
      SELECT 
        city, country, country_code, latitude, longitude,
        COUNT(*) as total_attacks,
        SUM(CASE WHEN is_threat = 1 THEN 1 ELSE 0 END) as threat_attacks,
        MAX(timestamp) as last_attack,
        GROUP_CONCAT(DISTINCT src_ip) as sample_ips,
        GROUP_CONCAT(DISTINCT dst_port) as targeted_ports
      FROM firewall_logs
      ${whereSql}
      GROUP BY latitude, longitude, city, country
      ORDER BY total_attacks DESC
      LIMIT 300
    `, params);

    // Formata pontos para o Leaflet Map
    const formatted = points.map(pt => {
      const ips = (pt.sample_ips || '').split(',').slice(0, 5);
      const ports = (pt.targeted_ports || '').split(',').filter(p => p && p !== '0').slice(0, 5);

      return {
        lat: pt.latitude,
        lng: pt.longitude,
        city: pt.city,
        country: pt.country,
        countryCode: pt.country_code,
        totalAttacks: pt.total_attacks,
        threatAttacks: pt.threat_attacks,
        lastAttack: pt.last_attack,
        sampleIps: ips,
        targetedPorts: ports
      };
    });

    const routerSettings = await db.getAllSettings();
    const routerLocation = {
      lat: parseFloat(routerSettings['router_lat']) || config.router.lat,
      lng: parseFloat(routerSettings['router_lng']) || config.router.lng,
      name: routerSettings['router_name'] || config.router.name
    };

    res.json({
      success: true,
      timeframe: range,
      routerLocation,
      pointsCount: formatted.length,
      points: formatted
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/geoip/filters
 * Retorna listas dinâmicas de países e cidades para os filtros
 */
router.get('/filters', async (req, res) => {
  try {
    const cutoff = reportGenerator.getCutoffDate('7d');

    const [countries, cities] = await Promise.all([
      db.all(`
        SELECT DISTINCT country, country_code, COUNT(*) as count 
        FROM firewall_logs 
        WHERE timestamp >= ? AND country_code NOT IN ('LAN', 'XX')
        GROUP BY country_code 
        ORDER BY count DESC 
        LIMIT 50
      `, [cutoff]),

      db.all(`
        SELECT DISTINCT city, country, COUNT(*) as count 
        FROM firewall_logs 
        WHERE timestamp >= ? AND city NOT IN ('Desconhecido', 'Privado')
        GROUP BY city, country 
        ORDER BY count DESC 
        LIMIT 60
      `, [cutoff])
    ]);

    res.json({
      success: true,
      countries,
      cities
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
