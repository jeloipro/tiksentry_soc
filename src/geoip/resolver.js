const geoip = require('geoip-lite');
const config = require('../config');

// Mapa de Nomes de Países em Português para códigos ISO
const COUNTRY_NAMES = {
  BR: 'Brasil',
  US: 'Estados Unidos',
  CN: 'China',
  RU: 'Rússia',
  DE: 'Alemanha',
  FR: 'França',
  GB: 'Reino Unido',
  NL: 'Holanda',
  IN: 'Índia',
  JP: 'Japão',
  KR: 'Coreia do Sul',
  CA: 'Canadá',
  AU: 'Austrália',
  IT: 'Itália',
  ES: 'Espanha',
  UA: 'Ucrânia',
  PL: 'Polônia',
  SG: 'Cingapura',
  VN: 'Vietnã',
  ID: 'Indonésia',
  IR: 'Irã',
  TR: 'Turquia',
  RO: 'Romênia',
  BG: 'Bulgária',
  SE: 'Suécia',
  CH: 'Suíça',
  PT: 'Portugal',
  MX: 'México',
  AR: 'Argentina',
  CL: 'Chile',
  CO: 'Colômbia',
  PE: 'Peru',
  ZA: 'África do Sul',
  HK: 'Hong Kong',
  TW: 'Taiwan'
};

// Cache em memória para IPs já resolvidos (máximo 10.000 itens)
const ipCache = new Map();
const MAX_CACHE_SIZE = 10000;

/**
 * Verifica se um endereço IP é privado / RFC 1918 / Loopback / CGNAT
 */
function isPrivateIp(ip) {
  if (!ip || typeof ip !== 'string') return true;

  if (ip === '127.0.0.1' || ip === '::1' || ip.startsWith('127.')) return true;
  if (ip.startsWith('10.')) return true;
  if (ip.startsWith('192.168.')) return true;
  if (ip.startsWith('169.254.')) return true;

  // 172.16.0.0 a 172.31.255.255
  if (ip.startsWith('172.')) {
    const parts = ip.split('.');
    if (parts.length >= 2) {
      const second = parseInt(parts[1], 10);
      if (second >= 16 && second <= 31) return true;
    }
  }

  // 100.64.0.0/10 (CGNAT)
  if (ip.startsWith('100.')) {
    const parts = ip.split('.');
    if (parts.length >= 2) {
      const second = parseInt(parts[1], 10);
      if (second >= 64 && second <= 127) return true;
    }
  }

  return false;
}

/**
 * Resolve informações de GeoIP para um endereço IP
 */
function resolveGeoIp(ip) {
  if (!ip) {
    return {
      country: 'Desconhecido',
      country_code: 'XX',
      city: 'Desconhecido',
      latitude: 0,
      longitude: 0,
      is_private: false
    };
  }

  // Verifica cache
  if (ipCache.has(ip)) {
    return ipCache.get(ip);
  }

  // Se for IP privado / LAN
  if (isPrivateIp(ip)) {
    const result = {
      country: 'Rede Local / LAN',
      country_code: 'LAN',
      city: 'Privado',
      latitude: config.router.lat,
      longitude: config.router.lng,
      is_private: true
    };
    cacheResult(ip, result);
    return result;
  }

  try {
    const geo = geoip.lookup(ip);
    if (geo && geo.country) {
      const code = geo.country.toUpperCase();
      const countryName = COUNTRY_NAMES[code] || geo.country;
      const city = geo.city || 'Desconhecido';
      const lat = geo.ll && geo.ll[0] ? geo.ll[0] : 0;
      const lng = geo.ll && geo.ll[1] ? geo.ll[1] : 0;

      const result = {
        country: countryName,
        country_code: code,
        city: city,
        latitude: lat,
        longitude: lng,
        is_private: false
      };

      cacheResult(ip, result);
      return result;
    }
  } catch (err) {
    console.error(`[GeoIP] Erro ao resolver IP ${ip}:`, err.message);
  }

  const fallback = {
    country: 'Desconhecido',
    country_code: 'XX',
    city: 'Desconhecido',
    latitude: 0,
    longitude: 0,
    is_private: false
  };

  cacheResult(ip, fallback);
  return fallback;
}

function cacheResult(ip, data) {
  if (ipCache.size >= MAX_CACHE_SIZE) {
    // Remove o item mais antigo
    const firstKey = ipCache.keys().next().value;
    ipCache.delete(firstKey);
  }
  ipCache.set(ip, data);
}

module.exports = {
  resolveGeoIp,
  isPrivateIp
};
