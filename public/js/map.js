/**
 * TIKSENTRY - MOTOR DO MAPA DE ATAQUES GEOIP (LEAFLET)
 */

let mapInstance = null;
let routerMarker = null;
let attackMarkersLayer = null;
let attackLinesLayer = null;
let currentRouterCoords = [-23.5505, -46.6333];

function initAttackMap() {
  if (mapInstance) {
    window.mapInstance = mapInstance;
    return;
  }

  const mapContainer = document.getElementById('attackMap');
  if (!mapContainer) return;

  // Inicializa o mapa com visual escuro de cibersegurança
  mapInstance = L.map('attackMap', {
    center: [20, 0],
    zoom: 2,
    minZoom: 2,
    maxZoom: 16,
    zoomControl: true
  });

  window.mapInstance = mapInstance;

  // Camada Base Dark Gray 100% gratuita da ESRI (sem necessidade de API Key)
  L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}', {
    attribution: '&copy; Esri &mdash; Esri, DeLorme, NAVTEQ | TikSentry SOC',
    maxZoom: 16
  }).addTo(mapInstance);

  // Camada de Rótulos de Países e Fronteiras (Dark Gray Reference)
  L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Reference/MapServer/tile/{z}/{y}/{x}', {
    attribution: '',
    maxZoom: 16,
    opacity: 0.85
  }).addTo(mapInstance);

  attackMarkersLayer = L.layerGroup().addTo(mapInstance);
  attackLinesLayer = L.layerGroup().addTo(mapInstance);

  // Força cálculo correto de dimensões
  setTimeout(() => {
    if (mapInstance) mapInstance.invalidateSize(true);
  }, 100);

  // Carrega filtros dinâmicos e dados
  loadMapFilters();
  refreshMapData();
}

/**
 * Carrega lista de Países e Cidades para os dropdowns de filtro
 */
async function loadMapFilters() {
  try {
    const res = await fetch('/api/geoip/filters');
    const data = await res.json();
    if (!data.success) return;

    const countrySelect = document.getElementById('filterMapCountry');
    const citySelect = document.getElementById('filterMapCity');

    if (countrySelect && data.countries) {
      countrySelect.innerHTML = '<option value="all">Todos os Países</option>';
      data.countries.forEach(c => {
        countrySelect.innerHTML += `<option value="${c.country_code}">${c.country} (${c.count})</option>`;
      });
    }

    if (citySelect && data.cities) {
      citySelect.innerHTML = '<option value="all">Todas as Cidades</option>';
      data.cities.forEach(ct => {
        citySelect.innerHTML += `<option value="${ct.city}">${ct.city} - ${ct.country} (${ct.count})</option>`;
      });
    }
  } catch (err) {
    console.error('Erro ao carregar filtros do mapa:', err);
  }
}

/**
 * Consulta a API com os filtros ativos e plota os ataques no mapa
 */
async function refreshMapData() {
  if (!mapInstance) return;

  const range = document.getElementById('filterMapRange')?.value || '24h';
  const country = document.getElementById('filterMapCountry')?.value || 'all';
  const city = document.getElementById('filterMapCity')?.value || 'all';
  const ip = document.getElementById('filterMapIp')?.value || '';
  const port = document.getElementById('filterMapPort')?.value || '';
  const protocol = document.getElementById('filterMapProto')?.value || 'all';

  const params = new URLSearchParams({ range, country, city, ip, port, protocol });

  try {
    const res = await fetch(`/api/geoip/attacks?${params.toString()}`);
    const data = await res.json();
    if (!data.success) return;

    // Atualiza localização do Roteador / Datacenter central
    if (data.routerLocation && data.routerLocation.lat && data.routerLocation.lng) {
      currentRouterCoords = [data.routerLocation.lat, data.routerLocation.lng];
      updateRouterMarker(data.routerLocation);
    }

    // Limpa marcadores anteriores
    attackMarkersLayer.clearLayers();
    attackLinesLayer.clearLayers();

    // Renderiza pontos de ataque
    data.points.forEach(pt => {
      renderAttackPoint(pt);
    });

    // Atualiza painel lateral com Top Países
    updateMapSidePanel(data.points);

    // Ajusta visualização se houver pontos
    const countBadge = document.getElementById('mapPointsCount');
    if (countBadge) countBadge.textContent = `${data.pointsCount} Origens`;

  } catch (err) {
    console.error('Erro ao atualizar dados do mapa:', err);
  }
}

function updateRouterMarker(routerLoc) {
  if (routerMarker) {
    routerMarker.remove();
  }

  const routerIcon = L.divIcon({
    className: 'router-map-icon',
    html: `
      <div style="position:relative; width:30px; height:30px;">
        <div style="position:absolute; width:100%; height:100%; border-radius:50%; background:#00ff9d; opacity:0.3; animation:pulse 2s infinite;"></div>
        <div style="position:absolute; top:6px; left:6px; width:18px; height:18px; border-radius:50%; background:#00ff9d; border:2px solid #fff; box-shadow:0 0 10px #00ff9d; display:flex; align-items:center; justify-content:center; font-size:10px;">🛡️</div>
      </div>
    `,
    iconSize: [30, 30],
    iconAnchor: [15, 15]
  });

  routerMarker = L.marker([routerLoc.lat, routerLoc.lng], { icon: routerIcon }).addTo(mapInstance);
  routerMarker.bindPopup(`
    <div class="map-popup">
      <h4>🛡️ ${routerLoc.name || 'MikroTik Gateway'}</h4>
      <p>Gateway Protegido pelo TikSentry SOC</p>
      <p>Coordenadas: <strong>${routerLoc.lat.toFixed(4)}, ${routerLoc.lng.toFixed(4)}</strong></p>
    </div>
  `);
}

function renderAttackPoint(pt) {
  const isHighThreat = pt.threatAttacks > 0;
  const radius = Math.min(Math.max(Math.sqrt(pt.totalAttacks) * 4, 7), 24);
  const color = isHighThreat ? '#ff0055' : '#00f0ff';

  const circleMarker = L.circleMarker([pt.lat, pt.lng], {
    radius: radius,
    fillColor: color,
    color: '#ffffff',
    weight: 1.5,
    opacity: 0.9,
    fillOpacity: 0.65
  });

  // Linha conectando o ataque ao Roteador
  const attackLine = L.polyline([[pt.lat, pt.lng], currentRouterCoords], {
    color: color,
    weight: 1.2,
    opacity: 0.35,
    dashArray: '4, 8'
  });

  attackLinesLayer.addLayer(attackLine);

  // Conteúdo do Popup
  const sampleIpsHtml = pt.sampleIps.map(ip => `
    <div style="display:flex; justify-content:space-between; align-items:center; margin:4px 0;">
      <span class="ip-badge" style="font-size:0.75rem;">${ip}</span>
      <button class="btn btn-danger btn-sm" onclick="quickBlockIp('${ip}', 'Bloqueio via Mapa GeoIP')">Bloquear</button>
    </div>
  `).join('');

  const popupHtml = `
    <div class="map-popup">
      <h4>📍 ${pt.city}, ${pt.country} (${pt.countryCode})</h4>
      <p>Total de Pacotes Descartados: <strong>${pt.totalAttacks}</strong></p>
      <p>Ataques Maliciosos (IDS): <strong style="color:${isHighThreat ? '#ff0055' : '#00ff9d'};">${pt.threatAttacks}</strong></p>
      <p>Portas Alvo: <strong>${pt.targetedPorts.join(', ') || 'N/A'}</strong></p>
      <p>Último Ataque: <strong>${new Date(pt.lastAttack).toLocaleTimeString()}</strong></p>
      <div style="margin-top:10px; border-top:1px solid #1a2742; padding-top:6px;">
        <span style="font-size:0.7rem; color:#8492a6; text-transform:uppercase; font-weight:700;">IPs Detectados nesta Localidade:</span>
        ${sampleIpsHtml}
      </div>
    </div>
  `;

  circleMarker.bindPopup(popupHtml);
  attackMarkersLayer.addLayer(circleMarker);
}

function updateMapSidePanel(points) {
  const container = document.getElementById('mapCountryList');
  if (!container) return;

  // Agrupa por País
  const countryMap = {};
  let totalAttacksSum = 0;

  points.forEach(pt => {
    if (!countryMap[pt.countryCode]) {
      countryMap[pt.countryCode] = {
        name: pt.country,
        code: pt.countryCode,
        count: 0
      };
    }
    countryMap[pt.countryCode].count += pt.totalAttacks;
    totalAttacksSum += pt.totalAttacks;
  });

  const sortedCountries = Object.values(countryMap).sort((a, b) => b.count - a.count).slice(0, 8);

  if (sortedCountries.length === 0) {
    container.innerHTML = '<p style="color:var(--text-muted); font-size:0.8rem; text-align:center; margin-top:20px;">Nenhum ataque registrado com os filtros atuais.</p>';
    return;
  }

  container.innerHTML = sortedCountries.map(c => {
    const pct = totalAttacksSum > 0 ? ((c.count / totalAttacksSum) * 100).toFixed(1) : 0;
    return `
      <div class="country-item">
        <div class="country-info">
          <span><strong>${c.code}</strong> ${c.name}</span>
          <span><strong>${c.count}</strong> (${pct}%)</span>
        </div>
        <div class="progress-bar-bg">
          <div class="progress-bar-fill" style="width: ${pct}%;"></div>
        </div>
      </div>
    `;
  }).join('');
}

/**
 * Função de bloqueio rápido a partir do popup do mapa
 */
async function quickBlockIp(ip, reason) {
  if (!confirm(`Deseja realmente bloquear o IP ${ip} no MikroTik imediatamente?`)) return;

  try {
    const res = await fetch('/api/ids/blocked', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, reason, duration_minutes: 120 })
    });
    const data = await res.json();
    if (data.success) {
      alert(`IP ${ip} foi adicionado à lista de bloqueio do MikroTik com sucesso!`);
      if (window.loadBlockedIps) window.loadBlockedIps();
      mapInstance.closePopup();
    } else {
      alert(`Erro ao bloquear IP: ${data.error}`);
    }
  } catch (err) {
    alert(`Erro na requisição: ${err.message}`);
  }
}

/**
 * Animação de pulso instantâneo no mapa quando chega um novo ataque pelo WebSocket
 */
function triggerLiveAttackOnMap(log) {
  if (!mapInstance || !log.latitude || !log.longitude) return;

  const pulseMarker = L.circleMarker([log.latitude, log.longitude], {
    radius: 12,
    fillColor: '#ff0055',
    color: '#ffffff',
    weight: 2,
    opacity: 1,
    fillOpacity: 0.9
  }).addTo(mapInstance);

  const laserLine = L.polyline([[log.latitude, log.longitude], currentRouterCoords], {
    color: '#ff0055',
    weight: 2.5,
    opacity: 0.9
  }).addTo(mapInstance);

  // Desaparece gradualmente em 3 segundos
  setTimeout(() => {
    try {
      pulseMarker.remove();
      laserLine.remove();
    } catch {}
  }, 2500);
}

window.initAttackMap = initAttackMap;
window.refreshMapData = refreshMapData;
window.triggerLiveAttackOnMap = triggerLiveAttackOnMap;
window.quickBlockIp = quickBlockIp;
window.mapInstance = mapInstance;
