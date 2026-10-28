/**
 * TIKSENTRY - ORQUESTRADOR DO FRONTEND SOC E WEBSOCKET CLIENT
 */

let wsConnection = null;
let isLogStreamingPaused = false;
let isAudioMuted = false;
let audioContext = null;

document.addEventListener('DOMContentLoaded', () => {
  initClock();
  initTabs();
  initWebSocket();
  initAudio();

  // Inicializa componentes
  if (window.initCharts) window.initCharts();
  if (window.initAttackMap) window.initAttackMap();

  // Carrega dados iniciais
  loadInitialData();

  // Atualização periódica dos cards a cada 10 segundos
  setInterval(loadDashboardStats, 10000);
});

/**
 * Controle de abas do SOC
 */
function initTabs() {
  const tabs = document.querySelectorAll('.nav-tab');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const targetId = tab.getAttribute('data-target');

      document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

      tab.classList.add('active');
      const targetContent = document.getElementById(targetId);
      if (targetContent) targetContent.classList.add('active');

      // Se abriu a aba do Mapa, garante inicialização e redimensiona o Leaflet
      if (targetId === 'tab-map') {
        if (!window.mapInstance && window.initAttackMap) {
          window.initAttackMap();
        }
        setTimeout(() => {
          if (window.mapInstance) {
            window.mapInstance.invalidateSize(true);
            if (window.refreshMapData) window.refreshMapData();
          }
        }, 100);
        setTimeout(() => {
          if (window.mapInstance) {
            window.mapInstance.invalidateSize(true);
          }
        }, 300);
      }

      // Se abriu a aba de IDS
      if (targetId === 'tab-ids') {
        if (window.loadIdsRules) window.loadIdsRules();
        if (window.loadBlockedIps) window.loadBlockedIps();
      }

      // Se abriu a aba de Configuração MikroTik
      if (targetId === 'tab-mikrotik') {
        if (window.loadMikrotikConfig) window.loadMikrotikConfig();
      }

      // Se abriu a aba de Relatórios
      if (targetId === 'tab-reports') {
        const range = document.getElementById('reportTimeRangeSelect')?.value || '24h';
        if (window.loadFullReport) window.loadFullReport(range);
        if (window.loadPruneConfigAndBackups) window.loadPruneConfigAndBackups();
      }
    });
  });
}

/**
 * Relógio em tempo real no cabeçalho
 */
function initClock() {
  const clockEl = document.getElementById('headerClock');
  const updateClock = () => {
    if (clockEl) {
      const now = new Date();
      clockEl.textContent = now.toLocaleTimeString() + ' UTC' + (now.getTimezoneOffset() <= 0 ? '+' : '-') + Math.abs(now.getTimezoneOffset() / 60);
    }
  };
  updateClock();
  setInterval(updateClock, 1000);
}

/**
 * WebSocket em tempo real para recebimento de logs e alertas
 */
function initWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws`;

  wsConnection = new WebSocket(wsUrl);

  wsConnection.onopen = () => {
    console.log('[WebSocket] Conectado ao servidor TikSentry.');
    const wsDot = document.getElementById('headerWsStatus');
    if (wsDot) wsDot.className = 'status-dot';
  };

  wsConnection.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      handleWebSocketMessage(data);
    } catch (err) {
      console.error('[WebSocket] Erro ao parsear mensagem:', err);
    }
  };

  wsConnection.onclose = () => {
    console.warn('[WebSocket] Conexão encerrada. Reconectando em 3s...');
    const wsDot = document.getElementById('headerWsStatus');
    if (wsDot) wsDot.className = 'status-dot danger';
    setTimeout(initWebSocket, 3000);
  };
}

function handleWebSocketMessage(msg) {
  if (msg.type === 'FIREWALL_LOG') {
    appendLogToStream(msg.log);
    if (msg.log.is_threat && window.triggerLiveAttackOnMap) {
      window.triggerLiveAttackOnMap(msg.log);
    }
  } else if (msg.type === 'IDS_ALERT') {
    const isLan = msg.alert && msg.alert.zone === 'LAN';
    const hideLan = localStorage.getItem('tiksentry_hide_lan_alerts') === 'true';
    if (isLan && hideLan) {
      // Alerta da rede interna (LAN) silenciado a pedido do usuário
      return;
    }

    showIdsAlertBanner(msg.alert);
    playAlertTone();
    if (window.triggerLiveAttackOnMap) {
      window.triggerLiveAttackOnMap(msg.alert);
    }
    // Atualiza contadores
    loadDashboardStats();
  }
}

/**
 * Adiciona log em tempo real na tabela de streaming
 */
function appendLogToStream(log) {
  if (isLogStreamingPaused) return;

  const tbody = document.getElementById('liveLogsTableBody');
  if (!tbody) return;

  const row = document.createElement('tr');
  if (log.is_threat) row.style.backgroundColor = 'rgba(255, 0, 85, 0.08)';

  const zone = log.zone || 'WAN';
  const timeStr = new Date(log.timestamp).toLocaleTimeString();
  const actionClass = (log.action || 'drop').toLowerCase();

  const zoneBadge = zone === 'LAN'
    ? `<span class="action-badge" style="background:rgba(255,170,0,0.15); color:var(--amber); border:1px solid rgba(255,170,0,0.4); font-size:0.7rem;">🏠 LAN</span>`
    : `<span class="action-badge" style="background:rgba(0,240,255,0.12); color:var(--cyan); border:1px solid rgba(0,240,255,0.35); font-size:0.7rem;">🌐 WAN</span>`;

  row.setAttribute('data-zone', zone);
  row.setAttribute('data-chain', (log.chain || '').toLowerCase());
  row.setAttribute('data-threat', log.is_threat ? '1' : '0');
  row.setAttribute('data-search', `${log.src_ip} ${log.dst_port} ${log.threat_reason || ''} ${log.in_interface || ''}`.toLowerCase());

  row.innerHTML = `
    <td style="font-family:var(--font-mono); font-size:0.75rem; color:var(--text-muted);">${timeStr}</td>
    <td>${zoneBadge}</td>
    <td><span class="action-badge ${actionClass}">${log.action}</span></td>
    <td><span class="port-badge">${log.chain || 'input'}</span></td>
    <td><span class="port-badge">${(log.protocol || 'TCP').toUpperCase()}</span></td>
    <td><span class="port-badge" style="font-size:0.7rem; color:#fff;">in:${log.in_interface || '-'}</span></td>
    <td>
      <span class="ip-badge">${log.src_ip}</span>:${log.src_port || 0}
      <div style="font-size:0.68rem; color:var(--text-muted);">${log.country || ''} (${log.city || ''})</div>
    </td>
    <td>
      <span class="ip-badge">${log.dst_ip}</span>:<strong style="color:var(--cyan);">${log.dst_port || 0}</strong>
    </td>
    <td style="font-size:0.75rem;">${log.packet_size || 0}B</td>
    <td style="font-size:0.75rem; color:${log.is_threat ? 'var(--crimson)' : 'var(--text-muted)'}; font-weight:${log.is_threat ? '700' : 'normal'};">
      ${log.threat_reason || log.tcp_flags || log.connection_state || '-'}
    </td>
  `;

  // Aplica filtro ativo imediatamente na linha recém-chegada
  applyRowVisibility(row);

  tbody.insertBefore(row, tbody.firstChild);

  // Limita a 200 linhas no DOM para performance ultra-leve
  if (tbody.children.length > 200) {
    tbody.removeChild(tbody.lastChild);
  }
}

function applyRowVisibility(row) {
  const zoneFilter = document.getElementById('filterLogsZone')?.value || 'all';
  const chainFilter = document.getElementById('filterLogsChain')?.value || 'all';
  const threatFilter = document.getElementById('filterLogsThreats')?.value || 'all';
  const searchFilter = (document.getElementById('filterLogsSearch')?.value || '').toLowerCase().trim();

  const rowZone = row.getAttribute('data-zone');
  const rowChain = row.getAttribute('data-chain');
  const rowThreat = row.getAttribute('data-threat');
  const rowSearch = row.getAttribute('data-search') || '';

  let visible = true;
  if (zoneFilter !== 'all' && rowZone !== zoneFilter) visible = false;
  if (chainFilter !== 'all' && rowChain !== chainFilter) visible = false;
  if (threatFilter === 'threats' && rowThreat !== '1') visible = false;
  if (searchFilter && !rowSearch.includes(searchFilter)) visible = false;

  row.style.display = visible ? '' : 'none';
}

function filterLiveLogs() {
  const tbody = document.getElementById('liveLogsTableBody');
  if (!tbody) return;
  for (const row of tbody.children) {
    applyRowVisibility(row);
  }
}

/**
 * Exibe banner superior para alertas críticos
 */
function showIdsAlertBanner(alert) {
  const banner = document.getElementById('alertBanner');
  const textEl = document.getElementById('alertBannerText');
  const btnMute = document.getElementById('btnMuteLanAlerts');
  if (!banner || !textEl) return;

  const isLan = alert.zone === 'LAN';
  if (isLan && localStorage.getItem('tiksentry_hide_lan_alerts') === 'true') {
    return;
  }

  if (btnMute) {
    btnMute.style.display = isLan ? 'inline-block' : 'none';
  }

  const zoneBadge = isLan ? '🏠 AMEAÇA INTERNA / LAN' : '🌐 ATAQUE EXTERNO / WAN';

  textEl.innerHTML = `
    <strong style="color:${isLan ? 'var(--amber)' : 'var(--cyan)'};">[${zoneBadge}]</strong> 
    <strong>${alert.rule_name}</strong> de 
    <span class="ip-badge" style="color:#fff;">${alert.src_ip}</span> 
    (${alert.city || 'Local'}, ${alert.country || 'LAN'}) porta <strong>${alert.dst_port || 'Scan'}</strong>
    ${alert.auto_blocked ? `— <strong style="color:var(--emerald);">ISOLADO NO MIKROTIK (${isLan ? 'Quarentena LAN' : 'Address-List WAN'})</strong>` : ''}
  `;

  banner.classList.remove('hidden');

  // Oculta após 15 segundos
  clearTimeout(banner._timer);
  banner._timer = setTimeout(() => {
    banner.classList.add('hidden');
  }, 15000);
}

function dismissAlertBanner() {
  const banner = document.getElementById('alertBanner');
  if (banner) banner.classList.add('hidden');
}

/**
 * Silencia e desativa alertas da LAN com 1 clique
 */
async function muteLanAlerts() {
  localStorage.setItem('tiksentry_hide_lan_alerts', 'true');
  dismissAlertBanner();
  try {
    await fetch('/api/mikrotik/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ monitor_lan_threats: false })
    });
  } catch {}
  updateLanStatusUI(false);
  alert('Alertas da Rede Interna (LAN) desativados! O sistema agora focará apenas nos ataques da Internet (WAN).');
}

/**
 * Toggle rápido de monitoramento da LAN no Dashboard
 */
async function quickToggleLanMonitor() {
  try {
    const res = await fetch('/api/mikrotik/config');
    const json = await res.json();
    const current = json.data?.monitor_lan_threats;
    const next = !current;
    await fetch('/api/mikrotik/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ monitor_lan_threats: next })
    });
    localStorage.setItem('tiksentry_hide_lan_alerts', next ? 'false' : 'true');
    updateLanStatusUI(next);
    alert(next ? 'Monitoramento de ameaças da LAN ativado com sucesso.' : 'Monitoramento de ameaças da LAN desativado com sucesso.');
  } catch (err) {
    alert('Erro ao alterar configuração: ' + err.message);
  }
}

function updateLanStatusUI(isActive) {
  const badge = document.getElementById('badgeLanStatus');
  const btn = document.getElementById('btnToggleLanMonitor');
  const chk = document.getElementById('mkMonitorLan');
  if (chk) chk.checked = isActive;
  if (badge) {
    badge.textContent = isActive ? 'LAN ATIVA' : 'LAN SILENCIADA';
    badge.style.background = isActive ? 'rgba(255,170,0,0.15)' : 'rgba(255,255,255,0.05)';
    badge.style.color = isActive ? 'var(--amber)' : 'var(--text-muted)';
    badge.style.borderColor = isActive ? 'rgba(255,170,0,0.4)' : 'var(--border-color)';
  }
  if (btn) {
    btn.textContent = isActive ? 'Silenciar / Desativar' : 'Ativar Monitoramento';
  }
}

/**
 * Sintetizador de áudio Web Audio API (sem dependência de arquivos externos de áudio)
 */
function initAudio() {
  const toggleBtn = document.getElementById('btnToggleMute');
  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => {
      isAudioMuted = !isAudioMuted;
      toggleBtn.innerHTML = isAudioMuted ? '🔇' : '🔔';
    });
  }
}

function playAlertTone() {
  if (isAudioMuted) return;

  try {
    if (!audioContext) {
      audioContext = new (window.AudioContext || window.webkitAudioContext)();
    }
    if (audioContext.state === 'suspended') {
      audioContext.resume();
    }

    const osc = audioContext.createOscillator();
    const gain = audioContext.createGain();

    osc.type = 'sawtooth';
    osc.frequency.setValueAtTime(880, audioContext.currentTime); // A5
    osc.frequency.exponentialRampToValueAtTime(440, audioContext.currentTime + 0.25);

    gain.gain.setValueAtTime(0.12, audioContext.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.25);

    osc.connect(gain);
    gain.connect(audioContext.destination);

    osc.start();
    osc.stop(audioContext.currentTime + 0.25);
  } catch {}
}

/**
 * Carrega dados iniciais do Dashboard
 */
async function loadInitialData() {
  await loadDashboardStats();
  if (window.loadFullReport) {
    window.loadFullReport('24h');
  }
}

async function loadDashboardStats() {
  try {
    const res = await fetch('/api/logs/stats');
    const json = await res.json();
    if (!json.success) return;

    const d = json.data;
    if (document.getElementById('dashTotalEvents')) document.getElementById('dashTotalEvents').textContent = d.totalEvents.toLocaleString();
    if (document.getElementById('dashThreats')) document.getElementById('dashThreats').textContent = d.threats.toLocaleString();
    if (document.getElementById('dashDropped')) document.getElementById('dashDropped').textContent = d.dropped.toLocaleString();
    if (document.getElementById('dashAttackers')) document.getElementById('dashAttackers').textContent = d.uniqueAttackers.toLocaleString();
    if (document.getElementById('dashBlockedIps')) document.getElementById('dashBlockedIps').textContent = d.activeBlockedIps.toLocaleString();
    if (document.getElementById('dashPpm')) document.getElementById('dashPpm').textContent = `${d.eventsPerMinute} logs/min`;

    // Atualiza contadores específicos WAN (Internet) e LAN (Rede Interna)
    if (document.getElementById('dashWanThreats')) document.getElementById('dashWanThreats').textContent = (d.wanThreats || 0).toLocaleString();
    if (document.getElementById('dashLanThreats')) document.getElementById('dashLanThreats').textContent = (d.lanThreats || 0).toLocaleString();
    if (document.getElementById('dashWanAttackers')) document.getElementById('dashWanAttackers').textContent = (d.uniqueWanAttackers || 0).toLocaleString();
    if (document.getElementById('dashLanDevices')) document.getElementById('dashLanDevices').textContent = (d.uniqueLanThreats || 0).toLocaleString();

    // Atualiza gráficos do Dashboard a cada ciclo
    const repRes = await fetch('/api/reports/full?range=24h');
    const repJson = await repRes.json();
    if (repJson.success && window.updateDashboardCharts) {
      window.updateDashboardCharts(repJson.data);
    }
    // Sincroniza estado de monitoramento da LAN
    try {
      const cfgRes = await fetch('/api/mikrotik/config');
      const cfgJson = await cfgRes.json();
      if (cfgJson.success && cfgJson.data) {
        updateLanStatusUI(cfgJson.data.monitor_lan_threats === true);
      }
    } catch {}
  } catch (err) {
    console.error('Erro ao atualizar estatísticas:', err);
  }
}

function toggleLogStreaming() {
  isLogStreamingPaused = !isLogStreamingPaused;
  const btn = document.getElementById('btnToggleStream');
  if (btn) {
    btn.textContent = isLogStreamingPaused ? '▶ Retomar Stream' : '⏸ Pausar Stream';
    btn.className = isLogStreamingPaused ? 'btn btn-outline btn-sm' : 'btn btn-primary btn-sm';
  }
}

function clearLogStreamTable() {
  const tbody = document.getElementById('liveLogsTableBody');
  if (tbody) tbody.innerHTML = '';
}

window.toggleLogStreaming = toggleLogStreaming;
window.clearLogStreamTable = clearLogStreamTable;
window.filterLiveLogs = filterLiveLogs;
window.dismissAlertBanner = dismissAlertBanner;
window.muteLanAlerts = muteLanAlerts;
window.quickToggleLanMonitor = quickToggleLanMonitor;
window.updateLanStatusUI = updateLanStatusUI;
