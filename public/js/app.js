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

  const timeStr = new Date(log.timestamp).toLocaleTimeString();
  const actionClass = (log.action || 'drop').toLowerCase();

  row.innerHTML = `
    <td style="font-family:var(--font-mono); font-size:0.75rem; color:var(--text-muted);">${timeStr}</td>
    <td><span class="action-badge ${actionClass}">${log.action}</span></td>
    <td><span class="port-badge">${log.chain}</span></td>
    <td><span class="port-badge">${(log.protocol || 'TCP').toUpperCase()}</span></td>
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

  tbody.insertBefore(row, tbody.firstChild);

  // Limita a 200 linhas no DOM para performance ultra-leve
  if (tbody.children.length > 200) {
    tbody.removeChild(tbody.lastChild);
  }
}

/**
 * Exibe banner superior para alertas críticos
 */
function showIdsAlertBanner(alert) {
  const banner = document.getElementById('alertBanner');
  const textEl = document.getElementById('alertBannerText');
  if (!banner || !textEl) return;

  textEl.innerHTML = `
    <strong>${alert.rule_name}</strong> detectado de 
    <span class="ip-badge" style="color:#fff;">${alert.src_ip}</span> 
    (${alert.city}, ${alert.country}) em direção à porta <strong>${alert.dst_port || 'Scan'}</strong>
    ${alert.auto_blocked ? '— <strong style="color:var(--emerald);">IP BLOQUEADO NO MIKROTIK</strong>' : ''}
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

    // Atualiza gráficos do Dashboard a cada ciclo
    const repRes = await fetch('/api/reports/full?range=24h');
    const repJson = await repRes.json();
    if (repJson.success && window.updateDashboardCharts) {
      window.updateDashboardCharts(repJson.data);
    }
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
window.dismissAlertBanner = dismissAlertBanner;
