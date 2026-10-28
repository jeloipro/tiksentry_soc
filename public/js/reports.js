/**
 * TIKSENTRY - GERADOR E RENDERIZADOR DE RELATÓRIOS FORMATADOS
 */

let currentReportData = null;

async function loadFullReport(range = '24h') {
  try {
    const res = await fetch(`/api/reports/full?range=${range}`);
    const json = await res.json();
    if (!json.success) return;

    currentReportData = json.data;
    renderReportView(currentReportData);
  } catch (err) {
    console.error('Erro ao carregar relatório formatado:', err);
  }
}

function renderReportView(data) {
  if (!data) return;

  // 1. Cabeçalho de Impressão e Metadados
  const printGenTime = document.getElementById('reportPrintDate');
  if (printGenTime) printGenTime.textContent = new Date(data.generatedAt).toLocaleString();

  // 2. Cards de Resumo Executivo
  const s = data.summary;
  if (document.getElementById('repTotalEvents')) document.getElementById('repTotalEvents').textContent = s.totalEvents.toLocaleString();
  if (document.getElementById('repTotalThreats')) document.getElementById('repTotalThreats').textContent = s.totalThreats.toLocaleString();
  if (document.getElementById('repTotalDrops')) document.getElementById('repTotalDrops').textContent = s.totalDrops.toLocaleString();
  if (document.getElementById('repUniqueAttackers')) document.getElementById('repUniqueAttackers').textContent = s.uniqueAttackers.toLocaleString();
  if (document.getElementById('repMitigationRate')) document.getElementById('repMitigationRate').textContent = `${s.mitigationRate}%`;
  if (document.getElementById('repActiveBlocked')) document.getElementById('repActiveBlocked').textContent = s.activeBlockedIps.toLocaleString();

  // 3. Tabela de Países Atacantes
  const countriesTbody = document.getElementById('repCountriesTableBody');
  if (countriesTbody && data.topCountries) {
    countriesTbody.innerHTML = data.topCountries.map(c => `
      <tr>
        <td><strong>${c.country}</strong> (${c.country_code})</td>
        <td><span class="port-badge">${c.count.toLocaleString()}</span></td>
        <td><strong style="color:var(--crimson);">${c.threats.toLocaleString()}</strong></td>
      </tr>
    `).join('');
  }

  // 4. Tabela de Portas Alvo
  const portsTbody = document.getElementById('repPortsTableBody');
  if (portsTbody && data.topPorts) {
    portsTbody.innerHTML = data.topPorts.slice(0, 10).map(p => `
      <tr>
        <td><span class="ip-badge">${p.port}</span></td>
        <td><span class="port-badge">${p.protocol}</span></td>
        <td><strong>${p.service}</strong></td>
        <td>${p.count.toLocaleString()}</td>
      </tr>
    `).join('');
  }

  // 5. Tabela de Top Atacantes
  const attackersTbody = document.getElementById('repAttackersTableBody');
  if (attackersTbody && data.topAttackers) {
    attackersTbody.innerHTML = data.topAttackers.map(a => {
      const isBlocked = a.blocked_at !== null;
      const statusBadge = isBlocked 
        ? '<span class="action-badge drop">BLOQUEADO</span>' 
        : '<span class="action-badge accept">ATIVO</span>';

      return `
        <tr>
          <td><span class="ip-badge">${a.src_ip}</span></td>
          <td>${a.country} (${a.country_code}) - ${a.city}</td>
          <td><strong>${a.hits.toLocaleString()}</strong></td>
          <td style="color:var(--crimson); font-weight:700;">${a.threat_hits}</td>
          <td style="font-size:0.75rem; color:var(--text-muted);">${new Date(a.last_seen).toLocaleTimeString()}</td>
          <td style="font-size:0.75rem;">${a.reasons || 'Varredura / Drop'}</td>
          <td>${statusBadge}</td>
        </tr>
      `;
    }).join('');
  }

  // 6. Threat Network Sub-redes (/24)
  const subnetsContainer = document.getElementById('threatSubnetsList');
  if (subnetsContainer && data.threatSubnets) {
    subnetsContainer.innerHTML = data.threatSubnets.map(sub => `
      <div style="background:var(--bg-input); border:1px solid var(--border-color); border-radius:6px; padding:10px; margin-bottom:8px; display:flex; justify-content:space-between; align-items:center;">
        <div>
          <span style="font-family:var(--font-mono); font-weight:700; color:var(--cyan);">${sub.subnet}</span>
          <span style="font-size:0.75rem; color:var(--text-muted); margin-left:8px;">${sub.country} (${sub.country_code})</span>
        </div>
        <div style="font-size:0.78rem;">
          <strong>${sub.count}</strong> pacotes / <strong>${sub.unique_ips}</strong> IPs
        </div>
      </div>
    `).join('');
  }
}

function printExecutiveReport() {
  window.print();
}

function exportCsvLogs() {
  const range = document.getElementById('reportTimeRangeSelect')?.value || '24h';
  window.location.href = `/api/reports/csv/logs?range=${range}`;
}

function exportCsvAttackers() {
  const range = document.getElementById('reportTimeRangeSelect')?.value || '24h';
  window.location.href = `/api/reports/csv/attackers?range=${range}`;
}

function exportJsonReport() {
  if (!currentReportData) return;
  const jsonStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentReportData, null, 2));
  const dlAnchor = document.createElement('a');
  dlAnchor.setAttribute("href", jsonStr);
  dlAnchor.setAttribute("download", `tiksentry-security-report-${Date.now()}.json`);
  document.body.appendChild(dlAnchor);
  dlAnchor.click();
  dlAnchor.remove();
}

/**
 * ===================================================================
 * GERENCIAMENTO DE LIMPEZA AGENDADA E BACKUPS (.CSV)
 * ===================================================================
 */

async function loadPruneConfigAndBackups() {
  try {
    // 1. Carrega configuração de agendamento
    const cfgRes = await fetch('/api/backups/config');
    const cfgData = await cfgRes.json();
    if (cfgData.success && cfgData.data) {
      const c = cfgData.data;
      if (document.getElementById('pruneFrequency')) document.getElementById('pruneFrequency').value = c.frequency || 'weekly';
      if (document.getElementById('pruneRetentionDays')) document.getElementById('pruneRetentionDays').value = c.retentionDays || '14';
      if (document.getElementById('pruneEnabled')) document.getElementById('pruneEnabled').checked = c.enabled !== false;
    }

    // 2. Carrega lista de arquivos de backup gerados
    const listRes = await fetch('/api/backups');
    const listData = await listRes.json();
    const tbody = document.getElementById('backupsListTableBody');
    if (!tbody) return;

    if (!listData.success || !listData.data || listData.data.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:var(--text-muted); padding:16px;">Nenhum backup arquivado no momento.</td></tr>';
      return;
    }

    tbody.innerHTML = listData.data.map(b => `
      <tr>
        <td><strong style="color:var(--cyan); font-family:var(--font-mono); font-size:0.78rem;">${b.filename}</strong></td>
        <td><span class="port-badge">${b.sizeFormatted}</span></td>
        <td style="font-size:0.75rem; color:var(--text-muted);">${new Date(b.createdAt).toLocaleString()}</td>
        <td>
          <a href="${b.downloadUrl}" class="btn btn-primary btn-sm" download style="text-decoration:none;">📥 Baixar .CSV</a>
          <button class="btn btn-outline btn-sm" onclick="deleteBackupFile('${b.filename}')" style="margin-left:6px;">Excluir</button>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Erro ao carregar backups:', err);
  }
}

async function savePruneConfig(e) {
  if (e) e.preventDefault();

  const enabled = document.getElementById('pruneEnabled')?.checked;
  const frequency = document.getElementById('pruneFrequency')?.value;
  const retention_days = document.getElementById('pruneRetentionDays')?.value;

  try {
    const res = await fetch('/api/backups/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled, frequency, retention_days, save_format: 'csv' })
    });
    const json = await res.json();
    if (json.success) {
      alert('Configurações de agendamento salvas com sucesso!');
    } else {
      alert(`Erro: ${json.error}`);
    }
  } catch (err) {
    alert(`Erro ao salvar: ${err.message}`);
  }
}

async function runManualPruneNow() {
  if (!confirm('Deseja iniciar o arquivamento e limpeza agora? Os logs mais antigos serão salvos em um arquivo .CSV e liberados do SQLite.')) return;

  try {
    const res = await fetch('/api/backups/run-now', { method: 'POST' });
    const json = await res.json();
    if (json.success) {
      if (json.archivedCount > 0) {
        alert(`Sucesso! ${json.archivedCount} registros foram arquivados no arquivo:\n${json.backupFile}\ne liberados do SQLite.`);
      } else {
        alert('Nenhum log anterior ao período de retenção foi encontrado para arquivar.');
      }
      loadPruneConfigAndBackups();
      if (window.loadDashboardStats) window.loadDashboardStats();
    } else {
      alert(`Falha: ${json.error}`);
    }
  } catch (err) {
    alert(`Erro na requisição: ${err.message}`);
  }
}

async function deleteBackupFile(filename) {
  if (!confirm(`Deseja realmente excluir o arquivo de backup ${filename}?`)) return;

  try {
    const res = await fetch(`/api/backups/${encodeURIComponent(filename)}`, { method: 'DELETE' });
    const json = await res.json();
    if (json.success) {
      loadPruneConfigAndBackups();
    } else {
      alert(`Erro: ${json.error}`);
    }
  } catch (err) {
    alert(`Erro: ${err.message}`);
  }
}

window.loadFullReport = loadFullReport;
window.printExecutiveReport = printExecutiveReport;
window.exportCsvLogs = exportCsvLogs;
window.exportCsvAttackers = exportCsvAttackers;
window.exportJsonReport = exportJsonReport;
window.loadPruneConfigAndBackups = loadPruneConfigAndBackups;
window.savePruneConfig = savePruneConfig;
window.runManualPruneNow = runManualPruneNow;
window.deleteBackupFile = deleteBackupFile;
