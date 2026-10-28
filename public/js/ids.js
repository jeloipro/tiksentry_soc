/**
 * TIKSENTRY - GERENCIADOR DE REGRAS IDS E IPS BLOQUEADOS
 */

async function loadIdsRules() {
  try {
    const res = await fetch('/api/ids/rules');
    const json = await res.json();
    if (!json.success) return;

    const tbody = document.getElementById('idsRulesTableBody');
    if (!tbody) return;

    if (json.data.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--text-muted);">Nenhuma regra IDS cadastrada.</td></tr>';
      return;
    }

    tbody.innerHTML = json.data.map(rule => {
      const sevColor = rule.severity === 'critical' ? 'var(--crimson)' : (rule.severity === 'high' ? 'var(--amber)' : 'var(--cyan)');
      return `
        <tr>
          <td>
            <strong>${rule.name}</strong>
            <div style="font-size:0.72rem; color:var(--text-muted);">${rule.description || ''}</div>
          </td>
          <td><span style="font-size:0.75rem; text-transform:uppercase; font-weight:700; color:${sevColor};">${rule.severity}</span></td>
          <td><span class="port-badge">${rule.category.toUpperCase()}</span></td>
          <td>
            <span style="font-family:var(--font-mono); font-size:0.8rem;">
              >= <strong>${rule.threshold_count}</strong> em <strong>${rule.threshold_window_seconds}s</strong>
            </span>
          </td>
          <td>
            <input type="number" class="form-control" style="width:75px; padding:3px 6px; font-size:0.75rem;" 
              value="${rule.block_duration_minutes}" 
              onchange="updateRuleParam('${rule.id}', 'block_duration_minutes', this.value)"> min
          </td>
          <td>
            <input type="checkbox" ${rule.auto_block === 1 ? 'checked' : ''} 
              onchange="updateRuleParam('${rule.id}', 'auto_block', this.checked)">
          </td>
          <td>
            <input type="checkbox" ${rule.enabled === 1 ? 'checked' : ''} 
              onchange="updateRuleParam('${rule.id}', 'enabled', this.checked)">
          </td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    console.error('Erro ao carregar regras IDS:', err);
  }
}

async function updateRuleParam(ruleId, param, value) {
  try {
    const payload = {};
    payload[param] = value;
    const res = await fetch(`/api/ids/rules/${ruleId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!data.success) {
      alert(`Falha ao atualizar regra: ${data.error}`);
    }
  } catch (err) {
    alert(`Erro ao salvar regra: ${err.message}`);
  }
}

async function loadBlockedIps() {
  try {
    const res = await fetch('/api/ids/blocked');
    const json = await res.json();
    if (!json.success) return;

    const tbody = document.getElementById('blockedIpsTableBody');
    const countBadge = document.getElementById('blockedIpsCount');
    if (countBadge) countBadge.textContent = `${json.data.length} Bloqueados`;

    if (!tbody) return;

    if (json.data.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--text-muted); padding:20px;">Nenhum IP bloqueado no momento.</td></tr>';
      return;
    }

    tbody.innerHTML = json.data.map(item => {
      const expStr = item.is_permanent ? '<span style="color:var(--amber);">Permanente</span>' : (item.expires_at ? new Date(item.expires_at).toLocaleString() : 'N/A');
      const syncedBadge = item.synced_to_mikrotik === 1 
        ? '<span style="color:var(--emerald); font-weight:700;">● Sincronizado</span>' 
        : '<span style="color:var(--amber);">○ Pendente</span>';

      return `
        <tr>
          <td><span class="ip-badge">${item.ip}</span></td>
          <td>${item.country} (${item.country_code}) - ${item.city}</td>
          <td><span style="font-size:0.75rem;">${item.reason}</span></td>
          <td style="font-size:0.75rem; color:var(--text-muted);">${new Date(item.blocked_at).toLocaleString()}</td>
          <td style="font-size:0.75rem;">${expStr}</td>
          <td><span class="port-badge">${item.hit_count} hits</span></td>
          <td>${syncedBadge}</td>
          <td>
            <button class="btn btn-danger btn-sm" onclick="unblockIp('${item.ip}')">Desbloquear</button>
          </td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    console.error('Erro ao carregar IPs bloqueados:', err);
  }
}

async function unblockIp(ip) {
  if (!confirm(`Deseja realmente desbloquear o IP ${ip} e liberá-lo no MikroTik?`)) return;

  try {
    const res = await fetch(`/api/ids/blocked/${encodeURIComponent(ip)}`, { method: 'DELETE' });
    const json = await res.json();
    if (json.success) {
      loadBlockedIps();
    } else {
      alert(`Erro ao desbloquear: ${json.error}`);
    }
  } catch (err) {
    alert(`Erro na requisição: ${err.message}`);
  }
}

async function syncWithMikroTik() {
  const btn = document.getElementById('btnSyncMikrotik');
  if (btn) btn.textContent = 'Sincronizando...';

  try {
    const res = await fetch('/api/ids/sync', { method: 'POST' });
    const json = await res.json();
    if (json.success) {
      alert(`Sincronização concluída com o MikroTik! Total no roteador: ${json.data.routerTotal}`);
      loadBlockedIps();
    } else {
      alert(`Erro na sincronização: ${json.error}`);
    }
  } catch (err) {
    alert(`Erro na sincronização: ${err.message}`);
  } finally {
    if (btn) btn.textContent = 'Sincronizar com MikroTik';
  }
}

function openManualBlockModal() {
  const modal = document.getElementById('manualBlockModal');
  if (modal) modal.classList.remove('hidden');
}

function closeManualBlockModal() {
  const modal = document.getElementById('manualBlockModal');
  if (modal) modal.classList.add('hidden');
}

async function submitManualBlock(e) {
  if (e) e.preventDefault();

  const ip = document.getElementById('manualBlockIp')?.value;
  const reason = document.getElementById('manualBlockReason')?.value;
  const duration = document.getElementById('manualBlockDuration')?.value;
  const isPermanent = document.getElementById('manualBlockPermanent')?.checked;

  if (!ip) {
    alert('Informe um IP válido.');
    return;
  }

  try {
    const res = await fetch('/api/ids/blocked', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ip,
        reason: reason || 'Bloqueio Manual via SOC',
        duration_minutes: parseInt(duration, 10) || 60,
        is_permanent: isPermanent
      })
    });
    const json = await res.json();
    if (json.success) {
      closeManualBlockModal();
      document.getElementById('manualBlockIp').value = '';
      loadBlockedIps();
    } else {
      alert(`Erro: ${json.error}`);
    }
  } catch (err) {
    alert(`Erro: ${err.message}`);
  }
}

window.loadIdsRules = loadIdsRules;
window.updateRuleParam = updateRuleParam;
window.loadBlockedIps = loadBlockedIps;
window.unblockIp = unblockIp;
window.syncWithMikroTik = syncWithMikroTik;
window.openManualBlockModal = openManualBlockModal;
window.closeManualBlockModal = closeManualBlockModal;
window.submitManualBlock = submitManualBlock;
