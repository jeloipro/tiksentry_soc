/**
 * TIKSENTRY - CONFIGURAÇÃO DA API MIKROTIK E GERADOR DE SCRIPT
 */

async function loadMikrotikConfig() {
  try {
    const res = await fetch('/api/mikrotik/config');
    const json = await res.json();
    if (!json.success) return;

    const data = json.data;
    if (document.getElementById('systemNameInput')) document.getElementById('systemNameInput').value = data.system_name || 'TikSentry SOC';
    if (document.getElementById('mkProtocol')) document.getElementById('mkProtocol').value = data.mikrotik_protocol || 'rest';
    if (document.getElementById('mkHost')) document.getElementById('mkHost').value = data.mikrotik_host || '';
    if (document.getElementById('mkPort')) document.getElementById('mkPort').value = data.mikrotik_port || '443';
    if (document.getElementById('mkUser')) document.getElementById('mkUser').value = data.mikrotik_username || 'admin';
    if (document.getElementById('mkUseTls')) document.getElementById('mkUseTls').checked = data.mikrotik_use_tls;
    if (document.getElementById('mkBlockList')) document.getElementById('mkBlockList').value = data.mikrotik_block_list || 'TIKSENTRY_BLOCKED';
    if (document.getElementById('mkAutoBlock')) document.getElementById('mkAutoBlock').checked = data.mikrotik_auto_block;
    if (document.getElementById('routerLat')) document.getElementById('routerLat').value = data.router_lat || '-23.5505';
    if (document.getElementById('routerLng')) document.getElementById('routerLng').value = data.router_lng || '-46.6333';
    if (document.getElementById('routerName')) document.getElementById('routerName').value = data.router_name || 'MikroTik Gateway';

    // Carrega o script MikroTik sugerido
    loadMikrotikScript();
  } catch (err) {
    console.error('Erro ao carregar configurações do MikroTik:', err);
  }
}

async function saveMikrotikConfig(e) {
  if (e) e.preventDefault();

  const payload = {
    system_name: document.getElementById('systemNameInput')?.value,
    mikrotik_protocol: document.getElementById('mkProtocol')?.value,
    mikrotik_host: document.getElementById('mkHost')?.value,
    mikrotik_port: document.getElementById('mkPort')?.value,
    mikrotik_username: document.getElementById('mkUser')?.value,
    mikrotik_password: document.getElementById('mkPass')?.value,
    mikrotik_use_tls: document.getElementById('mkUseTls')?.checked,
    mikrotik_block_list: document.getElementById('mkBlockList')?.value,
    mikrotik_auto_block: document.getElementById('mkAutoBlock')?.checked,
    router_lat: document.getElementById('routerLat')?.value,
    router_lng: document.getElementById('routerLng')?.value,
    router_name: document.getElementById('routerName')?.value
  };

  try {
    const res = await fetch('/api/mikrotik/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const json = await res.json();
    if (json.success) {
      alert('Configurações salvas com sucesso!');
      loadMikrotikScript();
    } else {
      alert(`Erro ao salvar: ${json.error}`);
    }
  } catch (err) {
    alert(`Erro ao conectar à API: ${err.message}`);
  }
}

async function testMikrotikConnection() {
  const resultDiv = document.getElementById('connectionTestResult');
  const btn = document.getElementById('btnTestConnection');

  if (resultDiv) {
    resultDiv.innerHTML = '<span style="color:var(--cyan);">Conectando ao MikroTik e testando credenciais...</span>';
    resultDiv.style.display = 'block';
  }
  if (btn) btn.disabled = true;

  const payload = {
    mikrotik_protocol: document.getElementById('mkProtocol')?.value,
    mikrotik_host: document.getElementById('mkHost')?.value,
    mikrotik_port: document.getElementById('mkPort')?.value,
    mikrotik_username: document.getElementById('mkUser')?.value,
    mikrotik_password: document.getElementById('mkPass')?.value,
    mikrotik_use_tls: document.getElementById('mkUseTls')?.checked
  };

  try {
    const res = await fetch('/api/mikrotik/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const json = await res.json();

    if (json.success) {
      resultDiv.innerHTML = `
        <div style="padding:12px; border-radius:6px; background:rgba(0, 255, 157, 0.1); border:1px solid rgba(0, 255, 157, 0.3); color:var(--emerald);">
          <strong>✔ Conexão com MikroTik Estabelecida com Sucesso!</strong><br>
          <div style="font-size:0.8rem; margin-top:6px; color:#fff;">
            ● Identidade: <strong>${json.identity}</strong> | Versão: <strong>${json.version}</strong><br>
            ● Modelo: <strong>${json.boardName}</strong> | Uptime: <strong>${json.uptime}</strong><br>
            ● Uso de CPU: <strong>${json.cpuLoad}</strong> | Memória Livre: <strong>${json.freeMemory}</strong>
          </div>
        </div>
      `;

      // Atualiza badge no topo do SOC
      const topBadge = document.getElementById('headerMikrotikStatus');
      if (topBadge) {
        topBadge.innerHTML = `<span class="status-dot"></span> MIKROTIK: ${json.identity.toUpperCase()}`;
      }
    } else {
      resultDiv.innerHTML = `
        <div style="padding:12px; border-radius:6px; background:rgba(255, 0, 85, 0.1); border:1px solid rgba(255, 0, 85, 0.3); color:var(--crimson);">
          <strong>✖ Falha na Conexão com o MikroTik:</strong><br>
          <span style="font-size:0.8rem; color:#fff;">${json.error}</span>
        </div>
      `;

      const topBadge = document.getElementById('headerMikrotikStatus');
      if (topBadge) {
        topBadge.innerHTML = '<span class="status-dot danger"></span> MIKROTIK OFFLINE';
      }
    }
  } catch (err) {
    resultDiv.innerHTML = `<span style="color:var(--crimson);">Erro de comunicação com o servidor: ${err.message}</span>`;
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function loadMikrotikScript() {
  try {
    const res = await fetch('/api/mikrotik/script');
    const json = await res.json();
    if (json.success && document.getElementById('mikrotikScriptCode')) {
      document.getElementById('mikrotikScriptCode').textContent = json.script;
    }
  } catch (err) {
    console.error('Erro ao gerar script:', err);
  }
}

function copyMikrotikScript() {
  const code = document.getElementById('mikrotikScriptCode')?.textContent;
  if (!code) return;

  navigator.clipboard.writeText(code).then(() => {
    alert('Script copiado para a área de transferência! Cole no terminal do MikroTik.');
  }).catch(() => {
    alert('Erro ao copiar automaticamente. Selecione e copie o texto manualmente.');
  });
}

window.loadMikrotikConfig = loadMikrotikConfig;
window.saveMikrotikConfig = saveMikrotikConfig;
window.testMikrotikConnection = testMikrotikConnection;
window.copyMikrotikScript = copyMikrotikScript;
