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
    if (document.getElementById('mkWanInterfaces')) document.getElementById('mkWanInterfaces').value = data.wan_interfaces || 'ether1,pppoe-out1,wan';
    if (document.getElementById('mkLanInterfaces')) document.getElementById('mkLanInterfaces').value = data.lan_interfaces || 'bridge,lan,bridge1';
    if (document.getElementById('mkLanQuarantineList')) document.getElementById('mkLanQuarantineList').value = data.lan_quarantine_list || 'TIKSENTRY_LAN_QUARANTINE';
    if (document.getElementById('mkMonitorLan')) document.getElementById('mkMonitorLan').checked = data.monitor_lan_threats === true;
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
    wan_interfaces: document.getElementById('mkWanInterfaces')?.value,
    lan_interfaces: document.getElementById('mkLanInterfaces')?.value,
    lan_quarantine_list: document.getElementById('mkLanQuarantineList')?.value,
    monitor_lan_threats: document.getElementById('mkMonitorLan')?.checked,
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

async function detectMikrotikWan() {
  const resultDiv = document.getElementById('wanDetectResult');
  const btn = document.getElementById('btnDetectWan');

  if (resultDiv) {
    resultDiv.innerHTML = '<span style="color:var(--cyan);">Inspecionando tabela de rotas (/ip/route) e interfaces WAN no MikroTik...</span>';
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
    const res = await fetch('/api/mikrotik/detect-wan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const json = await res.json();

    if (json.success) {
      const wanList = json.wanInterfaces || [];
      const lanList = json.lanInterfaces || [];
      const routes = json.defaultRoutes || [];

      let routesHtml = routes.map(r => `
        <div style="font-family:var(--font-mono); font-size:0.75rem; background:rgba(0,240,255,0.06); padding:6px 10px; border-radius:4px; margin-top:4px;">
          ➜ <strong>${r.dstAddress}</strong> via Gateway: <strong style="color:var(--cyan);">${r.gateway || 'N/A'}</strong> (Distância: ${r.distance}, Ativa: ${r.active ? 'SIM' : 'NÃO'})
        </div>
      `).join('');

      resultDiv.innerHTML = `
        <div style="padding:14px; border-radius:6px; background:rgba(0, 240, 255, 0.08); border:1px solid rgba(0, 240, 255, 0.25); color:var(--text-main);">
          <strong style="color:var(--cyan);">✔ Descoberta de Rotas e Interfaces Concluída!</strong>
          <div style="font-size:0.8rem; margin-top:8px;">
            <div style="color:var(--text-muted); margin-bottom:4px;">Rotas Padrão de Saída para a Internet (0.0.0.0/0):</div>
            ${routesHtml || '<div style="color:var(--amber);">Nenhuma rota explícita 0.0.0.0/0 retornada. Verifique as permissões de leitura de rotas do usuário.</div>'}
            
            <div style="margin-top:10px;">
              🌐 <strong>Interfaces WAN Detectadas:</strong> <span class="port-badge" style="color:var(--cyan);">${wanList.join(', ') || 'Nenhuma detectada'}</span>
            </div>
            <div style="margin-top:4px;">
              🏠 <strong>Interfaces LAN Detectadas:</strong> <span class="port-badge" style="color:var(--amber);">${lanList.join(', ') || 'Nenhuma detectada'}</span>
            </div>
            <div style="font-size:0.75rem; color:var(--text-muted); margin-top:8px;">
              Os campos de interfaces foram atualizados automaticamente e salvos nas configurações.
            </div>
          </div>
        </div>
      `;

      if (wanList.length > 0 && document.getElementById('mkWanInterfaces')) {
        document.getElementById('mkWanInterfaces').value = wanList.join(', ');
      }
      if (lanList.length > 0 && document.getElementById('mkLanInterfaces')) {
        document.getElementById('mkLanInterfaces').value = lanList.join(', ');
      }

      loadMikrotikScript();
    } else {
      resultDiv.innerHTML = `
        <div style="padding:12px; border-radius:6px; background:rgba(255, 0, 85, 0.1); border:1px solid rgba(255, 0, 85, 0.3); color:var(--crimson);">
          <strong>✖ Falha na Detecção de Interfaces WAN:</strong><br>
          <span style="font-size:0.8rem; color:#fff;">${json.error}</span>
        </div>
      `;
    }
  } catch (err) {
    resultDiv.innerHTML = `<span style="color:var(--crimson);">Erro de comunicação com o servidor: ${err.message}</span>`;
  } finally {
    if (btn) btn.disabled = false;
  }
}

window.loadMikrotikConfig = loadMikrotikConfig;
window.saveMikrotikConfig = saveMikrotikConfig;
window.testMikrotikConnection = testMikrotikConnection;
window.detectMikrotikWan = detectMikrotikWan;
window.copyMikrotikScript = copyMikrotikScript;
