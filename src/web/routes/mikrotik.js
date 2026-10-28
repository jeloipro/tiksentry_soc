const express = require('express');
const router = express.Router();
const db = require('../../storage/db');
const mikrotikClient = require('../../mikrotik/client');
const config = require('../../config');

/**
 * GET /api/mikrotik/config
 * Obtém as configurações salvas da API MikroTik
 */
router.get('/config', async (req, res) => {
  try {
    const settings = await db.getAllSettings();
    res.json({
      success: true,
      data: {
        system_name: settings['system_name'] || config.systemName,
        mikrotik_protocol: settings['mikrotik_protocol'] || config.mikrotik.protocol,
        mikrotik_host: settings['mikrotik_host'] || config.mikrotik.host,
        mikrotik_port: settings['mikrotik_port'] || config.mikrotik.port.toString(),
        mikrotik_username: settings['mikrotik_username'] || config.mikrotik.username,
        has_password: Boolean(settings['mikrotik_password'] || config.mikrotik.password),
        mikrotik_use_tls: (settings['mikrotik_use_tls'] || String(config.mikrotik.useTls)) === 'true',
        mikrotik_block_list: settings['mikrotik_block_list'] || config.mikrotik.blockListName,
        mikrotik_auto_block: (settings['mikrotik_auto_block'] || String(config.mikrotik.autoBlock)) === 'true',
        wan_interfaces: settings['wan_interfaces'] || 'ether1,pppoe-out1,wan,sfp-sfpplus1,internet',
        lan_interfaces: settings['lan_interfaces'] || 'bridge,lan,bridge1,ether2,ether3,ether4,ether5',
        lan_quarantine_list: settings['lan_quarantine_list'] || 'TIKSENTRY_LAN_QUARANTINE',
        auto_detect_wan: (settings['auto_detect_wan'] || 'true') === 'true',
        router_lat: settings['router_lat'] || config.router.lat.toString(),
        router_lng: settings['router_lng'] || config.router.lng.toString(),
        router_name: settings['router_name'] || config.router.name
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/mikrotik/config
 * Salva as configurações de conexão do MikroTik
 */
router.post('/config', async (req, res) => {
  try {
    const {
      system_name,
      mikrotik_protocol,
      mikrotik_host,
      mikrotik_port,
      mikrotik_username,
      mikrotik_password,
      mikrotik_use_tls,
      mikrotik_block_list,
      mikrotik_auto_block,
      wan_interfaces,
      lan_interfaces,
      lan_quarantine_list,
      auto_detect_wan,
      router_lat,
      router_lng,
      router_name
    } = req.body;

    if (system_name !== undefined) await db.setSetting('system_name', system_name.trim());
    if (mikrotik_protocol !== undefined) await db.setSetting('mikrotik_protocol', mikrotik_protocol);
    if (mikrotik_host !== undefined) await db.setSetting('mikrotik_host', mikrotik_host.trim());
    if (mikrotik_port !== undefined) await db.setSetting('mikrotik_port', mikrotik_port.toString());
    if (mikrotik_username !== undefined) await db.setSetting('mikrotik_username', mikrotik_username.trim());
    if (mikrotik_password !== undefined && mikrotik_password !== '') {
      await db.setSetting('mikrotik_password', mikrotik_password);
    }
    if (mikrotik_use_tls !== undefined) await db.setSetting('mikrotik_use_tls', mikrotik_use_tls ? 'true' : 'false');
    if (mikrotik_block_list !== undefined) await db.setSetting('mikrotik_block_list', mikrotik_block_list.trim().toUpperCase());
    if (mikrotik_auto_block !== undefined) await db.setSetting('mikrotik_auto_block', mikrotik_auto_block ? 'true' : 'false');
    if (wan_interfaces !== undefined) await db.setSetting('wan_interfaces', wan_interfaces.trim());
    if (lan_interfaces !== undefined) await db.setSetting('lan_interfaces', lan_interfaces.trim());
    if (lan_quarantine_list !== undefined) await db.setSetting('lan_quarantine_list', lan_quarantine_list.trim().toUpperCase());
    if (auto_detect_wan !== undefined) await db.setSetting('auto_detect_wan', auto_detect_wan ? 'true' : 'false');
    if (router_lat !== undefined) await db.setSetting('router_lat', router_lat.toString());
    if (router_lng !== undefined) await db.setSetting('router_lng', router_lng.toString());
    if (router_name !== undefined) await db.setSetting('router_name', router_name.trim());

    res.json({ success: true, message: 'Configurações atualizadas com sucesso!' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/mikrotik/test
 * Testa a conexão com o MikroTik
 */
router.post('/test', async (req, res) => {
  try {
    let customParams = null;
    if (req.body.mikrotik_host) {
      const settings = await db.getAllSettings();
      customParams = {
        protocol: req.body.mikrotik_protocol || 'rest',
        host: req.body.mikrotik_host.trim(),
        port: parseInt(req.body.mikrotik_port, 10) || (req.body.mikrotik_protocol === 'rest' ? 443 : 8728),
        username: req.body.mikrotik_username || 'admin',
        password: req.body.mikrotik_password !== undefined && req.body.mikrotik_password !== '' 
          ? req.body.mikrotik_password 
          : (settings['mikrotik_password'] || ''),
        useTls: req.body.mikrotik_use_tls === true || req.body.mikrotik_use_tls === 'true'
      };
    }

    const result = await mikrotikClient.testConnection(customParams);
    res.json(result);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/mikrotik/detect-wan
 * Detecta automaticamente as interfaces conectadas à Internet (rota 0.0.0.0/0 e interface-list WAN)
 */
router.post('/detect-wan', async (req, res) => {
  try {
    let customParams = null;
    if (req.body.mikrotik_host) {
      const settings = await db.getAllSettings();
      customParams = {
        protocol: req.body.mikrotik_protocol || 'rest',
        host: req.body.mikrotik_host.trim(),
        port: parseInt(req.body.mikrotik_port, 10) || (req.body.mikrotik_protocol === 'rest' ? 443 : 8728),
        username: req.body.mikrotik_username || 'admin',
        password: req.body.mikrotik_password !== undefined && req.body.mikrotik_password !== '' 
          ? req.body.mikrotik_password 
          : (settings['mikrotik_password'] || ''),
        useTls: req.body.mikrotik_use_tls === true || req.body.mikrotik_use_tls === 'true'
      };
    }

    const result = await mikrotikClient.detectWanInterfaces(customParams);
    res.json(result);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/mikrotik/script
 * Gera o script para colar no terminal do MikroTik configurando o syslog e firewall
 */
router.get('/script', async (req, res) => {
  try {
    const settings = await db.getAllSettings();
    const serverHost = req.hostname || 'SEU_IP_SERVIDOR';
    const syslogPort = config.syslogPort || 514;
    const blockList = settings['mikrotik_block_list'] || 'TIKSENTRY_BLOCKED';
    const quarantineList = settings['lan_quarantine_list'] || 'TIKSENTRY_LAN_QUARANTINE';
    const wanInterfaces = settings['wan_interfaces'] || 'ether1,pppoe-out1';

    const script = `# ====================================================================
# SCRIPT DE CONFIGURACAO AUTOMATICA MIKROTIK -> TIKSENTRY SOC
# Monitoramento: Internet (WAN 0.0.0.0/0) vs Rede Interna (LAN Outbound/Inbound)
# Copie e cole no New Terminal do seu Winbox / SSH
# ====================================================================

# 1. Configurar servidor Syslog remoto apontando para o TikSentry
/system logging action
add name=tiksentry-remote target=remote remote=${serverHost} remote-port=${syslogPort} src-address=0.0.0.0 bsd-syslog=yes syslog-facility=daemon

# 2. Enviar logs de Firewall, Tentativas de Login e Autenticacao
/system logging
add topics=firewall action=tiksentry-remote
add topics=system,error,critical action=tiksentry-remote
add topics=account action=tiksentry-remote

# 3. Bloqueio Automatico da Address-List de Atacantes Externos (WAN)
/ip firewall filter
add chain=input src-address-list=${blockList} action=drop comment="[TikSentry] Bloqueio WAN de Atacantes Externos" place-before=0
add chain=forward src-address-list=${blockList} action=drop comment="[TikSentry] Bloqueio Forward de Atacantes Externos" place-before=1

# 4. Quarentena de Hosts Locais Comprometidos / Varreduras Internas (LAN)
add chain=input src-address-list=${quarantineList} action=drop comment="[TikSentry] Quarentena LAN de Dispositivo Infectado" place-before=2
add chain=forward src-address-list=${quarantineList} action=drop comment="[TikSentry] Quarentena LAN Forward de Host Infectado" place-before=3

# --------------------------------------------------------------------
# 5. ATAQUES DA INTERNET (WAN / Rota 0.0.0.0/0):
# Captura invasores externos tentando Winbox, SSH, Telnet, API, Web, Scans
# --------------------------------------------------------------------
# 5.1 Descarte e Log de Ataques externos direcionados ao Roteador (Input)
add chain=input in-interface-list=WAN connection-state=invalid action=drop log=yes log-prefix="[TIKSENTRY-WAN-DROP]" comment="[TikSentry] Descarte Pacotes Invalidos WAN"
add chain=input in-interface-list=WAN action=drop log=yes log-prefix="[TIKSENTRY-WAN-DROP]" comment="[TikSentry] Descarte e Log de Ataques da Internet (Input)"

# 5.2 Descarte e Log de Ataques externos tentando invadir a Rede Interna (Forward)
add chain=forward in-interface-list=WAN connection-state=new connection-nat-state=!dstnat action=drop log=yes log-prefix="[TIKSENTRY-WAN-DROP]" comment="[TikSentry] Descarte e Log de Invasoes WAN para Rede Interna"

# --------------------------------------------------------------------
# 6. AMEACAS DA REDE INTERNA (LAN / Invasao e Vazamento de Interno para Externo):
# Detecta computadores infectados, Ransomware, Spam Botnets e Mineracao
# --------------------------------------------------------------------
# 6.1 Rastros de Ransomware / Propagacao SMB (Portas 445 e 139) saindo para a Internet
add chain=forward in-interface-list=LAN out-interface-list=WAN protocol=tcp dst-port=445,139 action=drop log=yes log-prefix="[TIKSENTRY-LAN-DROP]" comment="[TikSentry] Alerta LAN: Ransomware / SMB Outbound"

# 6.2 Rastros de Maquina Zumbi / Spam Botnet (Porta 25 SMTP saindo para a Internet)
add chain=forward in-interface-list=LAN out-interface-list=WAN protocol=tcp dst-port=25 action=drop log=yes log-prefix="[TIKSENTRY-LAN-DROP]" comment="[TikSentry] Alerta LAN: Maquina Infectada Spam Botnet (SMTP 25)"

# 6.3 Rastros de Malware C2 / Cryptomining (Portas 3333, 4444, 5555, 6666, 7777, 8888, 9999)
add chain=forward in-interface-list=LAN out-interface-list=WAN protocol=tcp dst-port=3333,4444,5555,6666,7777,8888,9999 action=drop log=yes log-prefix="[TIKSENTRY-LAN-DROP]" comment="[TikSentry] Alerta LAN: Malware C2 / Cryptomining para fora"

# 6.4 Varreduras ou ataques de maquinas da LAN tentando invadir o Roteador MikroTik (Input)
add chain=input in-interface-list=LAN connection-state=invalid action=drop log=yes log-prefix="[TIKSENTRY-LAN-DROP]" comment="[TikSentry] Descarte e Log de Anomalias LAN no Router"
`;

    res.json({
      success: true,
      script,
      serverHost,
      syslogPort,
      blockList,
      quarantineList,
      wanInterfaces
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
