const https = require('https');
const http = require('http');
const { RouterOSAPI } = require('node-routeros');
const db = require('../storage/db');
const config = require('../config');

class MikroTikClient {
  constructor() {
    this.cachedParams = null;
  }

  async getParams() {
    const settings = await db.getAllSettings();
    return {
      protocol: settings['mikrotik_protocol'] || config.mikrotik.protocol || 'rest',
      host: settings['mikrotik_host'] || config.mikrotik.host,
      port: parseInt(settings['mikrotik_port'] || config.mikrotik.port, 10),
      username: settings['mikrotik_username'] || config.mikrotik.username,
      password: settings['mikrotik_password'] !== undefined ? settings['mikrotik_password'] : config.mikrotik.password,
      useTls: (settings['mikrotik_use_tls'] || String(config.mikrotik.useTls)) === 'true',
      blockListName: settings['mikrotik_block_list'] || config.mikrotik.blockListName || 'TIKSENTRY_BLOCKED',
      autoBlock: (settings['mikrotik_auto_block'] || String(config.mikrotik.autoBlock)) === 'true'
    };
  }

  // Testa conexão e retorna detalhes do equipamento
  async testConnection(customParams = null) {
    const params = customParams || await this.getParams();

    if (params.protocol === 'rest') {
      return await this._testRest(params);
    } else {
      return await this._testSocketApi(params);
    }
  }

  // Detecta interfaces WAN (conectadas à internet com rota 0.0.0.0/0 e interface-list WAN)
  async detectWanInterfaces(customParams = null) {
    const params = customParams || await this.getParams();

    if (params.protocol === 'rest') {
      return await this._detectWanRest(params);
    } else {
      return await this._detectWanSocketApi(params);
    }
  }

  // =========================================================================
  // MIKROTIK REST API (RouterOS v7)
  // =========================================================================

  _getRestAgent(useTls) {
    if (useTls) {
      return new https.Agent({ rejectUnauthorized: false });
    }
    return new http.Agent();
  }

  async _fetchRest(params, endpoint, method = 'GET', body = null) {
    const protocol = params.useTls ? 'https' : 'http';
    const url = `${protocol}://${params.host}:${params.port}/rest${endpoint}`;
    const authHeader = 'Basic ' + Buffer.from(`${params.username}:${params.password}`).toString('base64');

    const options = {
      method,
      headers: {
        'Authorization': authHeader,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      agent: this._getRestAgent(params.useTls),
      signal: AbortSignal.timeout(8000)
    };

    if (body && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
      options.body = JSON.stringify(body);
    }

    const response = await fetch(url, options);
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`HTTP ${response.status} ${response.statusText}: ${errorText}`);
    }

    // Algumas respostas de DELETE ou 204 não têm conteúdo
    const text = await response.text();
    if (!text) return null;
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  }

  async _testRest(params) {
    try {
      const [resData, idData] = await Promise.all([
        this._fetchRest(params, '/system/resource'),
        this._fetchRest(params, '/system/identity')
      ]);

      const resource = Array.isArray(resData) ? resData[0] : resData;
      const identity = Array.isArray(idData) ? idData[0] : idData;

      return {
        success: true,
        protocol: 'rest',
        identity: identity?.name || 'MikroTik Router',
        version: resource?.version || 'RouterOS v7.x',
        boardName: resource?.['board-name'] || resource?.platform || 'RouterBOARD',
        uptime: resource?.uptime || 'N/A',
        cpuLoad: resource?.['cpu-load'] !== undefined ? `${resource['cpu-load']}%` : 'N/A',
        freeMemory: resource?.['free-memory'] ? `${Math.round(resource['free-memory'] / 1024 / 1024)} MB` : 'N/A'
      };
    } catch (err) {
      return {
        success: false,
        protocol: 'rest',
        error: err.message
      };
    }
  }

  async _detectWanRest(params) {
    try {
      const [routesData, interfaceListsData, allInterfacesData] = await Promise.all([
        this._fetchRest(params, '/ip/route').catch(() => []),
        this._fetchRest(params, '/interface/list/member').catch(() => []),
        this._fetchRest(params, '/interface').catch(() => [])
      ]);

      const routes = Array.isArray(routesData) ? routesData : [];
      const listMembers = Array.isArray(interfaceListsData) ? interfaceListsData : [];
      const interfaces = Array.isArray(allInterfacesData) ? allInterfacesData : [];

      const detectedWanSet = new Set();
      const detectedLanSet = new Set();

      // 1. Membros da lista WAN e LAN do RouterOS
      for (const m of listMembers) {
        const listName = (m.list || '').toUpperCase();
        const iface = m.interface;
        if (iface) {
          if (listName === 'WAN') detectedWanSet.add(iface);
          if (listName === 'LAN') detectedLanSet.add(iface);
        }
      }

      // 2. Extrai interfaces associadas à rota padrão 0.0.0.0/0 (Internet)
      const defaultRoutes = routes.filter(r => {
        const dst = r['dst-address'] || r.dstAddress || '';
        return dst === '0.0.0.0/0' || dst.startsWith('0.0.0.0/0');
      });

      const routeGateways = [];
      for (const dr of defaultRoutes) {
        const gw = dr.gateway || dr['immediate-gw'] || dr.interface || '';
        const active = dr.active === true || dr.active === 'true' || dr.disabled === false || dr.disabled === 'false';
        routeGateways.push({
          dstAddress: dr['dst-address'] || '0.0.0.0/0',
          gateway: gw,
          distance: dr.distance || 1,
          active
        });

        if (gw) {
          const cleanGw = gw.replace(/^%/, '').trim();
          const matchedIface = interfaces.find(i => i.name === cleanGw || cleanGw.includes(i.name));
          if (matchedIface) {
            detectedWanSet.add(matchedIface.name);
          } else if (!cleanGw.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)) {
            detectedWanSet.add(cleanGw);
          }
        }
      }

      // 3. Fallback inteligente por nomenclatura caso lista/rota estejam vazias
      if (detectedWanSet.size === 0) {
        for (const iface of interfaces) {
          const name = (iface.name || '').toLowerCase();
          if (name.includes('wan') || name.includes('pppoe') || name.includes('internet') || name === 'ether1' || name.startsWith('sfp')) {
            detectedWanSet.add(iface.name);
          }
        }
      }

      // Identifica interfaces LAN
      for (const iface of interfaces) {
        const name = (iface.name || '').toLowerCase();
        if (!detectedWanSet.has(iface.name)) {
          if (name.includes('lan') || name.includes('bridge') || name.startsWith('ether') || name.startsWith('wlan')) {
            detectedLanSet.add(iface.name);
          }
        }
      }

      const wanInterfaces = Array.from(detectedWanSet);
      const lanInterfaces = Array.from(detectedLanSet);

      if (wanInterfaces.length > 0) {
        await db.setSetting('wan_interfaces', wanInterfaces.join(','));
      }
      if (lanInterfaces.length > 0) {
        await db.setSetting('lan_interfaces', lanInterfaces.join(','));
      }

      return {
        success: true,
        protocol: 'rest',
        defaultRoutes: routeGateways,
        wanInterfaces,
        lanInterfaces,
        totalInterfaces: interfaces.length
      };
    } catch (err) {
      return {
        success: false,
        protocol: 'rest',
        error: err.message
      };
    }
  }

  // =========================================================================
  // MIKROTIK SOCKET API (RouterOS v6 & v7 via porta 8728)
  // =========================================================================

  async _testSocketApi(params) {
    const client = new RouterOSAPI({
      host: params.host,
      port: params.port || 8728,
      user: params.username,
      password: params.password,
      tls: params.useTls,
      timeout: 8
    });

    try {
      await client.connect();
      const identityRes = await client.write('/system/identity/print');
      const resourceRes = await client.write('/system/resource/print');
      await client.close();

      const identity = identityRes && identityRes[0] ? identityRes[0].name : 'MikroTik Router';
      const resource = resourceRes && resourceRes[0] ? resourceRes[0] : {};

      return {
        success: true,
        protocol: 'api',
        identity: identity,
        version: resource.version || 'RouterOS v6/v7',
        boardName: resource['board-name'] || resource.platform || 'RouterBOARD',
        uptime: resource.uptime || 'N/A',
        cpuLoad: resource['cpu-load'] !== undefined ? `${resource['cpu-load']}%` : 'N/A',
        freeMemory: resource['free-memory'] ? `${Math.round(resource['free-memory'] / 1024 / 1024)} MB` : 'N/A'
      };
    } catch (err) {
      try { await client.close(); } catch {}
      return {
        success: false,
        protocol: 'api',
        error: err.message || err.toString() || 'Falha na conexão com o MikroTik via API Socket (porta 8728)'
      };
    }
  }

  async _detectWanSocketApi(params) {
    const client = new RouterOSAPI({
      host: params.host,
      port: params.port || 8728,
      user: params.username,
      password: params.password,
      tls: params.useTls,
      timeout: 8
    });

    try {
      await client.connect();
      const routesRes = await client.write('/ip/route/print').catch(() => []);
      const listsRes = await client.write('/interface/list/member/print').catch(() => []);
      const ifacesRes = await client.write('/interface/print').catch(() => []);
      await client.close();

      const routes = Array.isArray(routesRes) ? routesRes : [];
      const listMembers = Array.isArray(listsRes) ? listsRes : [];
      const interfaces = Array.isArray(ifacesRes) ? ifacesRes : [];

      const detectedWanSet = new Set();
      const detectedLanSet = new Set();

      for (const m of listMembers) {
        const listName = (m.list || '').toUpperCase();
        const iface = m.interface;
        if (iface) {
          if (listName === 'WAN') detectedWanSet.add(iface);
          if (listName === 'LAN') detectedLanSet.add(iface);
        }
      }

      const defaultRoutes = routes.filter(r => {
        const dst = r['dst-address'] || '';
        return dst === '0.0.0.0/0' || dst.startsWith('0.0.0.0/0');
      });

      const routeGateways = [];
      for (const dr of defaultRoutes) {
        const gw = dr.gateway || dr['immediate-gw'] || dr.interface || '';
        routeGateways.push({
          dstAddress: dr['dst-address'] || '0.0.0.0/0',
          gateway: gw,
          distance: dr.distance || 1,
          active: dr.active === 'true' || dr.disabled === 'false'
        });

        if (gw) {
          const cleanGw = gw.replace(/^%/, '').trim();
          const matchedIface = interfaces.find(i => i.name === cleanGw || cleanGw.includes(i.name));
          if (matchedIface) {
            detectedWanSet.add(matchedIface.name);
          } else if (!cleanGw.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)) {
            detectedWanSet.add(cleanGw);
          }
        }
      }

      if (detectedWanSet.size === 0) {
        for (const iface of interfaces) {
          const name = (iface.name || '').toLowerCase();
          if (name.includes('wan') || name.includes('pppoe') || name.includes('internet') || name === 'ether1' || name.startsWith('sfp')) {
            detectedWanSet.add(iface.name);
          }
        }
      }

      for (const iface of interfaces) {
        const name = (iface.name || '').toLowerCase();
        if (!detectedWanSet.has(iface.name)) {
          if (name.includes('lan') || name.includes('bridge') || name.startsWith('ether') || name.startsWith('wlan')) {
            detectedLanSet.add(iface.name);
          }
        }
      }

      const wanInterfaces = Array.from(detectedWanSet);
      const lanInterfaces = Array.from(detectedLanSet);

      if (wanInterfaces.length > 0) {
        await db.setSetting('wan_interfaces', wanInterfaces.join(','));
      }
      if (lanInterfaces.length > 0) {
        await db.setSetting('lan_interfaces', lanInterfaces.join(','));
      }

      return {
        success: true,
        protocol: 'api',
        defaultRoutes: routeGateways,
        wanInterfaces,
        lanInterfaces,
        totalInterfaces: interfaces.length
      };
    } catch (err) {
      try { await client.close(); } catch {}
      return {
        success: false,
        protocol: 'api',
        error: err.message || err.toString()
      };
    }
  }

  // =========================================================================
  // GERENCIAMENTO DE ADDRESS-LIST NO MIKROTIK
  // =========================================================================

  /**
   * Adiciona um IP à Address-List do MikroTik
   */
  async addIpToAddressList(ip, reason = 'TikSentry Auto-Block', timeoutMinutes = 60, customList = null) {
    const params = await this.getParams();
    const listName = customList || params.blockListName;
    const timeoutStr = timeoutMinutes > 0 ? `${timeoutMinutes}m0s` : undefined;

    if (params.protocol === 'rest') {
      try {
        const payload = {
          list: listName,
          address: ip,
          comment: `[TikSentry] ${reason}`.substring(0, 80)
        };
        if (timeoutStr) {
          payload.timeout = timeoutStr;
        }

        await this._fetchRest(params, '/ip/firewall/address-list', 'PUT', payload);
        return { success: true };
      } catch (err) {
        console.error(`[MikroTik REST] Erro ao adicionar ${ip} na lista ${listName}:`, err.message);
        return { success: false, error: err.message };
      }
    } else {
      const client = new RouterOSAPI({
        host: params.host,
        port: params.port || 8728,
        user: params.username,
        password: params.password,
        tls: params.useTls,
        timeout: 8
      });

      try {
        await client.connect();
        const args = [
          `=list=${listName}`,
          `=address=${ip}`,
          `=comment=[TikSentry] ${reason}`.substring(0, 80)
        ];
        if (timeoutStr) {
          args.push(`=timeout=${timeoutStr}`);
        }

        await client.write('/ip/firewall/address-list/add', args);
        await client.close();
        return { success: true };
      } catch (err) {
        try { await client.close(); } catch {}
        console.error(`[MikroTik API] Erro ao adicionar ${ip} na lista ${listName}:`, err.message);
        return { success: false, error: err.message };
      }
    }
  }

  /**
   * Remove um IP da Address-List do MikroTik
   */
  async removeIpFromAddressList(ip, customList = null) {
    const params = await this.getParams();
    const listName = customList || params.blockListName;

    if (params.protocol === 'rest') {
      try {
        // Busca o ID do registro na lista
        const items = await this._fetchRest(params, `/ip/firewall/address-list?list=${encodeURIComponent(listName)}&address=${encodeURIComponent(ip)}`);
        if (Array.isArray(items) && items.length > 0) {
          for (const item of items) {
            const id = item['.id'];
            if (id) {
              await this._fetchRest(params, `/ip/firewall/address-list/${encodeURIComponent(id)}`, 'DELETE');
            }
          }
        }
        return { success: true };
      } catch (err) {
        console.error(`[MikroTik REST] Erro ao remover ${ip}:`, err.message);
        return { success: false, error: err.message };
      }
    } else {
      const client = new RouterOSAPI({
        host: params.host,
        port: params.port || 8728,
        user: params.username,
        password: params.password,
        tls: params.useTls,
        timeout: 8
      });

      try {
        await client.connect();
        const findRes = await client.write('/ip/firewall/address-list/print', [
          `?list=${listName}`,
          `?address=${ip}`
        ]);

        if (Array.isArray(findRes) && findRes.length > 0) {
          for (const item of findRes) {
            if (item['.id']) {
              await client.write('/ip/firewall/address-list/remove', [`=.id=${item['.id']}`]);
            }
          }
        }
        await client.close();
        return { success: true };
      } catch (err) {
        try { await client.close(); } catch {}
        console.error(`[MikroTik API] Erro ao remover ${ip}:`, err.message);
        return { success: false, error: err.message };
      }
    }
  }

  /**
   * Retorna os IPs atualmente bloqueados na lista do MikroTik
   */
  async getBlockedListFromMikroTik(customList = null) {
    const params = await this.getParams();
    const listName = customList || params.blockListName;

    if (params.protocol === 'rest') {
      try {
        const items = await this._fetchRest(params, `/ip/firewall/address-list?list=${encodeURIComponent(listName)}`);
        return Array.isArray(items) ? items : [];
      } catch (err) {
        return [];
      }
    } else {
      const client = new RouterOSAPI({
        host: params.host,
        port: params.port || 8728,
        user: params.username,
        password: params.password,
        tls: params.useTls,
        timeout: 8
      });

      try {
        await client.connect();
        const res = await client.write('/ip/firewall/address-list/print', [`?list=${listName}`]);
        await client.close();
        return Array.isArray(res) ? res : [];
      } catch (err) {
        try { await client.close(); } catch {}
        return [];
      }
    }
  }
}

const clientInstance = new MikroTikClient();
module.exports = clientInstance;
