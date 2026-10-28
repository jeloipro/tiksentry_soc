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
