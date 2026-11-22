(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.Shadow313NexusApi = api;
  if (root && root.document) {
    const start = () => api.mount(root.document);
    if (root.document.readyState === 'loading') {
      root.document.addEventListener('DOMContentLoaded', start, { once: true });
    } else {
      start();
    }
  }
})(typeof window !== 'undefined' ? window : globalThis, function () {
  'use strict';

  function normalizeStatus(payload) {
    if (!payload || typeof payload !== 'object') {
      return { connected: false, state: 'unavailable', label: 'BACKEND STATUS UNKNOWN',
        detail: 'The API returned an invalid status response.' };
    }
    if (payload.status === 'operational' || payload.backend_connected === true) {
      return { connected: true, state: 'connected', label: 'NEXUS BACKEND CONNECTED',
        detail: 'Live API status received from Shadow313 NEXUS.' };
    }
    if (payload.status === 'static-site-only' || payload.backend_connected === false) {
      return { connected: false, state: 'disconnected', label: 'WEBSITE ONLINE · BACKEND NOT CONNECTED',
        detail: payload.message || 'This site is serving the dashboard; connect the separately hosted Python API to enable live operations.' };
    }
    return { connected: false, state: 'unavailable', label: 'BACKEND UNAVAILABLE',
      detail: payload.message || 'The API did not report an operational backend.' };
  }

  async function fetchStatus(options) {
    const config = options || {};
    const fetcher = config.fetch || (typeof fetch === 'function' ? fetch : null);
    if (!fetcher) throw new Error('Fetch is not available in this environment.');
    const base = String(config.baseUrl || '/api').replace(/\/$/, '');
    const response = await fetcher(base + '/status', {
      method: 'GET',
      headers: { Accept: 'application/json' },
      cache: 'no-store'
    });
    if (!response || !response.ok) {
      throw new Error('NEXUS status request failed' + (response ? ' (HTTP ' + response.status + ')' : '.'));
    }
    return normalizeStatus(await response.json());
  }

  function mount(doc) {
    const target = doc.getElementById('nexus-backend-status');
    if (!target) return;
    target.dataset.state = 'checking';
    target.textContent = 'CHECKING NEXUS BACKEND…';
    const base = (typeof window !== 'undefined' && window.SHADOW313_API_BASE) || '/api';
    fetchStatus({ baseUrl: base }).then((status) => {
      target.dataset.state = status.state;
      target.textContent = status.label;
      target.title = status.detail;
      target.setAttribute('aria-label', status.label + '. ' + status.detail);
    }).catch((error) => {
      target.dataset.state = 'unavailable';
      target.textContent = 'BACKEND STATUS UNAVAILABLE';
      target.title = error.message;
      target.setAttribute('aria-label', 'Backend status unavailable. ' + error.message);
    });
  }

  return { normalizeStatus, fetchStatus, mount };
});
