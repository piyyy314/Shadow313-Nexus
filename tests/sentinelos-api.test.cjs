const { test } = require('node:test');
const assert = require('node:assert/strict');
const { normalizeStatus, fetchStatus } = require('../sentinelos/js/nexus-api.js');

test('reports the static-site adapter as disconnected, not as a live backend', () => {
  const status = normalizeStatus({ status: 'static-site-only', backend_connected: false });
  assert.equal(status.connected, false);
  assert.equal(status.state, 'disconnected');
  assert.match(status.label, /BACKEND NOT CONNECTED/);
});

test('recognizes an operational Python NEXUS API', () => {
  const status = normalizeStatus({ status: 'operational', api_endpoints: { detection: 'available' } });
  assert.equal(status.connected, true);
  assert.equal(status.state, 'connected');
});

test('does not treat unavailable or malformed responses as connected', () => {
  assert.equal(normalizeStatus({ status: 'unavailable' }).connected, false);
  assert.equal(normalizeStatus(null).connected, false);
});

test('fetches the configured status endpoint without caching', async () => {
  let request;
  const status = await fetchStatus({
    baseUrl: 'https://api.example.test/',
    fetch: async (url, options) => {
      request = { url, options };
      return { ok: true, json: async () => ({ status: 'operational' }) };
    }
  });
  assert.equal(request.url, 'https://api.example.test/api/status');
  assert.equal(request.options.cache, 'no-store');
  assert.equal(status.connected, true);
});

test('surfaces HTTP errors rather than claiming a connection', async () => {
  await assert.rejects(
    fetchStatus({ fetch: async () => ({ ok: false, status: 503 }) }),
    /HTTP 503/
  );
});
