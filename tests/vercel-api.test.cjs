const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const handler = require('../api/index.js');

async function request(path, method = 'GET') {
  const server = http.createServer(handler);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}${path}`, { method });
    return { status: response.status, body: method === 'HEAD' ? null : await response.json(),
      headers: response.headers };
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
}

test('health is public and status discloses backend availability', async () => {
  assert.equal((await request('/api/health?probe=1')).body.status, 'ok');
  const response = await request('/api/status');
  assert.equal(response.body.backend_connected, false);
  assert.equal(response.body.status, 'static-site-only');
  assert.equal(response.headers.get('cache-control'), 'no-store');
});

test('unavailable operations use HTTP 200 without fabricating results', async () => {
  const endpoints = [
    ['POST', '/api/detect'], ['POST', '/api/webshell/scan'], ['POST', '/api/bind/create'],
    ['GET', '/api/bind'], ['GET', '/api/bind/313-FAKE'], ['GET', '/api/modules'],
    ['GET', '/api/attck/coverage'], ['POST', '/api/mobile/scan'],
    ['GET', '/api/mobile/status'], ['GET', '/api/mobile/alerts'],
    ['GET', '/api/mobile/findings'], ['GET', '/api/mobile/sessions'],
    ['GET', '/api/audit'], ['GET', '/api/audit/chain'], ['GET', '/api/stream'],
    ['GET', '/api/events'],
    ['POST', '/api/webhooks/example'], ['POST', '/api/scan/recon'],
    ['POST', '/api/scan/vuln'], ['GET', '/api/docs'], ['GET', '/api/openapi.json'],
    ['POST', '/api/chat'],
  ];
  for (const [method, path] of endpoints) {
    const response = await request(path, method);
    assert.equal(response.status, 200, `${method} ${path}`);
    assert.equal(response.body.status, 'unavailable');
    assert.equal(response.body.backend_connected, false);
    assert.equal(response.body.detected, undefined);
    assert.equal(response.body.bind_id, undefined);
  }
});

test('unknown paths return JSON 404 and known paths reject incorrect methods', async () => {
  assert.equal((await request('/api/does-not-exist')).status, 404);
  const response = await request('/api/health', 'POST');
  assert.equal(response.status, 405);
  assert.match(response.headers.get('allow'), /GET/);
  assert.equal((await request('/api/health', 'HEAD')).status, 200);
});

// Use node:http rather than fetch: WHATWG URL parsing rewrites these targets.
test('malformed request targets return JSON and leave the server healthy', async () => {
  const server = http.createServer(handler);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const rawRequest = path => new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port: server.address().port, path }, res => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: JSON.parse(body) }));
    });
    req.setTimeout(2000, () => req.destroy(new Error('HTTP regression request timed out')));
    req.on('error', reject);
    req.end();
  });
  try {
    for (const path of ['//[', '//[?probe=1', '/api/unknown?url=//[']) {
      const response = await rawRequest(path);
      assert.equal(response.status, 404);
      assert.equal(response.body.error, 'not_found');
      assert.match(response.headers['content-type'], /application\/json/);
    }
    const health = await rawRequest('/api/health?probe=//[');
    assert.equal(health.status, 200);
    assert.equal(health.body.status, 'ok');
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
