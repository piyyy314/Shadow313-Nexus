const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const handlerModule = require('../api/index.js');

async function withServer(handler, callback) {
  const server = http.createServer(handler);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    await callback(`http://127.0.0.1:${server.address().port}`);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
}

async function request(handler, path, method = 'GET', body) {
  const server = http.createServer(handler);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}${path}`, {
      method,
      headers: body ? { 'content-type': 'application/json' } : {},
      body,
    });
    return {
      status: response.status,
      body: method === 'HEAD' ? null : await response.json(),
      headers: response.headers,
    };
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
}

test('health reports website health separately from backend connectivity', async () => {
  const handler = handlerModule.createHandler({ env: {} });
  const response = await request(handler, '/api/health?probe=1');
  assert.equal(response.status, 200);
  assert.equal(response.body.status, 'ok');
  assert.equal(response.body.backend_connected, false);
});

test('status clearly reports missing backend configuration', async () => {
  const handler = handlerModule.createHandler({ env: {} });
  const response = await request(handler, '/api/status');
  assert.equal(response.status, 200);
  assert.equal(response.body.status, 'static-site-only');
  assert.equal(response.body.backend_connected, false);
  assert.match(response.body.message, /SHADOW313_BACKEND_URL/);
  assert.equal(response.headers.get('cache-control'), 'no-store');
});

test('status checks the real Python backend before reporting connected', async () => {
  const handler = handlerModule.createHandler({
    env: { SHADOW313_BACKEND_URL: 'https://api.example.test' },
    fetch: async url => {
      assert.equal(url, 'https://api.example.test/api/status');
      return new Response(JSON.stringify({ status: 'operational', version: '4.0.0' }), {
        status: 200, headers: { 'content-type': 'application/json' },
      });
    },
  });
  const response = await request(handler, '/api/status');
  assert.equal(response.status, 200);
  assert.equal(response.body.backend_connected, true);
  assert.equal(response.body.gateway, 'vercel');
});

test('protected API requests are proxied with a server-side credential', async () => {
  let upstreamRequest;
  const handler = handlerModule.createHandler({
    env: {
      SHADOW313_BACKEND_URL: 'https://api.example.test',
      SHADOW313_BACKEND_API_KEY: 'server-only-test-key',
    },
    fetch: async (url, options) => {
      upstreamRequest = { url, options };
      return new Response(JSON.stringify({ modules: [{ name: 'detect' }] }), {
        status: 200, headers: { 'content-type': 'application/json' },
      });
    },
  });
  const response = await request(handler, '/api/modules?limit=5');
  assert.equal(response.status, 200);
  assert.equal(response.body.modules[0].name, 'detect');
  assert.equal(upstreamRequest.url, 'https://api.example.test/api/modules?limit=5');
  assert.equal(upstreamRequest.options.headers['X-API-Key'], 'server-only-test-key');
});

test('protected routes fail closed when the server-side API key is absent', async () => {
  const handler = handlerModule.createHandler({
    env: { SHADOW313_BACKEND_URL: 'https://api.example.test' },
    fetch: async () => { throw new Error('must not call backend'); },
  });
  const response = await request(handler, '/api/modules');
  assert.equal(response.status, 503);
  assert.equal(response.body.error, 'backend_auth_not_configured');
});

test('backend network failures are surfaced as 502, never fake success', async () => {
  const handler = handlerModule.createHandler({
    env: { SHADOW313_BACKEND_URL: 'https://api.example.test' },
    fetch: async () => { throw new Error('connection refused'); },
  });
  const response = await request(handler, '/api/status');
  assert.equal(response.status, 502);
  assert.equal(response.body.backend_connected, false);
  assert.equal(response.body.error, 'backend_unreachable');
});

test('backend health endpoint is proxied and normalized', async () => {
  const handler = handlerModule.createHandler({
    env: { SHADOW313_BACKEND_URL: 'https://api.example.test' },
    fetch: async url => {
      assert.equal(url, 'https://api.example.test/health');
      return new Response('{"status":"ok"}', { status: 200 });
    },
  });
  const response = await request(handler, '/api/health');
  assert.equal(response.status, 200);
  assert.equal(response.body.backend_connected, true);
});

test('backend URLs require HTTPS outside localhost', () => {
  assert.throws(
    () => handlerModule.resolveBackend({ SHADOW313_BACKEND_URL: 'http://api.example.test' }),
    /HTTPS/,
  );
  assert.equal(
    handlerModule.resolveBackend({ SHADOW313_BACKEND_URL: 'http://127.0.0.1:8313' }),
    'http://127.0.0.1:8313',
  );
});

test('unknown routes return JSON 404 and wrong methods return 405', async () => {
  const handler = handlerModule.createHandler({ env: {} });
  assert.equal((await request(handler, '/api/not-a-route')).status, 404);
  const wrongMethod = await request(handler, '/api/health', 'POST');
  assert.equal(wrongMethod.status, 405);
  assert.match(wrongMethod.headers.get('allow'), /GET/);
  assert.equal((await request(handler, '/api/health', 'HEAD')).status, 200);
});

test('request bodies are bounded before forwarding', async () => {
  const handler = handlerModule.createHandler({
    env: {
      SHADOW313_BACKEND_URL: 'https://api.example.test',
      SHADOW313_BACKEND_API_KEY: 'server-only-test-key',
    },
    fetch: async () => { throw new Error('must not call backend'); },
  });
  const response = await request(handler, '/api/chat', 'POST', JSON.stringify({ prompt: 'x'.repeat(1_048_600) }));
  assert.equal(response.status, 413);
  assert.equal(response.body.error, 'request_too_large');
});

test('malformed request targets return JSON and leave the server healthy', async () => {
  const handler = handlerModule.createHandler({ env: {} });
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

test('health does not report a backend connected when the health payload is unhealthy', async () => {
  const handler = handlerModule.createHandler({
    env: { SHADOW313_BACKEND_URL: 'https://api.example.test' },
    fetch: async () => new Response('{"status":"degraded"}', { status: 200 }),
  });
  const response = await request(handler, '/api/health');
  assert.equal(response.status, 503);
  assert.equal(response.body.backend_connected, false);
});
