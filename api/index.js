'use strict';

// Vercel is the public website/API gateway. The Python FastAPI service is hosted
// separately and is reached only through server-side environment variables.
const backendRoutes = [
  ['GET', /^\/api\/(modules|attck\/coverage|bind|audit|audit\/chain|stream|events|docs|openapi\.json)$/],
  ['GET', /^\/api\/bind\/(?!create$)[^/]+$/],
  ['GET', /^\/api\/mobile\/(status|alerts|findings|sessions)$/],
  ['POST', /^\/api\/(detect|webshell\/scan|bind\/create|mobile\/scan|scan\/recon|scan\/vuln|chat)$/],
  ['GET', /^\/api\/shiatoali(?:\/.*)?$/],
  ['POST', /^\/api\/shiatoali(?:\/.*)?$/],
  ['PATCH', /^\/api\/shiatoali\/cases\/[^/]+$/],
];

const MAX_REQUEST_BYTES = 1_048_576;
const MAX_RESPONSE_BYTES = 2_097_152;

function send(res, req, status, body, headers = {}) {
  res.statusCode = status;
  res.setHeader('Content-Type', headers['content-type'] || 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  for (const name of ['allow', 'retry-after']) {
    if (headers[name]) res.setHeader(name, headers[name]);
  }
  res.end(req.method === 'HEAD' ? undefined : body);
}

function json(res, req, status, body, headers = {}) {
  send(res, req, status, JSON.stringify(body), headers);
}

function resolveBackend(env) {
  const configured = env.SHADOW313_BACKEND_URL;
  if (!configured) return null;
  let url;
  try {
    url = new URL(configured);
  } catch {
    throw new Error('SHADOW313_BACKEND_URL must be a valid absolute URL');
  }
  const localHttp = url.protocol === 'http:' &&
    ['localhost', '127.0.0.1', '::1'].includes(url.hostname);
  if (url.protocol !== 'https:' && !localHttp) {
    throw new Error('SHADOW313_BACKEND_URL must use HTTPS outside localhost');
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error('SHADOW313_BACKEND_URL must not contain credentials, query, or fragment');
  }
  return url.toString().replace(/\/$/, '');
}

async function readRequestBody(req) {
  const chunks = [];
  let size = 0;
  let tooLarge = false;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_REQUEST_BYTES) {
      tooLarge = true;
      continue; // Drain the request so the gateway can return a clean 413 response.
    }
    if (!tooLarge) chunks.push(chunk);
  }
  if (tooLarge) {
    const error = new Error('Request body exceeds 1 MiB');
    error.statusCode = 413;
    throw error;
  }
  return Buffer.concat(chunks);
}

async function readResponseBody(response) {
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      const error = new Error('Backend response exceeds 2 MiB');
      error.statusCode = 502;
      throw error;
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks, size);
}

function createHandler(options = {}) {
  const env = options.env || process.env;
  const fetchImpl = options.fetch || globalThis.fetch;
  const timeoutMs = options.timeoutMs || 15000;

  async function requestBackend(base, path, method, body, includeKey = true) {
    const headers = { Accept: 'application/json' };
    if (body && body.length) headers['Content-Type'] = 'application/json';
    if (includeKey && env.SHADOW313_BACKEND_API_KEY) {
      headers['X-API-Key'] = env.SHADOW313_BACKEND_API_KEY;
    }
    const response = await fetchImpl(base + path, {
      method,
      headers,
      body: body && body.length ? body : undefined,
      cache: 'no-store',
      signal: AbortSignal.timeout(timeoutMs),
      redirect: 'error',
    });
    const responseBody = await readResponseBody(response);
    return {
      status: response.status,
      body: responseBody,
      headers: {
        'content-type': response.headers.get('content-type') || 'application/json; charset=utf-8',
        allow: response.headers.get('allow'),
        'retry-after': response.headers.get('retry-after'),
      },
    };
  }

  return async function handler(req, res) {
    const rawTarget = typeof req.url === 'string' ? req.url : '/';
    const path = rawTarget.split('?', 1)[0].replace(/\/$/, '') || '/';
    const method = req.method === 'HEAD' ? 'GET' : req.method;
    const health = path === '/api/health';
    const status = path === '/api/status';
    const matches = backendRoutes.filter(([, pattern]) => pattern.test(path));
    const route = matches.find(([allowed]) => allowed === method);

    if (!health && !status && matches.length === 0) {
      return json(res, req, 404, { error: 'not_found' });
    }
    const allowedMethods = health || status
      ? ['GET']
      : [...new Set(matches.map(([allowed]) => allowed))];
    if (!allowedMethods.includes(method)) {
      const allow = [
        ...allowedMethods,
        ...(allowedMethods.includes('GET') ? ['HEAD'] : []),
      ].join(', ');
      return json(res, req, 405, { error: 'method_not_allowed' }, { allow });
    }

    let base;
    try {
      base = resolveBackend(env);
    } catch (error) {
      return json(res, req, 503, {
        status: 'unavailable',
        backend_connected: false,
        error: 'backend_configuration_invalid',
        message: error.message,
      });
    }

    if (!base) {
      if (health) {
        return json(res, req, 200, {
          status: 'ok',
          service: 'shadow313-website-api',
          backend_connected: false,
          timestamp: new Date().toISOString(),
        });
      }
      return json(res, req, status ? 200 : 503, {
        status: 'static-site-only',
        platform: 'Shadow313 NEXUS',
        backend_connected: false,
        message: 'The website gateway is online, but SHADOW313_BACKEND_URL is not configured.',
      });
    }

    if (route && !health && !status && !env.SHADOW313_BACKEND_API_KEY) {
      return json(res, req, 503, {
        status: 'unavailable',
        backend_connected: true,
        error: 'backend_auth_not_configured',
        message: 'The backend URL is configured but the server-side API credential is missing.',
      });
    }

    try {
      const upstreamPath = health ? '/health' : status ? '/api/status' : rawTarget;
      const body = route && method !== 'GET' ? await readRequestBody(req) : undefined;
      const upstream = await requestBackend(base, upstreamPath, method, body, Boolean(route));
      if (health) {
        let healthy = false;
        try {
          const healthPayload = JSON.parse(upstream.body.toString('utf8'));
          healthy = upstream.status >= 200 && upstream.status < 300 && healthPayload.status === 'ok';
        } catch {
          healthy = false;
        }
        return json(res, req, healthy ? 200 : 503, {
          status: healthy ? 'ok' : 'unhealthy',
          service: 'shadow313-nexus-api',
          backend_connected: healthy,
        });
      }
      if (status) {
        let payload;
        try {
          payload = JSON.parse(upstream.body.toString('utf8'));
        } catch {
          return json(res, req, 502, {
            status: 'unavailable',
            backend_connected: false,
            error: 'invalid_backend_response',
          });
        }
        if (upstream.status < 200 || upstream.status >= 300) {
          return json(res, req, 503, {
            status: 'unavailable',
            backend_connected: false,
            error: 'backend_health_check_failed',
          });
        }
        return json(res, req, 200, {
          ...payload,
          backend_connected: payload.status === 'operational',
          gateway: 'vercel',
        });
      }
      return send(res, req, upstream.status, upstream.body, upstream.headers);
    } catch (error) {
      const statusCode = error.statusCode || (error.name === 'TimeoutError' ? 504 : 502);
      return json(res, req, statusCode, {
        status: 'unavailable',
        backend_connected: false,
        error: statusCode === 504 ? 'backend_timeout'
          : statusCode === 413 ? 'request_too_large'
            : statusCode === 502 && error.message.includes('Backend response') ? 'backend_response_too_large'
              : 'backend_unreachable',
        message: statusCode === 504
          ? 'The NEXUS backend did not respond before the gateway timeout.'
          : statusCode === 413
            ? 'The request body exceeds the configured gateway limit.'
            : 'The NEXUS backend could not complete the request.',
      });
    }
  };
}

const handler = createHandler();
handler.createHandler = createHandler;
handler.resolveBackend = resolveBackend;

if (require.main === module) {
  const port = process.env.PORT || 3000;
  require('node:http').createServer(handler).listen(port, () => {
    console.log('[Shadow313 Website API] Listening on port %s', port);
  });
}

module.exports = handler;
