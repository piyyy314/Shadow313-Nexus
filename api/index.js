// This static website does not run the Python security backend.
// Backend-dependent routes report unavailability rather than fabricated results.
const backendRoutes = [
  ['GET', /^\/api\/(modules|attck\/coverage|bind|audit|audit\/chain|stream|events|docs|openapi\.json)$/],
  ['GET', /^\/api\/bind\/[^/]+$/],
  ['GET', /^\/api\/mobile\/(status|alerts|findings|sessions)$/],
  ['POST', /^\/api\/(detect|webshell\/scan|bind\/create|mobile\/scan|scan\/recon|scan\/vuln|chat)$/],
  ['POST', /^\/api\/webhooks\/[^/]+$/],
];

function handler(req, res) {
  const path = req.url.split('?', 1)[0].replace(/\/$/, '');
  const method = req.method === 'HEAD' ? 'GET' : req.method;
  const health = path === '/api/health';
  const status = path === '/api/status';
  const routes = backendRoutes.filter(([, pattern]) => pattern.test(path));
  const route = routes.find(([allowed]) => method === allowed) || routes[0];
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');

  const send = (code, body) => {
    res.statusCode = code;
    res.end(req.method === 'HEAD' ? undefined : JSON.stringify(body));
  };
  if (!health && !status && !route) {
    return send(404, { error: 'not_found' });
  }
  const allowed = health || status ? 'GET' : route[0];
  if (method !== allowed) {
    res.setHeader('Allow', allowed === 'GET' ? 'GET, HEAD' : allowed);
    return send(405, { error: 'method_not_allowed' });
  }
  if (health) {
    return send(200, { status: 'ok', version: '4.0.0', timestamp: new Date().toISOString() });
  }
  if (status) {
    return send(200, {
      status: 'static-site-only', platform: 'Shadow313 NEXUS', version: '4.0.0',
      backend_connected: false,
    });
  }
  return send(200, {
    status: 'unavailable',
    backend_connected: false,
    message: 'This website does not run the Shadow313 Python backend. Use the locally hosted API; see /docs/api.',
  });
}

if (require.main === module) {
  const port = process.env.PORT || 3000;
  require('node:http').createServer(handler).listen(port, () => {
    console.log('[Shadow313 Website API] Listening on port %s', port);
  });
}
module.exports = handler;
