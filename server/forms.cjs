// Notification-only forms. No mailing list, automatic subscription, or live scanner.
const MAX_BYTES = 16384;
const EMAIL = /^[^\s@<>\r\n]+@[^\s@<>\r\n]+\.[^\s@<>\r\n]+$/;
const configured = env => ['RESEND_API_KEY', 'FORM_FROM_EMAIL', 'FORM_TO_EMAIL',
  'TURNSTILE_SECRET_KEY', 'TURNSTILE_SITE_KEY'].every(key => Boolean(env[key]));

async function readJSON(req) {
  if (req.body !== undefined) {
    const raw = Buffer.isBuffer(req.body) ? req.body.toString() :
      typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
    if (Buffer.byteLength(raw) > MAX_BYTES) throw new Error('size');
    return JSON.parse(raw);
  }
  const chunks = [];
  let bytes = 0;
  for await (const chunk of req) {
    bytes += Buffer.byteLength(chunk);
    if (bytes > MAX_BYTES) throw new Error('size');
    chunks.push(Buffer.from(chunk));
  }
  return JSON.parse(Buffer.concat(chunks).toString());
}

function createForms({env = process.env, fetcher = (...args) => fetch(...args)} = {}) {
  return async function forms(req, res, pathname) {
    const send = (status, body) => { res.statusCode = status; res.end(JSON.stringify(body)); };
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    if (pathname === '/api/forms/config') {
      if (req.method !== 'GET') { res.setHeader('Allow', 'GET'); return send(405, {error:'method_not_allowed'}); }
      return send(200, {enabled:configured(env), siteKey:configured(env) ? env.TURNSTILE_SITE_KEY : null});
    }
    if (req.method !== 'POST') { res.setHeader('Allow', 'POST'); return send(405, {error:'method_not_allowed'}); }
    if (!configured(env)) return send(503, {error:'forms_unavailable', message:'Online forms are not configured. Please use the direct email link.'});
    const allowed = new Set(['https://shadow313.com','https://www.shadow313.com','https://shadow313.dev','https://www.shadow313.dev']);
    if (env.VERCEL_URL) allowed.add(`https://${env.VERCEL_URL}`);
    if (!allowed.has(req.headers.origin)) return send(403, {error:'origin_rejected'});
    if (!/^application\/json(?:;|$)/i.test(req.headers['content-type'] || '')) return send(415, {error:'json_required'});
    let data;
    try { data = await readJSON(req); }
    catch { return send(400, {error:'invalid_or_oversized_body'}); }
    const contact = pathname === '/api/contact';
    const clean = (value, max) => typeof value === 'string' && value.trim().length <= max ? value.trim() : '';
    if (!data || Array.isArray(data) || typeof data !== 'object') return send(400, {error:'invalid_form'});
    const email = clean(data.email, 254);
    const name = clean(data.name, 100);
    const message = clean(data.message, 5000);
    const subject = clean(data.subject, 120);
    const token = clean(data.token, 2048);
    if (!EMAIL.test(email) || !token || data.consent !== true || data.website ||
        (contact && (!name || !message || /[\r\n]/.test(name + subject)))) return send(400, {error:'invalid_form'});
    // Recipient and sender are server configuration, never user-controlled input.
    if (!EMAIL.test(env.FORM_TO_EMAIL) || !EMAIL.test(env.FORM_FROM_EMAIL)) return send(503, {error:'forms_unavailable'});
    const action = contact ? 'contact' : 'waitlist';
    try {
      const verification = await fetcher('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method:'POST', headers:{'Content-Type':'application/json'}, signal:AbortSignal.timeout(10000),
        body:JSON.stringify({secret:env.TURNSTILE_SECRET_KEY, response:token}),
      });
      const check = await verification.json();
      const hostname = new URL(req.headers.origin).hostname;
      if (!verification.ok || !check.success || check.action !== action || check.hostname !== hostname) {
        return send(403, {error:'challenge_failed', message:'Please complete the verification again.'});
      }
      const response = await fetcher('https://api.resend.com/emails', {
        method:'POST', signal:AbortSignal.timeout(10000), headers:{
          Authorization:`Bearer ${env.RESEND_API_KEY}`, 'Content-Type':'application/json',
        },
        body:JSON.stringify({from:env.FORM_FROM_EMAIL, to:[env.FORM_TO_EMAIL], reply_to:email,
          subject: contact ? `Shadow313 contact: ${subject || 'General inquiry'}` : 'Shadow313 early-access request',
          text: contact ? `Name: ${name}\nEmail: ${email}\n\n${message}` :
            `Early-access notification request\nEmail: ${email}\nConsent: send this request to the site operator.\nThis is not a marketing subscription.`,
        }),
      });
      const result = await response.json();
      if (!response.ok || typeof result.id !== 'string') return send(502, {error:'delivery_failed', message:'The request could not be sent. Please email us directly.'});
      // Provider acceptance is not proof of inbox delivery. Do not overclaim.
      return send(202, {accepted:true, message:'Your request was accepted by our email provider. Inbox delivery is not yet confirmed.'});
    } catch {
      return send(502, {error:'delivery_failed', message:'The request could not be sent. Please email us directly.'});
    }
  };
}
module.exports = {createForms};
