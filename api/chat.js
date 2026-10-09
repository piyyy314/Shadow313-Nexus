const AI_GATEWAY_URL = 'https://ai-gateway.vercel.sh/v1/chat/completions';
const DEFAULT_MODEL = 'openai/gpt-5.5';
const DEFAULT_OLLAMA_URL = 'http://127.0.0.1:11434';
const MAX_BODY_BYTES = 1024 * 1024;
const MAX_MESSAGES = 50;
const RATE_LIMIT_WINDOW_SECONDS = Number(process.env.RATE_LIMIT_WINDOW_SECONDS || 60);
const RATE_LIMIT_WINDOW_MS = RATE_LIMIT_WINDOW_SECONDS * 1000;
const CHAT_RATE_LIMIT_MAX = Number(process.env.CHAT_RATE_LIMIT_MAX || 30);
const rateLimitHits = new Map();

function sendJson(res, status, payload) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.end(JSON.stringify(payload));
}

async function readJsonBody(req) {
  if (req.body) {
    return typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
  }

  let body = '';
  for await (const chunk of req) {
    body += chunk;
    if (Buffer.byteLength(body, 'utf8') > MAX_BODY_BYTES) {
      throw new Error('Request body too large');
    }
  }
  return body ? JSON.parse(body) : {};
}

function getClientIp(req) {
  const forwardedFor = req.headers['x-forwarded-for'];
  if (typeof forwardedFor === 'string' && forwardedFor.trim()) {
    return forwardedFor.split(',')[0].trim();
  }
  return req.socket?.remoteAddress || 'unknown';
}

function checkRateLimit(key, limit) {
  const now = Date.now();
  const windowStart = now - RATE_LIMIT_WINDOW_MS;
  const hits = (rateLimitHits.get(key) || []).filter((timestamp) => timestamp > windowStart);
  if (hits.length >= limit) {
    rateLimitHits.set(key, hits);
    return false;
  }
  hits.push(now);
  rateLimitHits.set(key, hits);
  return true;
}

function normalizeMessages(input) {
  const rawMessages = Array.isArray(input.messages)
    ? input.messages
    : [{ role: 'user', content: String(input.message || '') }];

  if (rawMessages.length > MAX_MESSAGES) {
    throw new Error(`Too many messages; limit is ${MAX_MESSAGES}`);
  }

  return rawMessages
    .map((message) => ({
      role:
        message.role === 'assistant'
          ? 'assistant'
          : message.role === 'system'
            ? 'system'
            : 'user',
      content: String(message.content || '').slice(0, 4000),
    }))
    .filter((message) => message.content.trim());
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return sendJson(res, 405, { error: 'Method not allowed' });
  }

  if (!checkRateLimit(`chat:${getClientIp(req)}`, CHAT_RATE_LIMIT_MAX)) {
    res.setHeader('Retry-After', String(Math.ceil(RATE_LIMIT_WINDOW_MS / 1000)));
    return sendJson(res, 429, { error: 'Too many requests. Please retry shortly.' });
  }

  const ollamaBaseUrl = process.env.OLLAMA_BASE_URL;

  // Only trust runtime credentials that are explicitly configured on the server.
  // Client-supplied OIDC headers are not accepted as auth material here.
  const gatewayToken = process.env.AI_GATEWAY_API_KEY || process.env.VERCEL_OIDC_TOKEN;
  const gatewayAuth = gatewayToken
    ? {
        Authorization: gatewayToken.startsWith('Bearer ')
          ? gatewayToken
          : 'Bearer ' + gatewayToken,
      }
    : {};
  if (!ollamaBaseUrl && !gatewayToken) {
    return sendJson(res, 503, {
      error: 'Configure AI_GATEWAY_API_KEY or OLLAMA_BASE_URL.',
      fallback: true,
    });
  }
  if (ollamaBaseUrl && !process.env.OLLAMA_MODEL) {
    return sendJson(res, 503, {
      error: 'Set OLLAMA_MODEL for the local Ollama provider.',
      fallback: true,
    });
  }

  let payload;
  try {
    const contentLength = Number(req.headers['content-length'] || 0);
    if (contentLength > MAX_BODY_BYTES) {
      return sendJson(res, 413, { error: 'Request body too large' });
    }
    payload = await readJsonBody(req);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Invalid JSON body';
    return sendJson(res, message === 'Request body too large' ? 413 : 400, { error: message });
  }

  let messages;
  try {
    messages = normalizeMessages(payload);
  } catch (error) {
    return sendJson(res, 400, { error: error.message || 'Invalid chat payload' });
  }
  if (!messages.length) {
    return sendJson(res, 400, { error: 'A message is required' });
  }

  try {
    const systemMessage = {
      role: 'system',
      content:
        'You are SHADOW313 QTE, a concise quantum-computing assistant for a static Vercel demo. Be accurate, label simulations clearly, and never claim real quantum hardware execution unless the user provides external results.',
    };
    const allMessages = [systemMessage, ...messages];

    if (ollamaBaseUrl) {
      const baseUrl = ollamaBaseUrl.replace(/\/$/, '') || DEFAULT_OLLAMA_URL;
      const ollamaResponse = await fetch(`${baseUrl}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: process.env.OLLAMA_MODEL,
          messages: allMessages,
          options: { temperature: 0.4, num_predict: 500 },
          stream: false,
        }),
      });

      if (!ollamaResponse.ok) {
        const detail = await ollamaResponse.text();
        console.error('Ollama error', ollamaResponse.status, detail.slice(0, 500));
        return sendJson(res, 502, {
          error: 'The local Ollama service encountered a temporary issue.',
          fallback: true,
        });
      }

      const data = await ollamaResponse.json();
      const reply = data?.message?.content?.trim();
      if (!reply) {
        return sendJson(res, 502, {
          error: 'The local Ollama service returned an empty response.',
          fallback: true,
        });
      }

      return sendJson(res, 200, { reply });
    }

    const gatewayResponse = await fetch(AI_GATEWAY_URL, {
      method: 'POST',
      headers: {
        ...gatewayAuth,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: process.env.AI_GATEWAY_MODEL || DEFAULT_MODEL,
        temperature: 0.4,
        max_tokens: 500,
        messages: allMessages,
      }),
    });

    if (!gatewayResponse.ok) {
      const detail = await gatewayResponse.text();
      console.error('AI Gateway error', gatewayResponse.status, detail.slice(0, 500));
      return sendJson(res, 502, {
        error: 'The AI service encountered a temporary issue.',
        fallback: true,
      });
    }

    const data = await gatewayResponse.json();
    const reply = data?.choices?.[0]?.message?.content?.trim();
    if (!reply) {
      return sendJson(res, 502, {
        error: 'The AI service returned an empty response.',
        fallback: true,
      });
    }

    return sendJson(res, 200, { reply });
  } catch (error) {
    console.error('AI chat failed', error);
    return sendJson(res, 502, {
      error: 'The AI service encountered a temporary issue.',
      fallback: true,
    });
  }
};
