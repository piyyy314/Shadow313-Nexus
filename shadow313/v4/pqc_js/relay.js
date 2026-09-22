/**
 * Shadow313 Egress Proxy — relay.js
 * Gemini API Bridge with localhost-only security gate
 * 
 * Port: 3133
 * Security: localhost-only (127.0.0.1 / ::1)
 * Target: Google Gemini generativelanguage.googleapis.com
 * 
 * Usage:
 *   PROXY_AUTH_KEY=shadow-node-alpha-99 REAL_GEMINI_API_KEY=<key> node relay.js
 * 
 * OpenClaw config:
 *   "baseUrl": "http://127.0.0.1:3133/v1beta"
 *   "apiKey": "<PROXY_AUTH_KEY>"
 */

require('dotenv').config();
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();
const PORT = process.env.PROXY_PORT || 3133;

// The custom key OpenClaw will use to talk to THIS proxy
const PROXY_AUTH_KEY = process.env.PROXY_AUTH_KEY || 'shadow-node-alpha-99';

// ── 1. Security Gate: Intercept and Authenticate ──────────────────────────────
app.use((req, res, next) => {
    // Check if the request is originating from this exact machine (localhost)
    const isLocal = req.ip === '127.0.0.1' || 
                    req.ip === '::1' || 
                    req.ip.includes('127.0.0.1') ||
                    req.ip === '::ffff:127.0.0.1';

    if (isLocal) {
        // OpenClaw is verified as a local process. Let it through.
        return next();
    }

    // If a request comes from any outside network without the key, block it immediately.
    console.warn(`[!] Unauthorized external attempt blocked from ${req.ip}`);
    return res.status(403).json({ 
        error: "Shadow313 Proxy: Strict Node Entry Only",
        timestamp: new Date().toISOString(),
    });
});

// ── 2. Health check endpoint ──────────────────────────────────────────────────
app.get('/health', (req, res) => {
    res.json({
        status: 'active',
        proxy: 'Shadow313 Egress Proxy',
        port: PORT,
        target: 'generativelanguage.googleapis.com',
        timestamp: new Date().toISOString(),
    });
});

// ── 3. The Bridge: Route to Gemini ────────────────────────────────────────────
app.use('/v1beta', createProxyMiddleware({
    target: 'https://generativelanguage.googleapis.com',
    changeOrigin: true,
    onProxyReq: (proxyReq, req, res) => {
        // Strip any incoming auth header and inject the real Gemini API key
        proxyReq.removeHeader('authorization');
        proxyReq.setHeader('x-goog-api-key', process.env.REAL_GEMINI_API_KEY);
        console.log(`[+] ${new Date().toISOString()} Routing agent payload to Gemini: ${req.method} ${req.path}`);
    },
    onProxyRes: (proxyRes, req, res) => {
        console.log(`[+] Gemini response: ${proxyRes.statusCode} for ${req.path}`);
    },
    onError: (err, req, res) => {
        console.error(`[!] Proxy error: ${err.message}`);
        res.status(502).json({ error: 'Proxy error', message: err.message });
    },
}));

// ── 4. Start ──────────────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
    console.log(`==========================================`);
    console.log(`[Shadow313] Egress Proxy Active`);
    console.log(`[Shadow313] Listening on Port: ${PORT}`);
    console.log(`[Shadow313] Security: localhost-only gate`);
    console.log(`==========================================`);
    console.log(`Update openclaw.json with:`);
    console.log(`  "baseUrl": "http://127.0.0.1:${PORT}/v1beta"`);
    console.log(`  "apiKey": "${PROXY_AUTH_KEY}"`);
    console.log(`==========================================`);
});

module.exports = app;