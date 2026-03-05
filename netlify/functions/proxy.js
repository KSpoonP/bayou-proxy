process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
const https = require('https');
const http = require('http');
const url = require('url');

// Headers that reveal embedding or cause frame blocking
const BLOCKED_HEADERS = [
  'x-frame-options',
  'content-security-policy',
  'content-security-policy-report-only',
  'cross-origin-embedder-policy',
  'cross-origin-opener-policy',
  'cross-origin-resource-policy',
  'x-content-type-options',
];

exports.handler = async (event) => {
  const target = event.queryStringParameters?.url;
  if (!target) return { statusCode: 400, body: 'Missing url param' };

  // Handle CORS preflight
  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': '*',
      },
      body: '',
    };
  }

  return new Promise((resolve) => {
    try {
      const parsed = new URL(target);
      const mod = parsed.protocol === 'https:' ? https : http;

      const options = {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method: event.httpMethod || 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.5',
          'Accept-Encoding': 'identity',
          'Upgrade-Insecure-Requests': '1',
          'Sec-Fetch-Dest': 'document',
          'Sec-Fetch-Mode': 'navigate',
          'Sec-Fetch-Site': 'none',
        },
      };

      const req = mod.request(options, (res) => {
        // Strip frame-blocking and CSP headers
        const safeHeaders = {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': '*',
        };

        for (const [key, val] of Object.entries(res.headers)) {
          if (!BLOCKED_HEADERS.includes(key.toLowerCase())) {
            safeHeaders[key] = val;
          }
        }

        // Rewrite location headers for redirects
        if (safeHeaders['location']) {
          try {
            const redirectUrl = new URL(safeHeaders['location'], target).toString();
            safeHeaders['location'] = `/.netlify/functions/proxy?url=${encodeURIComponent(redirectUrl)}`;
          } catch(e) {}
        }

        const chunks = [];
        res.on('data', chunk => chunks.push(chunk));
        res.on('end', () => {
          const body = Buffer.concat(chunks);
          const ct = (res.headers['content-type'] || '').toLowerCase();
          const isText = ct.includes('text') || ct.includes('javascript') || ct.includes('json') || ct.includes('xml');

          if (isText) {
            // Rewrite absolute URLs in HTML/JS to go through proxy
            let text = body.toString('utf8');
            const baseUrl = `${parsed.protocol}//${parsed.hostname}`;

            // Rewrite fetch/XHR/src/href to proxy URLs where possible
            text = text
              .replace(/(src|href|action)="(https?:\/\/[^"]+)"/gi, (_, attr, u) =>
                `${attr}="/.netlify/functions/proxy?url=${encodeURIComponent(u)}"`)
              .replace(/(src|href|action)='(https?:\/\/[^']+)'/gi, (_, attr, u) =>
                `${attr}='/.netlify/functions/proxy?url=${encodeURIComponent(u)}'`);

            resolve({
              statusCode: res.statusCode || 200,
              headers: safeHeaders,
              body: text,
            });
          } else {
            resolve({
              statusCode: res.statusCode || 200,
              headers: safeHeaders,
              body: body.toString('base64'),
              isBase64Encoded: true,
            });
          }
        });
      });

      req.on('error', (e) => {
        resolve({ statusCode: 500, body: 'Proxy error: ' + e.message });
      });

      req.end();
    } catch (e) {
      resolve({ statusCode: 500, body: 'Invalid URL: ' + e.message });
    }
  });
};
