process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
const https = require('https');
const http = require('http');

const STRIP_HEADERS = [
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
        },
      };

      const req = mod.request(options, (res) => {
        const safeHeaders = {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': '*',
        };

        for (const [key, val] of Object.entries(res.headers)) {
          const k = key.toLowerCase();
          if (STRIP_HEADERS.includes(k)) continue;
          // Netlify can't handle array headers — flatten to string
          if (Array.isArray(val)) {
            if (k === 'set-cookie') {
              // skip set-cookie entirely to avoid the error
              continue;
            }
            safeHeaders[key] = val.join(', ');
          } else {
            safeHeaders[key] = val;
          }
        }

        // Rewrite redirects through proxy
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
            let text = body.toString('utf8');
            // Rewrite absolute URLs through proxy
            text = text
              .replace(/(src|href|action)="(https?:\/\/[^"]+)"/gi, (_, attr, u) =>
                `${attr}="/.netlify/functions/proxy?url=${encodeURIComponent(u)}"`)
              .replace(/(src|href|action)='(https?:\/\/[^']+)'/gi, (_, attr, u) =>
                `${attr}='/.netlify/functions/proxy?url=${encodeURIComponent(u)}'`);

            resolve({ statusCode: res.statusCode || 200, headers: safeHeaders, body: text });
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

      req.on('error', (e) => resolve({ statusCode: 500, body: 'Proxy error: ' + e.message }));
      req.end();
    } catch (e) {
      resolve({ statusCode: 500, body: 'Invalid URL: ' + e.message });
    }
  });
};
