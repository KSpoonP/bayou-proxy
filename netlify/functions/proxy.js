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

const PROXY_BASE = '/.netlify/functions/proxy?url=';

function rewriteUrls(text, baseUrl) {
  const base = new URL(baseUrl);
  const origin = base.origin;

  // Rewrite absolute URLs in src/href/action attributes
  text = text
    .replace(/(src|href|action|data-src)="(https?:\/\/[^"]+)"/gi, (_, a, u) => `${a}="${PROXY_BASE}${encodeURIComponent(u)}"`)
    .replace(/(src|href|action|data-src)='(https?:\/\/[^']+)'/gi, (_, a, u) => `${a}='${PROXY_BASE}${encodeURIComponent(u)}'`);

  // Rewrite protocol-relative URLs
  text = text
    .replace(/(src|href|action)="(\/\/[^"]+)"/gi, (_, a, u) => `${a}="${PROXY_BASE}${encodeURIComponent('https:' + u)}"`)
    .replace(/(src|href|action)='(\/\/[^']+)'/gi, (_, a, u) => `${a}='${PROXY_BASE}${encodeURIComponent('https:' + u)}'`);

  // Rewrite root-relative URLs
  text = text
    .replace(/(src|href|action)="(\/[^/"'][^"]*?)"/gi, (_, a, u) => `${a}="${PROXY_BASE}${encodeURIComponent(origin + u)}"`)
    .replace(/(src|href|action)='(\/[^/'][^']*?)'/gi, (_, a, u) => `${a}='${PROXY_BASE}${encodeURIComponent(origin + u)}'`);

  // Rewrite fetch() calls in JS
  text = text
    .replace(/fetch\(["'`](https?:\/\/[^"'`]+)["'`]/g, (_, u) => `fetch("${PROXY_BASE}${encodeURIComponent(u)}"`)
    .replace(/fetch\(["'`](\/[^"'`]+)["'`]/g, (_, u) => `fetch("${PROXY_BASE}${encodeURIComponent(origin + u)}"`);

  // Rewrite XMLHttpRequest.open calls
  text = text
    .replace(/(\.open\s*\([^,]+,\s*["'`])(https?:\/\/[^"'`]+)(["'`])/g, (_, pre, u, post) => `${pre}${PROXY_BASE}${encodeURIComponent(u)}${post}`)
    .replace(/(\.open\s*\([^,]+,\s*["'`])(\/[^"'`]+)(["'`])/g, (_, pre, u, post) => `${pre}${PROXY_BASE}${encodeURIComponent(origin + u)}${post}`);

  // Inject script to intercept dynamic fetch/XHR at runtime
  if (text.includes('<head>') || text.includes('<HEAD>')) {
    const interceptor = `<script>
(function() {
  const PROXY = '${PROXY_BASE}';
  const ORIGIN = '${origin}';
  function proxify(url) {
    if (!url || typeof url !== 'string') return url;
    if (url.startsWith(PROXY)) return url;
    if (url.startsWith('http://') || url.startsWith('https://')) return PROXY + encodeURIComponent(url);
    if (url.startsWith('//')) return PROXY + encodeURIComponent('https:' + url);
    if (url.startsWith('/')) return PROXY + encodeURIComponent(ORIGIN + url);
    return url;
  }
  // Intercept fetch
  const origFetch = window.fetch;
  window.fetch = function(input, init) {
    if (typeof input === 'string') input = proxify(input);
    else if (input instanceof Request) input = new Request(proxify(input.url), input);
    return origFetch.call(this, input, init);
  };
  // Intercept XHR
  const origOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, ...rest) {
    return origOpen.call(this, method, proxify(url), ...rest);
  };
  // Intercept dynamic script/link creation
  const origCreate = document.createElement.bind(document);
  document.createElement = function(tag, ...args) {
    const el = origCreate(tag, ...args);
    if (tag.toLowerCase() === 'script' || tag.toLowerCase() === 'link' || tag.toLowerCase() === 'img') {
      const desc = Object.getOwnPropertyDescriptor(el.__proto__, 'src') || Object.getOwnPropertyDescriptor(el.__proto__, 'href');
      if (desc) {
        const attr = tag.toLowerCase() === 'link' ? 'href' : 'src';
        let _val = '';
        Object.defineProperty(el, attr, {
          get: () => _val,
          set: (v) => { _val = proxify(v); el.setAttribute(attr, _val); }
        });
      }
    }
    return el;
  };
})();
<\/script>`;
    text = text.replace(/<head>/i, '<head>' + interceptor);
  }

  return text;
}

exports.handler = async (event) => {
  const target = event.queryStringParameters?.url;
  if (!target) return { statusCode: 400, body: 'Missing url param' };

  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 204,
      headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': '*' },
      body: '',
    };
  }

  return new Promise((resolve) => {
    try {
      const parsed = new URL(target);
      const mod = parsed.protocol === 'https:' ? https : http;

      const reqHeaders = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'identity',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
      };

      // Forward POST body if present
      const postData = event.body || '';

      const options = {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method: event.httpMethod || 'GET',
        headers: reqHeaders,
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
          if (k === 'set-cookie') continue; // arrays break Netlify
          if (k === 'transfer-encoding') continue; // chunked breaks lambda
          if (Array.isArray(val)) safeHeaders[key] = val.join(', ');
          else safeHeaders[key] = val;
        }

        // Rewrite redirects
        if (safeHeaders['location']) {
          try {
            const redir = new URL(safeHeaders['location'], target).toString();
            safeHeaders['location'] = PROXY_BASE + encodeURIComponent(redir);
          } catch(e) {}
        }

        const chunks = [];
        res.on('data', chunk => chunks.push(chunk));
        res.on('end', () => {
          const body = Buffer.concat(chunks);
          const ct = (res.headers['content-type'] || '').toLowerCase();
          const isText = ct.includes('text') || ct.includes('javascript') || ct.includes('json') || ct.includes('xml');

          if (isText) {
            const text = rewriteUrls(body.toString('utf8'), target);
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

      req.on('error', e => resolve({ statusCode: 500, body: 'Proxy error: ' + e.message }));
      if (postData) req.write(postData);
      req.end();
    } catch(e) {
      resolve({ statusCode: 500, body: 'Invalid URL: ' + e.message });
    }
  });
};
