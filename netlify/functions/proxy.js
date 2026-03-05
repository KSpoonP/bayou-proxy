process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
const https = require('https');
const http = require('http');
const zlib = require('zlib');

const STRIP_HEADERS = [
  'x-frame-options',
  'content-security-policy',
  'content-security-policy-report-only',
  'cross-origin-embedder-policy',
  'cross-origin-opener-policy',
  'cross-origin-resource-policy',
  'x-content-type-options',
  'strict-transport-security',
  'transfer-encoding',
  'set-cookie',
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
      const origin = parsed.origin;
      const base = `${parsed.protocol}//${parsed.hostname}`;
      const PROXY = '/.netlify/functions/proxy?url=';
      const mod = parsed.protocol === 'https:' ? https : http;

      const options = {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method: event.httpMethod || 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.9',
          'Accept-Encoding': 'gzip, deflate, br',
          'Cache-Control': 'no-cache',
          'Pragma': 'no-cache',
          'Sec-Fetch-Dest': 'document',
          'Sec-Fetch-Mode': 'navigate',
          'Sec-Fetch-Site': 'none',
          'Sec-Fetch-User': '?1',
          'Upgrade-Insecure-Requests': '1',
        },
      };

      const req = mod.request(options, (res) => {
        // Build safe headers
        const safeHeaders = {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': '*',
        };

        for (const [key, val] of Object.entries(res.headers)) {
          const k = key.toLowerCase();
          if (STRIP_HEADERS.includes(k)) continue;
          if (Array.isArray(val)) safeHeaders[key] = val.join(', ');
          else safeHeaders[key] = val;
        }

        // Rewrite redirects
        if (safeHeaders['location']) {
          try {
            const redir = new URL(safeHeaders['location'], target).toString();
            safeHeaders['location'] = PROXY + encodeURIComponent(redir);
          } catch(e) {}
        }

        // Collect chunks
        const chunks = [];
        res.on('data', chunk => chunks.push(chunk));
        res.on('end', () => {
          const raw = Buffer.concat(chunks);
          const ct = (res.headers['content-type'] || '').toLowerCase();
          const enc = (res.headers['content-encoding'] || '').toLowerCase();
          const isText = ct.includes('text') || ct.includes('javascript') || ct.includes('json') || ct.includes('xml') || ct.includes('svg');

          if (!isText) {
            // Binary — pass through as base64
            delete safeHeaders['content-encoding'];
            resolve({
              statusCode: res.statusCode || 200,
              headers: safeHeaders,
              body: raw.toString('base64'),
              isBase64Encoded: true,
            });
            return;
          }

          // Decompress if needed
          function processText(buf) {
            let text = buf.toString('utf8');
            delete safeHeaders['content-encoding'];

            // Resolve a URL relative to the target page
            function resolveUrl(u) {
              try {
                if (u.startsWith('data:') || u.startsWith('blob:') || u.startsWith('javascript:') || u.startsWith('#')) return u;
                if (u.startsWith('//')) return PROXY + encodeURIComponent('https:' + u);
                if (u.startsWith('http://') || u.startsWith('https://')) return PROXY + encodeURIComponent(u);
                if (u.startsWith('/')) return PROXY + encodeURIComponent(origin + u);
                // Relative path
                const base2 = target.substring(0, target.lastIndexOf('/') + 1);
                return PROXY + encodeURIComponent(base2 + u);
              } catch(e) { return u; }
            }

            if (ct.includes('text/html')) {
              // Rewrite ALL src, href, action, srcset attributes
              text = text
                // src=
                .replace(/\bsrc\s*=\s*"([^"#][^"]*)"/gi, (_, u) => `src="${resolveUrl(u)}"`)
                .replace(/\bsrc\s*=\s*'([^'#][^']*)'/gi, (_, u) => `src='${resolveUrl(u)}'`)
                // href=
                .replace(/\bhref\s*=\s*"([^"#][^"]*)"/gi, (_, u) => `href="${resolveUrl(u)}"`)
                .replace(/\bhref\s*=\s*'([^'#][^']*)'/gi, (_, u) => `href='${resolveUrl(u)}'`)
                // action=
                .replace(/\baction\s*=\s*"([^"#][^"]*)"/gi, (_, u) => `action="${resolveUrl(u)}"`)
                .replace(/\baction\s*=\s*'([^'#][^']*)'/gi, (_, u) => `action='${resolveUrl(u)}'`)
                // data-src= (lazy loading)
                .replace(/\bdata-src\s*=\s*"([^"#][^"]*)"/gi, (_, u) => `data-src="${resolveUrl(u)}"`)
                .replace(/\bdata-src\s*=\s*'([^'#][^']*)'/gi, (_, u) => `data-src='${resolveUrl(u)}'`)
                // srcset=
                .replace(/\bsrcset\s*=\s*"([^"]*)"/gi, (_, s) => `srcset="${s.split(',').map(p => { const [u,...r]=p.trim().split(/\s+/); return [resolveUrl(u),...r].join(' '); }).join(', ')}"`)
                // <base href> - remove it so relative paths work correctly
                .replace(/<base[^>]+href[^>]*>/gi, '')
                // url() in inline styles
                .replace(/url\(['"]?((?!data:)[^'"\)]+)['"]?\)/gi, (_, u) => `url('${resolveUrl(u)}')`);

              // Inject runtime interceptor in <head>
              const interceptor = `<script>
(function(){
  const P='/.netlify/functions/proxy?url=';
  const O='${origin}';
  const T='${target}';
  const BASE=T.substring(0,T.lastIndexOf('/')+1);
  function px(u){
    if(!u||typeof u!=='string')return u;
    if(u.startsWith(P)||u.startsWith('data:')||u.startsWith('blob:')||u.startsWith('javascript:')||u.startsWith('#'))return u;
    try{
      if(u.startsWith('//'))return P+encodeURIComponent('https:'+u);
      if(/^https?:/.test(u))return P+encodeURIComponent(u);
      if(u.startsWith('/'))return P+encodeURIComponent(O+u);
      return P+encodeURIComponent(BASE+u);
    }catch(e){return u;}
  }
  // Intercept fetch
  const oFetch=window.fetch;
  window.fetch=function(input,init){
    if(typeof input==='string')input=px(input);
    else if(input&&input.url)input=new Request(px(input.url),input);
    return oFetch.call(this,input,init);
  };
  // Intercept XHR
  const oOpen=XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open=function(m,u,...r){return oOpen.call(this,m,px(u),...r);};
  // Intercept dynamic element src/href
  const oCreate=document.createElement.bind(document);
  document.createElement=function(tag,...a){
    const el=oCreate(tag,...a);
    const t=tag.toLowerCase();
    if(['script','link','img','iframe','source','audio','video'].includes(t)){
      const attr=t==='link'?'href':'src';
      const proto=Object.getPrototypeOf(el);
      const desc=Object.getOwnPropertyDescriptor(proto,attr);
      if(desc&&desc.set){
        Object.defineProperty(el,attr,{
          get(){return desc.get.call(this);},
          set(v){desc.set.call(this,px(v));},
          configurable:true
        });
      }
    }
    return el;
  };
  // Override window.open to proxy navigations
  const oOpen2=window.open;
  window.open=function(u,...r){return oOpen2.call(this,px(u),...r);};

  // Intercept all link clicks and form submissions
  document.addEventListener('click', function(e){
    const a=e.target.closest('a');
    if(!a)return;
    const href=a.getAttribute('href');
    if(!href||href.startsWith('#')||href.startsWith('javascript:'))return;
    try{
      const resolved=new URL(href, T).toString();
      if(!resolved.startsWith(P)){
        e.preventDefault();
        e.stopPropagation();
        // Post message to parent Bayou frame to navigate
        window.top.postMessage({type:'BAYOU_NAVIGATE',url:resolved},'*');
      }
    }catch(e2){}
  }, true);

  // Intercept right-clicks and send to parent Bayou
  document.addEventListener('contextmenu', function(e){
    const a=e.target.closest('a');
    const url=a?new URL(a.getAttribute('href')||'',T).toString():null;
    if(url&&!url.startsWith('#')&&!url.startsWith('javascript:')){
      e.preventDefault();
      e.stopPropagation();
      window.top.postMessage({type:'BAYOU_CONTEXTMENU',url,x:e.clientX,y:e.clientY},'*');
    }
  }, true);

  // Intercept form submissions
  document.addEventListener('submit', function(e){
    const form=e.target;
    const action=form.getAttribute('action');
    if(!action)return;
    try{
      const resolved=new URL(action, T).toString();
      if(!resolved.startsWith(P)){
        e.preventDefault();
        const method=(form.method||'GET').toUpperCase();
        const data=new FormData(form);
        const params=new URLSearchParams(data).toString();
        const url=method==='GET'?resolved+(resolved.includes('?')?'&':'?')+params:resolved;
        window.top.postMessage({type:'BAYOU_NAVIGATE',url:px(url)},'*');
      }
    }catch(e2){}
  }, true);
})();
<\/script>`;
              text = text.replace(/<head>/i, '<head>' + interceptor);
              // Also fix CSS url() references in <style> tags
              text = text.replace(/<style([^>]*)>([\s\S]*?)<\/style>/gi, (match, attrs, css) => {
                const fixedCss = css.replace(/url\(['"]?((?!data:)[^'"\)]+)['"]?\)/gi, (_, u) => `url('${resolveUrl(u)}')`);
                return `<style${attrs}>${fixedCss}</style>`;
              });
            } else if (ct.includes('css')) {
              // Rewrite url() in CSS files
              text = text.replace(/url\(['"]?((?!data:)[^'"\)]+)['"]?\)/gi, (_, u) => `url('${resolveUrl(u)}')`);
              // Rewrite @import
              text = text.replace(/@import\s+['"]([^'"]+)['"]/gi, (_, u) => `@import '${resolveUrl(u)}'`);
            } else if (ct.includes('javascript')) {
              // Rewrite fetch/XHR in JS files
              text = text
                .replace(/fetch\(['"`](https?:\/\/[^'"`]+)['"`]/g, (_, u) => `fetch('${PROXY}${encodeURIComponent(u)}'`)
                .replace(/\.open\(['"`]([A-Z]+)['"`]\s*,\s*['"`](https?:\/\/[^'"`]+)['"`]/g, (_, m, u) => `.open('${m}','${PROXY}${encodeURIComponent(u)}'`);
            }

            resolve({
              statusCode: res.statusCode || 200,
              headers: safeHeaders,
              body: text,
            });
          }

          // Handle compression
          if (enc === 'gzip') {
            zlib.gunzip(raw, (e, d) => processText(e ? raw : d));
          } else if (enc === 'br') {
            zlib.brotliDecompress(raw, (e, d) => processText(e ? raw : d));
          } else if (enc === 'deflate') {
            zlib.inflate(raw, (e, d) => processText(e ? raw : d));
          } else {
            processText(raw);
          }
        });
      });

      req.on('error', e => resolve({ statusCode: 500, body: 'Proxy error: ' + e.message }));
      if (event.body) req.write(event.body);
      req.end();
    } catch(e) {
      resolve({ statusCode: 500, body: 'Invalid URL: ' + e.message });
    }
  });
};
