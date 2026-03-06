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
  // set-cookie handled manually via x-bayou-cookies
];

exports.handler = async (event) => {
  const target = event.queryStringParameters?.url;
  if (!target) return { statusCode: 400, body: 'Missing url param' };

  // Read stored cookies passed from Bayou's JS cookie jar
  const storedCookies = event.queryStringParameters?.cookies || '';

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
          ...(storedCookies ? { 'Cookie': storedCookies } : {}),
        },
      };

      const req = mod.request(options, (res) => {
        const safeHeaders = {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': '*',
        };

        const setCookies = [];
        for (const [key, val] of Object.entries(res.headers)) {
          const k = key.toLowerCase();
          if (STRIP_HEADERS.includes(k)) continue;
          // Intercept set-cookie — don't let browser try to store them (wrong domain)
          // Instead pack them into x-bayou-cookies so Bayou's JS can store them
          if (k === 'set-cookie') {
            const cookies = Array.isArray(val) ? val : [val];
            cookies.forEach(c => {
              // Extract just name=value, drop path/domain/secure/httponly/samesite
              const nameVal = c.split(';')[0].trim();
              if (nameVal) setCookies.push(nameVal);
            });
            continue;
          }
          if (Array.isArray(val)) safeHeaders[key] = val.join(', ');
          else safeHeaders[key] = val;
        }
        // Pass captured cookies back to Bayou via custom header
        if (setCookies.length > 0) {
          safeHeaders['x-bayou-cookies'] = setCookies.join('; ');
          safeHeaders['x-bayou-cookie-host'] = parsed.hostname;
        }

        if (safeHeaders['location']) {
          try {
            const redir = new URL(safeHeaders['location'], target).toString();
            safeHeaders['location'] = PROXY + encodeURIComponent(redir);
          } catch(e) {}
        }

        const chunks = [];
        res.on('data', chunk => chunks.push(chunk));
        res.on('end', () => {
          const raw = Buffer.concat(chunks);
          const ct = (res.headers['content-type'] || '').toLowerCase();
          const enc = (res.headers['content-encoding'] || '').toLowerCase();
          const isText = ct.includes('text') || ct.includes('javascript') || ct.includes('json') || ct.includes('xml') || ct.includes('svg');

          if (!isText) {
            delete safeHeaders['content-encoding'];
            resolve({
              statusCode: res.statusCode || 200,
              headers: safeHeaders,
              body: raw.toString('base64'),
              isBase64Encoded: true,
            });
            return;
          }

          function processText(buf) {
            let text = buf.toString('utf8');
            delete safeHeaders['content-encoding'];

            function resolveUrl(u) {
              try {
                if (u.startsWith('data:') || u.startsWith('blob:') || u.startsWith('javascript:') || u.startsWith('#')) return u;
                if (u.startsWith('//')) return PROXY + encodeURIComponent('https:' + u);
                if (u.startsWith('http://') || u.startsWith('https://')) return PROXY + encodeURIComponent(u);
                if (u.startsWith('/')) return PROXY + encodeURIComponent(origin + u);
                const base2 = target.substring(0, target.lastIndexOf('/') + 1);
                return PROXY + encodeURIComponent(base2 + u);
              } catch(e) { return u; }
            }

            if (ct.includes('text/html')) {
              text = text
                .replace(/\bsrc\s*=\s*"([^"#][^"]*)"/gi, (_, u) => `src="${resolveUrl(u)}"`)
                .replace(/\bsrc\s*=\s*'([^'#][^']*)'/gi, (_, u) => `src='${resolveUrl(u)}'`)
                .replace(/\bhref\s*=\s*"([^"#][^"]*)"/gi, (_, u) => `href="${resolveUrl(u)}"`)
                .replace(/\bhref\s*=\s*'([^'#][^']*)'/gi, (_, u) => `href='${resolveUrl(u)}'`)
                .replace(/\baction\s*=\s*"([^"#][^"]*)"/gi, (_, u) => `action="${resolveUrl(u)}"`)
                .replace(/\baction\s*=\s*'([^'#][^']*)'/gi, (_, u) => `action='${resolveUrl(u)}'`)
                .replace(/\bdata-src\s*=\s*"([^"#][^"]*)"/gi, (_, u) => `data-src="${resolveUrl(u)}"`)
                .replace(/\bdata-src\s*=\s*'([^'#][^']*)'/gi, (_, u) => `data-src='${resolveUrl(u)}'`)
                .replace(/\bsrcset\s*=\s*"([^"]*)"/gi, (_, s) => `srcset="${s.split(',').map(p => { const [u,...r]=p.trim().split(/\s+/); return [resolveUrl(u),...r].join(' '); }).join(', ')}"`)
                .replace(/<base[^>]+href[^>]*>/gi, '')
                .replace(/url\(['"]?((?!data:)[^'"\)]+)['"]?\)/gi, (_, u) => `url('${resolveUrl(u)}')`);

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
  const oFetch=window.fetch;
  window.fetch=function(input,init){
    if(typeof input==='string')input=px(input);
    else if(input&&input.url)input=new Request(px(input.url),input);
    return oFetch.call(this,input,init);
  };
  const oOpen=XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open=function(m,u,...r){return oOpen.call(this,m,px(u),...r);};
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
  const oOpen2=window.open;
  window.open=function(u,...r){return oOpen2.call(this,px(u),...r);};
  document.addEventListener('click', function(e){
    const a=e.target.closest('a');
    if(!a)return;
    const href=a.getAttribute('href');
    if(!href||href.startsWith('#')||href.startsWith('javascript:')||href.startsWith('mailto:'))return;
    try{
      const resolved=new URL(href, T).toString();
      if(href.startsWith(P)||href.startsWith('/.netlify'))return;
      if(!resolved.startsWith(window.location.origin)){
        e.preventDefault();
        e.stopPropagation();
        window.top.postMessage({type:'BAYOU_NAVIGATE',url:resolved},'*');
      }
    }catch(e2){}
  }, true);
  document.addEventListener('contextmenu', function(e){
    const a=e.target.closest('a');
    const url=a?new URL(a.getAttribute('href')||'',T).toString():null;
    if(url&&!url.startsWith('#')&&!url.startsWith('javascript:')){
      e.preventDefault();
      e.stopPropagation();
      window.top.postMessage({type:'BAYOU_CONTEXTMENU',url,x:e.clientX,y:e.clientY},'*');
    }
  }, true);
  // Intercept document.cookie writes — capture and send to Bayou's cookie jar
  const _cookieDesc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie') ||
                      Object.getOwnPropertyDescriptor(HTMLDocument.prototype, 'cookie');
  if (_cookieDesc && _cookieDesc.set) {
    Object.defineProperty(document, 'cookie', {
      get() { return _cookieDesc.get.call(this); },
      set(val) {
        _cookieDesc.set.call(this, val);
        // Extract name=value and forward to Bayou
        const nameVal = val.split(';')[0].trim();
        if (nameVal) {
          window.top.postMessage({
            type: 'BAYOU_SET_COOKIES',
            host: window.location.hostname,
            cookies: nameVal
          }, '*');
        }
      },
      configurable: true
    });
  }

  document.addEventListener('submit', function(e){
    const form=e.target;
    const action=form.getAttribute('action');
    const method=(form.method||'GET').toUpperCase();
    try{
      const resolved=new URL(action||T, T).toString();
      e.preventDefault();
      e.stopPropagation();
      if(method==='GET'){
        const params=new URLSearchParams(new FormData(form)).toString();
        const url=resolved+(resolved.includes('?')?'&':'?')+params;
        window.top.postMessage({type:'BAYOU_NAVIGATE',url:resolved},'*');
      } else {
        // POST — send through proxy, capture cookies from response
        const fd=new FormData(form);
        const proxiedAction=px(resolved);
        fetch(proxiedAction,{method:'POST',body:new URLSearchParams(fd),credentials:'include',headers:{'Content-Type':'application/x-www-form-urlencoded'}})
          .then(res=>{
            // Harvest cookies from response headers
            const cookies=res.headers.get('x-bayou-cookies');
            const host=res.headers.get('x-bayou-cookie-host')||new URL(resolved).hostname;
            if(cookies){
              window.top.postMessage({type:'BAYOU_SET_COOKIES',host,cookies},'*');
            }
            // Navigate to wherever the server redirected us
            const finalUrl=res.url||resolved;
            // Strip proxy prefix to get real URL
            const rel='/.netlify/functions/proxy?url=';
            let dest=finalUrl;
            if(finalUrl.includes(rel)){
              try{dest=decodeURIComponent(finalUrl.slice(finalUrl.indexOf(rel)+rel.length));}catch(ex){}
            }
            window.top.postMessage({type:'BAYOU_NAVIGATE',url:dest},'*');
          })
          .catch(()=>{
            window.top.postMessage({type:'BAYOU_NAVIGATE',url:resolved},'*');
          });
      }
    }catch(e2){}
  }, true);
})();
<\/script>`;
              text = text.replace(/<head>/i, '<head>' + interceptor);
              text = text.replace(/<style([^>]*)>([\s\S]*?)<\/style>/gi, (match, attrs, css) => {
                const fixedCss = css.replace(/url\(['"]?((?!data:)[^'"\)]+)['"]?\)/gi, (_, u) => `url('${resolveUrl(u)}')`);
                return `<style${attrs}>${fixedCss}</style>`;
              });
            } else if (ct.includes('css')) {
              text = text.replace(/url\(['"]?((?!data:)[^'"\)]+)['"]?\)/gi, (_, u) => `url('${resolveUrl(u)}')`);
              text = text.replace(/@import\s+['"]([^'"]+)['"]/gi, (_, u) => `@import '${resolveUrl(u)}'`);
            } else if (ct.includes('javascript')) {
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
