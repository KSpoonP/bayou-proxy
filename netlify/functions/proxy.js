const https = require('https');
const http = require('http');

exports.handler = async (event) => {
  const target = event.queryStringParameters?.url;
  if (!target) return { statusCode: 400, body: 'Missing url param' };

  return new Promise((resolve) => {
    const mod = target.startsWith('https') ? https : http;
    mod.get(target, { headers: { 'User-Agent': 'Mozilla/5.0' } }, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => resolve({
        statusCode: 200,
        headers: { 'Access-Control-Allow-Origin': '*', 'Content-Type': res.headers['content-type'] || 'text/html' },
        body
      }));
    }).on('error', e => resolve({ statusCode: 500, body: e.message }));
  });
};
