// ⚠️ Minimal Vulnerable Test Server for ZAP
// Node 16+ required

const http = require('http');
const url = require('url');
const p = require('path');
const fs = require('fs');

const PORT = 3000;

function send(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'text/html' });
  res.end(body);
}

function safeParam(val, defaultVal='') {
  if (!val) return defaultVal;
  return String(val);
}

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);
  const path = parsed.pathname;
  const q = parsed.query;

  // --- SQLi simulation ---
  if (path === '/sqli') {
    const id = safeParam(q.id, '1').toLowerCase();

    if (id === '1') return send(res, 200, '<h1>User: admin</h1>');
    if (id.includes("' or ") || id.includes("1=1") || id.includes("union")) {
      return send(res, 500, `<h1>SQL Error near '${q.id}'</h1>`);
    }

    return send(res, 200, `<h1>User not found: ${q.id}</h1>`);
  }

  // --- XSS simulation ---
  if (path === '/xss') {
    const input = safeParam(q.q, 'test');
    // Reflection in multiple contexts
    const html = `
      <h1>Search Results</h1>
      <p>You searched for: ${input}</p>
      <script>var test="${input}";document.write("Input: ${input}")</script>
      <a href="javascript:alert('${input}')">Click me</a>
    `;
    return send(res, 200, html);
  }

  // --- LFI simulation ---
  if (path === '/file') {
    const file = safeParam(q.name, 'index.html');

    // Simulate /etc/passwd exposure
    if (file.includes('../etc/passwd')) {
      return send(res, 200, `
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
`);
    }

    // Default safe response
    return send(res, 200, `<h1>File requested: ${file}</h1>`);
  }

  // --- Default page ---

  // ---------- FAST CODE ----------------------
  send(res, 200, `
    <h1>Vulnerable Test Server</h1>
    <ul>
      <li>/sqli?id=1 OR '1'='1'</li>
      <li>/xss?q=&lt;script&gt;alert(1)&lt;/script&gt;</li>
      <li>/file?name=../../etc/passwd</li>
    </ul>
  `);

  // ---------- SLOW CODE ----------------------
  // let filePath = p.join(__dirname, 'index.html');
  // fs.readFile(filePath, (err, data) => {
  //       if (err) {
  //           res.writeHead(500, { 'Content-Type': 'text/plain' });
  //           res.end('Server error');
  //       } else {
  //           const header = {
  //               'Content-Type': 'text/html',
  //               'Connection': 'keep-alive',
  //               'Keep-Alive': 'timeout=5, max=1000'
  //           };
  //           res.writeHead(200, header);
  //           res.end(data);
  //       }
  //   });
});

server.listen(PORT, () => {
  console.log(`Vulnerable test server running on http://localhost:${PORT}`);
});
