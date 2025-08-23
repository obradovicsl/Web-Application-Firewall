const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');

const PORT = process.env.BACKEND_PORT || 3000;

const server = http.createServer((req, res) => {

    const parsedUrl = url.parse(req.url, true);
    const pathname = parsedUrl.pathname;

    // console.dir(req.headers, {depth: null});
    // console.log('Query:', parsedUrl.query);

    // --- API route ---
    if (pathname.startsWith('/api/users/')) {
        const id = pathname.split('/').pop(); // npr. '1' ili "'1'"
        console.log('User ID param:', id);

        // ovde može tvoja SQLi analiza
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ userId: id, name: 'Test user' }));
        return;
    }

    // --- index.HTML page ---
    let filePath = path.join(__dirname, 'index.html');

    if (pathname !== '/') {
        filePath = path.join(__dirname, 'index.html');
    }

    fs.readFile(filePath, (err, data) => {
        if (err) {
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end('Server error');
        } else {
            const header = {
                'Content-Type': 'text/html',
                'Connection': 'keep-alive',
                'Keep-Alive': 'timeout=5, max=1000'
            };
            res.writeHead(200, header);
            res.end(data);
        }
    });
});

server.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
});
