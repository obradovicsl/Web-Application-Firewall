const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.BACKEND_PORT || 3000;

const server = http.createServer((req, res) => {
    if (req.url === '/') {
        const filePath = path.join(__dirname, 'index.html');
        fs.readFile(filePath, (err, data) => {
            if (err) {
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end('Server error');
            } else {
                const header = {
                    'Content-Type': 'text/html',
                    'connection': 'keep-alive',
                    'keep-alive': 'timeout=5, max=1000'
                }

                res.writeHead(200, header);
                res.end(data);
            }
        });
        console.log('--- New request ---');
        console.log(`${req.method}: ${req.url}`);
        console.log('Headers:\n', req.headers);
    } else {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Page not found');
    }
});

server.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
});
