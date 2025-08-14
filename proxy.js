const http = require('http');
const { exec } = require('child_process');


const PORT = process.env.PROXY_PORT || 8080;
const backendHost = process.env.BACKEND_HOST || '127.0.0.1';
const backendPort = process.env.BACKEND_PORT || 3000;

const server = http.createServer((req, res) => {

    console.log('--- New request ---');
    console.log(`${req.method}: ${req.url}`);
    console.log('Headers:\n', req.headers);

    let body = [];

    req.on('data', chunk => {
        body.push(chunk)
    });

    req.on('end', () => {
        body = Buffer.concat(body);
        console.log('Body:\n', body.toString());

        const options = {
            hostname: backendHost,
            port: backendPort,
            path: req.url,
            method: req.method,
            headers: req.headers
        };

        const proxyReq = http.request(options, proxyRes => {
            res.writeHead(proxyRes.statusCode, proxyRes.headers);
            proxyRes.pipe(res, {end: true});
        });

        proxyReq.on('error', err => {
            console.log('Error in redirecting: ', err.message);
            res.writeHead(500, {'Content-Type': 'text/plain'});
            res.end('Proxy server error');
        });

        if(body.length) {
            proxyReq.write(body);
        }

        proxyReq.end();
    })

});

server.listen(PORT, () => {
    console.log(`Proxy listening on http://localhost:${PORT}`);
});

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

function shutdown() {
    console.log('\nShuting proxy down...');

    exec('./disable-proxy.sh', (error, stdout, stderr) => {
        if (error) {
            console.error(`Error while loading PF: ${error.message}`);
        } else {
            console.log(stdout || 'PF rules removed.');
        }
        process.exit();
    });
}
