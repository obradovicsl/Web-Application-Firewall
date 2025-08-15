const http = require('http');
const { exec } = require('child_process');

const backendAgent = new http.Agent({
    keepAlive: true,
    keepAliveMsecs: 1000,
    maxSockets: 50,
    maxFreeSockets: 10,
    timeout: 5000,
    freeSocketTimeout: 3000
});

const PORT = process.env.PROXY_PORT || 8080;
const backendHost = process.env.BACKEND_HOST || '127.0.0.1';
const backendPort = process.env.BACKEND_PORT || 3000;

const server = http.createServer((req, res) => {

    let body = [];

    req.on('data', chunk => {
        body.push(chunk)
    });

    req.on('end', () => {
        body = Buffer.concat(body);

        // Analyse

        const proxyHeader = {
            ...req.headers,
            'connection': 'keep-alive'
        };

        const options = {
            hostname: backendHost,
            port: backendPort,
            path: req.url,
            method: req.method,
            headers: proxyHeader,
            agent: backendAgent,
        };

        const proxyReq = http.request(options, proxyRes => {
            const responseHeaders = {
                ...proxyRes.headers,
                'connection': 'keep-alive',
                'keep-alive': 'timeout=5, max=1000'
            }

            res.writeHead(proxyRes.statusCode, responseHeaders);
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

setInterval(() => {
    const sockets = backendAgent.sockets;
    const freeSockets = backendAgent.freeSockets;
    
    let totalSockets = 0;
    let totalFreeSockets = 0;
    
    Object.values(sockets).forEach(socketArray => {
        totalSockets += socketArray.length;
    });
    
    Object.values(freeSockets).forEach(socketArray => {
        totalFreeSockets += socketArray.length;
    });
    
    console.log(`🔗 Agent stats: ${totalSockets} active, ${totalFreeSockets} free sockets`);
}, 5000);