const http = require('http');
const { exec } = require('child_process');
const WorkerPool = require('./worker-pool');

const backendAgent = new http.Agent({
    keepAlive: true,
    keepAliveMsecs: 30000,        
    maxSockets: 100,              
    maxFreeSockets: 50,           
    timeout: 10000,               
    freeSocketTimeout: 15000,     
    scheduling: 'fifo'            
});

const PORT = process.env.PROXY_PORT || 8080;
const backendHost = process.env.BACKEND_HOST || '127.0.0.1';
const backendPort = process.env.BACKEND_PORT || 3000;
const numberOfWorkers = process.env.WORKERS_NUM || 10

const workerPool = new WorkerPool(numberOfWorkers);

workerPool.on('ready', () => {
    console.log('Worker pool ready, starting proxy...')
    startProxy();
});


function startProxy() {
    
    const server = http.createServer((req, res) => {
        
        let body = [];
        
        req.on('data', chunk => {
            body.push(chunk)
        });
        
        req.on('end', async () => {
            body = Buffer.concat(body);
            
            try {
                // Analyse
                const startTime = Date.now();
                const result = await workerPool.analyze(req.url, req.headers, req.body);
                const analysisTime = Date.now() - startTime;

                // console.log(`Analysis took ${analysisTime}ms: ${result}`);

                if (result.status == 'attack') {
                    console.log(`🚨 ATTACK DETECTED: Type ${result.attack}`);
                    res.writeHead(403, {
                        'Content-Type': 'application/json',
                        'X-Attack-Type': result.attack.toString()
                    });
                    res.end(JSON.stringify({
                        error: 'Attack detected',
                        type: result.attack,
                        blocked: true
                    }));
                    return;
                }    
                
                
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
                        'keep-alive': 'timeout=30, max=100',
                        'x-proxy': 'security-proxy',
                        'x-analysis-time': analysisTime.toString()
                    }
                    
                    res.writeHead(proxyRes.statusCode, responseHeaders);
                    proxyRes.pipe(res, {end: true});
                });
                
                proxyReq.on('error', err => {
                    console.log('Error in redirecting: ', err.message);
                    if (!res.headersSent) {
                        res.writeHead(500, {'Content-Type': 'text/plain'});
                        res.end('Proxy server error');
                    }
                });
                
                if(body.length) {
                    proxyReq.write(body);
                }
                
                proxyReq.end();
            }catch(error) {
                console.error('Analysis error:', error);
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end('Analysis failed');
            }
        });
        
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
    
    // Connection pool stats
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


}
