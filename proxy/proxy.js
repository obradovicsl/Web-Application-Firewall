const http = require('http');
const { exec } = require('child_process');
const WorkerPool = require('./worker-pool');

const PORT = process.env.PROXY_PORT || 8080;
const backendHost = process.env.BACKEND_HOST || '127.0.0.1';
const backendPort = process.env.BACKEND_PORT || 3000;
const numberOfWorkers = process.env.WORKERS_NUM || 10


const workerPool = new WorkerPool(numberOfWorkers);

const avgAnalysisTime = {
    count: 0,
    sum: 0,
    calc() {
        console.log(`Avg analysis time: ${this.count != 0 ? Math.floor(this.sum/this.count) : '0'}ms`)
    }
}

workerPool.on('ready', () => {
    console.log('Worker pool ready, starting proxy...')
    startProxy();
});

const backendAgent = new http.Agent({
    keepAlive: true,
    keepAliveMsecs: 30000,        
    maxSockets: 100,              
    maxFreeSockets: 50,           
    timeout: 10000,               
    freeSocketTimeout: 15000,     
    scheduling: 'fifo'            
});

function startProxy() {
    
    const server = http.createServer(requestHandler);
    
    server.listen(PORT, () => {
        console.log(`Proxy listening on http://localhost:${PORT}`);
    });
    
    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);
    

    // setInterval(printStats, 2000);
}


// CALLBACK FUNCTIONS 

const requestHandler = function(req, res) {
        
    let body = [];
    
    // Data for body comes in chunks
    req.on('data', chunk => {
        body.push(chunk);
    });

    // When the whole request is recieved
    req.on('end', async () => {
        body = Buffer.concat(body);
        
        try {
            // Analyse
            const startTime = Date.now();
            const result = await workerPool.analyze(req.url, req.headers, body.toString());
            const analysisTime = Date.now() - startTime;

            avgAnalysisTime.count++;
            avgAnalysisTime.sum += analysisTime;

            // result = { "status": "clean" };

            addSecurityHeaders(req, result);
            
            forwardRequest(req, res, body);
            
        }catch(error) {
            console.error('Analysis error:', error);
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end('Analysis failed');
        }
    });
    
}

const forwardRequest = function(req, res, body) {
    const options = {
        hostname: backendHost,
        port: backendPort,
        path: req.url,
        method: req.method,
        headers: req.headers,
        agent: backendAgent,
    };
    
    const proxyReq = http.request(options, proxyRes => {
        const responseHeaders = {
            ...proxyRes.headers,
            'connection': 'keep-alive',
            'keep-alive': 'timeout=30, max=100',
            'x-proxy': 'security-proxy',
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
}

const addSecurityHeaders = function(req, result) {
    if (result.status == 'attack') {
        req.headers['x-security-status'] = 'attack';
        console.log(`🚨 ATTACK DETECTED: Type ${result}`);
        // console.dir(result, { depth: null, colors: true });
        // req.headers['x-security-findings'] = JSON.stringify(result.findings);

        const attackTypes = result.findings.map(f => f.attack).join(',');
        const severities = result.findings.map(f => f.severity).join(',');
        const locations = result.findings.map(f => f.location).join(',');
        
        req.headers['x-security-attack-types'] = attackTypes;
        req.headers['x-security-severities'] = severities;
        req.headers['x-security-locations'] = locations;
    } else {
        req.headers['x-security-status'] = 'clean';
    }
}

const shutdown = function() {
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

const printStats = function(){
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
    avgAnalysisTime.calc();
}