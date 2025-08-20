const cluster = require('cluster');
const os = require('os');

const http = require('http');
const { exec } = require('child_process');
const WorkerPool = require('./worker-pool');

const PORT = Number(process.env.PROXY_PORT) || 8080;
const backendHost = process.env.BACKEND_HOST || '127.0.0.1';
const backendPort = Number(process.env.BACKEND_PORT) || 3000;
const numberOfWorkersInPool = Number(process.env.WORKERS_NUM) || 10;
const numClusterWorkers = Number(process.env.CLUSTER_WORKERS) || os.cpus().length;


// ------------- Scheduling Policy -------------
if (cluster.isPrimary || cluster.isMaster) {
    try {
      cluster.schedulingPolicy = cluster.SCHED_RR;
    } catch {}
}

// ------------- Cluster -------------
if (cluster.isPrimary || cluster.isMaster) {
    let shuttingDown = false;

    // ================= MASTER PROCES =================
    console.log(`[cluster-primary ${process.pid}] starting ${numClusterWorkers} workers on port ${PORT} ...`);

    for (let i = 0; i < numClusterWorkers; i++) {
        cluster.fork();
    }

    cluster.on('online', (w) => {
        console.log(`[cluster-primary] worker ${w.process.pid} online`);
    });
    
    cluster.on('exit', (w, code, signal) => {
        if (shuttingDown) return;
        console.error(`[cluster-primary] worker ${w.process.pid} exited (code=${code}, signal=${signal}). Restarting...`);
        cluster.fork();
    });

    const shutdownPrimary = function() {
        console.log('\n[cluster-primary] Shutting cluster down...');
        shuttingDown = true;

        const workers = Object.values(cluster.workers);
        let remaining = workers.length;
    
        if (remaining === 0) {
            return runCleanup();
        }
    
        workers.forEach(worker => {
            worker.on('exit', () => {
                remaining--;
                if (remaining === 0) runCleanup();
            });
            worker.disconnect();
        });
    
        function runCleanup() {
            exec('./disable-proxy.sh', (error, stdout) => {
                if (error) console.error(`Error while unloading PF: ${error.message}`);
                else console.log(stdout || 'PF rules removed.');
                process.exit(0);
            });
        }
    }

    process.on('SIGTERM', shutdownPrimary);
    process.on('SIGINT', shutdownPrimary);
} else {
    // ================= WORKER PROCES =================
    const workerId = cluster.worker?.id || 'n/a';
    console.log(`[cluster-worker ${process.pid}#${workerId}] booting...`);

    const workerPool = new WorkerPool(numberOfWorkersInPool);

    const avgAnalysisTime = {
        count: 0,
        sum: 0,
        calc() {
            console.log(`[cluster-worker ${process.pid}] avg analysis: ${Math.floor(this.sum / this.count)}ms`);
        }
    }

    workerPool.on('ready', () => {
        console.log(`[cluster-worker ${process.pid}] worker-pool ready, starting proxy...`)
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
            console.log(`[cluster-worker ${process.pid}] proxy listening on http://localhost:${PORT}`);
        });
        
        process.on('SIGTERM', shutdownWorker);
        process.on('SIGINT', shutdownWorker);
        // setInterval(printStats, 2000);

        function shutdownWorker() { 
            console.log(`\n[cluster-worker ${process.pid}] shutting down...`);
            try { workerPool.shutdown(); } catch {}
            server.close(() => process.exit(0));

            setTimeout(() => process.exit(1), 5000).unref();
        }

        // CALLBACK FUNCTIONS 
    
        function requestHandler(req, res) {
                
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
                    console.error(`[cluster-worker ${process.pid}] Analysis error:`, error.message);
                    res.writeHead(500, { 'Content-Type': 'text/plain' });
                    res.end('Analysis failed');
                }
            });
            
        }

        function forwardRequest(req, res, body) {
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
                console.log(`[cluster-worker ${process.pid}] error in redirecting: `, err.message);
                if (!res.headersSent) {
                    res.writeHead(500, {'Content-Type': 'text/plain'});
                }
                res.end('Proxy server error');
            });
            
            if(body.length) {
                proxyReq.write(body);
            }
            
            proxyReq.end();
        }

        function addSecurityHeaders(req, result) {
            if (result.status == 'attack') {
                req.headers['x-security-status'] = 'attack';
                console.log(`[cluster-worker ${process.pid}] ATTACK DETECTED: Type ${result}`);
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

        function printStats(){
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
    }
}
