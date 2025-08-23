const cluster = require('cluster');
const os = require('os');
const fs = require('fs');
const path = require('path');

const http = require('http');
const { exec } = require('child_process');
const WorkerPool = require('./worker-pool');

const PORT = Number(process.env.PROXY_PORT) || 8080;
const backendHost = process.env.BACKEND_HOST || '127.0.0.1';
const backendPort = Number(process.env.BACKEND_PORT) || 3000;
const numberOfWorkersInPool = Number(process.env.WORKERS_NUM) || 10;
const numClusterWorkers = Number(process.env.CLUSTER_WORKERS) || os.cpus().length;


const configPath = path.join(__dirname, 'rules/config.json');
const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));

const whitelistPath = path.join(__dirname, `rules/${config.ip_whitelist}`);
const blacklistPath = path.join(__dirname, `rules/${config.ip_blacklist}`);

const whitelist = JSON.parse(fs.readFileSync(whitelistPath, 'utf8'));
const blacklist = JSON.parse(fs.readFileSync(blacklistPath, 'utf8'));

// Simple logger
function log(msg) {
    fs.appendFile(config.logFile, `[${new Date().toISOString()}] ${msg}\n`, err => {
        if (err) console.error('Log write failed:', err);
    });
}
  
 // Helper: check IP/hostname against list
function isListed(list, ip, host) {
   return list.ips.includes(ip) || list.hosts.includes(host);
}


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
            const ip = req.socket.remoteAddress.replace("::ffff:", "");
            const host = req.headers.host || "";

            // Check blacklisted
            if (isListed(blacklist, ip, host)) {
                log(`BLOCKED: ip=${ip} host=${host} method=${req.method} url=${req.url}, reason="blacklisted"`);
                res.writeHead(403, { 'Content-Type': 'text/plain' });
                return res.end('Forbidden');
            }

            // Check whitelisted
            if (isListed(whitelist, ip, host)) {
                return forwardRequestStream(req, res); 
            }
            
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

                    logAttack(result, ip, host, req);

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
        function logAttack(result_s, ip, host, req) {
            let result;
            try {
                result = JSON.parse(result_s);
            } catch (err) {
                console.error('Failed to parse analysis result:', err, result_s);
                return;
            }
        
            if (result.status === 'attack' && Array.isArray(result.findings)) {
                result.findings = groupFindings(result.findings);
        
                const reason = result.findings
                    .map(f => `${f.attack}@${f.location}: [${f.severities.join(', ')}]`)
                    .join('; ');
        
                log(`BLOCKED: ip=${ip} host=${host} method=${req.method} url=${req.url} reason="${reason}"`);
            }
        }
        

        function groupFindings(findings) {
            const map = new Map();
        
            for (const f of findings) {
                const key = `${f.attack}|${f.location}`;
                if (!map.has(key)) {
                    map.set(key, {
                        attack: f.attack,
                        location: f.location,
                        severities: []
                    });
                }
                map.get(key).severities.push(f.severity);
            }
        
            return Array.from(map.values());
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

        function forwardRequestStream(req, res) {
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
                };
                res.writeHead(proxyRes.statusCode, responseHeaders);
                proxyRes.pipe(res, { end: true });
            });
        
            proxyReq.on('error', err => {
                console.log(`[cluster-worker ${process.pid}] redirect error: `, err.message);
                if (!res.headersSent) {
                    res.writeHead(500, {'Content-Type': 'text/plain'});
                }
                res.end('Proxy server error');
            });
        
            // **ovo prosleđuje ceo body stream direktno backendu bez bufferinga**
            req.pipe(proxyReq, { end: true });
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
