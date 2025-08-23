const {spawn} = require('child_process');
const { randomUUID } = require('crypto');
const EventEmitter = require('events');

const analyzer = process.env.ANALYZER_NAME || 'analyze';
const batchSize = parseInt(process.env.BATCH_SIZE) || 32;


// Worker class - worker is a Node object that represents C process
class AnalyzerWorker extends EventEmitter {
    constructor(id) {
        super();
        this.id = id;
        this.busy = false;
        this.currentTasks = new Map(); // task.id -> {resolve, reject}
        this.responseBuffer = '';
        
        this.spawn();
    }

    spawn() {
        this.process = spawn(`./${analyzer}`, [], {
            stdio: ['pipe', 'pipe', 'pipe']
        });

        this.process.stdout.on('data', (data) => {
            this.responseBuffer += data.toString();
            this.processResponses();
        });
        
        this.process.stderr.on('data', (data) => {
            console.error(`Worker ${this.id} error: ${data.toString()}`);
        });

        this.process.on('exit', (code) => {
            console.error(`C worker ${this.id} exited with code ${code}`);
            this.active = false;
            
            if (this.timeoutID) {
                clearTimeout(this.timeoutID);
                this.timeoutID = null;
            }

            if (this.currentTasks.size > 0) {
                for (const [id, handlers] of this.currentTasks){
                    handlers.reject(new Error('Worker crashed'));
                    this.currentTasks.delete(id);
                }
            }
            this.busy = false;
            setTimeout(() => this.spawn(), 1000);
        });

        this.active = true
    }

    // Callback that is called when C sends data on stdout
    processResponses(){
        // Process only a completed line
        const lines = this.responseBuffer.split('\n');
        this.responseBuffer = lines.pop();
        
        for (const line of lines) {
            if (line.trim()) {
                try{ 
                    const response = JSON.parse(line)
                    // C will send data to stdout only if:
                    // the status is ready (on its start)
                    // the analyze is completed
                    if (response.status == 'ready') {
                        this.emit('ready');
                    } else if (Array.isArray(response)) {

                        // Clear timeout
                        if (this.timeoutID) {
                            clearTimeout(this.timeoutID);
                            this.timeoutID = null;
                        }

                        for (const res of response) {
                            const task = this.currentTasks.get(res.id);
                            if (!task) continue;
                            if (res.error) task.reject(res.error);
                            else task.resolve(res.result);
                            this.currentTasks.delete(res.id);
                        }   
                        this.busy = false;
                        this.emit('available');
                    }
                }catch (e) {
                    console.error(`Worker ${this.id} JSON parse error: ${e}`);
                }
            }
        }
    }

    analyze(tasks) {
        // If the worker is already busy
        if (this.busy) {
            return new Error('Worker is busy!');
        }
        // If the worker is not alive
        if (!this.active) {
            return new Error('Worker is not active!');
        }

        this.busy = true;
        for (const t of tasks){
            this.currentTasks.set(t.id, {resolve: t.resolve, reject: t.reject});
        }
        const payload = tasks.map(t => ({
            id: t.id,
            url: t.url, 
            headers: JSON.stringify(t.headers),
            body: t.body ? t.body.toString() : ''
        }));

        // Send request to a stdin of the C proces
        this.process.stdin.write(JSON.stringify(payload) + '\n');
        
        // If task is not completed in 5s, abort
        this.timeoutID = setTimeout(() => {
            for (const t of tasks) {
                if (this.currentTasks.has(t.id)) {
                    this.currentTasks.get(t.id).reject(new Error('Worker timeout'));
                    this.currentTasks.delete(t.id);
                }
            }
            this.busy = false;
            this.active = false;
            this.kill();
        }, 5000);
        
        return null;
    }

    kill() {
        if (this.process){
            this.process.kill('SIGKILL');
        }
    }
};


class WorkerPool extends EventEmitter {
    constructor(size = 10) {
        super();
        this.workers = [];
        this.taskQueue = [];
        this.readyWorkers = 0;

        this.initWorkers(size);
    }

    // Creates worker objects, register callbacks on 'ready' nad 'available' events
    initWorkers(size) {
        for (let i = 0; i < size; i++) {
            const worker = new AnalyzerWorker(i);

            worker.on('ready', () => {
                this.readyWorkers++;
                if (this.readyWorkers == size) {
                    console.log(`All ${size} workers ready!`);
                    this.emit('ready');
                }
                // If the worker is respawned
                this.processQueue();
            });

            worker.on('available', () => {
                this.processQueue();
            });

            this.workers.push(worker);
        }
    }

    getFreeWorker() {
        return this.workers.find(worker => !worker.busy && worker.active);
    }

    processQueue() {
        if (this.taskQueue.length == 0) return;

        const freeWorker = this.getFreeWorker();
        if (!freeWorker) return;

        // If there is more tasks waiting in queue -> send them in a batch
        const taskNumber = Math.min(batchSize, this.taskQueue.length);

        const tasks = this.taskQueue.splice(0, taskNumber);
        this.executeTask(freeWorker, tasks);
    }

    executeTask(worker, tasks) {
        for (const t of tasks) {
            t.id = randomUUID();
        }
        const err = worker.analyze(tasks);
        if (err instanceof Error) {
            this.taskQueue.unshift(...tasks);
            setImmediate(() => this.processQueue());
        }
    }

    analyze(url, headers, body) {
        return new Promise((resolve, reject) => {
            const task = { url, headers, body, resolve, reject };
            const freeWorker = this.getFreeWorker();
            if (freeWorker) {
                this.executeTask(freeWorker, [task]);
            }else{
                this.taskQueue.push(task);
            }
        });
    }

    shutdown() {
        this.workers.forEach(worker => worker.kill());
    }
}

module.exports = WorkerPool;