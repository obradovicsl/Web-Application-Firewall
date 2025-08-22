const {spawn} = require('child_process');
const { randomUUID } = require('crypto');
const EventEmitter = require('events');

const analyzer = process.env.ANALYZER_NAME || 'analyze';
const useThreads = process.env.THREADS == 'true' || false;
const threadNum = process.env.THREAD_NUM || 6;
const batchSize = parseInt(process.env.BATCH_SIZE) || 32;


// Worker class - worker is a Node object that represents C process
class AnalyzerWorker extends EventEmitter {
    constructor(id) {
        super();
        this.id = id;
        this.busy = false;
        this.currentTasks = new Map(); // task.id -> {resolve, reject} - for batch processing
        this.responseBuffer = '';
        
        // Spawns the actual C process
        this.spawn();
    }

    // Spawns C process, and register callbacks on stdout, stderr and exit
    spawn() {
        const args = useThreads ? [threadNum.toString()] : [];

        this.process = spawn(`./${analyzer}`, args, {
            stdio: ['pipe', 'pipe', 'pipe']
        });

        // Register callback that will be called if C process send data to stdout
        this.process.stdout.on('data', (data) => {
            // Data is not guaranteed to be the whole message - they're chunks
            this.responseBuffer += data.toString();
            this.processResponses();
        });
        
        // Register callback that will be called if C process send data to stderr
        this.process.stderr.on('data', (data) => {
            console.error(`Worker ${this.id} error: ${data.toString()}`);
        });

        // If C process exit -> it will be restarted
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
            // Restart worker
            setTimeout(() => this.spawn(), 1000);
        });

        this.active = true
    }

    // Callback that is called when C send data on stdout
    processResponses(){
        // Because 'data' event gives us chunks of data
        // We make sure to process only completed lines, and nothing more, nothing less
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


    // Method that will create a JSON request, and send it to the C process
    // It will return a Promise 
    // analyze(url, headers, body) {
    //     return new Promise((resolve, reject) => {
    //         // If the worker is already busy
    //         if (this.busy) {
    //             reject(new Error('Worker is busy!'));
    //             return;
    //         }
    //         if (!this.active) {
    //             reject(new Error('Worker is not active!'));
    //             return;
    //         }


    //         this.busy = true;
    //         this.currentTask = {resolve, reject};

    //         const request = {
    //             url, 
    //             headers: JSON.stringify(headers),
    //             body: body ? body.toString() : ''
    //         };

    //         // Send request to a stdin of the C proces
    //         this.process.stdin.write(JSON.stringify(request) + '\n');
            
    //         // If task is not completed in 5s, abort
    //         const timeoutId = setTimeout(() => {
    //             if (this.currentTask) {
    //                 this.currentTask.reject(new Error('Worker timeout'));
    //                 this.currentTask = null;
    //                 this.busy = false;
    //                 this.active = false;
    //                 this.kill();
    //             }
    //         }, 5000);

    //         // If we don't remove timer - worker will be killed after 5s if it has any task
    //         this.currentTask = {
    //             resolve: (result) => {
    //                 clearTimeout(timeoutId);
    //                 resolve(result);
    //             },
    //             reject: (error) => {
    //                 clearTimeout(timeoutId);
    //                 reject(error);
    //             }
    //         };
    //     });
    // }

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
    // So that we can do something when worker become ready or available
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

                // Optionall - if the tasQueue is overwhelmed - reject
            }
        });
    }

    shutdown() {
        this.workers.forEach(worker => worker.kill());
    }
}

module.exports = WorkerPool;