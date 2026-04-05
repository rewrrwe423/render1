const os = require('os');
const fs = require('fs');
const net = require('net');
const http = require('http');
const axios = require('axios');
const { Buffer } = require('buffer');

// ========== 配置部分 ==========

// VLESS UUID（按需改）
const UUID = '8e812669-72e7-4c0e-af5e-d110f1e7069c';

// 订阅路径和 XHTTP 路径（这里修改一下，可以随便输入一些字母或数字）
const SUB_PATH = 'sn11ofhiqofj';

const XPATH = 'kbkbvsdhc';

// 被伪装的真实站点 如 https://xxx.pages.dev
const PAGE_URL = 'https://www.8thcivic.com';

// 域名 / IP（可以写你的 Render 域名或留空自动探测）
const DOMAIN = '';     

// 订阅里显示的节点名（可随便改）
const NAME = 'Vls';

// HTTP 监听端口（Render 通常用环境变量 PORT，这里你硬编码，自行确保和平台配置一致）
const PORT = 3000;



// 核心配置
const SETTINGS = {
    ['UUID']: UUID,
    ['LOG_LEVEL']: 'none',       // none, debug, info, warn, error
    ['BUFFER_SIZE']: '2048',     // TCP 缓冲区大小（KB）
    ['XPATH']: `%2F${XPATH}`,    // XHTTP path (URL 编码后的 "/xxx")
    ['MAX_BUFFERED_POSTS']: 30,  // 单个会话最多缓存的分片数
    ['MAX_POST_SIZE']: 1000000,  // 单次 POST 最大字节数（1MB）
    ['SESSION_TIMEOUT']: 30000,  // 会话超时（毫秒）
    ['CHUNK_SIZE']: 1024 * 1024, // 转发时的 chunk 大小
    ['TCP_NODELAY']: true,
    ['TCP_KEEPALIVE']: true,
};

// ========== 工具函数和日志 ==========

function validate_uuid(left, right) {
    for (let i = 0; i < 16; i++) {
        if (left[i] !== right[i]) return false;
    }
    return true;
}

function concat_typed_arrays(first, ...args) {
    if (!args || args.length < 1) return first;
    let len = first.length;
    for (let a of args) len += a.length;
    const r = new first.constructor(len);
    r.set(first, 0);
    len = first.length;
    for (let a of args) {
        r.set(a, len);
        len += a.length;
    }
    return r;
}

// 扩展日志
function log(type, ...args) {
    if (SETTINGS.LOG_LEVEL === 'none') return;

    const levels = { debug: 0, info: 1, warn: 2, error: 3 };
    const colors = {
        debug: '\x1b[36m',
        info: '\x1b[32m',
        warn: '\x1b[33m',
        error: '\x1b[31m',
        reset: '\x1b[0m',
    };

    const configLevel = levels[SETTINGS.LOG_LEVEL] || 1;
    const messageLevel = levels[type] || 0;

    if (messageLevel >= configLevel) {
        const time = new Date().toISOString();
        const color = colors[type] || colors.reset;
        console.log(`${color}[${time}] [${type}]`, ...args, colors.reset);
    }
}

// ========== VLESS 解析相关 ==========

function parse_uuid(uuid) {
    uuid = uuid.replaceAll('-', '');
    const r = [];
    for (let index = 0; index < 16; index++) {
        r.push(parseInt(uuid.substr(index * 2, 2), 16));
    }
    return r;
}

async function read_vless_header(reader, cfg_uuid_str) {
    let readed_len = 0;
    let header = new Uint8Array();
    let read_result = { value: header, done: false };

    async function inner_read_until(offset) {
        if (read_result.done) throw new Error('header length too short');
        const len = offset - readed_len;
        if (len < 1) return;
        read_result = await read_atleast(reader, len);
        readed_len += read_result.value.length;
        header = concat_typed_arrays(header, read_result.value);
    }

    await inner_read_until(1 + 16 + 1);

    const version = header[0];
    const uuid = header.slice(1, 1 + 16);
    const cfg_uuid = parse_uuid(cfg_uuid_str);
    if (!validate_uuid(uuid, cfg_uuid)) {
        throw new Error('invalid UUID');
    }

    const pb_len = header[1 + 16];
    const addr_plus1 = 1 + 16 + 1 + pb_len + 1 + 2 + 1;
    await inner_read_until(addr_plus1 + 1);

    const cmd = header[1 + 16 + 1 + pb_len];
    const COMMAND_TYPE_TCP = 1;
    if (cmd !== COMMAND_TYPE_TCP) {
        throw new Error(`unsupported command: ${cmd}`);
    }

    const port = (header[addr_plus1 - 1 - 2] << 8) + header[addr_plus1 - 1 - 1];
    const atype = header[addr_plus1 - 1];

    const ADDRESS_TYPE_IPV4 = 1;
    const ADDRESS_TYPE_STRING = 2;
    const ADDRESS_TYPE_IPV6 = 3;
    let header_len = -1;

    if (atype === ADDRESS_TYPE_IPV4) header_len = addr_plus1 + 4;
    else if (atype === ADDRESS_TYPE_IPV6) header_len = addr_plus1 + 16;
    else if (atype === ADDRESS_TYPE_STRING) header_len = addr_plus1 + 1 + header[addr_plus1];

    if (header_len < 0) throw new Error('read address type failed');

    await inner_read_until(header_len);

    const idx = addr_plus1;
    let hostname = '';
    if (atype === ADDRESS_TYPE_IPV4) {
        hostname = header.slice(idx, idx + 4).join('.');
    } else if (atype === ADDRESS_TYPE_STRING) {
        hostname = new TextDecoder().decode(
            header.slice(idx + 1, idx + 1 + header[idx]),
        );
    } else if (atype === ADDRESS_TYPE_IPV6) {
        hostname = header
            .slice(idx, idx + 16)
            .reduce(
                (s, b2, i2, a) =>
                    i2 % 2 ? s.concat(((a[i2 - 1] << 8) + b2).toString(16)) : s,
                [],
            )
            .join(':');
    }

    if (!hostname) {
        log('error', 'Failed to parse hostname');
        throw new Error('parse hostname failed');
    }

    log('info', `VLESS connection to ${hostname}:${port}`);
    return {
        hostname,
        port,
        data: header.slice(header_len),
        resp: new Uint8Array([version, 0]),
    };
}

async function read_atleast(reader, n) {
    const buffs = [];
    let done = false;
    while (n > 0 && !done) {
        const r = await reader.read();
        if (r.value) {
            const b = new Uint8Array(r.value);
            buffs.push(b);
            n -= b.length;
        }
        done = r.done;
    }
    if (n > 0) throw new Error('not enough data to read');
    return { value: concat_typed_arrays(...buffs), done };
}

async function parse_header(uuid_str, client) {
    log('debug', 'Starting to parse VLESS header');
    const reader = client.readable.getReader();
    try {
        const vless = await read_vless_header(reader, uuid_str);
        log('debug', 'VLESS header parsed successfully');
        return vless;
    } catch (err) {
        log('error', `VLESS header parse error: ${err.message}`);
        throw new Error(`read vless header error: ${err.message}`);
    } finally {
        reader.releaseLock();
    }
}

// ========== TCP 连接 & 转发 ==========

async function connect_remote(hostname, port) {
    const timeout = 8000;
    try {
        const conn = await timed_connect(hostname, port, timeout);

        conn.setNoDelay(true);
        conn.setKeepAlive(true, 1000);
        conn.bufferSize = parseInt(SETTINGS.BUFFER_SIZE) * 1024;

        log('info', `Connected to ${hostname}:${port}`);
        return conn;
    } catch (err) {
        log('error', `Connection failed: ${err.message}`);
        throw err;
    }
}

function timed_connect(hostname, port, ms) {
    return new Promise((resolve, reject) => {
        const conn = net.createConnection({ host: hostname, port: port });
        const handle = setTimeout(() => {
            conn.destroy();
            reject(new Error('connect timeout'));
        }, ms);
        conn.on('connect', () => {
            clearTimeout(handle);
            resolve(conn);
        });
        conn.on('error', (err) => {
            clearTimeout(handle);
            reject(err);
        });
    });
}

function pipe_relay() {
    async function pump(src, dest, first_packet) {
        const chunkSize = parseInt(SETTINGS.CHUNK_SIZE);

        if (first_packet && first_packet.length > 0) {
            if (dest.write) {
                dest.cork && dest.cork();
                dest.write(first_packet);
                process.nextTick(() => dest.uncork && dest.uncork());
            } else {
                const writer = dest.writable.getWriter();
                try {
                    await writer.write(first_packet);
                } finally {
                    writer.releaseLock();
                }
            }
        }

        try {
            if (src.pipe) {
                src.pause();
                src.pipe(dest, { end: true, highWaterMark: chunkSize });
                src.resume();
            } else {
                await src.readable.pipeTo(dest.writable, {
                    preventClose: false,
                    preventAbort: false,
                    preventCancel: false,
                    signal: AbortSignal.timeout(SETTINGS.SESSION_TIMEOUT),
                });
            }
        } catch (err) {
            if (!err.message.includes('aborted')) {
                log('error', 'Relay error:', err.message);
            }
            throw err;
        }
    }
    return pump;
}

function socketToWebStream(socket) {
    let readController;
    let writeController;

    socket.on('error', (err) => {
        log('error', 'Socket error:', err.message);
        readController?.error(err);
        writeController?.error(err);
    });

    return {
        readable: new ReadableStream({
            start(controller) {
                readController = controller;
                socket.on('data', (chunk) => {
                    try {
                        controller.enqueue(chunk);
                    } catch (err) {
                        log('error', 'Read controller error:', err.message);
                    }
                });
                socket.on('end', () => {
                    try {
                        controller.close();
                    } catch (err) {
                        log('error', 'Read controller close error:', err.message);
                    }
                });
            },
            cancel() {
                socket.destroy();
            },
        }),
        writable: new WritableStream({
            start(controller) {
                writeController = controller;
            },
            write(chunk) {
                return new Promise((resolve, reject) => {
                    if (socket.destroyed) {
                        reject(new Error('Socket is destroyed'));
                        return;
                    }
                    socket.write(chunk, (err) => {
                        if (err) reject(err);
                        else resolve();
                    });
                });
            },
            close() {
                if (!socket.destroyed) {
                    socket.end();
                }
            },
            abort(err) {
                socket.destroy(err);
            },
        }),
    };
}

// ========== Session 管理 ==========

const sessions = new Map();

class Session {
    constructor(uuid) {
        this.uuid = uuid;
        this.nextSeq = 0;
        this.downstreamStarted = false;
        this.lastActivity = Date.now();
        this.vlessHeader = null;
        this.remote = null;
        this.initialized = false;
        this.responseHeader = null;
        this.headerSent = false;
        this.cleaned = false;
        this.currentStreamRes = null;
        this.pendingBuffers = new Map();
        log('debug', `Created new session with UUID: ${uuid}`);
    }

    async initializeVLESS(firstPacket) {
        if (this.initialized) return true;
        try {
            const readable = new ReadableStream({
                start(controller) {
                    controller.enqueue(firstPacket);
                    controller.close();
                },
            });

            const client = {
                readable,
                writable: new WritableStream(),
            };

            this.vlessHeader = await parse_header(SETTINGS.UUID, client);
            log('info', `VLESS header parsed: ${this.vlessHeader.hostname}:${this.vlessHeader.port}`);

            this.remote = await connect_remote(this.vlessHeader.hostname, this.vlessHeader.port);
            log('info', 'Remote connection established');

            this.initialized = true;
            return true;
        } catch (err) {
            log('error', `Failed to initialize VLESS: ${err.message}`);
            return false;
        }
    }

    async processPacket(seq, data) {
        try {
            this.pendingBuffers.set(seq, data);

            while (this.pendingBuffers.has(this.nextSeq)) {
                const nextData = this.pendingBuffers.get(this.nextSeq);
                this.pendingBuffers.delete(this.nextSeq);

                if (!this.initialized && this.nextSeq === 0) {
                    if (!(await this.initializeVLESS(nextData))) {
                        throw new Error('Failed to initialize VLESS connection');
                    }
                    this.responseHeader = Buffer.from(this.vlessHeader.resp);
                    await this._writeToRemote(this.vlessHeader.data);
                    if (this.currentStreamRes) this._startDownstreamResponse();
                } else {
                    if (!this.initialized) {
                        log('warn', `Received out-of-order packet seq=${seq} before initialization`);
                        continue;
                    }
                    await this._writeToRemote(nextData);
                }

                this.nextSeq++;
            }

            if (this.pendingBuffers.size > SETTINGS.MAX_BUFFERED_POSTS) {
                throw new Error('Too many buffered packets');
            }

            this.lastActivity = Date.now();
            return true;
        } catch (err) {
            log('error', `Process packet error: ${err.message}`);
            throw err;
        }
    }

    _startDownstreamResponse() {
        if (!this.currentStreamRes || !this.responseHeader || !this.remote) return;

        try {
            if (!this.headerSent) {
                this.currentStreamRes.write(this.responseHeader);
                this.headerSent = true;
            }

            this.remote.pipe(this.currentStreamRes);

            this.remote.on('end', () => {
                if (!this.currentStreamRes.writableEnded) {
                    this.currentStreamRes.end();
                }
            });

            this.remote.on('error', (err) => {
                log('error', `Remote error: ${err.message}`);
                if (!this.currentStreamRes.writableEnded) {
                    this.currentStreamRes.end();
                }
            });
        } catch (err) {
            log('error', `Error starting downstream: ${err.message}`);
            this.cleanup();
        }
    }

    startDownstream(res, headers) {
        if (!res.headersSent) {
            res.writeHead(200, headers);
        }

        this.currentStreamRes = res;

        if (this.initialized && this.responseHeader) {
            this._startDownstreamResponse();
        }

        res.on('close', () => {
            log('info', 'Client connection closed');
            this.cleanup();
            sessions.delete(this.uuid);  // 修复：会话关闭时从 Map 删除
        });

        return true;
    }

    async _writeToRemote(data) {
        if (!this.remote || this.remote.destroyed) {
            throw new Error('Remote connection not available');
        }
        return new Promise((resolve, reject) => {
            this.remote.write(data, (err) => {
                if (err) {
                    log('error', `Failed to write to remote: ${err.message}`);
                    reject(err);
                } else {
                    resolve();
                }
            });
        });
    }

    cleanup() {
        if (this.cleaned) return;
        this.cleaned = true;
        log('debug', `Cleaning up session ${this.uuid}`);
        if (this.remote) {
            this.remote.destroy();
            this.remote = null;
        }
        this.initialized = false;
        this.headerSent = false;
        this.pendingBuffers.clear();
        this.currentStreamRes = null;
    }
}

// ========== ISP & IP 信息（用于订阅显示） ==========

let ISP = 'Unknown';
try {
    const metaInfo = require('child_process').execSync(
        'curl -s https://speed.cloudflare.com/meta | awk -F\\" \'{print $26"-"$18}\' | sed -e \'s/ /_/g\'',
        { encoding: 'utf-8' },
    );
    ISP = metaInfo.trim();
} catch (e) {
    log('warn', 'Failed to get ISP info');
}

let IP = DOMAIN;
if (!DOMAIN) {
    try {
        IP = require('child_process').execSync('curl -s --max-time 2 ipv4.ip.sb', {
            encoding: 'utf-8',
        }).trim();
    } catch (err) {
        try {
            IP = `[${require('child_process').execSync(
                'curl -s --max-time 1 ipv6.ip.sb',
                { encoding: 'utf-8' },
            ).trim()}]`;
        } catch (ipv6Err) {
            log('error', 'Failed to get IP address:', ipv6Err.message);
            IP = 'localhost';
        }
    }
}

// ========== HTTP 服务 & 反向代理 ==========

function generatePadding(min, max) {
    const length = min + Math.floor(Math.random() * (max - min));
    return Buffer.from(Array(length).fill('X').join('')).toString('base64');
}

async function reverseProxyToPage(req, res) {
    if (!PAGE_URL) {
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Hello\n');
        return;
    }

    const base = PAGE_URL.replace(/\/$/, '');
    const targetUrl = base + (req.url === '/' ? '' : req.url);

    try {
        const upstream = await axios.get(targetUrl, {
            headers: {
                'User-Agent': req.headers['user-agent'] || 'Mozilla/5.0',
                'Accept-Language': req.headers['accept-language'] || 'zh-CN,zh;q=0.9',
            },
            responseType: 'arraybuffer',
            timeout: 8000,
            validateStatus: () => true,
        });

        const ct = upstream.headers['content-type'] || 'application/octet-stream';
        res.writeHead(upstream.status, { 'Content-Type': ct });
        res.end(upstream.data);
    } catch (e) {
        log('error', `Reverse proxy error: ${e.message}`);
        res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Bad Gateway');
    }
}

const server = http.createServer(async (req, res) => {
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST',
        'Cache-Control': 'no-store',
        'X-Accel-Buffering': 'no',
        'X-Padding': generatePadding(100, 1000),
    };

    // 订阅路径
    if (req.url === `/${SUB_PATH}`) {
        const vlessURL = `vless://${UUID}@${IP}:443?encryption=none&security=tls&sni=${IP}&fp=chrome&allowInsecure=1&type=xhttp&host=${IP}&path=${SETTINGS.XPATH}&mode=packet-up#${NAME}-${ISP}`;
        const base64Content = Buffer.from(vlessURL).toString('base64');
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(base64Content + '\n');
        return;
    }

    // VLESS XHTTP 路径匹配
    const pathMatch = req.url.match(new RegExp(`^/${XPATH}/([^/]+)(?:/([0-9]+))?$`));
    if (pathMatch) {
        const uuid = pathMatch[1];
        const seq = pathMatch[2] ? parseInt(pathMatch[2]) : null;

        if (req.method === 'GET' && seq === null) {
            headers['Content-Type'] = 'application/octet-stream';
            headers['Transfer-Encoding'] = 'chunked';

            let session = sessions.get(uuid);
            if (!session) {
                session = new Session(uuid);
                sessions.set(uuid, session);
                log('info', `Created new session for GET: ${uuid}`);
            }

            session.downstreamStarted = true;

            if (!session.startDownstream(res, headers)) {
                log('error', `Failed to start downstream for session: ${uuid}`);
                if (!res.headersSent) {
                    res.writeHead(500);
                    res.end();
                }
                session.cleanup();
                sessions.delete(uuid);
            }
            return;
        }

        if (req.method === 'POST' && seq !== null) {
            let session = sessions.get(uuid);
            if (!session) {
                session = new Session(uuid);
                sessions.set(uuid, session);
                log('info', `Created new session for POST: ${uuid}`);

                setTimeout(() => {
                    const currentSession = sessions.get(uuid);
                    if (currentSession && !currentSession.downstreamStarted) {
                        log('warn', `Session ${uuid} timed out without downstream`);
                        currentSession.cleanup();
                        sessions.delete(uuid);
                    }
                }, SETTINGS.SESSION_TIMEOUT);
            }

            let data = [];
            let size = 0;
            let headersSent = false;

            req.on('data', (chunk) => {
                size += chunk.length;
                if (size > SETTINGS.MAX_POST_SIZE) {
                    if (!headersSent) {
                        res.writeHead(413);
                        res.end();
                        headersSent = true;
                    }
                    return;
                }
                data.push(chunk);
            });

            req.on('end', async () => {
                if (headersSent) return;

                try {
                    const buffer = Buffer.concat(data);
                    await session.processPacket(seq, buffer);

                    if (!headersSent) {
                        res.writeHead(200, headers);
                        headersSent = true;
                    }
                    res.end();
                } catch (err) {
                    log('error', `Failed to process POST request: ${err.message}`);
                    session.cleanup();
                    sessions.delete(uuid);

                    if (!headersSent) {
                        res.writeHead(500);
                        headersSent = true;
                    }
                    res.end();
                }
            });
            return;
        }

        res.writeHead(404);
        res.end();
        return;
    }

    // 其它路径全部反代 Cloudflare Pages
    await reverseProxyToPage(req, res);
});

server.keepAliveTimeout = 620000;
server.headersTimeout = 625000;

server.on('error', (err) => {
    log('error', `Server error: ${err.message}`);
});

server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
