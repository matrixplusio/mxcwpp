/**
 * UDS reporter — 4 byte BE length + JSON UTF-8.
 *
 * 队列: 内存数组 capacity, drop-oldest on full.
 * 后台 timer 每 200ms flush, beforeExit 也 flush.
 * UDS 重连每 reconnectInterval ms 重试.
 */
'use strict';

const net = require('net');
const { Buffer } = require('buffer');

class Reporter {
  constructor(config) {
    this.config = config;
    this.queue = [];
    this.capacity = config.queueCapacity;
    this.sock = null;
    this.connecting = false;
    this.connected = false;
    this.timer = null;
    this.stopped = false;
    this.rps = 0;
    this.rpsResetAt = Date.now();
  }

  start() {
    this._connect();
    this.timer = setInterval(() => this.flush(), 200);
    if (this.timer.unref) this.timer.unref();
  }

  stop() {
    this.stopped = true;
    if (this.timer) clearInterval(this.timer);
    if (this.sock) this.sock.destroy();
  }

  enqueue(event) {
    // Rate limit
    const now = Date.now();
    if (now - this.rpsResetAt > 1000) {
      this.rps = 0;
      this.rpsResetAt = now;
    }
    if (this.rps >= this.config.maxEventsPerSecond) {
      return;
    }
    this.rps++;

    if (this.queue.length >= this.capacity) {
      this.queue.shift();
    }
    this.queue.push(event);
  }

  flush() {
    if (this.stopped) return;
    if (!this.connected) {
      if (!this.connecting) this._connect();
      return;
    }
    while (this.queue.length > 0) {
      const ev = this.queue.shift();
      const ok = this._writeFrame(ev);
      if (!ok) {
        this.queue.unshift(ev);
        break;
      }
    }
  }

  _writeFrame(ev) {
    try {
      const payload = Buffer.from(JSON.stringify(ev), 'utf8');
      const header = Buffer.alloc(4);
      header.writeUInt32BE(payload.length, 0);
      return this.sock.write(Buffer.concat([header, payload]));
    } catch (e) {
      this.connected = false;
      return false;
    }
  }

  _connect() {
    if (this.connecting || this.stopped) return;
    this.connecting = true;
    const sock = net.createConnection(this.config.udsPath);
    sock.on('connect', () => {
      this.sock = sock;
      this.connected = true;
      this.connecting = false;
    });
    sock.on('error', () => {
      this.connecting = false;
      this.connected = false;
      setTimeout(() => this._connect(), this.config.reconnectInterval);
    });
    sock.on('close', () => {
      this.connected = false;
      this.sock = null;
    });
  }
}

module.exports = Reporter;
