//! Node.js `http` and `https` shim — pure-JS implementation for the QuickJS
//! extension runtime.
//!
//! Provides `http.request`, `http.get`, `https.request`, `https.get` that route
//! all HTTP traffic through the capability-gated `pi.http()` hostcall. Uses the
//! `EventEmitter` from `node:events` for the standard Node.js event-based API.

/// The JS source for the `node:http` virtual module.
pub const NODE_HTTP_JS: &str = r#"
import EventEmitter from "node:events";

// ─── STATUS_CODES ────────────────────────────────────────────────────────────

const STATUS_CODES = {
  200: 'OK', 201: 'Created', 204: 'No Content',
  301: 'Moved Permanently', 302: 'Found', 304: 'Not Modified',
  400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden',
  404: 'Not Found', 405: 'Method Not Allowed', 408: 'Request Timeout',
  500: 'Internal Server Error', 502: 'Bad Gateway', 503: 'Service Unavailable',
};

const METHODS = [
  'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT',
  'OPTIONS', 'TRACE', 'PATCH',
];

// ─── IncomingMessage ─────────────────────────────────────────────────────────

class IncomingMessage extends EventEmitter {
  constructor(statusCode, headers, body) {
    super();
    this.statusCode = statusCode;
    this.statusMessage = STATUS_CODES[statusCode] || 'Unknown';
    this.headers = headers || {};
    this._body = body || '';
    this.complete = false;
    this.httpVersion = '1.1';
    this.method = null;
    this.url = '';
  }

  _deliver() {
    if (this._body && this._body.length > 0) {
      this.emit('data', this._body);
    }
    this.complete = true;
    this.emit('end');
  }

  setEncoding(_encoding) { return this; }
  resume() { return this; }
  pause() { return this; }
  destroy() { this.emit('close'); }
}

// ─── ClientRequest ───────────────────────────────────────────────────────────

class ClientRequest extends EventEmitter {
  constructor(options, callback) {
    super();
    this._options = options;
    this._body = [];
    this._ended = false;
    this._aborted = false;
    this.socket = { remoteAddress: '127.0.0.1', remotePort: 0 };
    this.method = options.method || 'GET';
    this.path = options.path || '/';

    if (typeof callback === 'function') {
      this.once('response', callback);
    }
  }

  write(chunk) {
    if (!this._ended && !this._aborted) {
      this._body.push(typeof chunk === 'string' ? chunk : String(chunk));
    }
    return true;
  }

  end(chunk, _encoding, callback) {
    if (typeof chunk === 'function') { callback = chunk; chunk = undefined; }
    if (typeof _encoding === 'function') { callback = _encoding; }
    if (chunk) this.write(chunk);
    if (typeof callback === 'function') this.once('finish', callback);

    this._ended = true;
    this._send();
    return this;
  }

  abort() {
    this._aborted = true;
    this.emit('abort');
    this.destroy();
  }

  destroy(error) {
    this._aborted = true;
    if (error) this.emit('error', error);
    this.emit('close');
    return this;
  }

  setTimeout(ms, callback) {
    if (typeof callback === 'function') this.once('timeout', callback);
    this._timeoutMs = ms;
    return this;
  }

  setNoDelay() { return this; }
  setSocketKeepAlive() { return this; }
  flushHeaders() {}
  getHeader(_name) { return undefined; }
  setHeader(_name, _value) { return this; }
  removeHeader(_name) {}

  _send() {
    const opts = this._options;
    const protocol = opts.protocol || 'http:';
    const hostname = opts.hostname || opts.host || 'localhost';
    const port = opts.port ? `:${opts.port}` : '';
    const path = opts.path || '/';
    const url = `${protocol}//${hostname}${port}${path}`;

    const headers = {};
    if (opts.headers) {
      for (const [k, v] of Object.entries(opts.headers)) {
        headers[k.toLowerCase()] = String(v);
      }
    }

    const body = this._body.length > 0 ? this._body.join('') : undefined;
    const method = (opts.method || 'GET').toUpperCase();

    const request = { url, method, headers };
    if (body) request.body = body;
    if (this._timeoutMs) request.timeout = this._timeoutMs;

    // Use pi.http() hostcall if available
    if (typeof globalThis.pi === 'object' && typeof globalThis.pi.http === 'function') {
      try {
        const promise = globalThis.pi.http(request);
        if (promise && typeof promise.then === 'function') {
          promise.then(
            (result) => this._handleResponse(result),
            (err) => this.emit('error', typeof err === 'string' ? new Error(err) : err)
          );
        } else {
          this._handleResponse(promise);
        }
      } catch (err) {
        this.emit('error', err);
      }
    } else {
      // No pi.http available — emit error
      this.emit('error', new Error('HTTP requests require pi.http() hostcall'));
    }

    this.emit('finish');
  }

  _handleResponse(result) {
    if (!result || typeof result !== 'object') {
      this.emit('error', new Error('Invalid HTTP response from hostcall'));
      return;
    }

    const statusCode = result.status || result.statusCode || 200;
    const headers = result.headers || {};
    const body = result.body || result.data || '';

    const res = new IncomingMessage(statusCode, headers, body);
    this.emit('response', res);
    // Deliver body asynchronously (in next microtask)
    Promise.resolve().then(() => res._deliver());
  }
}

// ─── Module API ──────────────────────────────────────────────────────────────

function _parseOptions(input, options) {
  if (typeof input === 'string') {
    try {
      const url = new URL(input);
      return {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port || undefined,
        path: url.pathname + url.search,
        ...(options || {}),
      };
    } catch (_e) {
      return { path: input, ...(options || {}) };
    }
  }
  if (input && typeof input === 'object' && !(input instanceof URL)) {
    return input;
  }
  if (input instanceof URL) {
    return {
      protocol: input.protocol,
      hostname: input.hostname,
      port: input.port || undefined,
      path: input.pathname + input.search,
      ...(options || {}),
    };
  }
  return options || {};
}

export function request(input, optionsOrCallback, callback) {
  let options;
  if (typeof optionsOrCallback === 'function') {
    callback = optionsOrCallback;
    options = _parseOptions(input);
  } else {
    options = _parseOptions(input, optionsOrCallback);
  }
  if (!options.protocol) options.protocol = 'http:';
  return new ClientRequest(options, callback);
}

export function get(input, optionsOrCallback, callback) {
  const req = request(input, optionsOrCallback, callback);
  req.end();
  return req;
}

export function createServer() {
  throw new Error('node:http.createServer is not available in PiJS');
}

export { STATUS_CODES, METHODS, IncomingMessage, ClientRequest };
export default { request, get, createServer, STATUS_CODES, METHODS, IncomingMessage, ClientRequest };
"#;

/// The JS source for the `node:https` virtual module.
pub const NODE_HTTPS_JS: &str = r#"
import EventEmitter from "node:events";
import * as http from "node:http";

export function request(input, optionsOrCallback, callback) {
  let options;
  if (typeof optionsOrCallback === 'function') {
    callback = optionsOrCallback;
    options = typeof input === 'string' || input instanceof URL
      ? { ...(typeof input === 'string' ? (() => { try { const u = new URL(input); return { protocol: u.protocol, hostname: u.hostname, port: u.port, path: u.pathname + u.search }; } catch(_) { return { path: input }; } })() : { protocol: input.protocol, hostname: input.hostname, port: input.port, path: input.pathname + input.search }) }
      : (input || {});
  } else {
    options = typeof input === 'string' || input instanceof URL
      ? { ...(typeof input === 'string' ? (() => { try { const u = new URL(input); return { protocol: u.protocol, hostname: u.hostname, port: u.port, path: u.pathname + u.search }; } catch(_) { return { path: input }; } })() : { protocol: input.protocol, hostname: input.hostname, port: input.port, path: input.pathname + input.search }), ...(optionsOrCallback || {}) }
      : { ...(input || {}), ...(optionsOrCallback || {}) };
  }
  if (!options.protocol) options.protocol = 'https:';
  return http.request(options, callback);
}

export function get(input, optionsOrCallback, callback) {
  const req = request(input, optionsOrCallback, callback);
  req.end();
  return req;
}

export function createServer() {
  throw new Error('node:https.createServer is not available in PiJS');
}

export const globalAgent = {};

export default { request, get, createServer, globalAgent };
"#;
