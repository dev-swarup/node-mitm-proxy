'use strict';

var async   = require('async');
var net     = require('net');
var http    = require('http');
var https   = require('https');
var util    = require('util');
var fs      = require('fs');
var path    = require('path');
var events  = require('events');
var WebSocket = require('ws');
var semaphore = require('semaphore');
var ca      = require('./ca.js');
const nodeCommon = require('_http_common');
const debug = require('debug')('http-mitm-proxy');

// ---------------------------------------------------------------------------
// Module-level compiled regex constants (Perf 1)
// ---------------------------------------------------------------------------
/** Matches HTTP scheme prefix in a host string (used in parseHost). */
const RE_HTTP_PREFIX    = /^http:\/\/(.*)/;
/** Matches proxy-* headers that must not be forwarded upstream. */
const RE_PROXY_HEADER   = /^proxy-/i;
/** Matches HPKP headers that must be filtered out. */
const RE_HPKP_HEADER    = /^public-key-pins/i;
/** Matches bare IP addresses (v4). Used to distinguish hostnames from IPs. */
const RE_IS_IP          = /^[\d.]+$/;
/** Matches the http:// prefix at the start of a request URL. */
const RE_HTTP_URL       = /^http:\/\/([^/]+)(.*)/;
/** Matches Basic auth scheme in Proxy-Authorization header. */
const RE_BASIC_AUTH     = /^Basic\s+(.+)$/i;

// ---------------------------------------------------------------------------
// Factory / exports
// ---------------------------------------------------------------------------

module.exports = function () {
  return new Proxy();
};

module.exports.gunzip   = require('./middleware/gunzip');
module.exports.wildcard = require('./middleware/wildcard');

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

/**
 * Creates a new MITM proxy instance.
 *
 * Obtain an instance via the factory:
 * ```js
 * var Proxy = require('@dev-swarup/http-mitm-proxy');
 * var proxy = Proxy();
 * ```
 *
 * @constructor
 */
var Proxy = function () {
  this.onConnectHandlers              = [];
  this.onRequestHandlers              = [];
  this.onRequestHeadersHandlers       = [];
  this.onWebSocketConnectionHandlers  = [];
  this.onWebSocketFrameHandlers       = [];
  this.onWebSocketCloseHandlers       = [];
  this.onWebSocketErrorHandlers       = [];
  this.onErrorHandlers                = [];
  this.onRequestDataHandlers          = [];
  this.onRequestEndHandlers           = [];
  this.onResponseHandlers             = [];
  this.onResponseHeadersHandlers      = [];
  this.onResponseDataHandlers         = [];
  this.onResponseEndHandlers          = [];
  this.socketMapping                  = new Map();
  this.responseContentPotentiallyModified = false;
  /** @type {function|null} Optional authenticator set via onAuthenticate(). */
  this.authenticator                  = null;
};

module.exports.Proxy = Proxy;

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/**
 * Starts the proxy listening on the given port/host.
 *
 * @param {object}   [options]              - Configuration options.
 * @param {number}   [options.port=8080]    - Port to listen on (0 = OS-assigned).
 * @param {string}   [options.host='localhost'] - Interface to bind to.
 * @param {string}   [options.sslCaDir]     - Directory for the root CA cert/key
 *   (default: `<cwd>/.http-mitm-proxy`). Per-host certs are kept in memory only.
 * @param {boolean}  [options.keepAlive=false] - Enable HTTP keep-alive.
 * @param {number}   [options.timeout=0]    - Socket inactivity timeout in ms.
 * @param {object}   [options.httpAgent]    - Custom http.Agent for upstream requests.
 * @param {object}   [options.httpsAgent]   - Custom https.Agent for upstream requests.
 * @param {boolean}  [options.forceSNI=false] - Route all HTTPS through a single
 *   SNI-capable HTTPS server instead of spawning one per hostname.
 * @param {number}   [options.httpsPort]    - Port for the SNI HTTPS server
 *   (only used when `forceSNI` is true).
 * @param {boolean}  [options.forceChunkedRequest=false] - Strip `content-length`
 *   from proxied requests, forcing chunked transfer encoding.
 * @param {function} [callback]             - `(err)` called when listening.
 * @returns {Proxy} `this` for chaining.
 */
Proxy.prototype.listen = function (options, callback = () => {}) {
  var self = this;
  this.options    = options || {};
  this.httpPort   = options.port || options.port === 0 ? options.port : 8080;
  this.httpHost   = options.host || 'localhost';
  this.timeout    = options.timeout || 0;
  this.keepAlive  = !!options.keepAlive;
  this.httpAgent  = typeof options.httpAgent  !== 'undefined' ? options.httpAgent  : new http.Agent({ keepAlive: this.keepAlive });
  this.httpsAgent = typeof options.httpsAgent !== 'undefined' ? options.httpsAgent : new https.Agent({ keepAlive: this.keepAlive });
  this.forceSNI   = !!options.forceSNI;
  if (this.forceSNI) {
    debug('SNI enabled. Clients not supporting SNI may fail');
  }
  this.httpsPort  = this.forceSNI ? options.httpsPort : undefined;
  this.sslCaDir   = options.sslCaDir || path.resolve(process.cwd(), '.http-mitm-proxy');

  ca.create(this.sslCaDir, function (err, caInstance) {
    if (err) {
      return callback(err);
    }
    self.ca          = caInstance;
    self.sslServers  = {};
    self.sslSemaphores = {};
    self.httpServer  = http.createServer();
    self.httpServer.timeout = self.timeout;
    self.httpServer.on('connect', self._onHttpServerConnect.bind(self));
    self.httpServer.on('request', self._onHttpServerRequest.bind(self, false));
    self.wsServer = new WebSocket.Server({ server: self.httpServer });
    self.wsServer.on('error', self._onError.bind(self, 'HTTP_SERVER_ERROR', null));
    self.wsServer.on('connection', (ws, req) => {
      ws.upgradeReq = req;
      self._onWebSocketServerConnect.call(self, false, ws, req);
    });
    const listenOptions = { host: self.httpHost, port: self.httpPort };
    if (self.forceSNI) {
      self._createHttpsServer({}, function (port, httpsServer, wssServer) {
        debug('https server started on ' + port);
        self.httpsServer = httpsServer;
        self.wssServer   = wssServer;
        self.httpsPort   = port;
        self.httpServer.listen(listenOptions, () => {
          self.httpPort = self.httpServer.address().port;
          callback();
        });
      });
    } else {
      self.httpServer.listen(listenOptions, () => {
        self.httpPort = self.httpServer.address().port;
        callback();
      });
    }
  });
  return this;
};

/**
 * Returns the address the HTTP server is bound to, or `null` if not yet
 * listening.
 *
 * @returns {net.AddressInfo|null}
 */
Proxy.prototype.address = function () {
  if (this.httpServer) {
    return this.httpServer.address();
  }
  return null;
};

/**
 * Stops the proxy and all associated HTTPS servers.
 * Closing is best-effort; errors are not propagated.
 *
 * @returns {Proxy} `this` for chaining.
 */
Proxy.prototype.close = function () {
  var self = this;
  // Close WebSocket servers before their underlying HTTP servers
  if (this.wsServer)  { this.wsServer.close();  delete this.wsServer;  }
  if (this.wssServer) { this.wssServer.close();  delete this.wssServer; }
  this.httpServer.close();
  delete this.httpServer;
  if (this.httpsServer) {
    this.httpsServer.close();
    delete this.httpsServer;
    delete this.sslServers;
  }
  if (this.sslServers) {
    Object.keys(this.sslServers).forEach(function (srvName) {
      var server = self.sslServers[srvName].server;
      if (server) server.close();
      delete self.sslServers[srvName];
    });
  }
  return this;
};

// ---------------------------------------------------------------------------
// Internal HTTPS server factory
// ---------------------------------------------------------------------------

/**
 * Creates and starts an HTTPS server with the given TLS options.
 *
 * @param {object}   options   - Passed directly to `https.createServer()`.
 * @param {function} callback  - `(port, httpsServer, wssServer)`.
 * @private
 */
Proxy.prototype._createHttpsServer = function (options, callback) {
  var httpsServer = https.createServer(options);
  httpsServer.timeout = this.timeout;
  httpsServer.on('error',       this._onError.bind(this, 'HTTPS_SERVER_ERROR', null));
  httpsServer.on('clientError', this._onError.bind(this, 'HTTPS_CLIENT_ERROR', null));
  httpsServer.on('connect',     this._onHttpServerConnect.bind(this));
  httpsServer.on('request',     this._onHttpServerRequest.bind(this, true));
  var self = this;
  var wssServer = new WebSocket.Server({ server: httpsServer });
  wssServer.on('connection', function (ws, req) {
    ws.upgradeReq = req;
    self._onWebSocketServerConnect.call(self, true, ws, req);
  });
  var listenOptions = { port: 0 };
  if (this.httpsPort && !options.hosts) {
    listenOptions.port = this.httpsPort;
  }
  if (this.httpHost) listenOptions.host = this.httpHost;
  httpsServer.listen(listenOptions, function () {
    if (callback) callback(httpsServer.address().port, httpsServer, wssServer);
  });
};

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

/**
 * Registers an optional authenticator function. When set, every inbound
 * CONNECT request (HTTPS tunnelling) and plain HTTP request must be
 * authorised before the proxy processes it.
 *
 * If this method is never called the proxy is open (no authentication).
 *
 * The authenticator receives a `credentials` object containing:
 *  - `ip`           {string}   — Direct TCP socket IP (unforgeable).
 *  - `forwardedFor` {string[]} — Parsed `X-Forwarded-For` chain, leftmost =
 *                                original client. Empty array if header absent.
 *                                ⚠ Advisory only — can be forged by clients.
 *  - `username`     {string=}  — Decoded from `Proxy-Authorization: Basic`.
 *  - `password`     {string=}  — Decoded from `Proxy-Authorization: Basic`.
 *
 * Call `callback()` (no argument) to allow the request, or
 * `callback(new Error('reason'))` to deny it with a `407` response.
 *
 * @example
 * // IP allowlist
 * proxy.onAuthenticate(function(req, credentials, callback) {
 *   if (credentials.ip === '127.0.0.1') return callback();
 *   return callback(new Error('IP not allowed'));
 * });
 *
 * @example
 * // Username + password
 * proxy.onAuthenticate(function(req, credentials, callback) {
 *   if (credentials.username === 'user' && credentials.password === 'pass') {
 *     return callback();
 *   }
 *   return callback(new Error('Unauthorized'));
 * });
 *
 * @param {function} fn - `(req, credentials, callback)` authenticator.
 * @returns {Proxy} `this` for chaining.
 */
Proxy.prototype.onAuthenticate = function (fn) {
  this.authenticator = fn;
  return this;
};

/**
 * Extracts authentication credentials from an incoming request.
 * Never throws.
 *
 * @param {http.IncomingMessage} req
 * @returns {{ ip: string, forwardedFor: string[], username?: string, password?: string }}
 * @private
 */
Proxy.prototype._parseCredentials = function (req) {
  var ip = (req.socket && req.socket.remoteAddress) || 'unknown';

  // Parse X-Forwarded-For chain (advisory — can be forged by clients).
  // Format: "client, proxy1, proxy2" — leftmost is the original client.
  var xffHeader = req.headers['x-forwarded-for'];
  var forwardedFor = xffHeader
    ? xffHeader.split(',').map(function (s) { return s.trim(); }).filter(Boolean)
    : [];

  var creds = { ip: ip, forwardedFor: forwardedFor };

  // Parse Proxy-Authorization: Basic <base64(username:password)>
  var authHeader = req.headers['proxy-authorization'];
  if (authHeader) {
    var m = authHeader.match(RE_BASIC_AUTH);
    if (m) {
      var decoded = Buffer.from(m[1], 'base64').toString('utf8');
      var sep = decoded.indexOf(':');
      if (sep !== -1) {
        creds.username = decoded.substring(0, sep);
        creds.password = decoded.substring(sep + 1);
      }
    }
  }
  return creds;
};

/**
 * Runs the registered authenticator (if any). Calls `rejectFn` on denial;
 * calls `callback` on success or when no authenticator is registered.
 *
 * @param {http.IncomingMessage} req
 * @param {function}             rejectFn  - Called with the error on denial.
 * @param {function}             callback  - Called with no args on success.
 * @private
 */
Proxy.prototype._checkAuth = function (req, rejectFn, callback) {
  if (!this.authenticator) return callback();
  var creds = this._parseCredentials(req);
  this.authenticator(req, creds, function (err) {
    if (err) return rejectFn(err);
    return callback();
  });
};

// ---------------------------------------------------------------------------
// Handler registration — public API
// ---------------------------------------------------------------------------

/**
 * Adds a handler invoked when an error occurs at any stage of proxying.
 *
 * @param {function} fn - `(ctx, err, errorKind)`.
 * @returns {Proxy} `this` for chaining.
 */
Proxy.prototype.onError = function (fn) {
  this.onErrorHandlers.push(fn);
  return this;
};

/**
 * Adds a handler for the HTTP CONNECT method, called before the proxy
 * attempts to tunnel the connection. Useful for forwarding HTTPS requests
 * to a different upstream proxy.
 *
 * @param {function} fn - `(req, socket, head, callback)`.
 * @returns {Proxy} `this` for chaining.
 */
Proxy.prototype.onConnect = function (fn) {
  this.onConnectHandlers.push(fn);
  return this;
};

/**
 * Adds a handler called after request headers have been parsed but before
 * the request is forwarded upstream. Allows header inspection / mutation.
 *
 * @param {function} fn - `(ctx, callback)`.
 * @returns {Proxy} `this` for chaining.
 */
Proxy.prototype.onRequestHeaders = function (fn) {
  this.onRequestHeadersHandlers.push(fn);
  return this;
};

/**
 * Adds a handler called at the beginning of each proxied request, before any
 * data is forwarded. Use this to modify `ctx.proxyToServerRequestOptions`.
 *
 * @param {function} fn - `(ctx, callback)`.
 * @returns {Proxy} `this` for chaining.
 */
Proxy.prototype.onRequest = function (fn) {
  this.onRequestHandlers.push(fn);
  return this;
};

/**
 * Adds a handler called for each chunk of request body data.
 *
 * @param {function} fn - `(ctx, chunk, callback)`. Pass a (possibly modified)
 *   `Buffer` to the callback as the second argument.
 * @returns {Proxy} `this` for chaining.
 */
Proxy.prototype.onRequestData = function (fn) {
  this.onRequestDataHandlers.push(fn);
  return this;
};

/**
 * Adds a handler called when the request body has been fully received.
 *
 * @param {function} fn - `(ctx, callback)`.
 * @returns {Proxy} `this` for chaining.
 */
Proxy.prototype.onRequestEnd = function (fn) {
  this.onRequestEndHandlers.push(fn);
  return this;
};

/**
 * Adds a handler called at the beginning of the upstream server's response,
 * before any body data is forwarded to the client.
 *
 * @param {function} fn - `(ctx, callback)`.
 * @returns {Proxy} `this` for chaining.
 */
Proxy.prototype.onResponse = function (fn) {
  this.onResponseHandlers.push(fn);
  return this;
};

/**
 * Adds a handler called after response headers are received from the upstream
 * server but before they are written to the client.
 *
 * @param {function} fn - `(ctx, callback)`.
 * @returns {Proxy} `this` for chaining.
 */
Proxy.prototype.onResponseHeaders = function (fn) {
  this.onResponseHeadersHandlers.push(fn);
  return this;
};

/**
 * Adds a handler called for each chunk of response body data.
 * Registering this handler switches the response to chunked transfer encoding.
 *
 * @param {function} fn - `(ctx, chunk, callback)`. Pass a (possibly modified)
 *   `Buffer` to the callback as the second argument.
 * @returns {Proxy} `this` for chaining.
 */
Proxy.prototype.onResponseData = function (fn) {
  this.onResponseDataHandlers.push(fn);
  this.responseContentPotentiallyModified = true;
  return this;
};

/**
 * Adds a handler called when the response body has been fully forwarded to
 * the client.
 *
 * @param {function} fn - `(ctx, callback)`.
 * @returns {Proxy} `this` for chaining.
 */
Proxy.prototype.onResponseEnd = function (fn) {
  this.onResponseEndHandlers.push(fn);
  return this;
};

/**
 * Adds a handler called when a WebSocket connection is established between
 * the client and the proxy.
 *
 * @param {function} fn - `(ctx, callback)`.
 * @returns {Proxy} `this` for chaining.
 */
Proxy.prototype.onWebSocketConnection = function (fn) {
  this.onWebSocketConnectionHandlers.push(fn);
  return this;
};

/**
 * Adds a handler for WebSocket frames sent **from the client** to the server.
 *
 * @param {function} fn - `(ctx, message, flags, callback)`.
 * @returns {Proxy} `this` for chaining.
 */
Proxy.prototype.onWebSocketSend = function (fn) {
  this.onWebSocketFrameHandlers.push(
    function (ctx, type, fromServer, data, flags, callback) {
      if (!fromServer && type === 'message') return this(ctx, data, flags, callback);
      else callback(null, data, flags);
    }.bind(fn)
  );
  return this;
};

/**
 * Adds a handler for WebSocket frames sent **from the server** to the client.
 *
 * @param {function} fn - `(ctx, message, flags, callback)`.
 * @returns {Proxy} `this` for chaining.
 */
Proxy.prototype.onWebSocketMessage = function (fn) {
  this.onWebSocketFrameHandlers.push(
    function (ctx, type, fromServer, data, flags, callback) {
      if (fromServer && type === 'message') return this(ctx, data, flags, callback);
      else callback(null, data, flags);
    }.bind(fn)
  );
  return this;
};

/**
 * Adds a handler for all WebSocket frames in both directions.
 *
 * @param {function} fn - `(ctx, type, fromServer, data, flags, callback)`.
 * @returns {Proxy} `this` for chaining.
 */
Proxy.prototype.onWebSocketFrame = function (fn) {
  this.onWebSocketFrameHandlers.push(fn);
  return this;
};

/**
 * Adds a handler called when a WebSocket connection is closed.
 *
 * @param {function} fn - `(ctx, code, message, callback)`.
 * @returns {Proxy} `this` for chaining.
 */
Proxy.prototype.onWebSocketClose = function (fn) {
  this.onWebSocketCloseHandlers.push(fn);
  return this;
};

/**
 * Adds a handler called when a WebSocket error occurs.
 *
 * @param {function} fn - `(ctx, err)`.
 * @returns {Proxy} `this` for chaining.
 */
Proxy.prototype.onWebSocketError = function (fn) {
  this.onWebSocketErrorHandlers.push(fn);
  return this;
};

/**
 * Installs a middleware module, registering all of its lifecycle hooks in one
 * call.  A module is a plain object whose properties are handler functions
 * matching the `on*` method names supported by the proxy.
 *
 * Built-in modules: `Proxy.gunzip`, `Proxy.wildcard`.
 *
 * @example
 * proxy.use({
 *   onRequest:      function(ctx, callback) { return callback(); },
 *   onResponseData: function(ctx, chunk, callback) { return callback(null, chunk); },
 * });
 *
 * @param {object} mod - Middleware module object.
 * @returns {Proxy} `this` for chaining.
 */
Proxy.prototype.use = function (mod) {
  if (mod.onError)              { this.onError(mod.onError); }
  if (mod.onConnect)            { this.onConnect(mod.onConnect); }
  if (mod.onRequest)            { this.onRequest(mod.onRequest); }
  if (mod.onRequestHeaders)     { this.onRequestHeaders(mod.onRequestHeaders); }
  if (mod.onRequestData)        { this.onRequestData(mod.onRequestData); }
  if (mod.onResponse)           { this.onResponse(mod.onResponse); }
  if (mod.onResponseHeaders)    { this.onResponseHeaders(mod.onResponseHeaders); }
  if (mod.onResponseData)       { this.onResponseData(mod.onResponseData); }
  if (mod.onWebSocketConnection){ this.onWebSocketConnection(mod.onWebSocketConnection); }
  if (mod.onWebSocketSend) {
    this.onWebSocketFrame(
      function (ctx, type, fromServer, data, flags, callback) {
        if (!fromServer && type === 'message') return this(ctx, data, flags, callback);
        else callback(null, data, flags);
      }.bind(mod.onWebSocketSend)
    );
  }
  if (mod.onWebSocketMessage) {
    this.onWebSocketFrame(
      function (ctx, type, fromServer, data, flags, callback) {
        if (fromServer && type === 'message') return this(ctx, data, flags, callback);
        else callback(null, data, flags);
      }.bind(mod.onWebSocketMessage)
    );
  }
  if (mod.onWebSocketFrame) { this.onWebSocketFrame(mod.onWebSocketFrame); }
  if (mod.onWebSocketClose) { this.onWebSocketClose(mod.onWebSocketClose); }
  if (mod.onWebSocketError) { this.onWebSocketError(mod.onWebSocketError); }
  return this;
};

// ---------------------------------------------------------------------------
// Internal error / socket handlers
// ---------------------------------------------------------------------------

/**
 * Logs socket-level errors (ECONNRESET etc.) at debug level.
 * These are non-fatal and common in proxy environments.
 *
 * @param {string} socketDescription - Human-readable label for the socket.
 * @param {Error}  err
 * @private
 */
Proxy.prototype._onSocketError = function (socketDescription, err) {
  debug('Got ' + (err && err.code) + ' on ' + socketDescription + '.');
};

// ---------------------------------------------------------------------------
// CONNECT handler
// ---------------------------------------------------------------------------

/**
 * Handles HTTP CONNECT requests used to establish HTTPS tunnels.
 * Runs auth check first, then custom `onConnect` handlers, then detects
 * whether the tunnelled traffic is TLS and routes accordingly.
 *
 * @param {http.IncomingMessage} req
 * @param {net.Socket}           socket
 * @param {Buffer}               head
 * @private
 */
Proxy.prototype._onHttpServerConnect = function (req, socket, head) {
  var self = this;

  socket.on('error', self._onSocketError.bind(self, 'CLIENT_TO_PROXY_SOCKET'));

  // ── Auth check ────────────────────────────────────────────────────────────
  self._checkAuth(req, function reject407(err) {
    debug('CONNECT denied (%s) from %s', err && err.message, req.socket && req.socket.remoteAddress);
    socket.write(
      'HTTP/1.1 407 Proxy Authentication Required\r\n' +
      'Proxy-Authenticate: Basic realm="proxy"\r\n' +
      'Content-Length: 0\r\n' +
      '\r\n'
    );
    socket.destroy();
  }, function afterAuth() {
    // ── Custom CONNECT handlers ─────────────────────────────────────────────
    return async.forEach(
      self.onConnectHandlers,
      function (fn, callback) {
        return fn.call(self, req, socket, head, callback);
      },
      function (err) {
        if (err) {
          return self._onError('ON_CONNECT_ERROR', null, err);
        }
        // Need the first byte to detect whether the tunnelled traffic is TLS
        if (!head || head.length === 0) {
          socket.once('data', self._onHttpServerConnectData.bind(self, req, socket));
          socket.write('HTTP/1.1 200 OK\r\n');
          if (self.keepAlive && req.headers['proxy-connection'] === 'keep-alive') {
            socket.write('Proxy-Connection: keep-alive\r\n');
            socket.write('Connection: keep-alive\r\n');
          }
          return socket.write('\r\n');
        } else {
          self._onHttpServerConnectData(req, socket, head);
        }
      }
    );
  });
};

/**
 * Inspects the first byte(s) of tunnelled data to determine whether the
 * connection is TLS-encrypted.  Routes TLS traffic to an HTTPS interception
 * server and plain traffic back to the HTTP server.
 *
 * TLS detection heuristic (from https://gist.github.com/tg-x/835636):
 *  - 0x16 = SSLv3 / TLSv1 record header
 *  - 0x80 / 0x00 = SSLv2 record header (MSB flag)
 *  - anything else = unencrypted
 *
 * @param {http.IncomingMessage} req
 * @param {net.Socket}           socket
 * @param {Buffer}               head
 * @private
 */
Proxy.prototype._onHttpServerConnectData = function (req, socket, head) {
  var self = this;

  socket.pause();

  if (head[0] === 0x16 || head[0] === 0x80 || head[0] === 0x00) {
    // ── TLS traffic — route to an HTTPS interception server ─────────────────
    var hostname   = new URL('http://' + req.url).hostname;
    var sslServer  = this.sslServers[hostname];
    if (sslServer) {
      return makeConnection(sslServer.port, this.httpHost);
    }
    var wildcardHost = hostname.replace(/[^.]+\./, '*.');
    var sem = self.sslSemaphores[wildcardHost];
    if (!sem) {
      sem = self.sslSemaphores[wildcardHost] = semaphore(1);
    }
    sem.take(function () {
      if (self.sslServers[hostname]) {
        process.nextTick(sem.leave.bind(sem));
        return makeConnection(self.sslServers[hostname].port, self.httpHost);
      }
      if (self.sslServers[wildcardHost]) {
        process.nextTick(sem.leave.bind(sem));
        self.sslServers[hostname] = { port: self.sslServers[wildcardHost].port };
        return makeConnection(self.sslServers[hostname].port, self.httpHost);
      }
      getHttpsServer(hostname, function (err, port) {
        process.nextTick(sem.leave.bind(sem));
        delete self.sslSemaphores[wildcardHost]; // Bug 3 fix: delete after server is ready
        if (err) {
          return self._onError('OPEN_HTTPS_SERVER_ERROR', null, err);
        }
        return makeConnection(port, self.httpHost);
      });
    });
  } else {
    // ── Plain HTTP — route back to the HTTP listener ─────────────────────────
    return makeConnection(this.httpPort, this.httpHost);
  }

  // ── TCP tunnel helpers ─────────────────────────────────────────────────────

  /**
   * Establishes a TCP tunnel between the client socket and the target port.
   * Handles bidirectional pipe teardown gracefully.
   *
   * @param {number} port
   * @param {string} host
   */
  function makeConnection(port, host) {
    // Single cleanup function shared across all three close-like events (Perf 4)
    function cleanupConn() {
      if (conn.localPort) {
        self.socketMapping.delete(conn.localPort);
      }
      if (!socket.readableFlowing && socket.writable) {
        socket.end();
      }
    }

    var conn = net.connect({ host: host, port: port }, function () {
      if (conn.localPort) {
        self.socketMapping.set(conn.localPort, socket);
      }
      conn.write(head);
      conn.pipe(socket);
      socket.pipe(conn);
    });

    // Bug 2 fix: actually call _onSocketError instead of just binding it
    conn.on('error', function (err) {
      if (conn.localPort) {
        self.socketMapping.delete(conn.localPort);
      }
      self._onSocketError.call(self, 'PROXY_TO_PROXY_SOCKET', err);
    });

    // Use once so only the first of (end/finish/close) triggers cleanup
    conn.once('end',    cleanupConn);
    conn.once('finish', cleanupConn);
    conn.once('close',  cleanupConn);
    conn.setNoDelay();

    socket.once('end',    function () { if (!conn.readableFlowing && conn.writable) conn.end(); });
    socket.once('finish', function () { if (!conn.readableFlowing && conn.writable) conn.end(); });
    socket.once('close',  function () { if (!conn.readableFlowing && conn.writable) conn.end(); });
    socket.setNoDelay();
  }

  /**
   * Obtains (or creates) an HTTPS interception server for the given hostname.
   * Certificates are generated on first use and stored in `ca._certCache` in
   * memory only — nothing is written to disk.
   *
   * Wildcard grouping: `a.example.com` and `b.example.com` share a single
   * `*.example.com` certificate to minimise crypto overhead.
   *
   * @param {string}   hostname
   * @param {function} callback - `(err, port)`.
   */
  function getHttpsServer(hostname, callback) {
    var wildcardHost = hostname.replace(/[^.]+\./, '*.');
    var cacheKey     = self.sslServers[wildcardHost] ? wildcardHost : hostname;
    var hosts        = [hostname, wildcardHost];

    /**
     * Starts (or reuses via SNI) an HTTPS server with the given PEM strings.
     *
     * @param {string}   keyPEM
     * @param {string}   certPEM
     * @param {function} cb - `(err, port)`.
     */
    function startServer(keyPEM, certPEM, cb) {
      var httpsOptions = { key: keyPEM, cert: certPEM };
      if (self.forceSNI && !hostname.match(RE_IS_IP)) {
        debug('creating SNI context for ' + hostname);
        hosts.forEach(function (host) {
          self.httpsServer.addContext(host, httpsOptions);
          self.sslServers[host] = { port: self.httpsPort };
        });
        return cb(null, self.httpsPort);
      } else {
        debug('starting server for ' + hostname);
        httpsOptions.hosts = hosts;
        try {
          self._createHttpsServer(httpsOptions, function (port, httpsServer, wssServer) {
            var sslServer = { server: httpsServer, wsServer: wssServer, port: port };
            hosts.forEach(function (host) {
              self.sslServers[host] = sslServer; // Bug 5 fix: use loop var `host`
            });
            return cb(null, port);
          });
        } catch (err) {
          return cb(err);
        }
      }
    }

    // Check in-memory cert cache first
    if (self.ca._certCache.has(cacheKey)) {
      var cached = self.ca._certCache.get(cacheKey);
      return startServer(cached.key, cached.cert, callback);
    }

    // Generate a new cert entirely in memory — never written to disk
    self.ca.generateServerCertificateKeys(hosts, function (certPEM, keyPEM, err) {
      if (err) return callback(err);
      self.ca._certCache.set(cacheKey, { key: keyPEM, cert: certPEM });
      startServer(keyPEM, certPEM, callback);
    });
  }
};

// ---------------------------------------------------------------------------
// HTTP request handler
// ---------------------------------------------------------------------------

/**
 * Handles proxied HTTP and intercepted HTTPS requests.
 * Runs auth check first, then builds the request context and pipelines.
 *
 * @param {boolean}              isSSL
 * @param {http.IncomingMessage} clientToProxyRequest
 * @param {http.ServerResponse}  proxyToClientResponse
 * @private
 */
Proxy.prototype._onHttpServerRequest = function (isSSL, clientToProxyRequest, proxyToClientResponse) {
  var self = this;

  // ── Auth check ────────────────────────────────────────────────────────────
  self._checkAuth(clientToProxyRequest, function reject407() {
    debug('Request denied from %s', clientToProxyRequest.socket && clientToProxyRequest.socket.remoteAddress);
    proxyToClientResponse.writeHead(407, {
      'Proxy-Authenticate': 'Basic realm="proxy"',
      'Content-Type': 'text/plain; charset=utf-8',
    });
    proxyToClientResponse.end('Proxy Authentication Required');
  }, function afterAuth() {
    // ── Socket mapping ───────────────────────────────────────────────────────
    const remotePort = clientToProxyRequest.socket.remotePort;
    if (remotePort && self.socketMapping.has(remotePort)) {
      clientToProxyRequest.originalSocket = self.socketMapping.get(remotePort);
    }
    // Bug 6 fix: guard delete with truthiness check
    if (remotePort) self.socketMapping.delete(remotePort);

    // ── Build request context ────────────────────────────────────────────────
    var ctx = {
      isSSL: isSSL,
      clientToProxyRequest: clientToProxyRequest,
      proxyToClientResponse: proxyToClientResponse,
      onRequestHandlers:     [],
      onErrorHandlers:       [],
      onRequestDataHandlers: [],
      onRequestEndHandlers:  [],
      onResponseHandlers:    [],
      onResponseDataHandlers:[],
      onResponseEndHandlers: [],
      requestFilters:        [],
      responseFilters:       [],
      responseContentPotentiallyModified: false,
      onRequest: function (fn) { ctx.onRequestHandlers.push(fn);  return ctx; },
      onError:   function (fn) { ctx.onErrorHandlers.push(fn);    return ctx; },
      onRequestData: function (fn) { ctx.onRequestDataHandlers.push(fn); return ctx; },
      onRequestEnd:  function (fn) { ctx.onRequestEndHandlers.push(fn);  return ctx; },
      addRequestFilter: function (filter) { ctx.requestFilters.push(filter); return ctx; },
      onResponse:    function (fn) { ctx.onResponseHandlers.push(fn);    return ctx; },
      onResponseData: function (fn) {
        ctx.onResponseDataHandlers.push(fn);
        ctx.responseContentPotentiallyModified = true;
        return ctx;
      },
      onResponseEnd:  function (fn) { ctx.onResponseEndHandlers.push(fn);  return ctx; },
      addResponseFilter: function (filter) {
        ctx.responseFilters.push(filter);
        ctx.responseContentPotentiallyModified = true;
        return ctx;
      },
      use: function (mod) {
        if (mod.onError)          { ctx.onError(mod.onError); }
        if (mod.onRequest)        { ctx.onRequest(mod.onRequest); }
        if (mod.onRequestHeaders) { ctx.onRequestHeaders(mod.onRequestHeaders); }
        if (mod.onRequestData)    { ctx.onRequestData(mod.onRequestData); }
        if (mod.onResponse)       { ctx.onResponse(mod.onResponse); }
        if (mod.onResponseData)   { ctx.onResponseData(mod.onResponseData); }
        return ctx;
      },
    };

    ctx.clientToProxyRequest.on('error', self._onError.bind(self, 'CLIENT_TO_PROXY_REQUEST_ERROR', ctx));
    ctx.proxyToClientResponse.on('error', self._onError.bind(self, 'PROXY_TO_CLIENT_RESPONSE_ERROR', ctx));
    ctx.clientToProxyRequest.pause();

    var hostPort = Proxy.parseHostAndPort(ctx.clientToProxyRequest, ctx.isSSL ? 443 : 80);
    if (hostPort === null) {
      ctx.clientToProxyRequest.resume();
      ctx.proxyToClientResponse.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' });
      ctx.proxyToClientResponse.end('Bad request: Host missing...', 'UTF-8');
      return;
    }

    // Build upstream request headers, stripping proxy-specific headers
    var headers = {};
    for (var h in ctx.clientToProxyRequest.headers) {
      if (!RE_PROXY_HEADER.test(h)) {
        headers[h] = ctx.clientToProxyRequest.headers[h];
      }
    }
    if (self.options.forceChunkedRequest) {
      delete headers['content-length'];
    }

    ctx.proxyToServerRequestOptions = {
      method:  ctx.clientToProxyRequest.method,
      path:    ctx.clientToProxyRequest.url,
      host:    hostPort.hostUnescaped,
      port:    hostPort.port,
      headers: headers,
      agent:   ctx.isSSL ? self.httpsAgent : self.httpAgent,
    };

    return self._onRequest(ctx, function (err) {
      if (err) { return self._onError('ON_REQUEST_ERROR', ctx, err); }
      return self._onRequestHeaders(ctx, function (err) {
        if (err) { return self._onError('ON_REQUESTHEADERS_ERROR', ctx, err); }
        return makeProxyToServerRequest();
      });
    });

    // ── Upstream request pipeline ────────────────────────────────────────────

    function makeProxyToServerRequest() {
      var proto = ctx.isSSL ? https : http;
      ctx.proxyToServerRequest = proto.request(ctx.proxyToServerRequestOptions, proxyToServerRequestComplete);
      ctx.proxyToServerRequest.on('error', self._onError.bind(self, 'PROXY_TO_SERVER_REQUEST_ERROR', ctx));
      ctx.requestFilters.push(new ProxyFinalRequestFilter(self, ctx));
      var prevRequestPipeElem = ctx.clientToProxyRequest;
      ctx.requestFilters.forEach(function (filter) {
        filter.on('error', self._onError.bind(self, 'REQUEST_FILTER_ERROR', ctx));
        prevRequestPipeElem = prevRequestPipeElem.pipe(filter);
      });
      ctx.clientToProxyRequest.resume();
    }

    // ── Upstream response pipeline ───────────────────────────────────────────

    function proxyToServerRequestComplete(serverToProxyResponse) {
      serverToProxyResponse.on('error', self._onError.bind(self, 'SERVER_TO_PROXY_RESPONSE_ERROR', ctx));
      serverToProxyResponse.pause();
      ctx.serverToProxyResponse = serverToProxyResponse;
      return self._onResponse(ctx, function (err) {
        if (err) { return self._onError('ON_RESPONSE_ERROR', ctx, err); }
        if (self.responseContentPotentiallyModified || ctx.responseContentPotentiallyModified) {
          ctx.serverToProxyResponse.headers['transfer-encoding'] = 'chunked';
          delete ctx.serverToProxyResponse.headers['content-length'];
        }
        if (self.keepAlive) {
          if (ctx.clientToProxyRequest.headers['proxy-connection']) {
            ctx.serverToProxyResponse.headers['proxy-connection'] = 'keep-alive';
            ctx.serverToProxyResponse.headers['connection']       = 'keep-alive';
          }
        } else {
          ctx.serverToProxyResponse.headers['connection'] = 'close';
        }
        return self._onResponseHeaders(ctx, function (err) {
          if (err) { return self._onError('ON_RESPONSEHEADERS_ERROR', ctx, err); }
          ctx.proxyToClientResponse.writeHead(
            ctx.serverToProxyResponse.statusCode,
            ctx.serverToProxyResponse.statusMessage,
            Proxy.filterAndCanonizeHeaders(ctx.serverToProxyResponse.headers)
          );
          ctx.responseFilters.push(new ProxyFinalResponseFilter(self, ctx));
          var prevResponsePipeElem = ctx.serverToProxyResponse;
          ctx.responseFilters.forEach(function (filter) {
            filter.on('error', self._onError.bind(self, 'RESPONSE_FILTER_ERROR', ctx));
            prevResponsePipeElem = prevResponsePipeElem.pipe(filter);
          });
          return ctx.serverToProxyResponse.resume();
        });
      });
    }
  }); // end afterAuth
};

// ---------------------------------------------------------------------------
// Filter constructors
// ---------------------------------------------------------------------------

/**
 * Terminal request filter that fans chunks through `onRequestData` handlers
 * and then writes them to the upstream request.
 *
 * @param {Proxy}  proxy
 * @param {object} ctx
 * @constructor
 * @private
 */
var ProxyFinalRequestFilter = function (proxy, ctx) {
  events.EventEmitter.call(this);
  this.writable = true;

  this.write = function (chunk) {
    proxy._onRequestData(ctx, chunk, function (err, chunk) {
      if (err) { return proxy._onError('ON_REQUEST_DATA_ERROR', ctx, err); }
      if (chunk) { return ctx.proxyToServerRequest.write(chunk); }
    });
    return true;
  };

  this.end = function (chunk) {
    if (chunk) {
      return proxy._onRequestData(ctx, chunk, function (err, chunk) {
        if (err) { return proxy._onError('ON_REQUEST_DATA_ERROR', ctx, err); }
        return proxy._onRequestEnd(ctx, function (err) {
          if (err) { return proxy._onError('ON_REQUEST_END_ERROR', ctx, err); }
          return ctx.proxyToServerRequest.end(chunk);
        });
      });
    } else {
      return proxy._onRequestEnd(ctx, function (err) {
        if (err) { return proxy._onError('ON_REQUEST_END_ERROR', ctx, err); }
        return ctx.proxyToServerRequest.end(chunk || undefined);
      });
    }
  };
};
util.inherits(ProxyFinalRequestFilter, events.EventEmitter);

/**
 * Terminal response filter that fans chunks through `onResponseData` handlers
 * and then writes them to the client response.
 *
 * @param {Proxy}  proxy
 * @param {object} ctx
 * @constructor
 * @private
 */
var ProxyFinalResponseFilter = function (proxy, ctx) {
  events.EventEmitter.call(this);
  this.writable = true;

  this.write = function (chunk) {
    proxy._onResponseData(ctx, chunk, function (err, chunk) {
      if (err) { return proxy._onError('ON_RESPONSE_DATA_ERROR', ctx, err); }
      if (chunk) { return ctx.proxyToClientResponse.write(chunk); }
    });
    return true;
  };

  this.end = function (chunk) {
    if (chunk) {
      return proxy._onResponseData(ctx, chunk, function (err, chunk) {
        if (err) { return proxy._onError('ON_RESPONSE_DATA_ERROR', ctx, err); }
        return proxy._onResponseEnd(ctx, function (err) {
          if (err) { return proxy._onError('ON_RESPONSE_END_ERROR', ctx, err); }
          return ctx.proxyToClientResponse.end(chunk || undefined);
        });
      });
    } else {
      return proxy._onResponseEnd(ctx, function (err) {
        if (err) { return proxy._onError('ON_RESPONSE_END_ERROR', ctx, err); }
        return ctx.proxyToClientResponse.end(chunk || undefined);
      });
    }
  };

  return this;
};
util.inherits(ProxyFinalResponseFilter, events.EventEmitter);

// ---------------------------------------------------------------------------
// Internal lifecycle dispatchers
// ---------------------------------------------------------------------------

/** @private */
Proxy.prototype._onError = function (kind, ctx, err) {
  this.onErrorHandlers.forEach(function (handler) {
    return handler(ctx, err, kind);
  });
  if (ctx) {
    ctx.onErrorHandlers.forEach(function (handler) {
      return handler(ctx, err, kind);
    });
    if (ctx.proxyToClientResponse && ctx.proxyToClientResponse.writable && !ctx.proxyToClientResponse.headersSent) {
      ctx.proxyToClientResponse.writeHead(504, 'Proxy Error');
    }
    if (ctx.proxyToClientResponse && ctx.proxyToClientResponse.writable) {
      ctx.proxyToClientResponse.end('' + kind + ': ' + err, 'utf8');
    }
  }
};

/** @private */
Proxy.prototype._onRequestHeaders = function (ctx, callback) {
  // Perf 5: short-circuit when no handlers registered
  if (!this.onRequestHeadersHandlers.length) return callback();
  async.forEach(
    this.onRequestHeadersHandlers,
    function (fn, callback) { return fn(ctx, callback); },
    callback
  );
};

/** @private */
Proxy.prototype._onRequest = function (ctx, callback) {
  var handlers = this.onRequestHandlers.concat(ctx.onRequestHandlers);
  if (!handlers.length) return callback(); // Perf 5
  async.forEach(
    handlers,
    function (fn, callback) { return fn(ctx, callback); },
    callback
  );
};

/** @private */
Proxy.prototype._onRequestData = function (ctx, chunk, callback) {
  var self     = this;
  var handlers = this.onRequestDataHandlers.concat(ctx.onRequestDataHandlers);
  if (!handlers.length) return callback(null, chunk); // Perf 5
  async.forEach(
    handlers,
    function (fn, cb) {
      return fn(ctx, chunk, function (err, newChunk) {
        if (err) { return cb(err); }
        chunk = newChunk;
        return cb(null, newChunk);
      });
    },
    function (err) {
      if (err) { return self._onError('ON_REQUEST_DATA_ERROR', ctx, err); }
      return callback(null, chunk);
    }
  );
};

/** @private */
Proxy.prototype._onRequestEnd = function (ctx, callback) {
  var self     = this;
  var handlers = this.onRequestEndHandlers.concat(ctx.onRequestEndHandlers);
  if (!handlers.length) return callback(null); // Perf 5
  async.forEach(
    handlers,
    function (fn, callback) { return fn(ctx, callback); },
    function (err) {
      if (err) { return self._onError('ON_REQUEST_END_ERROR', ctx, err); }
      return callback(null);
    }
  );
};

/** @private */
Proxy.prototype._onResponse = function (ctx, callback) {
  var handlers = this.onResponseHandlers.concat(ctx.onResponseHandlers);
  if (!handlers.length) return callback(); // Perf 5
  async.forEach(
    handlers,
    function (fn, callback) { return fn(ctx, callback); },
    callback
  );
};

/** @private */
Proxy.prototype._onResponseHeaders = function (ctx, callback) {
  if (!this.onResponseHeadersHandlers.length) return callback(); // Perf 5
  async.forEach(
    this.onResponseHeadersHandlers,
    function (fn, callback) { return fn(ctx, callback); },
    callback
  );
};

/** @private */
Proxy.prototype._onResponseData = function (ctx, chunk, callback) {
  var self     = this;
  var handlers = this.onResponseDataHandlers.concat(ctx.onResponseDataHandlers);
  if (!handlers.length) return callback(null, chunk); // Perf 5
  async.forEach(
    handlers,
    function (fn, cb) {
      return fn(ctx, chunk, function (err, newChunk) {
        if (err) { return cb(err); }
        chunk = newChunk;
        return cb(null, newChunk);
      });
    },
    function (err) {
      if (err) { return self._onError('ON_RESPONSE_DATA_ERROR', ctx, err); }
      return callback(null, chunk);
    }
  );
};

/** @private */
Proxy.prototype._onResponseEnd = function (ctx, callback) {
  var self     = this;
  var handlers = this.onResponseEndHandlers.concat(ctx.onResponseEndHandlers);
  if (!handlers.length) return callback(null); // Perf 5
  async.forEach(
    handlers,
    function (fn, callback) { return fn(ctx, callback); },
    function (err) {
      if (err) { return self._onError('ON_RESPONSE_END_ERROR', ctx, err); }
      return callback(null);
    }
  );
};

// ---------------------------------------------------------------------------
// WebSocket handlers
// ---------------------------------------------------------------------------

/**
 * Handles a new WebSocket connection from the client and establishes a
 * corresponding proxied WebSocket connection to the upstream server.
 *
 * @param {boolean}   isSSL
 * @param {WebSocket} ws
 * @param {http.IncomingMessage} upgradeReq
 * @private
 */
Proxy.prototype._onWebSocketServerConnect = function (isSSL, ws, upgradeReq) {
  var self = this;
  var ctx = {
    isSSL: isSSL,
    clientToProxyWebSocket: ws,
    onWebSocketConnectionHandlers: [],
    onWebSocketFrameHandlers:      [],
    onWebSocketCloseHandlers:      [],
    onWebSocketErrorHandlers:      [],
    onWebSocketConnection: function (fn) { ctx.onWebSocketConnectionHandlers.push(fn); return ctx; },
    onWebSocketSend: function (fn) {
      ctx.onWebSocketFrameHandlers.push(
        function (ctx, type, fromServer, data, flags, callback) {
          if (!fromServer && type === 'message') return this(ctx, data, flags, callback);
          else callback(null, data, flags);
        }.bind(fn)
      );
      return ctx;
    },
    onWebSocketMessage: function (fn) {
      ctx.onWebSocketFrameHandlers.push(
        function (ctx, type, fromServer, data, flags, callback) {
          if (fromServer && type === 'message') return this(ctx, data, flags, callback);
          else callback(null, data, flags);
        }.bind(fn)
      );
      return ctx;
    },
    onWebSocketFrame: function (fn) { ctx.onWebSocketFrameHandlers.push(fn);  return ctx; },
    onWebSocketClose: function (fn) { ctx.onWebSocketCloseHandlers.push(fn);  return ctx; },
    onWebSocketError: function (fn) { ctx.onWebSocketErrorHandlers.push(fn);  return ctx; },
    use: function (mod) {
      if (mod.onWebSocketConnection) { ctx.onWebSocketConnection(mod.onWebSocketConnection); }
      if (mod.onWebSocketSend) {
        ctx.onWebSocketFrame(
          function (ctx, type, fromServer, data, flags, callback) {
            if (!fromServer && type === 'message') return this(ctx, data, flags, callback);
            else callback(null, data, flags);
          }.bind(mod.onWebSocketSend)
        );
      }
      if (mod.onWebSocketMessage) {
        ctx.onWebSocketFrame(
          function (ctx, type, fromServer, data, flags, callback) {
            if (fromServer && type === 'message') return this(ctx, data, flags, callback);
            else callback(null, data, flags);
          }.bind(mod.onWebSocketMessage)
        );
      }
      if (mod.onWebSocketFrame) { ctx.onWebSocketFrame(mod.onWebSocketFrame); }
      if (mod.onWebSocketClose) { ctx.onWebSocketClose(mod.onWebSocketClose); }
      if (mod.onWebSocketError) { ctx.onWebSocketError(mod.onWebSocketError); }
      return ctx;
    },
  };

  ctx.clientToProxyWebSocket.on('message', self._onWebSocketFrame.bind(self, ctx, 'message', false));
  ctx.clientToProxyWebSocket.on('ping',    self._onWebSocketFrame.bind(self, ctx, 'ping',    false));
  ctx.clientToProxyWebSocket.on('pong',    self._onWebSocketFrame.bind(self, ctx, 'pong',    false));
  ctx.clientToProxyWebSocket.on('error',   self._onWebSocketError.bind(self, ctx));
  ctx.clientToProxyWebSocket._socket.on('error', self._onWebSocketError.bind(self, ctx));
  ctx.clientToProxyWebSocket.on('close',   self._onWebSocketClose.bind(self, ctx, false));
  ctx.clientToProxyWebSocket._socket.pause();

  var wsUrl;
  if (upgradeReq.url === '' || /^\//.test(upgradeReq.url)) {
    var hostPort = Proxy.parseHostAndPort(upgradeReq);
    wsUrl = (ctx.isSSL ? 'wss' : 'ws') + '://' + hostPort.host +
      (hostPort.port ? ':' + hostPort.port : '') + upgradeReq.url;
  } else {
    const upgradeReqUrl = new URL(upgradeReq.url);
    upgradeReqUrl.protocol = ctx.isSSL ? 'wss:' : 'ws:';
    wsUrl = upgradeReqUrl.href;
  }

  // Forward all non-websocket-protocol headers to the upstream WebSocket
  var ptosHeaders = {};
  var ctopHeaders = upgradeReq.headers;
  for (var key in ctopHeaders) {
    if (key.indexOf('sec-websocket') !== 0) {
      ptosHeaders[key] = ctopHeaders[key];
    }
  }

  ctx.proxyToServerWebSocketOptions = {
    url:     wsUrl,
    agent:   ctx.isSSL ? self.httpsAgent : self.httpAgent,
    headers: ptosHeaders,
  };

  return self._onWebSocketConnection(ctx, function (err) {
    if (err) { return self._onWebSocketError(ctx, err); }
    return makeProxyToServerWebSocket();
  });

  function makeProxyToServerWebSocket() {
    ctx.proxyToServerWebSocket = new WebSocket(
      ctx.proxyToServerWebSocketOptions.url,
      ctx.proxyToServerWebSocketOptions
    );
    ctx.proxyToServerWebSocket.on('message', self._onWebSocketFrame.bind(self, ctx, 'message', true));
    ctx.proxyToServerWebSocket.on('ping',    self._onWebSocketFrame.bind(self, ctx, 'ping',    true));
    ctx.proxyToServerWebSocket.on('pong',    self._onWebSocketFrame.bind(self, ctx, 'pong',    true));
    ctx.proxyToServerWebSocket.on('error',   self._onWebSocketError.bind(self, ctx));
    ctx.proxyToServerWebSocket.on('close',   self._onWebSocketClose.bind(self, ctx, true));
    ctx.proxyToServerWebSocket.on('open', function () {
      ctx.proxyToServerWebSocket._socket.on('error', self._onWebSocketError.bind(self, ctx));
      if (ctx.clientToProxyWebSocket.readyState === WebSocket.OPEN) {
        ctx.clientToProxyWebSocket._socket.resume();
      }
    });
  }
};

/** @private */
Proxy.prototype._onWebSocketConnection = function (ctx, callback) {
  var handlers = this.onWebSocketConnectionHandlers.concat(ctx.onWebSocketConnectionHandlers);
  if (!handlers.length) return callback();
  async.forEach(
    handlers,
    function (fn, callback) { return fn(ctx, callback); },
    callback
  );
};

/** @private */
Proxy.prototype._onWebSocketFrame = function (ctx, type, fromServer, data, flags) {
  var self = this;
  async.forEach(
    this.onWebSocketFrameHandlers.concat(ctx.onWebSocketFrameHandlers),
    function (fn, callback) {
      return fn(ctx, type, fromServer, data, flags, function (err, newData, newFlags) {
        if (err) { return callback(err); }
        data  = newData;
        flags = newFlags;
        return callback(null, data, flags);
      });
    },
    function (err) {
      if (err) { return self._onWebSocketError(ctx, err); }
      var destWebSocket = fromServer ? ctx.clientToProxyWebSocket : ctx.proxyToServerWebSocket;
      if (destWebSocket.readyState === WebSocket.OPEN) {
        switch (type) {
          case 'message': destWebSocket.send(data, { binary: flags }); break;
          case 'ping':    destWebSocket.ping(data, flags);             break;
          case 'pong':    destWebSocket.pong(data, flags);             break;
        }
      } else {
        self._onWebSocketError(ctx, new Error(
          'Cannot send ' + type + ' because ' +
          (fromServer ? 'clientToProxy' : 'proxyToServer') +
          ' WebSocket connection state is not OPEN'
        ));
      }
    }
  );
};

/** @private */
Proxy.prototype._onWebSocketClose = function (ctx, closedByServer, code, message) {
  var self = this;
  if (!ctx.closedByServer && !ctx.closedByClient) {
    ctx.closedByServer = closedByServer;
    ctx.closedByClient = !closedByServer;
    async.forEach(
      this.onWebSocketCloseHandlers.concat(ctx.onWebSocketCloseHandlers),
      function (fn, callback) { return fn(ctx, code, message, callback); },
      function (err) {
        if (err) { return self._onWebSocketError(ctx, err); }
        if (ctx.clientToProxyWebSocket.readyState !== ctx.proxyToServerWebSocket.readyState) {
          try {
            if (ctx.clientToProxyWebSocket.readyState === WebSocket.CLOSED &&
                ctx.proxyToServerWebSocket.readyState === WebSocket.OPEN) {
              code === 1005
                ? ctx.proxyToServerWebSocket.close()
                : ctx.proxyToServerWebSocket.close(code, message);
            } else if (ctx.proxyToServerWebSocket.readyState === WebSocket.CLOSED &&
                       ctx.clientToProxyWebSocket.readyState === WebSocket.OPEN) {
              // Bug 4 fix: close clientToProxy, not proxyToServer again
              code === 1005
                ? ctx.clientToProxyWebSocket.close()
                : ctx.clientToProxyWebSocket.close(code, message);
            }
          } catch (err) {
            return self._onWebSocketError(ctx, err);
          }
        }
      }
    );
  }
};

/** @private */
Proxy.prototype._onWebSocketError = function (ctx, err) {
  this.onWebSocketErrorHandlers.forEach(function (handler) {
    return handler(ctx, err);
  });
  if (ctx) {
    ctx.onWebSocketErrorHandlers.forEach(function (handler) {
      return handler(ctx, err);
    });
  }
  if (ctx.proxyToServerWebSocket &&
      ctx.clientToProxyWebSocket.readyState !== ctx.proxyToServerWebSocket.readyState) {
    try {
      if (ctx.clientToProxyWebSocket.readyState === WebSocket.CLOSED &&
          ctx.proxyToServerWebSocket.readyState === WebSocket.OPEN) {
        ctx.proxyToServerWebSocket.close();
      } else if (ctx.proxyToServerWebSocket.readyState === WebSocket.CLOSED &&
                 ctx.clientToProxyWebSocket.readyState === WebSocket.OPEN) {
        ctx.clientToProxyWebSocket.close();
      }
    } catch (err) {
      // ignore — already in error handler
    }
  }
};

// ---------------------------------------------------------------------------
// Static helpers
// ---------------------------------------------------------------------------

/**
 * Parses the target host and port from an HTTP request.  For absolute-URI
 * requests (plain HTTP proxying), the host is taken from the URL.  For
 * relative-URI requests (intercepted HTTPS), it is taken from the `Host`
 * header.
 *
 * As a side-effect, rewrites `req.url` to a path-only form when the URL
 * contained an absolute origin.
 *
 * @param {http.IncomingMessage} req
 * @param {number}               [defaultPort]
 * @returns {{ host: string, hostUnescaped: string, port: number }|null}
 *   Returns `null` when no host can be determined.
 */
Proxy.parseHostAndPort = function (req, defaultPort) {
  var m = req.url.match(RE_HTTP_URL);
  if (m) {
    req.url = m[2] || '/';
    return Proxy.parseHost(m[1], defaultPort);
  } else if (req.headers.host) {
    return Proxy.parseHost(req.headers.host, defaultPort);
  } else {
    return null;
  }
};

/**
 * Parses a `host[:port]` string into its components.
 * Handles IPv6 addresses enclosed in square brackets.
 *
 * @param {string} hostString  - e.g. `"example.com:443"`, `"[::1]:8080"`.
 * @param {number} defaultPort - Used when no port is present in `hostString`.
 * @returns {{ host: string, hostUnescaped: string, port: number }}
 */
Proxy.parseHost = function (hostString, defaultPort) {
  function unescapeHost(host) {
    return host.replace('[', '').replace(']', '');
  }

  // Handle absolute HTTP URLs that ended up in the host string
  var m = hostString.match(RE_HTTP_PREFIX);
  if (m) {
    var parsedUrl = new URL(hostString); // Bug 10 fix: replace deprecated url.parse
    return {
      host:          parsedUrl.hostname,
      hostUnescaped: unescapeHost(parsedUrl.hostname),
      port:          parsedUrl.port || null,
    };
  }

  var host;
  if (hostString.indexOf(']') !== -1) {
    // IPv6 — bracket notation
    host = hostString.substring(0, hostString.indexOf(']') + 1);
  } else if (hostString.indexOf(':') !== -1) {
    host = hostString.substring(0, hostString.indexOf(':'));
  } else {
    host = hostString;
  }
  var portString = hostString.substring(host.length + 1);
  var port       = portString.length > 0 ? +portString : defaultPort;

  return {
    host:          host,
    hostUnescaped: unescapeHost(host),
    port:          port,
  };
};

/**
 * Filters and canonicalises response headers before forwarding them to the
 * client.
 *
 * - Removes HTTP Public Key Pinning (HPKP) headers — these would pin the
 *   upstream server's certificate, breaking future proxied connections.
 * - Removes headers whose values contain invalid characters per the HTTP spec.
 * - Trims any surrounding whitespace from header names.
 *
 * @param {object} originalHeaders - Raw headers from the upstream response.
 * @returns {object} Filtered, canonicalised header object.
 */
Proxy.filterAndCanonizeHeaders = function (originalHeaders) {
  var headers = {};
  for (var key in originalHeaders) {
    // Perf 2: skip trim allocation when key is already canonical
    var canonizedKey = (key === key.trim()) ? key : key.trim();
    if (RE_HPKP_HEADER.test(canonizedKey)) {
      continue; // Drop HPKP headers
    }
    if (!nodeCommon._checkInvalidHeaderChar(originalHeaders[key])) {
      headers[canonizedKey] = originalHeaders[key];
    }
  }
  return headers;
};
