# @dev-swarup/http-mitm-proxy

HTTP Man In The Middle (MITM) Proxy written in Node.js. Supports capturing and modifying HTTP and HTTPS request/response data, WebSocket frames, and optional proxy authentication.

[![NPM version](http://img.shields.io/npm/v/@dev-swarup/http-mitm-proxy.svg)](https://www.npmjs.com/package/@dev-swarup/http-mitm-proxy)
[![Downloads](https://img.shields.io/npm/dm/@dev-swarup/http-mitm-proxy.svg)](https://www.npmjs.com/package/@dev-swarup/http-mitm-proxy)

---

## Changelog

* **2026-07-26: 1.0.0** — In-memory certificate generation (no disk writes per host), optional proxy authentication (`onAuthenticate`), gzip/deflate/Brotli decompression middleware, 9 bug fixes, performance improvements, full JSDoc.
* 2025-01-27: 0.9.6 — Dependency bump
* 2024-03-27: 0.9.5 — Patch for custom status messages, dependency bump
* 2022-04-08: 0.9.4 — Address accessor, typings fix
* 2022-04-04: 0.9.3 — Patch for cert filenames with IPv6 sites
* 2022-03-31: 0.9.2 — Updated dependencies, improved HTTPS stability, IPv6 support

---

## Install

```bash
npm install --save @dev-swarup/http-mitm-proxy
```

### Node.js Compatibility

Node.js **≥ 14** is required. Testing targets current LTS releases.

### TypeScript

Type definitions are bundled — no extra steps required.

---

## Quick Example

Intercept Google search responses and replace all result titles with "Pwned!":

```javascript
var Proxy = require('@dev-swarup/http-mitm-proxy');
var proxy = Proxy();

proxy.onError(function(ctx, err, errorKind) {
  var url = (ctx && ctx.clientToProxyRequest) ? ctx.clientToProxyRequest.url : '';
  console.error(errorKind + ' on ' + url + ':', err);
});

proxy.onRequest(function(ctx, callback) {
  if (ctx.clientToProxyRequest.headers.host === 'www.google.com'
    && ctx.clientToProxyRequest.url.indexOf('/search') === 0) {
    ctx.use(Proxy.gunzip);

    ctx.onResponseData(function(ctx, chunk, callback) {
      chunk = Buffer.from(chunk.toString().replace(/<h3.*?<\/h3>/g, '<h3>Pwned!</h3>'));
      return callback(null, chunk);
    });
  }
  return callback();
});

proxy.listen({ port: 8081 });
```

---

## SSL / HTTPS Interception

The proxy intercepts HTTPS traffic by acting as a MITM. It auto-generates TLS certificates on demand using a local root CA (powered by [node-forge](https://github.com/digitalbazaar/forge)).

**Certificates are generated entirely in memory** — only the root CA cert/key is stored on disk so that it can be trusted once across proxy restarts.

After first run, import the CA certificate into your browser, device, or OS trust store:

```
<sslCaDir>/certs/ca.pem   (default: <cwd>/.http-mitm-proxy/certs/ca.pem)
```

---

## Authentication

Use `proxy.onAuthenticate(fn)` to restrict access by IP address or HTTP Basic credentials. If this method is never called the proxy is **open** (no authentication required).

Unauthenticated requests receive a `407 Proxy Authentication Required` response. Credentials are **never forwarded** to upstream servers.

```javascript
// IP allowlist — use the direct socket IP (unforgeable)
proxy.onAuthenticate(function(req, credentials, callback) {
  var allowed = ['127.0.0.1', '::1'];
  if (allowed.includes(credentials.ip)) return callback();
  return callback(new Error('IP not allowed'));
});

// Username + password (Proxy-Authorization: Basic header)
proxy.onAuthenticate(function(req, credentials, callback) {
  if (credentials.username === 'user' && credentials.password === 'pass') {
    return callback();
  }
  return callback(new Error('Unauthorized'));
});

// Combined: local IP bypasses auth, everyone else needs credentials
proxy.onAuthenticate(function(req, credentials, callback) {
  if (credentials.ip === '127.0.0.1') return callback();
  if (credentials.username === 'user' && credentials.password === 'pass') return callback();
  return callback(new Error('Unauthorized'));
});

// Behind a reverse proxy — check X-Forwarded-For chain
proxy.onAuthenticate(function(req, credentials, callback) {
  // credentials.forwardedFor is the parsed X-Forwarded-For header chain
  // (leftmost = original client). ⚠ Advisory only — can be forged by clients.
  var originIp = credentials.forwardedFor[0] || credentials.ip;
  if (originIp === '10.0.0.5') return callback();
  return callback(new Error('IP not allowed'));
});
```

### `credentials` object

| Property | Type | Description |
|----------|------|-------------|
| `ip` | `string` | Direct TCP socket IP — always present, **unforgeable** |
| `forwardedFor` | `string[]` | Parsed `X-Forwarded-For` chain, `[]` if header absent. Advisory only — can be forged. |
| `username` | `string?` | Decoded from `Proxy-Authorization: Basic` header |
| `password` | `string?` | Decoded from `Proxy-Authorization: Basic` header |

---

## API Reference

### Proxy

| Method | Description |
|--------|-------------|
| [`proxy.listen(options, [callback])`](#proxylisten) | Start the proxy |
| [`proxy.close()`](#proxyclose) | Stop the proxy |
| [`proxy.address()`](#proxyaddress) | Get the bound address |
| [`proxy.onAuthenticate(fn)`](#proxyonauthenticate) | Optional authentication |
| [`proxy.onError(fn)`](#proxyonerror) | Error handler |
| [`proxy.onConnect(fn)`](#proxyonconnect) | CONNECT method handler |
| [`proxy.onRequestHeaders(fn)`](#proxyonrequestheaders) | Request header hook |
| [`proxy.onRequest(fn)`](#proxyonrequest) | Request start hook |
| [`proxy.onRequestData(fn)`](#proxyonrequestdata) | Request body chunk hook |
| [`proxy.onRequestEnd(fn)`](#proxyonrequestend) | Request body end hook |
| [`proxy.onResponseHeaders(fn)`](#proxyonresponseheaders) | Response header hook |
| [`proxy.onResponse(fn)`](#proxyonresponse) | Response start hook |
| [`proxy.onResponseData(fn)`](#proxyonresponsedata) | Response body chunk hook |
| [`proxy.onResponseEnd(fn)`](#proxyonresponseend) | Response body end hook |
| [`proxy.onWebSocketConnection(fn)`](#proxyonwebsocketconnection) | WebSocket connect hook |
| [`proxy.onWebSocketSend(fn)`](#proxyonwebsocketsend) | Client→server frame hook |
| [`proxy.onWebSocketMessage(fn)`](#proxyonwebsocketmessage) | Server→client frame hook |
| [`proxy.onWebSocketFrame(fn)`](#proxyonwebsocketframe) | All WebSocket frames hook |
| [`proxy.onWebSocketError(fn)`](#proxyonwebsocketerror) | WebSocket error hook |
| [`proxy.onWebSocketClose(fn)`](#proxyonwebsocketclose) | WebSocket close hook |
| [`proxy.use(module)`](#proxyuse) | Install a middleware module |

### Context

All `on*` methods above are also available on the `ctx` object inside handlers, scoping the effect to the current request only.

Additional context-only methods:

| Method | Description |
|--------|-------------|
| [`ctx.addRequestFilter(stream)`](#ctxaddrequestfilter) | Insert a transform stream into the request pipeline |
| [`ctx.addResponseFilter(stream)`](#ctxaddresponsefilter) | Insert a transform stream into the response pipeline |

---

### proxy.listen

Starts the proxy listening on the given port.

**Arguments**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `port` | `number` | `8080` | Port to listen on. Use `0` for an OS-assigned port. |
| `host` | `string` | `'localhost'` | Interface to bind to. Pass `'::'` to listen on all IPv4/IPv6 interfaces. |
| `sslCaDir` | `string` | `<cwd>/.http-mitm-proxy` | Directory for the root CA certificate and key. Per-host certs are kept in memory only. |
| `keepAlive` | `boolean` | `false` | Enable HTTP persistent connections. |
| `timeout` | `number` | `0` | Socket inactivity timeout in ms (0 = no timeout). |
| `httpAgent` | `http.Agent` | internal | Custom agent for upstream HTTP requests. |
| `httpsAgent` | `https.Agent` | internal | Custom agent for upstream HTTPS requests. |
| `forceSNI` | `boolean` | `false` | Route all HTTPS through a single SNI-capable server. |
| `httpsPort` | `number` | — | Port for the SNI HTTPS server (`forceSNI` must be `true`). |
| `forceChunkedRequest` | `boolean` | `false` | Strip `content-length` from proxied requests, forcing chunked encoding. |

```javascript
proxy.listen({ port: 8080 }, function(err) {
  if (err) throw err;
  console.log('Proxy listening on', proxy.httpPort);
});
```

---

### proxy.close

Stops the proxy and all associated HTTPS interception servers.

```javascript
proxy.close();
```

---

### proxy.address

Returns the address the HTTP server is bound to, or `null` if not yet listening.

```javascript
var addr = proxy.address();
// { address: '127.0.0.1', family: 'IPv4', port: 8080 }
```

---

### proxy.onAuthenticate

Registers an optional authenticator. See the [Authentication](#authentication) section above for full details and examples.

```javascript
proxy.onAuthenticate(function(req, credentials, callback) {
  // credentials = { ip, forwardedFor, username?, password? }
  if (credentials.ip === '127.0.0.1') return callback();
  return callback(new Error('Unauthorized'));
});
```

---

### proxy.onError

Adds a handler called when an error occurs at any stage.

```javascript
proxy.onError(function(ctx, err, errorKind) {
  // ctx may be null for server-level errors
  var url = (ctx && ctx.clientToProxyRequest) ? ctx.clientToProxyRequest.url : '';
  console.error(errorKind + ' on ' + url + ':', err);
});
```

---

### proxy.onConnect

Adds a handler for the HTTP CONNECT method, called before the proxy tunnels the connection. Returning without an error allows the default tunnelling behaviour.

```javascript
proxy.onConnect(function(req, socket, head, callback) {
  console.log('CONNECT', req.url);
  return callback();
});
```

---

### proxy.onRequestHeaders

Adds a handler called after request headers are parsed but before forwarding upstream. Modify `ctx.proxyToServerRequestOptions.headers` here.

```javascript
proxy.onRequestHeaders(function(ctx, callback) {
  ctx.proxyToServerRequestOptions.headers['x-forwarded-by'] = 'my-proxy';
  return callback();
});
```

---

### proxy.onRequest

Adds a handler called at the beginning of each proxied request. Modify `ctx.proxyToServerRequestOptions` to change the upstream target, method, or headers.

```javascript
proxy.onRequest(function(ctx, callback) {
  console.log('REQUEST:', ctx.clientToProxyRequest.method, ctx.clientToProxyRequest.url);
  return callback();
});
```

---

### proxy.onRequestData

Adds a handler for each chunk of request body data. Pass the (possibly modified) `Buffer` back via `callback(null, chunk)`.

```javascript
proxy.onRequestData(function(ctx, chunk, callback) {
  console.log('REQUEST BODY CHUNK:', chunk.toString());
  return callback(null, chunk);
});
```

---

### proxy.onRequestEnd

Adds a handler called when the entire request body has been received.

```javascript
var chunks = [];

proxy.onRequestData(function(ctx, chunk, callback) {
  chunks.push(chunk);
  return callback(null, chunk);
});

proxy.onRequestEnd(function(ctx, callback) {
  console.log('REQUEST BODY:', Buffer.concat(chunks).toString());
  return callback();
});
```

---

### proxy.onResponseHeaders

Adds a handler called after response headers arrive from the server but before they are sent to the client. Modify `ctx.serverToProxyResponse.headers` here.

```javascript
proxy.onResponseHeaders(function(ctx, callback) {
  ctx.serverToProxyResponse.headers['x-proxied-by'] = 'my-proxy';
  return callback();
});
```

---

### proxy.onResponse

Adds a handler called at the beginning of each upstream response.

```javascript
proxy.onResponse(function(ctx, callback) {
  console.log('RESPONSE:', ctx.serverToProxyResponse.statusCode, ctx.clientToProxyRequest.url);
  return callback();
});
```

---

### proxy.onResponseData

Adds a handler for each chunk of response body data. Registering this handler switches the response to **chunked transfer encoding** (removes `content-length`). Pass the (possibly modified) `Buffer` back via `callback(null, chunk)`.

```javascript
proxy.onResponseData(function(ctx, chunk, callback) {
  // Replace text in the response body
  chunk = Buffer.from(chunk.toString().replace(/foo/g, 'bar'));
  return callback(null, chunk);
});
```

---

### proxy.onResponseEnd

Adds a handler called when the entire response body has been forwarded.

```javascript
proxy.onResponseEnd(function(ctx, callback) {
  console.log('RESPONSE END');
  return callback();
});
```

---

### proxy.onWebSocketConnection

Adds a handler called when a WebSocket connection is established through the proxy.

```javascript
proxy.onWebSocketConnection(function(ctx, callback) {
  console.log('WEBSOCKET CONNECT:', ctx.proxyToServerWebSocketOptions.url);
  return callback();
});
```

---

### proxy.onWebSocketSend

Adds a handler for WebSocket messages sent **from the client to the server**.

```javascript
proxy.onWebSocketSend(function(ctx, message, flags, callback) {
  console.log('WS CLIENT→SERVER:', message);
  return callback(null, message, flags);
});
```

---

### proxy.onWebSocketMessage

Adds a handler for WebSocket messages sent **from the server to the client**.

```javascript
proxy.onWebSocketMessage(function(ctx, message, flags, callback) {
  console.log('WS SERVER→CLIENT:', message);
  return callback(null, message, flags);
});
```

---

### proxy.onWebSocketFrame

Adds a handler for **all** WebSocket frames in both directions (type is `'message'`, `'ping'`, or `'pong'`).

```javascript
proxy.onWebSocketFrame(function(ctx, type, fromServer, data, flags, callback) {
  console.log('WS FRAME', type, 'from', fromServer ? 'server' : 'client');
  return callback(null, data, flags);
});
```

---

### proxy.onWebSocketError

Adds a handler called when a WebSocket error occurs.

```javascript
proxy.onWebSocketError(function(ctx, err) {
  console.error('WS ERROR:', err);
});
```

---

### proxy.onWebSocketClose

Adds a handler called when a WebSocket connection is closed.

```javascript
proxy.onWebSocketClose(function(ctx, code, message, callback) {
  console.log('WS CLOSED by', ctx.closedByServer ? 'server' : 'client', code);
  callback(null, code, message);
});
```

---

### proxy.use

Installs a middleware module — a plain object with any combination of lifecycle hooks.

```javascript
proxy.use({
  onError:               function(ctx, err) { },
  onRequest:             function(ctx, callback) { return callback(); },
  onRequestData:         function(ctx, chunk, callback) { return callback(null, chunk); },
  onResponse:            function(ctx, callback) { return callback(); },
  onResponseData:        function(ctx, chunk, callback) { return callback(null, chunk); },
  onWebSocketConnection: function(ctx, callback) { return callback(); },
  onWebSocketSend:       function(ctx, message, flags, callback) { return callback(null, message, flags); },
  onWebSocketMessage:    function(ctx, message, flags, callback) { return callback(null, message, flags); },
  onWebSocketError:      function(ctx, err) { },
  onWebSocketClose:      function(ctx, code, message, callback) { },
});
```

**Built-in modules**

| Module | Description |
|--------|-------------|
| `Proxy.gunzip` | Transparently decompresses `gzip`, `deflate`, and `br` (Brotli) response bodies before `onResponseData` handlers. Also advertises `accept-encoding: gzip, deflate, br` to upstream servers. |
| `Proxy.wildcard` | No-op stub kept for backwards compatibility. Wildcard certificate grouping is now handled internally. |

```javascript
proxy.use(Proxy.gunzip);
```

---

### ctx.addRequestFilter

Inserts a Node.js transform stream into the request body pipeline.

```javascript
proxy.onRequest(function(ctx, callback) {
  ctx.addRequestFilter(zlib.createGunzip());
  return callback();
});
```

---

### ctx.addResponseFilter

Inserts a Node.js transform stream into the response body pipeline. Using this method automatically switches the response to chunked transfer encoding.

```javascript
proxy.onResponse(function(ctx, callback) {
  ctx.addResponseFilter(zlib.createGzip());
  return callback();
});
```

---

## Context Properties

| Property | Type | Description |
|----------|------|-------------|
| `ctx.isSSL` | `boolean` | `true` when the request arrived via an intercepted HTTPS tunnel |
| `ctx.clientToProxyRequest` | `http.IncomingMessage` | Request received from the client |
| `ctx.proxyToClientResponse` | `http.ServerResponse` | Response being written back to the client |
| `ctx.proxyToServerRequest` | `http.ClientRequest` | Request being sent to the upstream server |
| `ctx.serverToProxyResponse` | `http.IncomingMessage` | Response received from the upstream server |
| `ctx.proxyToServerRequestOptions` | `object` | Upstream request options — mutate in `onRequest` to change target/method/headers |
| `ctx.requestFilters` | `stream[]` | Streams added via `addRequestFilter()` |
| `ctx.responseFilters` | `stream[]` | Streams added via `addResponseFilter()` |

## WebSocket Context Properties

| Property | Type | Description |
|----------|------|-------------|
| `ctx.isSSL` | `boolean` | `true` for WSS connections |
| `ctx.clientToProxyWebSocket` | `WebSocket` | Client-side WebSocket connection |
| `ctx.proxyToServerWebSocket` | `WebSocket` | Server-side WebSocket connection |
| `ctx.closedByServer` | `boolean?` | Set after close — `true` if the server initiated the close |

---

## Debugging

Set the `DEBUG` environment variable to enable verbose logging:

```bash
DEBUG=http-mitm-proxy node your-proxy.js
```

---

## License

```
Copyright (c) 2015 Joe Ferner
Copyright (c) 2026 Swarup Banerjee

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```
