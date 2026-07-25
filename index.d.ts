// Type definitions for @dev-swarup/http-mitm-proxy
// Project: https://github.com/dev-swarup/node-http-mitm-proxy

import http  = require('http');
import https = require('https');
import net   = require('net');

declare namespace HttpMitmProxy {

  // ── Factory / static ────────────────────────────────────────────────────────

  export interface IProxyStatic {
    (): IProxy;
    /** Gunzip middleware: transparently decompresses gzip/deflate/br responses. */
    gunzip: any;
    /**
     * Wildcard middleware: no-op stub kept for backwards compatibility.
     * Wildcard certificate grouping is now handled internally.
     */
    wildcard: any;
  }

  // ── Options ─────────────────────────────────────────────────────────────────

  export interface IProxyOptions {
    /** Port to listen on (default: 8080). Use 0 for an OS-assigned port. */
    port?: number;
    /** Hostname or local address to bind to (default: 'localhost'). */
    host?: string;
    /**
     * Directory used to store the root CA certificate and private key.
     * Per-host server certificates are kept in memory only and never written
     * to disk.
     * Default: `<cwd>/.http-mitm-proxy`
     */
    sslCaDir?: string;
    /** Enable HTTP persistent connections (keep-alive). Default: false. */
    keepAlive?: boolean;
    /**
     * Socket inactivity timeout in milliseconds.
     * Default: 0 (no timeout).
     */
    timeout?: number;
    /**
     * Custom `http.Agent` for upstream HTTP requests.
     * Useful for chaining proxies.
     * Default: internal agent configured with the `keepAlive` option.
     */
    httpAgent?: http.Agent;
    /**
     * Custom `https.Agent` for upstream HTTPS requests.
     * Useful for chaining proxies.
     * Default: internal agent configured with the `keepAlive` option.
     */
    httpsAgent?: https.Agent;
    /**
     * Force all HTTPS interception through a single SNI-capable HTTPS server
     * rather than spawning one per hostname.
     * Clients that do not support SNI may fail.
     * Default: false.
     */
    forceSNI?: boolean;
    /**
     * Port for the shared SNI HTTPS server.
     * Only used when `forceSNI` is `true`.
     */
    httpsPort?: number;
    /**
     * When `true`, removes the `content-length` header from proxied requests,
     * forcing chunked transfer encoding.
     * Default: false.
     */
    forceChunkedRequest?: boolean;
  }

  // ── Authentication ──────────────────────────────────────────────────────────

  /**
   * Credentials extracted from an inbound proxy request.
   * Supplied to the function registered via `proxy.onAuthenticate()`.
   */
  export interface ICredentials {
    /**
     * Direct TCP socket IP of the connecting client.
     * Always present and unforgeable — use this for security-critical decisions.
     */
    ip: string;
    /**
     * Parsed `X-Forwarded-For` header chain.
     * The leftmost entry is the original client IP as reported by an upstream
     * proxy. Empty array when the header is absent.
     *
     * ⚠ Advisory only — clients can forge this header. Only trust its contents
     * when the proxy sits behind a known, controlled reverse proxy.
     */
    forwardedFor: string[];
    /**
     * Username decoded from a `Proxy-Authorization: Basic` header.
     * `undefined` when the header is absent or cannot be decoded.
     */
    username?: string;
    /**
     * Password decoded from a `Proxy-Authorization: Basic` header.
     * `undefined` when the header is absent or cannot be decoded.
     */
    password?: string;
  }

  // ── Proxy interface ─────────────────────────────────────────────────────────

  export type IProxy = ICallbacks & {
    /**
     * Starts the proxy listening on the given port.
     *
     * @example
     * proxy.listen({ port: 8080 });
     */
    listen(options?: IProxyOptions, callback?: (err?: Error) => void): IProxy;

    /**
     * Stops the proxy and all associated HTTPS interception servers.
     *
     * @example
     * proxy.close();
     */
    close(): IProxy;

    /** Returns the address the HTTP server is bound to, or null. */
    address(): net.AddressInfo | null;

    /**
     * Registers an optional authenticator function.  When set, every inbound
     * CONNECT request and plain HTTP request must pass authentication before
     * the proxy processes it.  If this method is never called the proxy is
     * open (no authentication required).
     *
     * Call `callback()` (no arguments) to **allow** the request.
     * Call `callback(new Error('reason'))` to **deny** it — the proxy will
     * respond with `407 Proxy Authentication Required`.
     *
     * The `Proxy-Authorization` header is automatically stripped from
     * forwarded requests and is never sent to upstream servers.
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
     */
    onAuthenticate(
      fn: (
        req: http.IncomingMessage,
        credentials: ICredentials,
        callback: (err?: Error) => void
      ) => void
    ): IProxy;

    onConnect(
      fcn: (
        req: http.IncomingMessage,
        socket: net.Socket,
        head: any,
        callback: (error?: Error) => void
      ) => void
    ): IProxy;

    onRequestHeaders(
      fcn: (ctx: IContext, callback: (error?: Error) => void) => void
    ): IProxy;

    onResponseHeaders(
      fcn: (ctx: IContext, callback: (error?: Error) => void) => void
    ): IProxy;

    onWebSocketConnection(
      fcn: (ctx: IContext, callback: (error?: Error) => void) => void
    ): IProxy;

    onWebSocketSend(
      fcn: (
        ctx: IContext,
        message: any,
        flags: any,
        callback: (err: Error | undefined, message: any, flags: any) => void
      ) => void
    ): IProxy;

    onWebSocketMessage(
      fcn: (
        ctx: IContext,
        message: any,
        flags: any,
        callback: (err: Error | undefined, message: any, flags: any) => void
      ) => void
    ): IProxy;

    onWebSocketFrame(
      fcn: (
        ctx: IContext,
        type: string,
        fromServer: boolean,
        message: any,
        flags: any,
        callback: (err: Error | undefined, message: any, flags: any) => void
      ) => void
    ): IProxy;

    onWebSocketError(
      fcn: (ctx: IContext, err: Error | undefined) => void
    ): IProxy;

    onWebSocketClose(
      fcn: (
        ctx: IContext,
        code: number,
        message: any,
        callback: (err: Error | undefined, code: number, message: any) => void
      ) => void
    ): IProxy;

    options:     IProxyOptions;
    httpPort:    number;
    timeout:     number;
    keepAlive:   boolean;
    httpAgent:   http.Agent;
    httpsAgent:  https.Agent;
    forceSNI:    boolean;
    httpsPort?:  number;
  };

  // ── Shared callbacks ────────────────────────────────────────────────────────

  /** Lifecycle callback signatures shared between IProxy and IContext. */
  export interface ICallbacks {
    /**
     * Adds a function called whenever an error occurs during proxying.
     *
     * @example
     * proxy.onError(function(ctx, err, errorKind) {
     *   console.error(errorKind, err);
     * });
     */
    onError(
      callback: (context: IContext, err?: Error, errorKind?: string) => void
    ): void;

    /**
     * Adds a function called at the beginning of each proxied request.
     * Use `ctx.proxyToServerRequestOptions` to modify the upstream request.
     *
     * @example
     * proxy.onRequest(function(ctx, callback) {
     *   console.log('REQUEST:', ctx.clientToProxyRequest.url);
     *   return callback();
     * });
     */
    onRequest(
      fcn: (ctx: IContext, callback: (error?: Error) => void) => void
    ): void;

    /** Adds a function called for each chunk of request body data. */
    onRequestData(
      fcn: (
        ctx: IContext,
        chunk: Buffer,
        callback: (error?: Error, chunk?: Buffer) => void
      ) => void
    ): void;

    /** Adds a function called when the request body has been fully received. */
    onRequestEnd(
      fcn: (ctx: IContext, callback: (error?: Error) => void) => void
    ): void;

    /**
     * Adds a function called at the beginning of the upstream server response.
     *
     * @example
     * proxy.onResponse(function(ctx, callback) {
     *   console.log('BEGIN RESPONSE', ctx.serverToProxyResponse.statusCode);
     *   return callback();
     * });
     */
    onResponse(
      fcn: (ctx: IContext, callback: (error?: Error) => void) => void
    ): void;

    /**
     * Adds a function called for each chunk of response body data.
     * Registering this handler switches the response to chunked transfer
     * encoding.
     */
    onResponseData(
      fcn: (
        ctx: IContext,
        chunk: Buffer,
        callback: (error?: Error, chunk?: Buffer) => void
      ) => void
    ): void;

    /** Adds a function called when the response body has been fully forwarded. */
    onResponseEnd(
      fcn: (ctx: IContext, callback: (error?: Error) => void) => void
    ): void;

    /**
     * Installs a middleware module, registering all of its lifecycle hooks.
     *
     * @example
     * proxy.use({
     *   onError:        function(ctx, err) { },
     *   onRequest:      function(ctx, callback) { return callback(); },
     *   onRequestData:  function(ctx, chunk, callback) { return callback(null, chunk); },
     *   onResponse:     function(ctx, callback) { return callback(); },
     *   onResponseData: function(ctx, chunk, callback) { return callback(null, chunk); },
     *   onWebSocketConnection: function(ctx, callback) { return callback(); },
     *   onWebSocketSend:    function(ctx, message, flags, callback) { return callback(null, message, flags); },
     *   onWebSocketMessage: function(ctx, message, flags, callback) { return callback(null, message, flags); },
     *   onWebSocketError:   function(ctx, err) { },
     *   onWebSocketClose:   function(ctx, code, message, callback) { },
     * });
     */
    use(mod: any): void;
  }

  // ── Context ─────────────────────────────────────────────────────────────────

  export type IContext = ICallbacks & {
    /** `true` when this request arrived via an intercepted HTTPS tunnel. */
    isSSL: boolean;

    /** Set to `true` when the WebSocket was closed by the upstream server. */
    closedByServer?: boolean;

    /** The request received from the client. */
    clientToProxyRequest:  http.IncomingMessage;
    /** The response being written back to the client. */
    proxyToClientResponse: http.ServerResponse;
    /** The request being sent to the upstream server. */
    proxyToServerRequest:  http.ClientRequest;
    /** The response received from the upstream server. */
    serverToProxyResponse: http.IncomingMessage;

    /** Client-to-proxy WebSocket (ws library instance). */
    clientToProxyWebSocket: any;
    /** Proxy-to-server WebSocket (ws library instance). */
    proxyToServerWebSocket: any;

    /**
     * Adds a transform stream into the request body pipeline.
     *
     * @example
     * ctx.addRequestFilter(zlib.createGunzip());
     */
    addRequestFilter(stream: any): void;

    /**
     * Adds a transform stream into the response body pipeline.
     *
     * @example
     * ctx.addResponseFilter(zlib.createGzip());
     */
    addResponseFilter(stream: any): void;

    /** Streams added via `addRequestFilter()`. */
    requestFilters: any[];
    /** Streams added via `addResponseFilter()`. */
    responseFilters: any[];

    /**
     * Options used to construct the upstream request.
     * Modify these inside an `onRequest` handler to change upstream behaviour.
     */
    proxyToServerRequestOptions: {
      method:  string;
      path:    string;
      host:    string;
      port:    number | null;
      headers: { [key: string]: string };
      agent:   http.Agent;
    };

    onResponseDataHandlers: Function[];
    onResponseEndHandlers:  Function[];
  };
}

declare const HttpMitmProxy: HttpMitmProxy.IProxyStatic;
export = HttpMitmProxy;
export as namespace HttpMitmProxy;
