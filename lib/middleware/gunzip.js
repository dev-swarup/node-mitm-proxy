'use strict';

var zlib = require('zlib');

/**
 * Gunzip middleware for http-mitm-proxy.
 *
 * Transparently decompresses response bodies compressed with gzip, deflate, or
 * Brotli (`br`) before they reach `onResponseData` handlers, and advertises
 * support for all three encodings to upstream servers.
 *
 * Usage:
 * ```js
 * var Proxy = require('@dev-swarup/http-mitm-proxy');
 * var proxy = Proxy();
 * proxy.use(Proxy.gunzip);
 * ```
 *
 * @module middleware/gunzip
 */
module.exports = {
  /**
   * Strips the `content-encoding` header and inserts the appropriate
   * decompression transform stream into the response pipeline.
   * Supports `gzip`, `deflate`, and `br` (Brotli) encodings.
   *
   * @param {object}   ctx      - Request context.
   * @param {function} callback - Middleware continuation.
   */
  onResponse: function (ctx, callback) {
    var enc = (ctx.serverToProxyResponse.headers['content-encoding'] || '').toLowerCase();
    if (enc === 'gzip') {
      delete ctx.serverToProxyResponse.headers['content-encoding'];
      ctx.addResponseFilter(zlib.createGunzip());
    } else if (enc === 'deflate') {
      delete ctx.serverToProxyResponse.headers['content-encoding'];
      ctx.addResponseFilter(zlib.createInflate());
    } else if (enc === 'br') {
      delete ctx.serverToProxyResponse.headers['content-encoding'];
      ctx.addResponseFilter(zlib.createBrotliDecompress());
    }
    return callback();
  },

  /**
   * Advertises support for gzip, deflate, and Brotli compression to the
   * upstream server so that it may compress its response.
   *
   * @param {object}   ctx      - Request context.
   * @param {function} callback - Middleware continuation.
   */
  onRequest: function (ctx, callback) {
    ctx.proxyToServerRequestOptions.headers['accept-encoding'] = 'gzip, deflate, br';
    return callback();
  },
};
