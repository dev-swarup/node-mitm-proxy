'use strict';

/**
 * Wildcard middleware for http-mitm-proxy.
 *
 * Previously this module provided an `onCertificateRequired` hook that grouped
 * subdomains under a shared wildcard certificate to reduce certificate
 * generation overhead.  That logic has been moved into the proxy core where
 * wildcard grouping is now performed automatically as part of the in-memory
 * certificate cache (`ca._certCache`).
 *
 * This module is retained as an empty export so that existing code that calls
 * `proxy.use(Proxy.wildcard)` continues to work without modification.
 *
 * Usage:
 * ```js
 * var Proxy = require('@dev-swarup/http-mitm-proxy');
 * var proxy = Proxy();
 * proxy.use(Proxy.wildcard); // no-op, safe to leave in place
 * ```
 *
 * @module middleware/wildcard
 */
module.exports = {};
