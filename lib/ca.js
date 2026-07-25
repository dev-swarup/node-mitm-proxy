'use strict';

var FS = require('fs');
var path = require('path');
var Forge = require('node-forge');
var pki = Forge.pki;
const { mkdirp } = require('mkdirp');
var async = require('async');

/**
 * Distinguished-name attributes used for the root CA certificate.
 * @private
 */
var CAattrs = [
  { name: 'commonName',       value: 'NodeMITMProxyCA'    },
  { name: 'countryName',      value: 'Internet'           },
  { shortName: 'ST',          value: 'Internet'           },
  { name: 'localityName',     value: 'Internet'           },
  { name: 'organizationName', value: 'Node MITM Proxy CA' },
  { shortName: 'OU',          value: 'CA'                 },
];

/**
 * X.509 extensions applied to the root CA certificate.
 * @private
 */
var CAextensions = [
  { name: 'basicConstraints', cA: true },
  {
    name: 'keyUsage',
    keyCertSign: true, digitalSignature: true, nonRepudiation: true,
    keyEncipherment: true, dataEncipherment: true,
  },
  {
    name: 'extKeyUsage',
    serverAuth: true, clientAuth: true, codeSigning: true,
    emailProtection: true, timeStamping: true,
  },
  {
    name: 'nsCertType',
    client: true, server: true, email: true, objsign: true,
    sslCA: true, emailCA: true, objCA: true,
  },
  { name: 'subjectKeyIdentifier' },
];

/**
 * Distinguished-name attributes used for generated server certificates.
 * CommonName is prepended per-host at generation time.
 * @private
 */
var ServerAttrs = [
  { name: 'countryName',      value: 'Internet'                        },
  { shortName: 'ST',          value: 'Internet'                        },
  { name: 'localityName',     value: 'Internet'                        },
  { name: 'organizationName', value: 'Node MITM Proxy CA'              },
  { shortName: 'OU',          value: 'Node MITM Proxy Server Certificate' },
];

/**
 * X.509 extensions applied to generated server certificates.
 * A subjectAltName extension with the actual hostnames is appended at
 * generation time.
 * @private
 */
var ServerExtensions = [
  { name: 'basicConstraints', cA: false },
  {
    name: 'keyUsage',
    keyCertSign: false, digitalSignature: true, nonRepudiation: false,
    keyEncipherment: true, dataEncipherment: true,
  },
  {
    name: 'extKeyUsage',
    serverAuth: true, clientAuth: true, codeSigning: false,
    emailProtection: false, timeStamping: false,
  },
  {
    name: 'nsCertType',
    client: true, server: true, email: false, objsign: false,
    sslCA: false, emailCA: false, objCA: false,
  },
  { name: 'subjectKeyIdentifier' },
];

/** @constructor */
var CA = function () {};

/**
 * Initialises a CA instance, creating the on-disk directory structure and
 * generating (or loading) the root CA certificate and key pair.
 *
 * The root CA certificate and keys are persisted to `caFolder` so that
 * clients can install the CA cert once and trust it across proxy restarts.
 * Per-host server certificates are kept in memory only (see `_certCache`).
 *
 * @param {string}   caFolder  - Absolute path to the CA storage directory.
 * @param {function} callback  - `(err, ca)` called when ready.
 */
CA.create = function (caFolder, callback) {
  var ca = new CA();
  ca.baseCAFolder = caFolder;
  ca.certsFolder  = path.join(ca.baseCAFolder, 'certs');
  ca.keysFolder   = path.join(ca.baseCAFolder, 'keys');

  /**
   * In-memory cache of generated server certificate PEM pairs.
   * Keys are hostname strings (may be wildcard roots such as `*.example.com`).
   * Values are `{ key: string, cert: string }`.
   * @type {Map<string, {key: string, cert: string}>}
   */
  ca._certCache = new Map();

  mkdirp(ca.baseCAFolder)
    .then(() =>
      mkdirp(ca.certsFolder).then(() =>
        mkdirp(ca.keysFolder).then(() => {
          if (FS.existsSync(path.join(ca.certsFolder, 'ca.pem'))) {
            ca.loadCA((err) => (err ? callback(err) : callback(null, ca)));
          } else {
            ca.generateCA((err) => (err ? callback(err) : callback(null, ca)));
          }
        })
      )
    )
    .catch((err) => callback(err));
};

/**
 * Generates a random 16-byte hex serial number for use in X.509 certificates.
 *
 * @returns {string} Hex serial number string.
 */
CA.prototype.randomSerialNumber = function () {
  var sn = '';
  for (var i = 0; i < 4; i++) {
    sn += ('00000000' + Math.floor(Math.random() * Math.pow(256, 4)).toString(16)).slice(-8);
  }
  return sn;
};

/**
 * Generates a new 2048-bit RSA root CA certificate and persists it to disk.
 * The certificate is valid for 2 years from yesterday (to avoid clock-skew
 * issues with clients in different timezones).
 *
 * @param {function} callback - `(err)` called when the CA has been written.
 */
CA.prototype.generateCA = function (callback) {
  var self = this;
  pki.rsa.generateKeyPair({ bits: 2048 }, function (err, keys) {
    if (err) {
      return callback(err);
    }
    var cert = pki.createCertificate();
    cert.publicKey      = keys.publicKey;
    cert.serialNumber   = self.randomSerialNumber();
    cert.validity.notBefore = new Date();
    cert.validity.notBefore.setDate(cert.validity.notBefore.getDate() - 1);
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 2);
    cert.setSubject(CAattrs);
    cert.setIssuer(CAattrs);
    cert.setExtensions(CAextensions);
    cert.sign(keys.privateKey, Forge.md.sha256.create());
    self.CAcert = cert;
    self.CAkeys = keys;
    async.parallel(
      [
        FS.writeFile.bind(null, path.join(self.certsFolder, 'ca.pem'),           pki.certificateToPem(cert)),
        FS.writeFile.bind(null, path.join(self.keysFolder,  'ca.private.key'),   pki.privateKeyToPem(keys.privateKey)),
        FS.writeFile.bind(null, path.join(self.keysFolder,  'ca.public.key'),    pki.publicKeyToPem(keys.publicKey)),
      ],
      callback
    );
  });
};

/**
 * Loads an existing root CA certificate and key pair from disk into memory.
 *
 * @param {function} callback - `(err)` called when loading is complete.
 */
CA.prototype.loadCA = function (callback) {
  var self = this;
  async.auto(
    {
      certPEM: function (callback) {
        FS.readFile(path.join(self.certsFolder, 'ca.pem'), 'utf-8', callback);
      },
      keyPrivatePEM: function (callback) {
        FS.readFile(path.join(self.keysFolder, 'ca.private.key'), 'utf-8', callback);
      },
      keyPublicPEM: function (callback) {
        FS.readFile(path.join(self.keysFolder, 'ca.public.key'), 'utf-8', callback);
      },
    },
    function (err, results) {
      if (err) {
        return callback(err);
      }
      self.CAcert = pki.certificateFromPem(results.certPEM);
      self.CAkeys = {
        privateKey:  pki.privateKeyFromPem(results.keyPrivatePEM),
        publicKey:   pki.publicKeyFromPem(results.keyPublicPEM),
      };
      return callback();
    }
  );
};

/**
 * Generates a signed TLS server certificate for the given hostnames entirely
 * in memory — the result is never written to disk.
 *
 * The RSA key pair is generated asynchronously so that the Node.js event loop
 * is not blocked during the ~200–400 ms crypto operation.
 *
 * @param {string|string[]} hosts - One or more hostnames / wildcard patterns
 *   to include in the certificate's Subject Alternative Name extension.
 *   If a plain string is supplied it is coerced to a single-element array.
 * @param {function} cb - `(certPEM, privateKeyPEM)` called with the generated
 *   PEM strings on success. Errors from `generateKeyPair` are currently
 *   unhandled by node-forge's async path and will reject the promise
 *   internally — wrap the call site in a try/catch if needed.
 */
CA.prototype.generateServerCertificateKeys = function (hosts, cb) {
  var self = this;
  if (typeof hosts === 'string') hosts = [hosts];
  var mainHost = hosts[0];

  // Async RSA keygen — does not block the event loop (unlike the 2-arg form)
  pki.rsa.generateKeyPair({ bits: 2048 }, function (err, keysServer) {
    if (err) {
      // Pass error back as null certs so the caller can propagate it
      return cb(null, null, err);
    }

    var certServer = pki.createCertificate();
    certServer.publicKey    = keysServer.publicKey;
    certServer.serialNumber = self.randomSerialNumber();
    certServer.validity.notBefore = new Date();
    certServer.validity.notBefore.setDate(certServer.validity.notBefore.getDate() - 1);
    certServer.validity.notAfter = new Date();
    certServer.validity.notAfter.setFullYear(certServer.validity.notBefore.getFullYear() + 2);

    var attrsServer = ServerAttrs.slice(0);
    attrsServer.unshift({ name: 'commonName', value: mainHost });
    certServer.setSubject(attrsServer);
    certServer.setIssuer(this.CAcert.issuer.attributes);
    certServer.setExtensions(
      ServerExtensions.concat([
        {
          name: 'subjectAltName',
          altNames: hosts.map(function (host) {
            if (host.match(/^[\d.]+$/)) {
              return { type: 7, ip: host };
            }
            return { type: 2, value: host };
          }),
        },
      ])
    );
    certServer.sign(self.CAkeys.privateKey, Forge.md.sha256.create());

    cb(pki.certificateToPem(certServer), pki.privateKeyToPem(keysServer.privateKey));
  }.bind(this));
};

module.exports = CA;
