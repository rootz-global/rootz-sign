/**
 * keys.mjs — key generation, storage and DNS publication.
 *
 * Ed25519 throughout: small keys, small signatures, no curve parameters to get
 * wrong, and native support in Node's crypto since v12.
 *
 * The public key goes in DNS, following the pattern DKIM has used for twenty
 * years. That matters more than the cryptography: DNS control IS domain
 * control, the lookup is independent of the site being verified, and every
 * network already knows how to resolve it. Nobody has to trust us to fetch it.
 */
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { promises as dns } from 'dns';

/** Where private keys live by default. Never inside a project directory. */
export const DEFAULT_KEY_DIR = path.join(os.homedir(), '.rootz', 'keys');

/** DNS label the public key is published under. */
export const DNS_LABEL = '_ai-authority';

/**
 * Generate a new signing keypair.
 *
 * @param {object} p
 * @param {string} p.domain Domain the key will speak for.
 * @param {string} [p.keyId] Short identifier; defaults to a dated one.
 * @param {number} [p.validMonths=12] How long the key is authorised for.
 * @returns {object} {keyId, domain, publicKey, privateKeyPem, created, notBefore, notAfter}
 */
export function generateKey({ domain, keyId, validMonths = 12 }) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');

  const raw = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  const id = keyId || `${new Date().toISOString().slice(0, 7)}`;

  const created = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');

  /*
   * The validity window is generated WITH the key and saved alongside it.
   * It was previously computed only for the DNS record and thrown away, so
   * proofs carried validity: null and the verifier could not check whether a
   * key was authorised at signing time — the one property that must survive a
   * key rotation.
   */
  const notAfter = new Date(Date.parse(created) + validMonths * 30 * 86400000)
    .toISOString().replace(/\.\d{3}Z$/, 'Z');

  return {
    keyId: id,
    domain,
    algorithm: 'ed25519',
    publicKey: raw.toString('base64'),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    created,
    notBefore: created,
    notAfter,
  };
}

/**
 * Write a private key to disk with owner-only permissions.
 *
 * Stored outside any project directory on purpose. A private key inside a repo
 * is a private key in a backup, in a deploy artefact, and eventually in a
 * public commit.
 *
 * @param {object} key Key object from generateKey.
 * @param {string} [dir] Target directory.
 * @returns {string} Path written.
 */
export function saveKey(key, dir = DEFAULT_KEY_DIR) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const file = path.join(dir, `${key.domain}.${key.keyId}.pem`);

  if (fs.existsSync(file)) {
    throw new Error(
      `A key already exists at ${file}. Refusing to overwrite it — that would ` +
      'orphan every signature it has already made. Use a different --key-id to rotate.'
    );
  }

  fs.writeFileSync(file, key.privateKeyPem, { mode: 0o600 });

  const meta = { ...key };
  delete meta.privateKeyPem;
  fs.writeFileSync(path.join(dir, `${key.domain}.${key.keyId}.json`), JSON.stringify(meta, null, 2), { mode: 0o600 });

  return file;
}

/**
 * Load a private key from disk.
 *
 * @param {string} domain Domain.
 * @param {string} keyId Key identifier.
 * @param {string} [dir] Key directory.
 * @returns {{privateKey: crypto.KeyObject, meta: object}}
 */
export function loadKey(domain, keyId, dir = DEFAULT_KEY_DIR) {
  const file = path.join(dir, `${domain}.${keyId}.pem`);
  if (!fs.existsSync(file)) {
    throw new Error(`No key at ${file}. Run: rootz-sign keygen --domain ${domain}`);
  }
  const privateKey = crypto.createPrivateKey(fs.readFileSync(file, 'utf8'));
  const metaFile = path.join(dir, `${domain}.${keyId}.json`);
  const meta = fs.existsSync(metaFile) ? JSON.parse(fs.readFileSync(metaFile, 'utf8')) : { domain, keyId };
  return { privateKey, meta };
}

/**
 * The DNS TXT record to publish.
 *
 * @param {object} key Key object or metadata.
 * @param {object} [validity] {notBefore, notAfter} ISO dates.
 * @returns {{name: string, type: string, value: string}}
 */
export function dnsRecord(key, validity = {}) {
  const parts = [
    'v=rootz1',
    `k=${key.keyId}`,
    'a=ed25519',
    `p=${key.publicKey}`,
  ];
  // Validity in the record itself, so a verifier learns the window from DNS
  // rather than from the document it is checking. A document should never be
  // the authority on whether its own signature was valid.
  if (validity.notBefore) parts.push(`nb=${validity.notBefore}`);
  if (validity.notAfter) parts.push(`na=${validity.notAfter}`);

  return {
    name: `${DNS_LABEL}.${key.domain}`,
    type: 'TXT',
    value: parts.join('; '),
  };
}

/**
 * Resolve a published key from DNS.
 *
 * @param {string} domain Domain.
 * @param {string} [keyId] Specific key; omit for any.
 * @returns {Promise<object|null>} Parsed record or null.
 */
export async function resolveKey(domain, keyId) {
  let records;
  try {
    records = await dns.resolveTxt(`${DNS_LABEL}.${domain}`);
  } catch (e) {
    return null;
  }

  for (const chunks of records) {
    const raw = chunks.join('');
    if (!raw.startsWith('v=rootz1')) continue;

    const fields = {};
    for (const part of raw.split(';')) {
      const [k, ...rest] = part.trim().split('=');
      if (k) fields[k] = rest.join('=');
    }
    if (keyId && fields.k !== keyId) continue;

    return {
      keyId: fields.k,
      algorithm: fields.a || 'ed25519',
      publicKey: fields.p,
      notBefore: fields.nb || null,
      notAfter: fields.na || null,
      raw,
    };
  }
  return null;
}

/**
 * Rebuild a Node public key object from a base64 raw Ed25519 key.
 *
 * @param {string} base64 Raw 32-byte key, base64.
 * @returns {crypto.KeyObject}
 */
export function publicKeyFromBase64(base64) {
  // SPKI prefix for Ed25519, then the 32 raw bytes.
  const prefix = Buffer.from('302a300506032b6570032100', 'hex');
  const der = Buffer.concat([prefix, Buffer.from(base64, 'base64')]);
  return crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
}
