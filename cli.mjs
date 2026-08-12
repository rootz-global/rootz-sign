#!/usr/bin/env node
/**
 * rootz-sign — sign what you publish, and let anyone check it without asking you.
 *
 *   rootz-sign keygen --domain example.com
 *   rootz-sign sign article.md --domain example.com --url https://example.com/x
 *   rootz-sign verify article.md --proof article.proof.json
 *   rootz-sign dns --domain example.com
 *
 * Signing is an act a person takes. This is a command someone runs on purpose,
 * not a step in a deploy pipeline — if a build server signs automatically with
 * a key it holds, the signature is a machine's, and the "executed or adopted by
 * a person with intent to sign" element that gives it legal weight under E-SIGN
 * is gone.
 */
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { generateKey, saveKey, loadKey, dnsRecord, DEFAULT_KEY_DIR } from './lib/keys.mjs';
import { hashContent, extractScope, signingPayload } from './lib/canonical.mjs';
import { buildProof } from './lib/proof.mjs';
import { verifyProof } from './lib/verify.mjs';

const argv = process.argv.slice(2);
const cmd = argv[0];
const arg = (n, d = null) => {
  const i = argv.indexOf('--' + n);
  return i >= 0 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : d;
};
const flag = (n) => argv.includes('--' + n);
const positional = argv.slice(1).filter((a) => !a.startsWith('--') && argv[argv.indexOf(a) - 1]?.startsWith('--') !== true);

/** Print usage. */
function usage() {
  console.log(`rootz-sign — prove that what you published is yours and unaltered

  keygen  --domain <d> [--key-id <id>] [--valid-months <n>]
          Create a signing key and print the DNS record to publish.

  sign    <file> --domain <d> [--key-id <id>] [--url <u>] [--title <t>]
                 [--author <name>] [--out <file>]
          Sign a document. Writes <file>.proof.json.

  verify  <file> [--proof <file>] [--no-dns]
          Check a document against its proof. Needs no account and no
          connection to Rootz — only DNS.

  dns     --domain <d> [--key-id <id>]
          Reprint the DNS record for an existing key.

Keys live in ${DEFAULT_KEY_DIR} with owner-only permissions, never in your project.`);
}

/**
 * Mark a scope region in a file if it has none.
 *
 * @param {string} file Path.
 * @returns {string} Contents.
 */
function read(file) {
  if (!file || !fs.existsSync(file)) {
    console.error(`No such file: ${file}`);
    process.exit(1);
  }
  return fs.readFileSync(file, 'utf8');
}

// ── keygen ───────────────────────────────────────────────────────────────────
if (cmd === 'keygen') {
  const domain = arg('domain');
  if (!domain) { console.error('--domain is required'); process.exit(1); }

  const key = generateKey({ domain, keyId: arg('key-id'), validMonths: Number(arg('valid-months', 12)) });
  const { notBefore, notAfter } = key;

  const file = saveKey(key);
  const rec = dnsRecord(key, { notBefore, notAfter });

  console.log(`Key created for ${domain}`);
  console.log(`  key id   : ${key.keyId}`);
  console.log(`  private  : ${file}  (owner-only, never commit this)`);
  console.log(`  valid    : ${notBefore} → ${notAfter}`);
  console.log('');
  console.log('Publish this DNS record, then anyone can verify your signatures');
  console.log('without involving us:');
  console.log('');
  console.log(`  name : ${rec.name}`);
  console.log(`  type : ${rec.type}`);
  console.log(`  value: ${rec.value}`);
  console.log('');
  console.log('The validity window is in the record on purpose. A document should');
  console.log('never be the authority on whether its own signature was valid.');

// ── sign ─────────────────────────────────────────────────────────────────────
} else if (cmd === 'sign') {
  const file = argv[1];
  const domain = arg('domain');
  if (!file || !domain) { console.error('usage: rootz-sign sign <file> --domain <d>'); process.exit(1); }

  const document = read(file);
  const scope = extractScope(document);
  const { contentHash, bytes } = hashContent(scope.text);

  const keyId = arg('key-id') || (() => {
    const dir = DEFAULT_KEY_DIR;
    const found = fs.existsSync(dir)
      ? fs.readdirSync(dir).filter((f) => f.startsWith(domain + '.') && f.endsWith('.pem'))
      : [];
    if (found.length === 1) return found[0].slice(domain.length + 1, -4);
    if (found.length === 0) { console.error(`No key for ${domain}. Run: rootz-sign keygen --domain ${domain}`); process.exit(1); }
    console.error(`Several keys for ${domain}; specify --key-id. Found: ${found.join(', ')}`);
    process.exit(1);
  })();

  const { privateKey, meta } = loadKey(domain, keyId);
  const signedAt = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');

  const signature = crypto.sign(
    null,
    signingPayload({ contentHash, domain, keyId, signedAt }),
    privateKey
  ).toString('base64');

  const proof = buildProof({
    scope: { description: scope.description, contentHash },
    signer: {
      domain,
      keyId,
      name: arg('author') || null,
      keySource: 'software',
      publicKey: meta.publicKey,
    },
    signature,
    signedAt,
    validity: meta.notBefore ? { notBefore: meta.notBefore, notAfter: meta.notAfter } : null,
    document: {
      url: arg('url'),
      title: arg('title'),
      author: arg('author'),
      publishedAt: arg('published'),
    },
  });

  const out = arg('out') || file.replace(/\.[^.]+$/, '') + '.proof.json';
  fs.writeFileSync(out, JSON.stringify(proof, null, 2));

  console.log(`Signed ${file}`);
  console.log(`  scope    : ${scope.description}`);
  console.log(`  bytes    : ${bytes}`);
  console.log(`  hash     : ${contentHash}`);
  console.log(`  assurance: L${proof.assurance.level} (${proof.assurance.label})`);
  console.log(`  proof    : ${out}`);
  console.log('');
  console.log(`  establishes    : ${proof.assurance.establishes}`);
  console.log(`  does NOT       : ${proof.assurance.doesNotEstablish}`);

// ── verify ───────────────────────────────────────────────────────────────────
} else if (cmd === 'verify') {
  const file = argv[1];
  if (!file) { console.error('usage: rootz-sign verify <file> [--proof <file>]'); process.exit(1); }

  const document = read(file);
  const proofFile = arg('proof') || file.replace(/\.[^.]+$/, '') + '.proof.json';
  const proof = JSON.parse(read(proofFile));

  const result = await verifyProof({ document, proof, opts: { useDns: !flag('no-dns') } });

  for (const c of result.checks) {
    console.log(`  ${c.ok ? 'ok  ' : 'FAIL'}  ${c.name.padEnd(18)} ${c.detail}`);
  }
  console.log('');
  console.log(result.summary);
  if (result.ok) {
    console.log('');
    console.log(`  establishes : ${result.establishes}`);
    console.log(`  does NOT    : ${result.doesNotEstablish}`);
  }
  process.exit(result.ok ? 0 : 1);

// ── dns ──────────────────────────────────────────────────────────────────────
} else if (cmd === 'dns') {
  const domain = arg('domain');
  const keyId = arg('key-id');
  if (!domain || !keyId) { console.error('usage: rootz-sign dns --domain <d> --key-id <id>'); process.exit(1); }
  const { meta } = loadKey(domain, keyId);
  const rec = dnsRecord(meta, { notBefore: meta.notBefore, notAfter: meta.notAfter });
  console.log(`${rec.name}  ${rec.type}  "${rec.value}"`);

} else {
  usage();
  process.exit(cmd ? 1 : 0);
}
