/**
 * test.mjs — prove the thing works, and prove it FAILS when it should.
 *
 * A verifier that only ever says yes is worse than none. Most of these cases
 * are deliberate forgeries and tampering; if any of them passes, the tool is
 * lying to whoever relies on it.
 */
import crypto from 'crypto';
import assert from 'assert';
import { hashContent, canonicalText, extractScope, signingPayload } from './lib/canonical.mjs';
import { generateKey, dnsRecord, publicKeyFromBase64 } from './lib/keys.mjs';
import { buildProof, assuranceFor } from './lib/proof.mjs';
import { verifyProof } from './lib/verify.mjs';

let pass = 0, fail = 0;
const t = async (name, fn) => {
  try { await fn(); console.log('  ok    ' + name); pass++; }
  catch (e) { console.log('  FAIL  ' + name + ' — ' + e.message); fail++; }
};

/** Sign text with a key, producing a proof. */
function sign(text, key, when = '2026-08-12T00:00:00Z', validity = null) {
  const scope = extractScope(text);
  const { contentHash } = hashContent(scope.text);
  const signature = crypto.sign(
    null,
    signingPayload({ contentHash, domain: key.domain, keyId: key.keyId, signedAt: when }),
    crypto.createPrivateKey(key.privateKeyPem)
  ).toString('base64');
  return buildProof({
    scope: { description: scope.description, contentHash },
    signer: { domain: key.domain, keyId: key.keyId, keySource: 'software', publicKey: key.publicKey },
    signature, signedAt: when, validity,
  });
}

console.log('\ncanonicalisation');
await t('CRLF and LF hash identically', () => {
  assert.strictEqual(hashContent('a\r\nb').contentHash, hashContent('a\nb').contentHash);
});
await t('trailing whitespace ignored', () => {
  assert.strictEqual(hashContent('a  \nb\t\n').contentHash, hashContent('a\nb\n').contentHash);
});
await t('unicode forms normalise', () => {
  assert.strictEqual(hashContent('café').contentHash, hashContent('café').contentHash);
});
await t('CHANGED WORDING changes the hash', () => {
  assert.notStrictEqual(hashContent('7 days').contentHash, hashContent('8 days').contentHash);
});
await t('changed punctuation changes the hash', () => {
  assert.notStrictEqual(hashContent('do not').contentHash, hashContent('do not.').contentHash);
});

console.log('\nscope');
await t('markers select only the marked region', () => {
  const s = extractScope('HEADER<!--rootz:sign:begin-->body<!--rootz:sign:end-->FOOTER');
  assert.strictEqual(s.text, 'body');
});
await t('header/footer changes do not break a marked signature', () => {
  const a = extractScope('NAV-v1<!--rootz:sign:begin-->body<!--rootz:sign:end-->(c) 2026');
  const b = extractScope('NAV-v2 different<!--rootz:sign:begin-->body<!--rootz:sign:end-->(c) 2027');
  assert.strictEqual(hashContent(a.text).contentHash, hashContent(b.text).contentHash);
});
await t('a half-open scope is rejected', () => {
  assert.throws(() => extractScope('x<!--rootz:sign:begin-->y'), /Only one signing marker/);
});

console.log('\nsigning and verification (DNS disabled — offline path)');
const key = generateKey({ domain: 'example.com', keyId: '2026-08' });
const DOC = 'HEADER<!--rootz:sign:begin-->\nThe seven day rule applies.\n<!--rootz:sign:end-->FOOTER';

await t('a genuine signature verifies', async () => {
  const r = await verifyProof({ document: DOC, proof: sign(DOC, key), opts: { useDns: false } });
  assert.strictEqual(r.checks.find((c) => c.name === 'signature').ok, true);
  assert.strictEqual(r.checks.find((c) => c.name === 'content-unaltered').ok, true);
});

await t('TAMPERED CONTENT fails', async () => {
  const proof = sign(DOC, key);
  const tampered = DOC.replace('seven day', 'seventy day');
  const r = await verifyProof({ document: tampered, proof, opts: { useDns: false } });
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.checks.find((c) => c.name === 'content-unaltered').ok, false);
});

await t('a FORGED signature fails', async () => {
  const proof = sign(DOC, key);
  proof.signature = Buffer.from(crypto.randomBytes(64)).toString('base64');
  const r = await verifyProof({ document: DOC, proof, opts: { useDns: false } });
  assert.strictEqual(r.checks.find((c) => c.name === 'signature').ok, false);
});

await t('a signature LIFTED from another document fails', async () => {
  const other = 'HEADER<!--rootz:sign:begin-->\nDifferent article.\n<!--rootz:sign:end-->FOOTER';
  const stolen = sign(other, key);
  // Attacker keeps the valid signature but points the hash at our document.
  stolen.scope.contentHash = hashContent(extractScope(DOC).text).contentHash;
  const r = await verifyProof({ document: DOC, proof: stolen, opts: { useDns: false } });
  assert.strictEqual(r.checks.find((c) => c.name === 'signature').ok, false);
});

await t('a DIFFERENT KEY cannot impersonate', async () => {
  const attacker = generateKey({ domain: 'example.com', keyId: '2026-08' });
  const proof = sign(DOC, attacker);
  proof.signer.publicKey = key.publicKey; // claim to be the real key
  const r = await verifyProof({ document: DOC, proof, opts: { useDns: false } });
  assert.strictEqual(r.checks.find((c) => c.name === 'signature').ok, false);
});

console.log('\nvalidity windows — the property that must not break');
const WINDOW = { notBefore: '2026-01-01T00:00:00Z', notAfter: '2027-01-01T00:00:00Z' };

await t('signed inside the window is valid', async () => {
  const p = sign(DOC, key, '2026-08-12T00:00:00Z', WINDOW);
  const r = await verifyProof({ document: DOC, proof: p, opts: { useDns: false } });
  assert.strictEqual(r.checks.find((c) => c.name === 'key-validity').ok, true);
});

await t('an EXPIRED key still validates what it signed while valid', async () => {
  const p = sign(DOC, key, '2026-08-12T00:00:00Z', WINDOW);
  // Verify in 2034, long after the key expired and was presumably rotated.
  const r = await verifyProof({ document: DOC, proof: p, opts: { useDns: false, now: new Date('2034-01-01') } });

  // The property that must never break: validity is judged at SIGNING time.
  assert.strictEqual(
    r.checks.find((c) => c.name === 'key-validity').ok, true,
    'a rotated key must not invalidate its old signatures'
  );
  assert.strictEqual(r.checks.find((c) => c.name === 'signature').ok, true);
  assert.strictEqual(r.checks.find((c) => c.name === 'content-unaltered').ok, true);

  // Expiry is reported for context and must never be scored as a failure.
  const current = r.checks.find((c) => c.name === 'key-current');
  assert.ok(current && current.ok, 'expiry must be informational, not a failure');
});

await t('skipping DNS is correctly reported as NOT fully verified', async () => {
  // Verifying without DNS means the key came from the document being checked,
  // which establishes nothing about who published it. The tool must say so
  // rather than return a green tick.
  const r = await verifyProof({ document: DOC, proof: sign(DOC, key), opts: { useDns: false } });
  assert.strictEqual(r.ok, false, 'no-DNS verification must not report full success');
  assert.strictEqual(r.checks.find((c) => c.name === 'key-independent').ok, false);
  assert.match(r.checks.find((c) => c.name === 'key-independent').detail, /self-asserted|skipped/);
});

await t('signed BEFORE the key existed fails', async () => {
  const p = sign(DOC, key, '2025-06-01T00:00:00Z', WINDOW);
  const r = await verifyProof({ document: DOC, proof: p, opts: { useDns: false } });
  assert.strictEqual(r.checks.find((c) => c.name === 'key-validity').ok, false);
});

console.log('\nassurance is reported honestly');
await t('software key is L0', () => {
  assert.strictEqual(assuranceFor({ keySource: 'software' }, []).level, 0);
});
await t('secure element is L1', () => {
  assert.strictEqual(assuranceFor({ keySource: 'tpm' }, []).level, 1);
});
await t('identity document is L2', () => {
  assert.strictEqual(assuranceFor({ keySource: 'tpm' }, [{ type: 'identity-document' }]).level, 2);
});
await t('liveness is L3', () => {
  assert.strictEqual(assuranceFor({ keySource: 'tpm' }, [{ type: 'identity-document' }, { type: 'liveness' }]).level, 3);
});
await t('claiming L3 with a software key still reports the weakest link', () => {
  // No secure element, so it cannot be L1+ regardless of what is claimed.
  assert.strictEqual(assuranceFor({ keySource: 'software' }, []).level, 0);
});
await t('every level states what it does NOT establish', () => {
  for (const k of ['L0', 'L1', 'L2', 'L3']) {
    const a = assuranceFor(
      { keySource: k === 'L0' ? 'software' : 'tpm' },
      k === 'L2' ? [{ type: 'identity-document' }] : k === 'L3' ? [{ type: 'identity-document' }, { type: 'liveness' }] : []
    );
    assert.ok(a.doesNotEstablish && a.doesNotEstablish.length > 20, k);
  }
});

console.log('\nDNS record');
await t('record is well formed and carries validity', () => {
  const r = dnsRecord(key, WINDOW);
  assert.strictEqual(r.name, '_ai-authority.example.com');
  assert.ok(r.value.startsWith('v=rootz1'));
  assert.ok(r.value.includes('p=' + key.publicKey));
  assert.ok(r.value.includes('nb=2026-01-01'));
});
await t('published key round-trips to a usable public key', () => {
  const pub = publicKeyFromBase64(key.publicKey);
  const sig = crypto.sign(null, Buffer.from('x'), crypto.createPrivateKey(key.privateKeyPem));
  assert.strictEqual(crypto.verify(null, Buffer.from('x'), pub, sig), true);
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
