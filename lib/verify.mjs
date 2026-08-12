/**
 * verify.mjs — check a proof.
 *
 * The design constraint that matters: THIS MUST WORK WITHOUT ROOTZ. A verifier
 * that phones home is a subscription, not a proof. Everything here needs only
 * the document, the proof, and public DNS. No API, no account, no chain, no
 * network call to us.
 *
 * It also reports rather than adjudicates. It returns what it established and
 * what it could not, and refuses to collapse that into a green tick — because
 * "verified" is exactly the word that makes people stop reading.
 */
import crypto from 'crypto';
import { hashContent, extractScope, signingPayload } from './canonical.mjs';
import { resolveKey, publicKeyFromBase64 } from './keys.mjs';

/**
 * Verify a proof against a document.
 *
 * @param {object} p
 * @param {string} p.document The published text.
 * @param {object} p.proof The proof envelope.
 * @param {object} [p.opts]
 * @param {boolean} [p.opts.useDns=true] Resolve the key from DNS (recommended).
 * @param {Date} [p.opts.now] Override current time, for testing.
 * @returns {Promise<object>} Verification report.
 */
export async function verifyProof({ document, proof, opts = {} }) {
  const now = opts.now || new Date();
  const checks = [];
  const add = (name, ok, detail) => checks.push({ name, ok, detail });

  // ── 1. Is this even the right shape? ──────────────────────────────────────
  if (!proof || proof['@type'] !== 'RootzProof') {
    return report(false, [{ name: 'envelope', ok: false, detail: 'Not a RootzProof envelope.' }], proof);
  }
  add('envelope', true, `RootzProof v${proof.version}`);

  // ── 2. Does the content still hash to what was signed? ────────────────────
  let scope;
  try {
    scope = extractScope(document);
  } catch (e) {
    return report(false, [...checks, { name: 'scope', ok: false, detail: e.message }], proof);
  }
  const { contentHash } = hashContent(scope.text);
  const hashMatches = contentHash === proof.scope.contentHash;
  add(
    'content-unaltered',
    hashMatches,
    hashMatches
      ? 'The text hashes to exactly what was signed.'
      : `The text has changed since signing. Signed ${proof.scope.contentHash}, found ${contentHash}.`
  );

  // ── 3. Get the key INDEPENDENTLY of the document ──────────────────────────
  // Using the key embedded in the proof to check the proof proves nothing — a
  // forger would simply embed their own. DNS is the independent source.
  let key = null;
  let keySource = 'embedded';
  if (opts.useDns !== false) {
    key = await resolveKey(proof.signer.domain, proof.signer.keyId);
    if (key) keySource = 'dns';
  }

  if (!key) {
    add(
      'key-independent',
      false,
      opts.useDns === false
        ? 'DNS lookup skipped, so the key came from the document itself and establishes nothing about who published it.'
        : `No key published at _ai-authority.${proof.signer.domain}. Falling back to the key inside the document, which is self-asserted.`
    );
    key = { publicKey: proof.signer.publicKey, keyId: proof.signer.keyId, notBefore: null, notAfter: null };
  } else {
    const matches = key.publicKey === proof.signer.publicKey;
    add(
      'key-independent',
      matches,
      matches
        ? `Key ${key.keyId} confirmed in DNS at _ai-authority.${proof.signer.domain}.`
        : 'The key in DNS does not match the key in the document. Treat this document as unverified.'
    );
    if (!matches) return report(false, checks, proof);
  }

  // ── 4. Does the signature actually verify? ────────────────────────────────
  let sigOk = false;
  try {
    const payload = signingPayload({
      contentHash: proof.scope.contentHash,
      domain: proof.signer.domain,
      keyId: proof.signer.keyId,
      signedAt: proof.signedAt,
    });
    sigOk = crypto.verify(
      null,
      payload,
      publicKeyFromBase64(key.publicKey),
      Buffer.from(proof.signature, 'base64')
    );
  } catch (e) {
    sigOk = false;
  }
  add('signature', sigOk, sigOk ? 'Signature is valid for this key.' : 'Signature does not verify.');

  // ── 5. Was the key valid AT THE TIME OF SIGNING? ──────────────────────────
  // Never "is it valid now". A key revoked in 2028 signed perfectly good
  // articles in 2026, and those must keep verifying.
  const signedAt = new Date(proof.signedAt);
  const nb = key.notBefore || proof.validity?.notBefore;
  const na = key.notAfter || proof.validity?.notAfter;

  if (!nb && !na) {
    add('key-validity', true, 'No validity window published, so this cannot be checked. Signature stands on the key alone.');
  } else {
    const afterStart = !nb || signedAt >= new Date(nb);
    const beforeEnd = !na || signedAt <= new Date(na);
    const within = afterStart && beforeEnd;
    add(
      'key-validity',
      within,
      within
        ? `Key was authorised when this was signed (${nb || 'no start'} → ${na || 'no end'}). Still valid at time of signing even if the key has since been retired.`
        : `Signed ${proof.signedAt}, outside the key's authorised window (${nb || 'no start'} → ${na || 'no end'}).`
    );
  }

  // Reported for context, never as a failure — an expired key does not
  // retroactively unsign anything.
  if (na && now > new Date(na)) {
    add('key-current', true, `This key expired ${na}. That does not affect signatures it made while valid.`);
  }

  const ok = checks.every((c) => c.ok);
  return report(ok, checks, proof);
}

/**
 * Assemble the report.
 *
 * @param {boolean} ok Whether every check passed.
 * @param {object[]} checks Individual checks.
 * @param {object} proof The envelope.
 * @returns {object}
 */
function report(ok, checks, proof) {
  const a = proof?.assurance;
  return {
    ok,
    checks,
    // Stated every time. The commonest misreading of a verified signature is
    // that it vouches for the content.
    establishes: ok && a ? a.establishes : null,
    doesNotEstablish: ok && a ? a.doesNotEstablish : null,
    assuranceLevel: a ? a.level : null,
    summary: !ok
      ? 'Could not verify. See the failed checks.'
      : `Verified at assurance level L${a?.level ?? 0} (${a?.label ?? 'unknown'}). This establishes origin and integrity only — not that the content is accurate or current.`,
  };
}
