/**
 * proof.mjs — the envelope.
 *
 * One schema for every assurance level. The whole design rests on that: L0 is
 * not a lesser format, it is the same format with one link in the chain instead
 * of four. When Ralph's anchor identity exists, his existing posts re-render at
 * a higher level without their URLs or their content hashes changing.
 *
 * ASSURANCE IS A MEASUREMENT, NOT A GATE
 * The envelope reports what was actually established and leaves the weighing to
 * whoever is reading. It never says "trusted". A consumer that only accepts L3
 * is free to do that; a consumer that treats a domain key as sufficient is also
 * free to do that. Our job is to state what happened accurately.
 *
 * WHY VALIDITY WINDOWS MATTER MORE THAN THEY LOOK
 * Keys rotate. A posting key issued in 2026 may be revoked in 2028. An article
 * signed in 2026 must still verify in 2034 as "validly signed at the time" —
 * otherwise a routine rotation silently invalidates the author's entire back
 * catalogue, which for someone whose value is a durable record is the one
 * unrecoverable mistake. So the envelope records WHEN the key was authorised,
 * and verification asks "was this key valid when this was signed", never "is
 * this key valid now".
 */

/** Envelope format version. Bump only on breaking changes. */
export const PROOF_VERSION = '1.0';

/**
 * Assurance levels, in the order they strengthen.
 *
 * Each level states plainly what it does and does not establish, because the
 * commonest failure of a trust marker is a reader assuming it proves more than
 * it does.
 */
export const ASSURANCE = {
  L0: {
    level: 0,
    label: 'domain-key',
    establishes: 'The text is unaltered since signing, and was signed by whoever controls this domain.',
    doesNotEstablish: 'Who that person is. Anyone able to change the domain’s DNS could publish a key.',
  },
  L1: {
    level: 1,
    label: 'device-key',
    establishes: 'As L0, and the signing key is held in a hardware secure element that cannot export it.',
    doesNotEstablish: 'Who was operating the device.',
  },
  L2: {
    level: 2,
    label: 'verified-identity',
    establishes: 'As L1, and the key is bound to a person whose government-issued identity document was verified against its issuing authority.',
    doesNotEstablish: 'That the person was present at this particular signing.',
  },
  L3: {
    level: 3,
    label: 'present-identity',
    establishes: 'As L2, and a liveness check placed that person at the signing.',
    doesNotEstablish: 'Anything about whether the content is correct. Provenance is not accuracy.',
  },
};

/**
 * Build a proof envelope.
 *
 * @param {object} p
 * @param {object} p.scope    What exactly was signed: {description, contentHash, algorithm}.
 * @param {object} p.signer   {domain, keyId, keySource, publicKey, name?}.
 * @param {string} p.signature Base64url signature over the canonical bytes.
 * @param {string} p.signedAt ISO 8601, seconds precision.
 * @param {object} [p.validity] {notBefore, notAfter} for the signing key.
 * @param {object[]} [p.chain] Additional assurance links, strongest last.
 * @param {object} [p.document] {url, title, author, publishedAt}.
 * @returns {object} The envelope.
 */
export function buildProof({ scope, signer, signature, signedAt, validity, chain = [], document = {} }) {
  const assurance = assuranceFor(signer, chain);

  return {
    '@type': 'RootzProof',
    version: PROOF_VERSION,

    // WHAT was signed. Ambiguity here makes the whole thing worthless: a
    // signature over unspecified bytes proves nothing anyone can check.
    scope: {
      description: scope.description,
      algorithm: scope.algorithm || 'sha256',
      contentHash: scope.contentHash,
    },

    document: {
      url: document.url || null,
      title: document.title || null,
      author: document.author || null,
      publishedAt: document.publishedAt || null,
    },

    signer: {
      domain: signer.domain,
      name: signer.name || null,
      keyId: signer.keyId,
      // Reported, never used to gate. A software key is not invalid, it is
      // differently assured, and the reader decides what that is worth.
      keySource: signer.keySource,
      algorithm: signer.algorithm || 'ed25519',
      publicKey: signer.publicKey,
      // Where to fetch the key independently of this document, so verification
      // never has to trust the envelope for its own key.
      keyLocation: signer.keyLocation || `_ai-authority.${signer.domain} (DNS TXT)`,
    },

    signature,
    signedAt,

    // Absence means "unknown", not "valid forever". A verifier should say so.
    validity: validity ? { notBefore: validity.notBefore, notAfter: validity.notAfter } : null,

    assurance: {
      level: assurance.level,
      label: assurance.label,
      establishes: assurance.establishes,
      doesNotEstablish: assurance.doesNotEstablish,
      chain: chain.map((c) => ({ type: c.type, establishes: c.establishes, reference: c.reference || null })),
    },

    // Said out loud because it is the thing people most often assume.
    disclaimer:
      'This establishes origin and integrity. It says nothing about whether the content is accurate, current, or fit for any purpose.',
  };
}

/**
 * Determine the assurance level from the signer and any additional links.
 *
 * Deliberately conservative: the level is the weakest thing actually
 * demonstrated, never the strongest thing claimed.
 *
 * @param {object} signer Signer descriptor.
 * @param {object[]} chain Additional assurance links.
 * @returns {object} One of ASSURANCE.
 */
export function assuranceFor(signer, chain = []) {
  const types = new Set(chain.map((c) => c.type));
  if (types.has('liveness')) return ASSURANCE.L3;
  if (types.has('identity-document')) return ASSURANCE.L2;
  if (signer.keySource === 'tpm' || signer.keySource === 'secure-element') return ASSURANCE.L1;
  return ASSURANCE.L0;
}
