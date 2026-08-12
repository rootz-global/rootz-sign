/**
 * canonical.mjs — decide exactly which bytes are signed, and make that
 * decision reproducible by anyone.
 *
 * This is the part that makes or breaks the whole thing. A signature over
 * "the article" is worthless if two people disagree about where the article
 * starts and stops. Steven's July 4 proof page got this right and almost
 * nobody else does — it states "essay title through 'CEO, Rootz', excludes
 * postscript". That sentence is why a stranger can check it.
 *
 * So: the scope is explicit, it travels inside the proof, and canonicalisation
 * is boring and documented rather than clever.
 */
import crypto from 'crypto';

/**
 * Normalise text before hashing.
 *
 * Every rule here exists because something otherwise-invisible would change the
 * hash and make a valid signature look forged:
 *
 *   - CRLF vs LF: a Windows editor rewrites every line ending on save.
 *   - Trailing whitespace: editors and formatters strip or add it silently.
 *   - Leading/trailing blank lines: templates add them when embedding.
 *   - Unicode form: "é" has two encodings that look identical. NFC picks one.
 *
 * We do NOT touch internal spacing, punctuation, capitalisation or wording.
 * Anything that changes meaning must change the hash — that is the point.
 *
 * @param {string} text Raw text.
 * @returns {string} Canonical text.
 */
export function canonicalText(text) {
  return String(text)
    .normalize('NFC')
    .replace(/\r\n?/g, '\n')
    .split('\n')
    .map((line) => line.replace(/[ \t]+$/, ''))
    .join('\n')
    .replace(/^\n+/, '')
    .replace(/\n+$/, '\n');
}

/**
 * Hash canonical text.
 *
 * @param {string} text Raw text.
 * @returns {{contentHash: string, canonical: string, bytes: number}}
 */
export function hashContent(text) {
  const canonical = canonicalText(text);
  const digest = crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
  return {
    contentHash: 'sha256:' + digest,
    canonical,
    bytes: Buffer.byteLength(canonical, 'utf8'),
  };
}

/**
 * Extract the signed region from a document using explicit markers.
 *
 * Markers beat line numbers and beat "the whole file": a file gains front
 * matter, a footer, a nav bar, an analytics snippet — and every one of those
 * would break a whole-file hash while changing nothing the author wrote.
 *
 * If no markers are present the whole document is signed and the scope says so,
 * which is honest but brittle for anything rendered inside a template.
 *
 * @param {string} document Full document text.
 * @param {object} [opts]
 * @param {string} [opts.begin] Begin marker.
 * @param {string} [opts.end] End marker.
 * @returns {{text: string, description: string}}
 */
export function extractScope(document, opts = {}) {
  const begin = opts.begin || '<!--rootz:sign:begin-->';
  const end = opts.end || '<!--rootz:sign:end-->';

  const i = document.indexOf(begin);
  const j = document.indexOf(end);

  if (i !== -1 && j !== -1 && j > i) {
    return {
      text: document.slice(i + begin.length, j),
      description: `The text between the markers ${begin} and ${end}. Everything outside them — headers, navigation, footers, comments — is excluded and unsigned.`,
    };
  }

  if (i !== -1 || j !== -1) {
    throw new Error(
      'Only one signing marker found. Both a begin and an end marker are required, ' +
      'because a half-open scope is ambiguous about what was signed.'
    );
  }

  return {
    text: document,
    description:
      'The complete file as published. No markers were present, so the entire document is in scope — including any header or footer it contains.',
  };
}

/**
 * The bytes actually signed.
 *
 * The signature covers the content hash plus the binding facts — who, when, and
 * which key. Signing the hash alone would let a valid signature be lifted from
 * one document and presented on another with a different author or date.
 *
 * @param {object} p {contentHash, domain, keyId, signedAt}
 * @returns {Buffer}
 */
export function signingPayload({ contentHash, domain, keyId, signedAt }) {
  // Fixed field order, one per line, explicitly labelled. Deliberately
  // human-readable so anyone can reconstruct it by hand and check our work.
  const payload = [
    'rootz-proof-v1',
    `contentHash: ${contentHash}`,
    `domain: ${domain}`,
    `keyId: ${keyId}`,
    `signedAt: ${signedAt}`,
  ].join('\n');
  return Buffer.from(payload, 'utf8');
}
