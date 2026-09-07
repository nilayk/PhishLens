#!/usr/bin/env node
/**
 * Refreshes `src/shared/tlds.ts` from IANA's authoritative list of delegated top-level domains.
 *
 * Run by hand, not by the build. A build that reaches the network cannot be reproduced offline, and a
 * detection rule whose input changes silently between builds is one whose behaviour nobody can review —
 * so the snapshot is committed and its refresh is a visible diff.
 *
 *   node scripts/gen-tlds.mjs
 */
import { writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const SOURCE = 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const outfile = path.join(root, 'src/shared/tlds.ts');

/** Wraps a long space-separated string at a column, so the generated file is reviewable in a diff. */
function wrap(words, width) {
  const lines = [];
  let line = '';
  for (const word of words) {
    if (line !== '' && line.length + word.length + 1 > width) {
      lines.push(line);
      line = '';
    }
    line = line === '' ? word : `${line} ${word}`;
  }
  if (line !== '') lines.push(line);
  return lines;
}

const response = await fetch(SOURCE);
if (!response.ok) throw new Error(`${SOURCE} returned ${String(response.status)}`);
const body = await response.text();

const lines = body.split('\n').map((l) => l.trim());
const version = lines.find((l) => l.startsWith('#'))?.replace(/^#\s*/u, '') ?? 'unknown';
const tlds = lines.filter((l) => l !== '' && !l.startsWith('#')).map((l) => l.toLowerCase());

if (tlds.length < 1000) throw new Error(`only ${String(tlds.length)} TLDs parsed; refusing to write`);

const punycode = tlds.filter((t) => t.startsWith('xn--')).length;

const file = `/**
 * Every top-level domain IANA has delegated, as a snapshot.
 *
 * **What this is for.** \`isMalformedHost\` in \`url.ts\` checks that a TLD is *shaped* like one; this
 * checks that it *is* one. A sending domain under a TLD that does not exist cannot resolve, cannot
 * accept a reply, and cannot have been registered by anyone — so the From address is fabricated, which
 * is worth stating plainly rather than inferring from softer signals.
 *
 * **Why a snapshot and not a lookup.** Nothing in this extension performs DNS or any other network
 * request on data derived from a message; see the privacy guarantees in docs/PRIVACY.md. A committed
 * list is the only form of this check that keeps that promise.
 *
 * **The failure mode this creates.** A TLD delegated after this snapshot reads as nonexistent. New
 * delegations are rare and slow, and the consequence is bounded by design: the rule consuming this is
 * \`high\`, never \`critical\`, so a stale entry can raise a legitimate message to "suspicious" but can
 * never on its own produce "high risk". Refresh with \`node scripts/gen-tlds.mjs\`.
 *
 * Generated file — do not edit by hand.
 * Source: ${SOURCE}
 * ${version}
 * ${String(tlds.length)} entries, of which ${String(punycode)} are internationalised (\`xn--\`).
 */

const DELEGATED = [
${wrap(tlds, 96)
  .map((line) => `  '${line}',`)
  .join('\n')}
].join(' ');

export const IANA_TLDS: ReadonlySet<string> = new Set(DELEGATED.split(' '));
`;

await writeFile(outfile, file, 'utf8');
console.log(`wrote ${path.relative(root, outfile)}: ${String(tlds.length)} TLDs (${version})`);
