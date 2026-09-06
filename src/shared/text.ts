/**
 * Text primitives for hostile input.
 *
 * All body text is truncated before any regex touches it: an attacker controls both the pattern
 * subject and its length, and unbounded input is the precondition for pathological matching.
 */

/** Hard ceiling on how much body text the engine will ever consider. */
export const MAX_BODY_CHARS = 200_000;

/** Ceiling on how much text is shown in a UI explanation. */
export const MAX_EVIDENCE_CHARS = 160;

export function truncate(text: string, max: number): string {
  return text.length <= max ? text : text.slice(0, max);
}

/** Collapses all whitespace runs to single spaces and trims. */
export function collapseWhitespace(text: string): string {
  return text.replace(/\s+/gu, ' ').trim();
}

/**
 * Canonical form for keyword matching: bounded length, whitespace-collapsed, lowercased, with
 * zero-width characters removed and typographic punctuation folded to ASCII.
 *
 * The last two matter because patterns are written in plain ASCII: `pass\u200bword` and `don’t` would
 * otherwise slip past a rule spelling them the obvious way. Letter-spacing (`p a s s w o r d`) is *not*
 * flattened here — that is `skeleton()`'s job, and it is applied where brand claims are matched.
 */
export function normalizeForMatching(text: string): string {
  return collapseWhitespace(truncate(text, MAX_BODY_CHARS))
    .toLowerCase()
    .replace(/[\u200b-\u200f\u2060\ufeff\u00ad]/gu, '')
    .replace(/[\u2018\u2019\u201b\u2032]/gu, "'")
    .replace(/[\u201c\u201d\u201f\u2033]/gu, '"')
    .replace(/[\u2010-\u2015\u2212]/gu, '-');
}

/**
 * Joins items for prose: `a`, `a and b`, `a, b and c`, and `a, b, c and 2 more` past `max`.
 *
 * Bounded by default because every list here is derived from attacker-controlled input — forty
 * attachment names do not belong in a sentence.
 */
export function formatList(items: readonly string[], max = 3): string {
  if (items.length <= 1) return items[0] ?? '';

  const shown = items.slice(0, max);
  const extra = items.length - shown.length;
  const tail = extra > 0 ? `${String(extra)} more` : (shown.pop() ?? '');
  return `${shown.join(', ')} and ${tail}`;
}

/** Extracts a short, safe excerpt centred on a match, for use as UI evidence. */
export function excerpt(text: string, index: number, length: number): string {
  const start = Math.max(0, index - 32);
  const end = Math.min(text.length, index + length + 32);
  const slice = collapseWhitespace(text.slice(start, end));
  const prefix = start > 0 ? '…' : '';
  const suffix = end < text.length ? '…' : '';
  return `${prefix}${truncate(slice, MAX_EVIDENCE_CHARS)}${suffix}`;
}

/**
 * Splits a `Display Name <local@domain>` mailbox string.
 * Gmail usually gives us these separately, but Reply-To is often only available as a raw string.
 */
export function parseMailbox(raw: string): { name?: string; email?: string } {
  const value = raw.trim();
  if (value === '') return {};

  const angled = /^(.*?)<\s*([^<>\s]+@[^<>\s]+)\s*>$/u.exec(value);
  if (angled !== null) {
    const name = angled[1]?.trim().replace(/^["']|["']$/gu, '') ?? '';
    const email = angled[2]?.trim().toLowerCase();
    return { ...(name !== '' ? { name } : {}), ...(email !== undefined ? { email } : {}) };
  }
  if (/^[^<>\s]+@[^<>\s]+$/u.test(value)) {
    return { email: value.toLowerCase() };
  }
  return { name: value };
}

/** The domain part of an email address, normalised. Returns `''` for anything unparseable. */
export function emailDomain(address: string | undefined): string {
  if (address === undefined) return '';
  const at = address.lastIndexOf('@');
  if (at < 0 || at === address.length - 1) return '';
  return address
    .slice(at + 1)
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/gu, '')
    .replace(/\.$/u, '');
}

export function emailLocalPart(address: string | undefined): string {
  if (address === undefined) return '';
  const at = address.lastIndexOf('@');
  return at < 0 ? '' : address.slice(0, at).trim().toLowerCase();
}

/**
 * The local part with its original case.
 *
 * `emailLocalPart` lowercases, which is correct for every comparison and wrong for the one thing that
 * needs the original: spotting randomised capitalisation like `DoNoT.rEpLy`. Use this only to inspect
 * formatting, never to compare two addresses.
 */
export function emailLocalPartPreservingCase(address: string | undefined): string {
  if (address === undefined) return '';
  const at = address.lastIndexOf('@');
  return at < 0 ? '' : address.slice(0, at).trim();
}

/**
 * The final extension of a filename, lowercased, without the dot.
 * Ignores trailing dots/spaces (a Windows trick) and direction-override characters.
 */
export function fileExtension(filename: string): string {
  const cleaned = stripFilenameNoise(filename);
  const dot = cleaned.lastIndexOf('.');
  if (dot <= 0 || dot === cleaned.length - 1) return '';
  return cleaned.slice(dot + 1).toLowerCase();
}

/** All extension-looking segments of a filename, e.g. `invoice.pdf.exe` → `['pdf','exe']`. */
export function fileExtensionChain(filename: string): string[] {
  const parts = stripFilenameNoise(filename).split('.');
  if (parts.length < 2) return [];
  return parts
    .slice(1)
    .map((p) => p.trim().toLowerCase())
    .filter((p) => /^[a-z0-9]{1,8}$/u.test(p));
}

/** Drops direction-override characters and trailing dots/spaces, both used to disguise extensions. */
function stripFilenameNoise(filename: string): string {
  return filename.replace(/[\u200b-\u200f\u202a-\u202e\u2066-\u2069]/gu, '').replace(/[.\s]+$/u, '');
}

/** Finds the first match and returns it with its index, or `null`. */
export function firstMatch(text: string, pattern: RegExp): { match: string; index: number } | null {
  const re = new RegExp(pattern.source, pattern.flags.replace('g', ''));
  const result = re.exec(text);
  if (result === null) return null;
  return { match: result[0], index: result.index };
}
