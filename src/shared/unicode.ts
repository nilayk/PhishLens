/**
 * Unicode spoofing primitives: punycode decoding, script mixing, and confusable folding.
 *
 * Why this exists: `URL` hands us `xn--pypal-4ve.com`, which tells us *that* the name is non-ASCII
 * but not *what it looks like*. Without decoding it we cannot tell the user "this renders as
 * pаypal.com with a Cyrillic а", and we cannot compare the rendered form against a brand name.
 */

// ---------------------------------------------------------------------------
// RFC 3492 punycode decoding
// ---------------------------------------------------------------------------

const BASE = 36;
const TMIN = 1;
const TMAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 128;
const MAX_INT = 0x7fffffff;

function basicToDigit(codePoint: number): number {
  if (codePoint >= 0x30 && codePoint <= 0x39) return codePoint - 0x16; // 0-9 -> 26..35
  if (codePoint >= 0x41 && codePoint <= 0x5a) return codePoint - 0x41; // A-Z -> 0..25
  if (codePoint >= 0x61 && codePoint <= 0x7a) return codePoint - 0x61; // a-z -> 0..25
  return BASE;
}

function adaptBias(delta: number, numPoints: number, firstTime: boolean): number {
  let d = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
  d += Math.floor(d / numPoints);
  let k = 0;
  while (d > ((BASE - TMIN) * TMAX) >> 1) {
    d = Math.floor(d / (BASE - TMIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - TMIN + 1) * d) / (d + SKEW));
}

/**
 * Decodes a single punycode label body (i.e. the part after `xn--`).
 * Returns `null` on any malformed input — this parses attacker-controlled data, so it never throws
 * and never returns a partial guess.
 */
export function punycodeDecodeLabel(body: string): string | null {
  if (body === '') return null;

  const output: number[] = [];
  const lastDelimiter = body.lastIndexOf('-');
  let index = 0;

  if (lastDelimiter > 0) {
    for (let i = 0; i < lastDelimiter; i++) {
      const cp = body.charCodeAt(i);
      if (cp >= 0x80) return null; // basic code points must be ASCII
      output.push(cp);
    }
    index = lastDelimiter + 1;
  }

  let n = INITIAL_N;
  let bias = INITIAL_BIAS;
  let i = 0;

  while (index < body.length) {
    const oldI = i;
    let w = 1;
    for (let k = BASE; ; k += BASE) {
      if (index >= body.length) return null;
      const digit = basicToDigit(body.charCodeAt(index));
      index += 1;
      if (digit >= BASE) return null;
      if (digit > Math.floor((MAX_INT - i) / w)) return null;
      i += digit * w;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break;
      if (w > Math.floor(MAX_INT / (BASE - t))) return null;
      w *= BASE - t;
    }
    const outLength = output.length + 1;
    bias = adaptBias(i - oldI, outLength, oldI === 0);
    if (Math.floor(i / outLength) > MAX_INT - n) return null;
    n += Math.floor(i / outLength);
    i %= outLength;
    if (n > 0x10ffff || (n >= 0xd800 && n <= 0xdfff)) return null;
    output.splice(i, 0, n);
    i += 1;
  }

  try {
    return String.fromCodePoint(...output);
  } catch {
    return null;
  }
}

/**
 * Converts an ASCII (possibly punycode) hostname into its rendered Unicode form.
 * Labels that fail to decode are left as-is rather than dropped.
 */
export function decodeIdnHost(hostname: string): string {
  if (!hostname.includes('xn--')) return hostname;
  return hostname
    .split('.')
    .map((label) => {
      if (!label.startsWith('xn--')) return label;
      const decoded = punycodeDecodeLabel(label.slice(4));
      return decoded ?? label;
    })
    .join('.');
}

// ---------------------------------------------------------------------------
// Script mixing
// ---------------------------------------------------------------------------

const SCRIPT_TESTS: readonly [string, RegExp][] = [
  ['Latin', /\p{Script=Latin}/u],
  ['Cyrillic', /\p{Script=Cyrillic}/u],
  ['Greek', /\p{Script=Greek}/u],
  ['Armenian', /\p{Script=Armenian}/u],
  ['Hebrew', /\p{Script=Hebrew}/u],
  ['Arabic', /\p{Script=Arabic}/u],
  ['Han', /\p{Script=Han}/u],
  ['Hiragana', /\p{Script=Hiragana}/u],
  ['Katakana', /\p{Script=Katakana}/u],
  ['Hangul', /\p{Script=Hangul}/u],
  ['Thai', /\p{Script=Thai}/u],
  ['Devanagari', /\p{Script=Devanagari}/u],
  ['Cherokee', /\p{Script=Cherokee}/u],
];

export function scriptsUsed(text: string): string[] {
  return SCRIPT_TESTS.filter(([, re]) => re.test(text)).map(([name]) => name);
}

/**
 * True when a single label mixes scripts that no real word mixes — the classic homoglyph attack.
 * CJK+Latin is common and legitimate (product names), so it is excluded.
 */
export function hasSuspiciousScriptMixing(label: string): boolean {
  const scripts = scriptsUsed(label);
  if (scripts.length < 2) return false;
  const cjkOnly = new Set(['Han', 'Hiragana', 'Katakana', 'Hangul', 'Latin']);
  if (scripts.every((s) => cjkOnly.has(s))) return false;
  return true;
}

/**
 * Unicode direction-override and invisible characters. In a filename these produce
 * `invoice_gnp.exe` rendering as `invoice_exe.png`; in display names they hide text.
 */
const BIDI_AND_INVISIBLE = /[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff\u00ad\u180e]/u;

export function hasBidiOrInvisible(text: string): boolean {
  return BIDI_AND_INVISIBLE.test(text);
}

/**
 * Letters from Unicode's mathematical alphabets — the block that exists so a mathematician can write a
 * bold variable, and that spam uses to write `𝗣aym𝗲nt` in a form no text rule matches.
 *
 * Deliberately *not* folded away and forgotten. `skeleton()` normalises these to plain letters, which is
 * right for comparison and throws away the observation: a sender whose name is spelled in mathematical
 * sans-serif has taken trouble to be unreadable to software while looking ordinary to a person, and that
 * intent is itself the finding.
 *
 * The second alternative covers the holes in the block. Unicode did not duplicate characters it already
 * had, so the script and fraktur alphabets are missing letters that live in Letterlike Symbols
 * (`ℋ`, `ℎ`, `ℝ`) — a spammer spelling a whole word needs them, so a rule that ignored them would miss
 * the words most likely to be spelled this way. They are enumerated rather than taken as a range because
 * the same block holds `™`, `№` and `℃`, which appear in ordinary display names.
 *
 * Fullwidth Latin is not included even though it is equally decorative here: it is the normal way to
 * write Latin letters in Japanese text, and `skeleton()` already folds it for comparison.
 */
const STYLED_LETTERFORMS =
  /[\u{1d400}-\u{1d7ff}]|[ℂℊℋℌℍℎℐℑℒℓℕℙℚℛℜℝℤℨℬℭℯℰℱℳℴ℘ⅅⅆⅇⅈⅉ]/u;

export function hasStyledLetterforms(text: string): boolean {
  return STYLED_LETTERFORMS.test(text);
}

export function stripBidiAndInvisible(text: string): string {
  return text.replace(new RegExp(BIDI_AND_INVISIBLE, 'gu'), '');
}

// ---------------------------------------------------------------------------
// Confusable folding ("skeleton")
// ---------------------------------------------------------------------------

/**
 * A pragmatic subset of the Unicode confusables table, plus the ASCII-on-ASCII tricks
 * (`rn`→`m`, `vv`→`w`, `1`→`l`) that the official table does not cover because they are
 * multi-character.
 */
const CONFUSABLE_MAP: Readonly<Record<string, string>> = {
  // Cyrillic
  а: 'a', б: '6', в: 'b', г: 'r', д: 'd', е: 'e', ж: 'x', з: '3', и: 'u', й: 'u', к: 'k',
  л: 'n', м: 'm', н: 'h', о: 'o', п: 'n', р: 'p', с: 'c', т: 't', у: 'y', ф: 'o', х: 'x',
  ц: 'u', ч: 'h', ш: 'w', щ: 'w', ъ: 'b', ы: 'bi', ь: 'b', э: 'e', ю: 'io', я: 'r',
  ѕ: 's', і: 'i', ј: 'j', ԁ: 'd', ԛ: 'q', ԝ: 'w', ѡ: 'w', ғ: 'f', ҫ: 'c', ұ: 'y',
  // Greek
  α: 'a', β: 'b', γ: 'y', δ: 'd', ε: 'e', ζ: 'z', η: 'n', θ: '0', ι: 'i', κ: 'k', λ: 'l',
  μ: 'u', ν: 'v', ο: 'o', π: 'n', ρ: 'p', σ: 'o', τ: 't', υ: 'u', φ: 'o', χ: 'x', ψ: 'w',
  ω: 'w', ϲ: 'c', ϳ: 'j', Ρ: 'p', Α: 'a', Β: 'b', Ε: 'e', Ζ: 'z', Η: 'h', Ι: 'i', Κ: 'k',
  Μ: 'm', Ν: 'n', Ο: 'o', Τ: 't', Υ: 'y', Χ: 'x',
  // Armenian / Cherokee / other lookalikes
  ա: 'w', օ: 'o', ո: 'n', պ: 'y', Ꭺ: 'a', Ꮃ: 'w', Ꮋ: 'h', Ꮶ: 'k', Ꮮ: 'l', Ꮲ: 'p', Ꮪ: 's',
  // Fullwidth
  ａ: 'a', ｂ: 'b', ｃ: 'c', ｄ: 'd', ｅ: 'e', ｆ: 'f', ｇ: 'g', ｈ: 'h', ｉ: 'i', ｊ: 'j',
  ｋ: 'k', ｌ: 'l', ｍ: 'm', ｎ: 'n', ｏ: 'o', ｐ: 'p', ｑ: 'q', ｒ: 'r', ｓ: 's', ｔ: 't',
  ｕ: 'u', ｖ: 'v', ｗ: 'w', ｘ: 'x', ｙ: 'y', ｚ: 'z', '．': '.', '－': '-',
  // Mathematical / styled Latin (a huge family; the common ones)
  '𝐚': 'a', '𝐨': 'o', '𝐩': 'p', '𝗮': 'a', '𝗼': 'o', '𝘢': 'a', '𝙖': 'a', 'ⅼ': 'l', 'ⅰ': 'i',
  // Digits / punctuation used as letters
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '9': 'g',
  '$': 's', '@': 'a', '!': 'i', '|': 'l', '¡': 'i',
  // Latin with diacritics that read as bare ASCII at a glance
  à: 'a', á: 'a', â: 'a', ã: 'a', ä: 'a', å: 'a', ā: 'a', ă: 'a', ą: 'a',
  ç: 'c', ć: 'c', č: 'c', ĉ: 'c',
  è: 'e', é: 'e', ê: 'e', ë: 'e', ē: 'e', ĕ: 'e', ė: 'e', ę: 'e', ě: 'e',
  ì: 'i', í: 'i', î: 'i', ï: 'i', ĩ: 'i', ī: 'i', į: 'i', ı: 'i',
  ñ: 'n', ń: 'n', ň: 'n', ņ: 'n',
  ò: 'o', ó: 'o', ô: 'o', õ: 'o', ö: 'o', ø: 'o', ō: 'o', ŏ: 'o', ő: 'o',
  ù: 'u', ú: 'u', û: 'u', ü: 'u', ũ: 'u', ū: 'u', ŭ: 'u', ů: 'u', ű: 'u', ų: 'u',
  ý: 'y', ÿ: 'y', ŷ: 'y',
  ß: 'b', š: 's', ś: 's', ş: 's', ż: 'z', ź: 'z', ž: 'z', ť: 't', ţ: 't', ď: 'd', ł: 'l',
  ğ: 'g', ĝ: 'g', ħ: 'h', ř: 'r', ŕ: 'r', đ: 'd', þ: 'p', ƒ: 'f',
};

const MULTI_CHAR_CONFUSABLES: readonly [RegExp, string][] = [
  [/rn/g, 'm'],
  [/vv/g, 'w'],
  [/cl/g, 'd'],
  [/nn/g, 'm'],
];

/**
 * The `i`/`l`/`1` family, collapsed onto one representative as UTS#39 does.
 *
 * This has to be a separate pass applied *after* everything else, for two reasons. It must run after
 * case folding, because the attack is usually a capital `I` standing in for a lowercase `l`
 * (`northwind-Iogistics.com`) — and folding only the capital would make `MICROSOFT` and `microsoft`
 * produce different skeletons, which is worse than the gap it closes. It must also run after the
 * multi-character rules, so that `cl`→`d` cannot fire on a `ci` that this pass created.
 */
const IL_FAMILY = /[i!¡]/g;

/**
 * Folds a string to a canonical "skeleton" so that visually identical strings compare equal.
 *
 * `skeleton('pаypal')` (Cyrillic а) === `skeleton('paypal')`
 * `skeleton('rnicrosoft')` === `skeleton('microsoft')`
 *
 * Lossy by design. Only ever used for *comparison*, never for display or for building a URL.
 */
export function skeleton(input: string): string {
  const normalized = stripBidiAndInvisible(input)
    .normalize('NFKD')
    .replace(/\p{Mn}/gu, '') // drop combining marks left behind by NFKD
    .toLowerCase();

  let folded = '';
  for (const ch of normalized) {
    folded += CONFUSABLE_MAP[ch] ?? ch;
  }
  for (const [pattern, replacement] of MULTI_CHAR_CONFUSABLES) {
    folded = folded.replace(pattern, replacement);
  }
  folded = folded.replace(IL_FAMILY, 'l');
  // Collapse separators that phishers insert to break exact matching: `pay-pal`, `pay.pal`.
  return folded.replace(/[\s._\-+]/g, '');
}

/** True when the rendered form differs from the plain-ASCII reading of it. */
export function isConfusableWith(candidate: string, target: string): boolean {
  return candidate !== target && skeleton(candidate) === skeleton(target);
}

// ---------------------------------------------------------------------------
// Edit distance
// ---------------------------------------------------------------------------

/**
 * Damerau–Levenshtein distance (with transpositions), bounded so a hostile 253-character hostname
 * against 40 brands stays cheap. Returns `max + 1` when the true distance exceeds `max`.
 */
export function editDistance(a: string, b: string, max = 3): number {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > max) return max + 1;
  // Handled up front because the bounded main loop below never executes its inner loop when one side
  // is empty, and would therefore report "over the bound" for a distance it never measured.
  if (a.length === 0 || b.length === 0) return Math.max(a.length, b.length);

  // Row-major flat grid: cell (i, j) lives at `i * width + j`. Flat rather than an array of arrays so
  // that no row lookup can be missing, which keeps the inner loop free of per-row null handling.
  const width = b.length + 1;
  const grid = new Array<number>((a.length + 1) * width).fill(0);

  for (let i = 0; i <= a.length; i++) grid[i * width] = i;
  for (let j = 0; j <= b.length; j++) grid[j] = j;

  for (let i = 1; i <= a.length; i++) {
    let rowMin = Number.POSITIVE_INFINITY;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let value = Math.min(
        (grid[(i - 1) * width + j] ?? 0) + 1,
        (grid[i * width + j - 1] ?? 0) + 1,
        (grid[(i - 1) * width + j - 1] ?? 0) + cost,
      );
      // Transposition: `paypa1` vs `payap1`.
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        value = Math.min(value, (grid[(i - 2) * width + j - 2] ?? 0) + 1);
      }
      grid[i * width + j] = value;
      rowMin = Math.min(rowMin, value);
    }
    // Early exit: once every cell in a row exceeds the bound, the final distance must too.
    if (rowMin > max) return max + 1;
  }
  return grid[a.length * width + b.length] ?? max + 1;
}
