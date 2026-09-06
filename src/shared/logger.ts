/**
 * The only sanctioned logging surface in the extension. Two structural guarantees:
 *
 *  1. Every method is a no-op unless `__PHISHLENS_DEV__` is true. esbuild replaces that flag with the
 *     literal `false` in production, so the calls and their arguments are dropped from the bundle.
 *  2. `scrub()` removes anything resembling message content, so even a dev build cannot print an email
 *     body to the console.
 */

declare const __PHISHLENS_DEV__: boolean;

const DEV = typeof __PHISHLENS_DEV__ === 'undefined' ? false : __PHISHLENS_DEV__;

const PREFIX = '[PhishLens]';

/** Anything longer than this is assumed to be message content and is not logged verbatim. */
const MAX_LOGGABLE_STRING = 120;

const EMAIL_PATTERN = /[^\s@]+@[^\s@]+\.[^\s@]+/gu;

/**
 * Reduces a value to something safe to print. Long strings become a length summary, email addresses
 * become `<local>@domain`, and objects are walked to a shallow depth.
 */
function scrub(value: unknown, depth = 0): unknown {
  if (typeof value === 'string') {
    const redacted = value.replace(EMAIL_PATTERN, (m) => {
      const at = m.lastIndexOf('@');
      return `<redacted>@${m.slice(at + 1)}`;
    });
    return redacted.length > MAX_LOGGABLE_STRING
      ? `<${String(redacted.length)} chars omitted>`
      : redacted;
  }
  if (value === null || typeof value !== 'object') return value;
  if (depth >= 2) return '<…>';
  if (Array.isArray(value)) {
    return value.slice(0, 20).map((v) => scrub(v, depth + 1));
  }
  if (value instanceof Error) return `${value.name}: ${scrub(value.message, depth + 1) as string}`;
  const out: Record<string, unknown> = {};
  for (const [key, v] of Object.entries(value)) {
    // Never log fields that are message content by definition, at any depth.
    if (/^(bodyText|body|text|subject|prompt|reasons?)$/u.test(key)) {
      out[key] = typeof v === 'string' ? `<${String(v.length)} chars omitted>` : '<omitted>';
      continue;
    }
    out[key] = scrub(v, depth + 1);
  }
  return out;
}

export const logger = {
  debug(message: string, ...values: unknown[]): void {
    if (!DEV) return;
    console.debug(PREFIX, message, ...values.map((v) => scrub(v)));
  },
  info(message: string, ...values: unknown[]): void {
    if (!DEV) return;
    console.info(PREFIX, message, ...values.map((v) => scrub(v)));
  },
  /** Dev-only like the rest: a stack trace containing message fragments is a leak, not a debug aid. */
  error(message: string, ...values: unknown[]): void {
    if (!DEV) return;
    console.error(PREFIX, message, ...values.map((v) => scrub(v)));
  },
};

export const __testables = { scrub };
