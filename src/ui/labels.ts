/**
 * The names PhishLens gives things on screen.
 *
 * Separate from `format.ts` for one structural reason: this file imports nothing but types, so a surface
 * that needs only the vocabulary — the popup — does not pull in domain parsing and the IANA table behind
 * it. Wording that is *derived* rather than looked up belongs in `format.ts`.
 *
 * Every table is a `Record` over a union, so adding a classification or severity cannot compile until it
 * has a name.
 */
import type { Classification, Severity, SignalCategory } from '../shared/types.js';

/**
 * Not alarmist, deliberately. "Caution" and "Suspicious", never "DANGER": a badge that overstates gets
 * dismissed, and a dismissed badge protects nobody.
 */
export const CLASSIFICATION_LABELS: Readonly<Record<Classification, string>> = {
  low: 'Low Risk',
  caution: 'Caution',
  suspicious: 'Suspicious',
  'high-risk': 'High Risk',
};

/**
 * Text characters rather than emoji, so they render identically across platforms and do not shift the
 * badge's height.
 */
export const CLASSIFICATION_GLYPHS: Readonly<Record<Classification, string>> = {
  low: '✓',
  caution: '!',
  suspicious: '⚠',
  'high-risk': '⛔',
};

export const SEVERITY_LABELS: Readonly<Record<Severity, string>> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  info: 'NOTE',
};

export const CATEGORY_LABELS: Readonly<Record<SignalCategory, string>> = {
  authentication: 'Authentication',
  identity: 'Sender',
  link: 'Links',
  content: 'Wording',
  attachment: 'Attachments',
  llm: 'AI assessment',
};

/**
 * What a message that could not be read is called.
 *
 * "Not checked" rather than "Unknown" or an error glyph: it says what did not happen, in the same
 * grammatical shape as the risk labels, and cannot be misread as a verdict of any kind.
 */
export const UNREADABLE_LABEL = 'Not checked';
export const UNREADABLE_GLYPH = '?';

export const UNREADABLE_ARIA =
  'PhishLens could not read this message and has not checked it. Activate for details.';
