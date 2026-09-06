/**
 * Presentation strings. Wording is a security control here, not decoration:
 *
 *  1. **Not alarmist.** "Caution" and "Suspicious", never "DANGER". A badge that overstates gets
 *     dismissed, and a dismissed badge protects nobody.
 *  2. **Observations and assessments read differently.** Deterministic findings state what was measured;
 *     semantic ones are framed as opinion, so a model's guess never looks like a proven fact.
 */
import type {
  AiMode,
  Classification,
  EmailMessage,
  SecuritySignal,
  SemanticStatus,
  Severity,
  SignalCategory,
} from '../shared/types.js';
import { normalizeDomain } from '../shared/url.js';

export const CLASSIFICATION_LABELS: Readonly<Record<Classification, string>> = {
  low: 'Low Risk',
  caution: 'Caution',
  suspicious: 'Suspicious',
  'high-risk': 'High Risk',
};

/**
 * Glyphs match the states suggested in the brief. Text-only characters rather than emoji so they
 * render identically across platforms and do not shift the badge's height.
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

export function ariaLabel(classification: Classification, score: number, findings: number): string {
  const noun = findings === 1 ? 'finding' : 'findings';
  return `PhishLens: ${CLASSIFICATION_LABELS[classification]}, ${String(score)} out of 100, ${String(findings)} ${noun}. Activate for details.`;
}

/**
 * The one-line identification of the message an assessment belongs to.
 *
 * The sending domain is shown in full rather than reduced to its registrable form, because a
 * subdomain is frequently the whole point of the deception (`paypal.com.secure-login.example`).
 */
export function messageReference(email: EmailMessage): { sender: string; subject: string } {
  const address = email.senderEmail ?? '';
  const at = address.lastIndexOf('@');
  const parts = [
    (email.senderName ?? '').trim(),
    at < 0 ? '' : normalizeDomain(address.slice(at + 1)),
  ].filter((part) => part !== '');

  const subject = (email.subject ?? '').trim();
  return {
    sender: parts.length === 0 ? 'Unknown sender' : parts.join(' · '),
    subject: subject === '' ? '(no subject)' : subject,
  };
}

/** A signal is locatable when the UI can point at the thing in the message it refers to. */
export function isLocatable(signal: SecuritySignal): boolean {
  if (signal.category === 'llm') return false;
  return (
    (signal.evidence?.url !== undefined && signal.evidence.url !== '') ||
    (signal.evidence?.text !== undefined && signal.evidence.text.length >= 12)
  );
}

/**
 * The evidence block: a label and the value beneath it.
 *
 * One function so the two cannot disagree. They were separate, with opposite precedence, so a signal
 * carrying both a URL and a value showed the value under the heading "Destination".
 */
export function evidenceOf(signal: SecuritySignal): { label: string; body: string } | null {
  const evidence = signal.evidence;
  if (evidence === undefined) return null;
  if (evidence.value !== undefined && evidence.value !== '') {
    return { label: 'Observed', body: evidence.value };
  }
  if (evidence.url !== undefined && evidence.url !== '') {
    return { label: 'Destination', body: evidence.url };
  }
  if (evidence.text !== undefined && evidence.text !== '') {
    return { label: 'From the message', body: `“${evidence.text}”` };
  }
  return null;
}

/** Shown when there *is* an assessment: what the AI section is and is not. */
export const AI_DISCLAIMER =
  'The findings above are technical observations. The assessment below is a language model’s reading of the message’s intent — informed, but not proof.';

/**
 * Why there is no assessment, keyed by how the semantic stage ended. `null` means there is one.
 *
 * Worded so no two can be mistaken for each other: `unavailable` describes the browser and is
 * permanent, the rest describe this one attempt and say nothing about the next. A `Record` rather than a
 * switch so adding a status cannot compile until it has been given wording. Each entry names whatever
 * was going to do the reading, because "the on-device model" is a lie in cloud mode.
 */
const AI_ABSENCE_NOTES: Readonly<Record<SemanticStatus, ((source: string) => string) | null>> = {
  ready: null,
  pending: () => 'The score above may change when this finishes. Technical checks are already complete.',
  off: () => 'AI analysis is switched off, so this score is based entirely on technical checks.',
  unavailable: (source) =>
    `${source} is unavailable, so this score is based entirely on technical checks. No message content left this browser.`,
  'no-output': (source) =>
    `${source} did not return a usable assessment for this message. The score is based entirely on technical checks.`,
  // `cancelled` belongs to a message no longer on screen and should not reach the card; worded as the
  // unfinished attempt it is, rather than implying the model looked and found nothing.
  error: (source) =>
    `${source} could not finish assessing this message. The score is based entirely on technical checks.`,
  cancelled: (source) =>
    `${source} could not finish assessing this message. The score is based entirely on technical checks.`,
};

/**
 * Sentence-initial name for whichever analyzer the current mode uses. Naming it matters because the
 * modes differ in where the message went, and a note that says "the on-device model" while a server was
 * doing the reading misleads about exactly the thing a privacy-conscious reader is checking.
 *
 * The `off` entry is never rendered — that note takes no source — but a `Record` costs nothing and means
 * a fifth mode cannot be added without wording.
 */
const ANALYZER_NAMES: Readonly<Record<AiMode, string>> = {
  off: 'The on-device model',
  local: 'The on-device model',
  cloud: 'The analysis service',
  server: 'Your model server',
};

/** Why there is no assessment, or `null` when there is one. */
export function aiAbsenceNote(status: SemanticStatus, aiMode: AiMode): string | null {
  return AI_ABSENCE_NOTES[status]?.(ANALYZER_NAMES[aiMode]) ?? null;
}

const PENDING_LABELS: Readonly<Record<AiMode, string>> = {
  off: 'Reading the message on-device…',
  local: 'Reading the message on-device…',
  cloud: 'Sending for analysis…',
  server: 'Waiting for your model server…',
};

export function pendingLabel(aiMode: AiMode): string {
  return PENDING_LABELS[aiMode];
}
