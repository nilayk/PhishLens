/**
 * The verdict available from a message list, where the only thing on screen is a sender line.
 *
 * An inbox row has no body, no links, no attachments and no authentication table, so it cannot be
 * scored — and the temptation this module exists to refuse is scoring it anyway. A number derived from
 * a quarter of the evidence would sit beside a number derived from all of it, look like the same kind of
 * thing, and be wrong in the reassuring direction for every message whose problem is in its body.
 *
 * So this returns one of two things: a warning, or nothing. There is no all-clear. A row with no marker
 * means "nothing visible from here", which is what the absence of a marker naturally reads as, and the
 * marker's own wording says the message has not been opened or checked.
 *
 * Only the identity rules run, and only those needing nothing beyond the sender line — see
 * `SENDER_ONLY_RULES`. Pure, like everything else in `analysis/`: the caller supplies the two strings it
 * scraped and gets a verdict, with no notion of a DOM anywhere in here.
 */
import type { Severity } from '../shared/types.js';
import { buildContext } from './context.js';
import { detectIdentitySignals } from './rules/identity.js';
import { isAtLeast, sortSignalsForDisplay } from './scoring/aggregate.js';

/**
 * Identity findings that need nothing but the sender's name and address.
 *
 * An allowlist rather than a denylist, so a new rule reading the body cannot join triage by default. The
 * cost is that a new *sender-only* rule has to be added here to appear in a list row, which is the safe
 * direction to fail — and `test/triage.test.ts` asserts that every identity rule the fixture corpus
 * produces appears in this set or in `NEEDS_MORE_THAN_SENDER`, so the choice cannot be made by omission.
 */
const SENDER_ONLY_RULES: ReadonlySet<string> = new Set([
  'identity.display_name_impersonation',
  'identity.lookalike_sender_domain',
  'identity.lookalike_of_recipient_domain',
  'identity.sender_punycode_domain',
  'identity.sender_invisible_characters',
  'identity.styled_display_name',
  'identity.nonexistent_sender_tld',
  'identity.private_use_sender_tld',
  'identity.unparseable_sender',
  'identity.sender_ip_domain',
  'identity.malformed_sender_domain',
  'identity.brand_domain_in_subdomain',
  'identity.disposable_sender_domain',
  'identity.sender_deep_subdomain',
  'identity.unsupported_org_claim',
  'identity.implausible_local_part',
  'identity.randomised_address_case',
]);

/**
 * Identity rules deliberately kept out of a list row, with the reason each is excluded.
 *
 * Exists so that "not in the allowlist" can mean "nobody has looked at it yet" and be caught, rather
 * than being indistinguishable from a considered decision.
 */
const NEEDS_MORE_THAN_SENDER: ReadonlySet<string> = new Set([
  // Needs the Reply-To header, which a row does not carry.
  'identity.reply_to_mismatch',
  // Reads the body, so from a row it would fire on a display name alone.
  'identity.external_executive_claim',
  'identity.external_financial_request',
  // Correlations, by definition: each is an inference drawn from a sender finding plus a body or link
  // finding, and neither of the latter exists in a row.
  'identity.impersonation_with_credential_request',
  // Both need the other messages in the conversation, which a row does not show.
  'identity.thread_lookalike_participant',
  'identity.thread_participant_name_reuse',
]);

/**
 * The severities a row can show. Narrower than `Severity` so the marker needs no branch for a level it
 * can never be given, and so that moving the floor cannot produce a mark with no glyph defined for it.
 */
export type TriageSeverity = Extract<Severity, 'high' | 'critical'>;

/**
 * The floor for marking a row at all, and deliberately higher than the floor for reporting a finding in
 * the card.
 *
 * `medium` was tried and is wrong here. The generous half of `identity.unsupported_org_claim` fires on
 * `"Accounts Receivable" <ar@a-supplier.example>` — a departmental name that shares no word with its own
 * company's domain — which is a reasonable thing to mention beside a full score and a bad thing to put on
 * an inbox row, where it is the *only* thing said about the message. At `high` the marks left are
 * impersonations of a named brand, of the reader's own domain, and outright malformed senders.
 *
 * The softer findings are not lost. They appear in the card, next to the body and links that give them
 * the context a row cannot.
 */
const TRIAGE_MIN_SEVERITY: TriageSeverity = 'high';

export interface TriageVerdict {
  severity: TriageSeverity;
  /** The finding's own title. Shown verbatim, so it must remain a sentence a user can act on. */
  title: string;
  /** The rule that fired, for the marker's `data-` attribute and for tests. */
  id: string;
}

export interface TriageInput {
  senderName: string;
  senderEmail: string;
  /** The signed-in address, when the page gave one up. Enables the lookalike-of-recipient check. */
  recipientEmail?: string;
}

/**
 * The worst sender-only finding, or `null` when there is nothing to warn about.
 *
 * One finding rather than all of them: a row has space for a marker and a tooltip, and the message's own
 * card is where a complete list belongs. The worst is the one that decides whether to open the message
 * carefully, which is the only decision being made at this point.
 */
export function triageSender(input: TriageInput): TriageVerdict | null {
  const senderEmail = input.senderEmail.trim();
  if (senderEmail === '') return null;

  const context = buildContext({
    senderName: input.senderName,
    senderEmail,
    ...(input.recipientEmail === undefined ? {} : { recipientEmail: input.recipientEmail }),
    // A row shows a subject and a snippet, and neither is read here. Every rule below keys off the
    // sender line, and passing text that only *some* of them would see makes the verdict depend on how
    // much of a snippet Gmail happened to render.
    bodyText: '',
    links: [],
    attachments: [],
  });

  // Ordered exactly as the card orders findings, so the row's one marker names the same finding a reader
  // will see at the top of the card when they open the message.
  const [worst] = sortSignalsForDisplay(
    detectIdentitySignals(context).filter(
      (s) => SENDER_ONLY_RULES.has(baseId(s.id)) && isAtLeast(s.severity, TRIAGE_MIN_SEVERITY),
    ),
  );
  if (worst === undefined) return null;

  const severity = asTriageSeverity(worst.severity);
  return severity === null ? null : { severity, title: worst.title, id: worst.id };
}

/**
 * Narrows a severity the filter above has already established. A test rather than a cast, so lowering
 * `TRIAGE_MIN_SEVERITY` without widening `TriageSeverity` drops the mark instead of producing one with no
 * glyph defined for it.
 */
function asTriageSeverity(severity: Severity): TriageSeverity | null {
  return severity === 'high' || severity === 'critical' ? severity : null;
}

/** Strips the `.<index>` suffix the per-item rules append, so the sets hold rule names only. */
function baseId(id: string): string {
  const parts = id.split('.');
  return parts.length > 2 && /^\d+$/u.test(parts[parts.length - 1] ?? '')
    ? parts.slice(0, -1).join('.')
    : id;
}

/** Exposed for the allowlist guard in `test/triage.test.ts`, which has no other way to see these. */
export const __testables = { SENDER_ONLY_RULES, NEEDS_MORE_THAN_SENDER, baseId };
