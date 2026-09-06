/**
 * Builds the minimised payload for the (unbuilt) cloud path.
 *
 * This module exists so that "what would leave the browser" is a single, readable, reviewable
 * function rather than an implicit consequence of whatever the cloud adapter happens to serialise.
 * If cloud analysis is ever enabled, this file is the thing to audit.
 *
 * What is deliberately dropped:
 *  - the recipient's address (the backend does not need to know who received the mail)
 *  - the sender's local part (`accounts-noreply@` → just the domain)
 *  - message and thread ids (no cross-request correlation of a user's mailbox)
 *  - attachment filenames (extensions only — filenames contain client names, case numbers, staff names)
 *  - full link URLs (registrable domains only — paths and query strings carry tracking identifiers
 *    that tie the message to a specific recipient)
 */
import { collapseWhitespace, truncate } from '../../shared/text.js';
import type { EmailMessage } from '../../shared/types.js';
import { addressDomain, normalizeDomain, registrableDomain } from '../../shared/url.js';
import type { CloudAnalyzeRequest } from '../../shared/messaging.js';
import { MAX_PROMPT_BODY_CHARS } from './prompt.js';

export type CloudPayload = CloudAnalyzeRequest['payload'];

export function buildCloudPayload(
  email: EmailMessage,
  deterministicSignalIds: readonly string[],
): CloudPayload {
  const senderDomain = addressDomain(email.senderEmail);
  const replyToDomain = addressDomain(email.replyTo);

  return {
    subject: truncate(collapseWhitespace(email.subject ?? ''), 300),
    bodyExcerpt: redactAddresses(truncate(email.bodyText, MAX_PROMPT_BODY_CHARS)),
    senderDomain,
    // The display name's *shape* is what matters for impersonation, not the name itself.
    senderNameShape: describeNameShape(email.senderName ?? ''),
    ...(replyToDomain !== '' && replyToDomain !== senderDomain ? { replyToDomain } : {}),
    linkDomains: [
      ...new Set(
        email.links
          .map((l) => registrableDomain(l.normalizedDomain))
          .filter((d) => d !== ''),
      ),
    ].slice(0, 25),
    attachmentExtensions: [
      ...new Set(email.attachments.map((a) => a.extension.toLowerCase()).filter((e) => e !== '')),
    ].slice(0, 15),
    deterministicSignalIds: [...deterministicSignalIds].slice(0, 40),
  };
}

/**
 * Replaces email addresses in body text with `<address@domain>`.
 *
 * The domain is retained because it is load-bearing for the analysis (a body that quotes a
 * mismatched address is a real signal); the local part is not.
 */
export function redactAddresses(text: string): string {
  return text.replace(/[\w.+-]+@([\w-]+(?:\.[\w-]+)+)/gu, (_match, domain: string) => {
    return `<address@${normalizeDomain(domain)}>`;
  });
}

/**
 * Describes a display name without revealing it: `"Jane Okonkwo"` → `"two-words"`,
 * `"Microsoft Account Team"` → `"three-words-brandlike"`.
 *
 * Enough for the backend to reason about impersonation shape, not enough to identify a person.
 */
export function describeNameShape(name: string): string {
  const trimmed = collapseWhitespace(name);
  if (trimmed === '') return 'empty';

  const words = trimmed.split(' ').filter((w) => w !== '');
  const parts: string[] = [`${countWord(words.length)}-word${words.length === 1 ? '' : 's'}`];

  if (/[<>@]/u.test(trimmed)) parts.push('contains-address');
  if (/^[A-Z\s]+$/u.test(trimmed) && trimmed.length > 3) parts.push('all-caps');
  if (/[^\p{ASCII}]/u.test(trimmed)) parts.push('non-ascii');
  if (/\b(team|support|service|security|admin|notification|alert|help ?desk|no-?reply)\b/iu.test(trimmed)) {
    parts.push('role-account');
  }
  return parts.join('-');
}

function countWord(n: number): string {
  const names = ['zero', 'one', 'two', 'three', 'four', 'five'];
  return names[n] ?? 'many';
}
