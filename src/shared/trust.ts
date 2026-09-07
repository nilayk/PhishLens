/**
 * Senders the user has said they trust.
 *
 * An allowlist is the most dangerous feature a phishing tool can have — the whole point of the attack is
 * to look like someone you trust — so the shape of this one is defensive by construction. Three rules,
 * each enforced here or by the single caller in `rules/index.ts` rather than by convention:
 *
 *  1. **Trust needs proof.** An entry only applies to a message Gmail could cryptographically tie to that
 *     domain (`isSenderProven`). Spoofing a trusted From address gains nothing, because the spoof is
 *     exactly what fails the check. Trust with no proof is reported, and ignored.
 *  2. **Trust never silences.** It feeds the existing dampening stage, which lowers the weight of
 *     *wording* findings and leaves every finding visible. It cannot remove a finding, and any real
 *     technical finding cancels it outright.
 *  3. **Trust is as narrow as the sender is.** A domain nobody in particular controls — Gmail, Outlook,
 *     a disposable mailbox — cannot be trusted as a domain at all, only as one address, because trusting
 *     `gmail.com` would mean trusting everybody.
 *
 * Pure, and importable from both the analysis engine and the UI: deciding whether to *offer* trust is a
 * UI question, deciding whether it *applies* is an analysis question, and both need the same answers.
 */
import { DISPOSABLE_DOMAINS, FREEMAIL_DOMAINS } from './public-suffix.js';
import { MAX_ENTRY_CHARS, MAX_TRUSTED_SENDERS, normalizeTrustList } from './settings.js';
import type { Classification, EmailAuthInfo } from './types.js';
import { addressDomain, registrableDomain, sameRegistrableDomain, normalizeDomain } from './url.js';

/**
 * What the user would be trusting for a given sender, or `null` when there is nothing safe to offer.
 *
 * A shared mailbox host gives an address; anything else gives the registrable domain, which is the unit a
 * single organisation actually controls. Deliberately *not* the full sending domain: mail from a real
 * organisation moves between `email.`, `mail.` and `notifications.` subdomains, and an entry that breaks
 * when it does would train the user to add three.
 */
export function trustEntryFor(senderEmail: string): string | null {
  const address = senderEmail.trim().toLowerCase();
  if (address === '' || !address.includes('@')) return null;
  if (address.length > MAX_ENTRY_CHARS) return null;

  const registrable = registrableDomain(addressDomain(address));
  if (registrable === '') return null;
  // A disposable-mailbox address is not a stable identity, so neither form of entry means anything.
  if (DISPOSABLE_DOMAINS.has(registrable)) return null;
  return FREEMAIL_DOMAINS.has(registrable) ? address : registrable;
}

/** The entry that covers this sender, or `undefined`. Matching is exact; there are no wildcards. */
export function matchingTrustEntry(
  trusted: readonly string[],
  senderEmail: string,
): string | undefined {
  const address = senderEmail.trim().toLowerCase();
  if (address === '') return undefined;
  const registrable = registrableDomain(addressDomain(address));

  return trusted.find((entry) =>
    entry.includes('@') ? entry === address : entry !== '' && entry === registrable,
  );
}

/**
 * Whether Gmail's own surfaces prove this message came from the sender's domain.
 *
 * Strict on purpose. DMARC passing means the message aligned with the From domain under a policy that
 * domain published, and an aligned DKIM signature means the domain signed the message itself. SPF alone
 * is not accepted: it authenticates the envelope rather than the From header, so it passes for mail that
 * merely *claims* the From address — which is the one case this function exists to exclude.
 *
 * Everything here is best-effort, because a content script reads rendered HTML rather than headers. An
 * absent details table therefore returns `false`, and trust simply does not apply. That is the safe
 * direction: the cost is a false positive the user has already seen, and the alternative is an allowlist
 * that works on unauthenticated mail.
 */
export function isSenderProven(auth: EmailAuthInfo | undefined, senderDomain: string): boolean {
  if (auth === undefined || senderDomain === '') return false;
  if (auth.spf === 'fail' || auth.dkim === 'fail' || auth.dmarc === 'fail') return false;
  if (auth.dmarc === 'pass') return true;

  const signedBy = normalizeDomain(auth.signedBy ?? '');
  return auth.dkim === 'pass' && signedBy !== '' && sameRegistrableDomain(signedBy, senderDomain);
}

/**
 * What the card says about trust for the message on screen.
 *
 * `offer` is withheld above `caution` deliberately: the moment to add a sender to an allowlist is not
 * while looking at a message the tool has just called suspicious, and a button there would be the one
 * click an attacker most wants.
 */
export type TrustState =
  /** Trusted, and Gmail proved this message really came from that sender. */
  | { kind: 'trusted'; entry: string }
  /** Trusted, but nothing proved this message's origin, so the trust was not applied to this score. */
  | { kind: 'unproven'; entry: string }
  | { kind: 'offer'; entry: string }
  | { kind: 'none' };

export function trustState(
  trusted: readonly string[],
  senderEmail: string,
  auth: EmailAuthInfo | undefined,
  classification: Classification,
): TrustState {
  const existing = matchingTrustEntry(trusted, senderEmail);
  const proven = isSenderProven(auth, addressDomain(senderEmail));

  if (existing !== undefined) {
    return proven ? { kind: 'trusted', entry: existing } : { kind: 'unproven', entry: existing };
  }

  if (!proven) return { kind: 'none' };
  if (classification !== 'low' && classification !== 'caution') return { kind: 'none' };
  if (trusted.length >= MAX_TRUSTED_SENDERS) return { kind: 'none' };

  const entry = trustEntryFor(senderEmail);
  return entry === null ? { kind: 'none' } : { kind: 'offer', entry };
}

/** Adds an entry, keeping the list normalised and bounded. Returns the list unchanged if it is full. */
export function withTrustedSender(trusted: readonly string[], entry: string): string[] {
  return normalizeTrustList([...trusted, entry]);
}

export function withoutTrustedSender(trusted: readonly string[], entry: string): string[] {
  const target = entry.trim().toLowerCase();
  return trusted.filter((existing) => existing !== target);
}
