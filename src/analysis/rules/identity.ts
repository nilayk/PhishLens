/**
 * Sender / domain identity detectors.
 *
 * The question every rule here answers: *is the sender who the message says it is?* All of it is
 * decidable from strings — no judgement required — which is exactly why it belongs in rules rather
 * than in the LLM.
 */
import { BRANDS, brandOwningDomain } from '../../shared/brands.js';
import { FREEMAIL_DOMAINS } from '../../shared/public-suffix.js';
import type { SecuritySignal } from '../../shared/types.js';
import {
  hasPunycode,
  isIpHost,
  isKnownTrackingRedirector,
  isMalformedHost,
  normalizeDomain,
  sameRegistrableDomain,
} from '../../shared/url.js';
import {
  decodeIdnHost,
  editDistance,
  hasBidiOrInvisible,
  hasSuspiciousScriptMixing,
  scriptsUsed,
  skeleton,
} from '../../shared/unicode.js';
import { DETECTION_TUNING } from '../scoring/config.js';
import type { AnalysisContext } from '../context.js';
import { signal } from './types.js';
import type { Detect } from './types.js';

/**
 * The display name claims a brand, but the sending domain is not one that brand owns.
 *
 * This is the single highest-yield phishing signal in practice: `"Microsoft Account Team"
 * <security@notify-ms-alerts.com>`. Scoped to display name and local part rather than body text,
 * because "we accept PayPal" in a body is not an identity claim.
 */
function displayNameImpersonation(context: AnalysisContext): SecuritySignal[] {
  const claim = context.claims.find(
    (c) => c.source === 'sender-name' || c.source === 'sender-local-part',
  );
  if (claim === undefined) return [];
  if (context.senderRegistrable === '') return [];
  if (claim.brand.domains.includes(context.senderRegistrable)) return [];

  // A brand's own domain sending mail that mentions another brand is not impersonation
  // (e.g. LinkedIn mail referencing Microsoft).
  const owner = brandOwningDomain(context.senderRegistrable);
  if (owner?.id === claim.brand.id) return [];

  const viaFreemail = context.senderIsFreemail;
  return [
    signal({
      id: 'identity.display_name_impersonation',
      category: 'identity',
      severity: viaFreemail ? 'critical' : 'high',
      score: viaFreemail ? 40 : 30,
      title: `Sender name claims ${claim.brand.label}, but the domain is unrelated`,
      description: viaFreemail
        ? `The sender presents itself as ${claim.brand.label} but the message was sent from a consumer mailbox at ${context.senderRegistrable}. ${claim.brand.label} does not send business mail from free email providers.`
        : `The sender presents itself as ${claim.brand.label}, but ${context.senderRegistrable} is not a domain owned by ${claim.brand.label}.`,
      evidence: {
        text: context.senderName !== '' ? context.senderName : context.senderEmail,
        value: context.senderRegistrable,
      },
    }),
  ];
}

/**
 * The sender's own domain is a near-miss of a real brand domain: `paypa1.com`, `micros0ft.com`,
 * `arnazon.com`. Uses confusable folding first (catches homoglyph and character substitution) and
 * bounded edit distance second (catches insertion/deletion/transposition).
 */
function lookalikeSenderDomain(context: AnalysisContext): SecuritySignal[] {
  if (context.senderRegistrable === '') return [];
  const match = findLookalike(context.senderRegistrable);
  if (match === null) return [];

  return [
    signal({
      id: 'identity.lookalike_sender_domain',
      category: 'identity',
      severity: 'critical',
      score: 45,
      title: `Sender domain imitates ${match.brandLabel}`,
      description: `The message was sent from ${context.senderRegistrable}, which is a near-identical imitation of the legitimate domain ${match.target}${match.kind === 'confusable' ? ' using visually similar characters' : ''}. It is not owned by ${match.brandLabel}.`,
      evidence: { value: `${context.senderRegistrable} vs ${match.target}` },
    }),
  ];
}

export interface LookalikeMatch {
  target: string;
  brandLabel: string;
  kind: 'confusable' | 'edit-distance';
  distance: number;
}

/**
 * Compares a registrable domain against every known brand domain.
 *
 * Exported because the link detectors need exactly the same comparison — one implementation means
 * a link and a sender are judged by the same standard.
 */
export function findLookalike(candidate: string): LookalikeMatch | null {
  const domain = normalizeDomain(candidate);
  if (domain === '' || isIpHost(domain)) return null;

  // An exact match against a real brand domain is the opposite of a lookalike.
  if (brandOwningDomain(domain) !== undefined) return null;

  const rendered = decodeIdnHost(domain);
  const candidateSkeleton = skeleton(stripTld(rendered));

  let best: LookalikeMatch | null = null;

  for (const brand of BRANDS) {
    for (const target of brand.lookalikeTargets) {
      const targetCore = stripTld(target);
      const targetSkeleton = skeleton(targetCore);
      if (targetSkeleton.length < 4) continue;

      // Identical after folding, which covers both a visual substitution (`pаypal`, `paypa1`,
      // `rnicrosoft`) and the same core under a different TLD (`paypal.co`), since the TLD is stripped
      // from both sides before comparison.
      if (candidateSkeleton === targetSkeleton) {
        return { target, brandLabel: brand.label, kind: 'confusable', distance: 0 };
      }

      const distance = editDistance(
        candidateSkeleton,
        targetSkeleton,
        DETECTION_TUNING.lookalikeMaxEditDistance,
      );
      if (distance > DETECTION_TUNING.lookalikeMaxEditDistance) continue;

      // Guard against short-name false positives: an edit distance of 2 is meaningless on a
      // 5-character name, where unrelated words collide constantly.
      const minLength = Math.min(candidateSkeleton.length, targetSkeleton.length);
      if (distance > 1 && minLength < 8) continue;
      if (minLength < 5) continue;

      if (best === null || distance < best.distance) {
        best = { target, brandLabel: brand.label, kind: 'edit-distance', distance };
      }
    }
  }
  return best;
}

function stripTld(domain: string): string {
  const dot = domain.indexOf('.');
  return dot <= 0 ? domain : domain.slice(0, dot);
}

/**
 * A Reply-To pointing somewhere other than the From domain. Standard in business email compromise:
 * the message appears to come from a colleague, the reply goes to the attacker.
 */
function replyToMismatch(context: AnalysisContext): SecuritySignal[] {
  if (!context.hasReplyTo) return [];
  if (context.senderRegistrable === '' || context.replyToRegistrable === '') return [];
  if (sameRegistrableDomain(context.senderDomain, context.replyToDomain)) return [];

  // Legitimate senders route replies to a related brand domain or to an ESP. Same brand owner on
  // both sides is fine (e.g. From `@github.com`, Reply-To `@notifications.github.com`).
  const fromOwner = brandOwningDomain(context.senderRegistrable);
  const replyOwner = brandOwningDomain(context.replyToRegistrable);
  if (fromOwner !== undefined && fromOwner.id === replyOwner?.id) return [];

  const replyToFreemail = context.replyToRegistrable !== '' && isFreemail(context.replyToRegistrable);
  const senderIsCorporate = !context.senderIsFreemail && context.senderRegistrable !== '';

  return [
    signal({
      id: 'identity.reply_to_mismatch',
      category: 'identity',
      severity: replyToFreemail && senderIsCorporate ? 'high' : 'medium',
      score: replyToFreemail && senderIsCorporate ? 26 : 16,
      title: 'Replies would go to a different domain than the sender',
      description: replyToFreemail && senderIsCorporate
        ? `The message appears to come from ${context.senderRegistrable}, but replies are directed to a personal mailbox at ${context.replyToRegistrable}. This is the standard shape of a business email compromise attempt.`
        : `The From address is at ${context.senderRegistrable} but the Reply-To address is at ${context.replyToRegistrable}, so a reply would not reach the apparent sender.`,
      evidence: { value: `From ${context.senderDomain} → Reply-To ${context.replyToDomain}` },
    }),
  ];
}

function isFreemail(registrable: string): boolean {
  return FREEMAIL_DOMAINS.has(registrable);
}

/** Punycode or mixed scripts in the sender's own domain. */
function senderDomainUnicodeSpoofing(context: AnalysisContext): SecuritySignal[] {
  const domain = context.senderDomain;
  if (domain === '') return [];
  const signals: SecuritySignal[] = [];

  if (hasPunycode(domain)) {
    const rendered = decodeIdnHost(domain);
    const labels = rendered.split('.');
    const mixed = labels.some((l) => hasSuspiciousScriptMixing(l));
    signals.push(
      signal({
        id: 'identity.sender_punycode_domain',
        category: 'identity',
        severity: mixed ? 'critical' : 'high',
        score: mixed ? 40 : 24,
        title: 'Sender domain uses an internationalised (punycode) name',
        description: mixed
          ? `The sender's domain renders as "${rendered}" but is actually ${domain}. It mixes characters from ${scriptsUsed(rendered).join(' and ')} scripts, which is how a domain is made to look like a familiar one while being entirely different.`
          : `The sender's domain ${domain} renders as "${rendered}". Internationalised domains are legitimate, but they are also the standard way to imitate a familiar name.`,
        evidence: { value: `${rendered} (${domain})` },
      }),
    );
  }

  if (hasBidiOrInvisible(context.senderName) || hasBidiOrInvisible(context.senderEmail)) {
    signals.push(
      signal({
        id: 'identity.sender_invisible_characters',
        category: 'identity',
        severity: 'high',
        score: 24,
        title: 'Sender name contains hidden or direction-changing characters',
        description:
          'The sender name or address contains zero-width or text-direction characters. These are invisible when rendered and are used to disguise what the address actually is.',
        evidence: { text: context.senderName },
      }),
    );
  }

  return signals;
}

/**
 * The sender's domain is structurally implausible: an IP literal, a bare label, or a hostname that
 * cannot exist publicly.
 */
function malformedSenderDomain(context: AnalysisContext): SecuritySignal[] {
  const domain = context.senderDomain;
  if (domain === '') {
    // Only report when we had an address at all; a message with no readable sender is an extraction
    // gap, not a finding.
    if (context.senderEmail === '') return [];
    return [
      signal({
        id: 'identity.unparseable_sender',
        category: 'identity',
        severity: 'low',
        score: 8,
        title: 'Sender address could not be parsed',
        description: `The sender address "${context.senderEmail}" is not a well-formed email address.`,
        evidence: { value: context.senderEmail },
      }),
    ];
  }

  if (isIpHost(domain)) {
    return [
      signal({
        id: 'identity.sender_ip_domain',
        category: 'identity',
        severity: 'high',
        score: 28,
        title: 'Sender address uses a raw IP address instead of a domain',
        description: `The sender's address resolves to the literal host ${domain}. Legitimate organisations send mail from named domains, not bare IP addresses.`,
        evidence: { value: domain },
      }),
    ];
  }

  if (isMalformedHost(domain)) {
    return [
      signal({
        id: 'identity.malformed_sender_domain',
        category: 'identity',
        severity: 'medium',
        score: 18,
        title: 'Sender domain is malformed',
        description: `The sender's domain "${domain}" is not a valid public hostname.`,
        evidence: { value: domain },
      }),
    ];
  }
  return [];
}

/**
 * A brand name buried in the subdomain or local part while the actual registrable domain is
 * something else: `security@microsoft.com.account-verify.example`, `paypal-support@srv12.example`.
 */
function brandInWrongPosition(context: AnalysisContext): SecuritySignal[] {
  if (context.senderRegistrable === '') return [];
  if (brandOwningDomain(context.senderRegistrable) !== undefined) return [];

  const subdomain = context.senderDomain.slice(
    0,
    Math.max(0, context.senderDomain.length - context.senderRegistrable.length - 1),
  );
  if (subdomain === '') return [];

  const foldedSub = skeleton(subdomain);
  for (const brand of BRANDS) {
    for (const domain of brand.domains) {
      const folded = skeleton(domain);
      if (folded.length >= 6 && foldedSub.includes(folded)) {
        return [
          signal({
            id: 'identity.brand_domain_in_subdomain',
            category: 'identity',
            severity: 'critical',
            score: 40,
            title: `Sender domain embeds ${brand.label}'s domain as a subdomain`,
            description: `The address looks like ${brand.label} at a glance, but "${domain}" appears only in the subdomain. The domain that actually controls this mail is ${context.senderRegistrable}.`,
            evidence: { value: context.senderDomain },
          }),
        ];
      }
    }
  }
  return [];
}

/** A sender at a disposable / throwaway mailbox provider. */
function disposableSender(context: AnalysisContext): SecuritySignal[] {
  if (!context.senderIsDisposable) return [];
  return [
    signal({
      id: 'identity.disposable_sender_domain',
      category: 'identity',
      severity: 'high',
      score: 26,
      title: 'Sender uses a disposable email service',
      description: `${context.senderRegistrable} provides temporary throwaway mailboxes. Legitimate correspondence does not originate from these.`,
      evidence: { value: context.senderRegistrable },
    }),
  ];
}

/**
 * Excessive subdomain nesting in the sender's domain, e.g.
 * `mail.secure.login.verify.account.example.com`.
 */
function suspiciousSenderSubdomainStructure(context: AnalysisContext): SecuritySignal[] {
  const domain = context.senderDomain;
  if (domain === '' || isIpHost(domain)) return [];
  const registrable = context.senderRegistrable;
  if (domain === registrable) return [];
  const labels = domain.slice(0, domain.length - registrable.length - 1).split('.');
  if (labels.length <= DETECTION_TUNING.maxReasonableSubdomainLabels) return [];

  return [
    signal({
      id: 'identity.sender_deep_subdomain',
      category: 'identity',
      severity: 'low',
      score: 10,
      title: 'Sender domain has an unusually deep subdomain structure',
      description: `The sender's hostname has ${String(labels.length)} subdomain levels beneath ${registrable}. Deep nesting is used to push a recognisable word into the visible part of an address.`,
      evidence: { value: domain },
    }),
  ];
}

/**
 * The message claims to be from an executive at the recipient's own organisation, but arrives from
 * outside it. The classic wire-transfer / gift-card precursor.
 */
function externalExecutiveClaim(context: AnalysisContext): SecuritySignal[] {
  const recipientDomain = context.recipientRegistrable;
  if (recipientDomain === '' || context.senderRegistrable === '') return [];
  if (recipientDomain === context.senderRegistrable) return [];
  if (!context.senderIsFreemail) return [];

  const execPattern =
    /\b(ceo|cfo|coo|cto|chief executive|chief financial|managing director|president|vice president|vp of|head of finance|chairman|founder)\b/u;
  const nameOrSubject = `${context.senderName} ${context.subject}`.toLowerCase();
  if (!execPattern.test(nameOrSubject) && !execPattern.test(context.matchText.slice(0, 500))) return [];

  return [
    signal({
      id: 'identity.external_executive_claim',
      category: 'identity',
      severity: 'high',
      score: 28,
      title: 'Claims to be a company executive but was sent from an outside personal account',
      description: `The message presents itself as coming from a senior member of staff, but it was sent from ${context.senderRegistrable} rather than ${recipientDomain}. Impersonating an executive from a personal mailbox is the opening move of most invoice and gift-card fraud.`,
      evidence: { text: context.senderName, value: context.senderEmail },
    }),
  ];
}

/**
 * The display name asserts an *institutional* identity that the sending domain does not support.
 *
 * Every other impersonation rule is gated on `BRANDS`, and no table will ever hold every insurer, bank,
 * utility and agency — so `"Fidelity Life Offer" <…@mt50sys.com>` scored zero on identity. This asks a
 * brand-list-free question: does the display name share any name with the domain that sent it?
 * `"Kestrel Coffee Roasters" <hello@kestrelcoffee.co.uk>` does; the Fidelity example does not.
 *
 * Scoped narrowly to stay out of ordinary mail: the name must assert an organisation rather than a
 * person, known-brand claims are left to `displayNameImpersonation`, brand-owned domains may call
 * themselves what they like, and a recognised relay (`<no-reply@sendgrid.net>`) is a third-party sender
 * rather than an impersonation.
 */
function unsupportedOrganizationalClaim(context: AnalysisContext): SecuritySignal[] {
  if (context.senderName === '' || context.senderRegistrable === '') return [];
  if (context.primaryClaim !== undefined) return [];
  // A brand's own domain may call itself whatever it likes. Freemail is the exception: `gmail.com` is
  // Google-owned, but a Gmail *mailbox* is not Google, and exempting it here would exempt every
  // consumer mailbox — the single most important case this rule exists to catch.
  if (context.senderOwnedByBrand !== undefined && !context.senderIsFreemail) return [];
  if (isKnownTrackingRedirector(context.senderDomain)) return [];
  if (!ORGANISATION_MARKER.test(context.senderName.toLowerCase())) return [];

  const nameTokens = organisationNameTokens(context.senderName);
  if (nameTokens.length === 0) return [];

  const domainTokens = senderDomainTokens(context.senderDomain);
  // Any lexical relationship at all clears the check. This is deliberately generous: the finding is
  // "shares *no* name with the sender", so a partial match is enough to stay quiet.
  const related = nameTokens.some((name) =>
    domainTokens.some((domain) => domain.includes(name) || name.includes(domain)),
  );
  if (related) return [];

  // Escalation is reserved for claims that a *regulated or official* body is writing from a consumer
  // mailbox, which does not happen. The softer markers do not escalate: a sports club or a sole trader
  // legitimately sends "… Team" mail from Gmail, and flagging that `high` would trip the severity
  // floor and report ordinary mail as suspicious.
  const institutional =
    context.senderIsFreemail && INSTITUTIONAL_MARKER.test(context.senderName.toLowerCase());

  return [
    signal({
      id: 'identity.unsupported_org_claim',
      category: 'identity',
      severity: institutional ? 'high' : 'medium',
      score: institutional ? 26 : 18,
      title: institutional
        ? 'Sender claims to be a financial institution but wrote from a personal mailbox'
        : 'Sender name claims an organisation unrelated to the sending domain',
      description: institutional
        ? `The message presents itself as "${context.senderName}", but it was sent from a personal mailbox at ${context.senderRegistrable}. Banks, insurers and payment providers do not send mail from free email providers.`
        : `The message presents itself as "${context.senderName}", but it was sent from ${context.senderRegistrable}, which shares no name with it. Legitimate organisations send from a domain recognisably their own.`,
      evidence: { text: context.senderName, value: context.senderRegistrable },
    }),
  ];
}

/**
 * Words that make a display name an *institutional* claim rather than a person or a product.
 *
 * Kept to terms that assert an organisation or an official function, since those are what confer the
 * borrowed authority this rule is about.
 */
const ORGANISATION_MARKER =
  /\b(inc|llc|ltd|limited|corp|corporation|company|group|holdings|team|support|helpdesk|help desk|services?|notifications?|alerts?|billing|invoices?|payments?|payroll|security|accounts?|offers?|quotes?|rewards?|benefits|insurance|assurance|bank|banking|credit union|financial|finance|capital|mortgage|lending|loans?|claims?|customer (care|service|support)|no.?reply)\b/u;

/**
 * The subset of markers naming a body that is regulated, official, or handles money directly. These
 * never legitimately correspond to a free mailbox, which is what makes escalation safe.
 */
const INSTITUTIONAL_MARKER =
  /\b(bank|banking|credit union|insurance|assurance|financial|finance|mortgage|lending|loans?|capital|billing|invoices?|payments?|payroll|claims?|security)\b/u;

/**
 * Generic words carrying no identity: they say nothing about *which* organisation this is, so a
 * domain not containing them is unremarkable.
 */
const GENERIC_NAME_TOKENS: ReadonlySet<string> = new Set([
  'team', 'support', 'service', 'services', 'notification', 'notifications', 'alert', 'alerts',
  'billing', 'invoice', 'invoices', 'payment', 'payments', 'payroll', 'security', 'account',
  'accounts', 'offer', 'offers', 'quote', 'quotes', 'reward', 'rewards', 'benefit', 'benefits',
  'customer', 'care', 'helpdesk', 'reply', 'noreply', 'mail', 'email', 'info', 'news', 'newsletter',
  'online', 'official', 'department', 'group', 'company', 'limited', 'corp', 'corporation',
  'holdings', 'from', 'your', 'the', 'and', 'for', 'plans', 'plan',
]);

/** Identity-bearing words in a display name. */
function organisationNameTokens(name: string): string[] {
  return name
    .toLowerCase()
    .split(/[^\p{L}\p{N}]+/u)
    .filter((token) => token.length >= 4 && !GENERIC_NAME_TOKENS.has(token));
}

/** Comparable words in a sending domain, including subdomains, with and without digits. */
function senderDomainTokens(domain: string): string[] {
  const tokens = new Set<string>();
  for (const label of domain.split(/[.\-_]+/u)) {
    if (label.length >= 4) tokens.add(label);
    const letters = label.replace(/\p{N}+/gu, '');
    if (letters.length >= 4) tokens.add(letters);
  }
  return [...tokens];
}

/**
 * The sender's local part is not a plausible mailbox name.
 *
 * `DoNoT.rEpLy.DoNoT.rEpLy.DoNoT.rEpLy.DoNoT.rEpLy@…` is a real example. Repeating a token several
 * times is a bulk-sender fingerprint — it pads the address and varies it per send — and it does not
 * occur in mail from an organisation that runs its own mail properly.
 *
 * Only *structural* implausibility counts. Long opaque local parts are not enough on their own: ESP
 * bounce addresses like `bounces+124987-abcd-user=example.com@…` are long, random and entirely
 * legitimate, so length alone is deliberately not a trigger.
 */
function implausibleSenderLocalPart(context: AnalysisContext): SecuritySignal[] {
  const local = context.senderLocalPart;
  if (local.length < 12) return [];

  const repeats = repeatedUnitCount(local);
  if (repeats < DETECTION_TUNING.minRepeatedLocalPartUnits) return [];

  return [
    signal({
      id: 'identity.implausible_local_part',
      category: 'identity',
      severity: 'medium',
      score: 16,
      title: 'Sender address repeats the same fragment several times',
      description: `The part of the address before the @ repeats the same fragment ${String(repeats)} times. Mailboxes are not named this way; it is a pattern used to pad and vary a sending address across a bulk campaign.`,
      evidence: { value: context.senderEmail },
    }),
  ];
}

/**
 * The sender's address uses randomised capitalisation: `DoNoT.rEpLy@…`.
 *
 * Alternating case is a filter-evasion technique — it varies the address per send and defeats naive
 * string blocklists — and it is essentially absent from mail sent by an organisation that runs its own
 * mail. It reads as normal to a human, because a mail client displays the display name.
 *
 * Reads `rawSenderLocalPart`, since the normalised address has been case-folded by then. This is one of
 * the two detectors that needs a pre-normalisation value at all.
 */
function randomisedAddressCase(context: AnalysisContext): SecuritySignal[] {
  const local = context.rawSenderLocalPart;
  if (local.length < 6) return [];

  const scrambled = local
    .split(/[^\p{L}\p{N}]+/u)
    .filter((token) => token.length >= 4 && isCaseScrambled(token));
  if (scrambled.length < DETECTION_TUNING.minScrambledCaseTokens) return [];

  return [
    signal({
      id: 'identity.randomised_address_case',
      category: 'identity',
      severity: 'medium',
      score: 14,
      title: 'Sender address uses randomised capitalisation',
      description: `The address alternates upper and lower case within words (${scrambled.slice(0, 3).join(', ')}). Mail systems treat addresses case-insensitively, so this changes nothing about delivery — it exists to vary the address between sends and slip past filters that match on exact text.`,
      evidence: { value: context.email.raw?.senderEmail ?? context.senderEmail },
    }),
  ];
}

/**
 * Whether a word alternates case rather than being CamelCase.
 *
 * Distinguished by **run length**, not by counting capitals: `DoNoT` is five single-character case runs
 * (average 1.0), while `MyCompanyName` and `JohnSmith` have long lowercase runs after each capital
 * (average above 2). Counting capitals alone would flag every CamelCase mailbox name.
 */
export function isCaseScrambled(token: string): boolean {
  if (!/\p{Ll}/u.test(token) || !/\p{Lu}/u.test(token)) return false;

  let runs = 1;
  for (let i = 1; i < token.length; i++) {
    const previous = token[i - 1] ?? '';
    const current = token[i] ?? '';
    if (isUpper(previous) !== isUpper(current)) runs++;
  }

  return runs >= 4 && token.length / runs < 1.5;
}

function isUpper(char: string): boolean {
  return /\p{Lu}/u.test(char);
}

/**
 * How many times a repeated unit makes up the local part, or 0 when there is no repetition.
 *
 * Checks separator-delimited repetition (`donot.reply.donot.reply`) and raw periodicity
 * (`donotreplydonotreply`), because the same trick appears in both forms.
 */
export function repeatedUnitCount(localPart: string): number {
  const tokens = localPart.split(/[._+\-]+/u).filter((t) => t.length >= 3);
  if (tokens.length >= 3) {
    const counts = new Map<string, number>();
    for (const token of tokens) counts.set(token, (counts.get(token) ?? 0) + 1);
    const most = Math.max(...counts.values());
    if (most >= 3) return most;
  }

  const compact = localPart.replace(/[^\p{L}\p{N}]+/gu, '');
  for (let unit = 3; unit <= Math.floor(compact.length / 3); unit++) {
    if (compact.length % unit !== 0) continue;
    const candidate = compact.slice(0, unit);
    const repeats = compact.length / unit;
    if (candidate.repeat(repeats) === compact) return repeats;
  }
  return 0;
}

/**
 * The sender's domain imitates the *recipient's own* domain.
 *
 * The brand table cannot help here — nobody's brand list contains the user's employer. But
 * `northwind-Iogistics.com` (capital I for lowercase l) targeting `northwind-logistics.com` is one
 * of the most effective attacks there is, because internal mail carries implicit trust. The
 * recipient's domain is derived from the mailbox the message was delivered to, so this works for any
 * organisation without configuration.
 */
function lookalikeOfRecipientDomain(context: AnalysisContext): SecuritySignal[] {
  const recipientDomain = context.recipientRegistrable;
  if (recipientDomain === '' || context.senderRegistrable === '') return [];
  if (recipientDomain === context.senderRegistrable) return [];
  if (FREEMAIL_DOMAINS.has(recipientDomain)) return [];

  const senderCore = skeleton(stripTld(decodeIdnHost(context.senderRegistrable)));
  const recipientCore = skeleton(stripTld(recipientDomain));
  if (recipientCore.length < 5) return [];

  const maxDistance = DETECTION_TUNING.lookalikeMaxEditDistance;
  const confusable = senderCore === recipientCore;
  const distance = confusable ? 0 : editDistance(senderCore, recipientCore, maxDistance);
  // One edit on a name of reasonable length is a deliberate near-miss, not a coincidence. Two is only
  // allowed on a long name, where unrelated words do not collide by chance.
  const nearMiss = distance <= (recipientCore.length >= 10 ? maxDistance : 1);
  if (!confusable && !nearMiss) return [];

  return [
    signal({
      id: 'identity.lookalike_of_recipient_domain',
      category: 'identity',
      severity: 'critical',
      score: 45,
      title: 'Sender domain imitates your own organisation’s domain',
      description: confusable
        ? `The message was sent from ${context.senderRegistrable}, which is visually indistinguishable from your own domain ${recipientDomain} but is a different domain under someone else's control. Mail that appears to be internal is trusted more readily, which is the point.`
        : `The message was sent from ${context.senderRegistrable}, a near-miss of your own domain ${recipientDomain}. It is not part of your organisation.`,
      evidence: { value: `${context.senderRegistrable} vs ${recipientDomain}` },
    }),
  ];
}

const identityDetectors: Detect[] = [
  displayNameImpersonation,
  unsupportedOrganizationalClaim,
  implausibleSenderLocalPart,
  randomisedAddressCase,
  lookalikeSenderDomain,
  lookalikeOfRecipientDomain,
  replyToMismatch,
  senderDomainUnicodeSpoofing,
  malformedSenderDomain,
  brandInWrongPosition,
  disposableSender,
  suspiciousSenderSubdomainStructure,
  externalExecutiveClaim,
] as const;

export function detectIdentitySignals(context: AnalysisContext): SecuritySignal[] {
  return identityDetectors.flatMap((detect) => detect(context));
}
