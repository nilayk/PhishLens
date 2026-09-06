/**
 * Authentication detectors, based on what Gmail chooses to render.
 *
 * Important caveat, and the reason the `authentication` weight is 15 rather than the 30 the brief
 * suggested: a content script sees the DOM, not RFC 5322 headers. There is no way to read
 * `Authentication-Results` directly. Everything here is inferred from Gmail's own surfaces — the
 * "mailed-by"/"signed-by" details table, the `via` annotation, the unauthenticated-sender indicator,
 * and Gmail's red warning banner — all of which are frequently absent.
 *
 * So these detectors are written to be **silent when uncertain**. An absent SPF result produces no
 * signal, because "Gmail did not render a details table" is not evidence of anything.
 */
import { brandOwningDomain } from '../../shared/brands.js';
import type { AuthVerdict, SecuritySignal } from '../../shared/types.js';
import {
  isKnownTrackingRedirector,
  normalizeDomain,
  registrableDomain,
  sameRegistrableDomain,
} from '../../shared/url.js';
import type { AnalysisContext } from '../context.js';
import { signal } from './types.js';
import type { Detect } from './types.js';

function isFailure(verdict: AuthVerdict | undefined): boolean {
  return verdict === 'fail' || verdict === 'softfail';
}

/** Gmail reported an outright authentication failure. */
function authenticationFailure(context: AnalysisContext): SecuritySignal[] {
  const auth = context.email.auth;
  if (auth === undefined) return [];

  const failed: string[] = [];
  if (isFailure(auth.spf)) failed.push(`SPF (${auth.spf ?? ''})`);
  if (isFailure(auth.dkim)) failed.push(`DKIM (${auth.dkim ?? ''})`);
  if (isFailure(auth.dmarc)) failed.push(`DMARC (${auth.dmarc ?? ''})`);
  if (failed.length === 0) return [];

  // Deliberately `high` rather than `critical`, even though a hard SPF/DKIM failure looks conclusive.
  // Legitimate mail fails these routinely: forwarding breaks SPF, and mailing lists that rewrite a
  // subject line break DKIM. Since `critical` establishes a high-risk score floor on its own
  // (scoring/config.ts), treating every forwarded message as high risk would be the single largest
  // source of false positives in the product.
  return [
    signal({
      id: 'authentication.failure',
      category: 'authentication',
      severity: 'high',
      score: 35,
      title: 'Sender authentication failed',
      description: `Gmail reports that ${failed.join(' and ')} did not pass for this message. That means the sending server was not authorised to send mail for ${context.senderDomain === '' ? 'the sender\u2019s domain' : context.senderDomain}, so the From address cannot be trusted.`,
      evidence: { value: failed.join(', ') },
    }),
  ];
}

/**
 * The DKIM signing domain is unrelated to the From domain.
 *
 * Not automatically bad — plenty of legitimate senders sign as their ESP — but when the message also
 * claims a major brand, a signature from an unrelated domain is meaningful.
 */
function signingDomainMismatch(context: AnalysisContext): SecuritySignal[] {
  const auth = context.email.auth;
  const signedBy = normalizeDomain(auth?.signedBy ?? '');
  if (signedBy === '' || context.senderDomain === '') return [];
  if (sameRegistrableDomain(signedBy, context.senderDomain)) return [];

  const signerRegistrable = registrableDomain(signedBy);
  const fromOwner = brandOwningDomain(context.senderRegistrable);
  const signerOwner = brandOwningDomain(signerRegistrable);
  if (fromOwner !== undefined && fromOwner.id === signerOwner?.id) return [];

  // A brand's own domain sending through a recognised bulk-mail platform, which signs with its own
  // domain by design. The mismatch carries no information here, and reporting it at `medium` used to be
  // enough to block the false-positive dampening on exactly the mail that dampening exists for.
  if (fromOwner !== undefined && isKnownTrackingRedirector(signedBy)) return [];

  const claimsBrand = context.primaryClaim !== undefined;

  return [
    signal({
      id: 'authentication.signing_domain_mismatch',
      category: 'authentication',
      severity: claimsBrand ? 'medium' : 'low',
      score: claimsBrand ? 20 : 8,
      title: 'Message was signed by a domain unrelated to the sender',
      description: `The message is cryptographically signed by ${signerRegistrable}, not by ${context.senderRegistrable}. Mail providers and marketing platforms legitimately sign on a customer's behalf, so this alone is not conclusive${claimsBrand ? `, but a message presenting itself as ${context.primaryClaim?.brand.label ?? ''} would normally be signed by that organisation` : ''}.`,
      evidence: { value: `From ${context.senderRegistrable} · signed by ${signerRegistrable}` },
    }),
  ];
}

/** Gmail's `via` annotation, shown when the sending host is not the From domain. */
function sentViaUnrelatedHost(context: AnalysisContext): SecuritySignal[] {
  const via = normalizeDomain(context.email.auth?.via ?? '');
  if (via === '' || context.senderDomain === '') return [];
  if (sameRegistrableDomain(via, context.senderDomain)) return [];

  const viaRegistrable = registrableDomain(via);
  const claimsBrand = context.primaryClaim !== undefined;
  const brandClaimedButSentElsewhere =
    claimsBrand && !(context.primaryClaim?.brand.domains.includes(viaRegistrable) ?? false);

  // Almost all commercial mail is relayed through an ESP. When the relay is a recognised bulk-mail
  // platform and the message is not claiming to be a brand that would not use one, this is the
  // expected state of the world and reporting it is noise.
  if (!brandClaimedButSentElsewhere && isKnownTrackingRedirector(via)) return [];

  return [
    signal({
      id: 'authentication.via_unrelated_host',
      category: 'authentication',
      severity: brandClaimedButSentElsewhere ? 'medium' : 'low',
      score: brandClaimedButSentElsewhere ? 18 : 8,
      title: 'Message was relayed through an unrelated service',
      description: `Gmail shows this message as sent via ${viaRegistrable} rather than directly from ${context.senderRegistrable}. Bulk-mail services legitimately appear here${brandClaimedButSentElsewhere ? `, but the message presents itself as ${context.primaryClaim?.brand.label ?? ''}, which does not use this sender` : ''}.`,
      evidence: { value: viaRegistrable },
    }),
  ];
}

/** Gmail explicitly told the user something is wrong. Its own signal deserves to be surfaced. */
function gmailOwnWarning(context: AnalysisContext): SecuritySignal[] {
  const warning = context.email.auth?.gmailWarning;
  if (warning === undefined || warning.trim() === '') return [];

  return [
    signal({
      id: 'authentication.gmail_warning',
      category: 'authentication',
      severity: 'high',
      score: 30,
      title: 'Gmail displayed its own warning banner for this message',
      description:
        'Gmail flagged this message in its own interface. Gmail applies checks this extension cannot — including reputation data and account history — so its warning is independent corroboration.',
      evidence: { text: warning },
    }),
  ];
}

/** Gmail could not verify who sent the message (the `?` avatar). */
function unauthenticatedSender(context: AnalysisContext): SecuritySignal[] {
  if (context.email.auth?.unauthenticatedIndicator !== true) return [];
  // Suppressed when a hard failure was already reported, to avoid saying the same thing twice.
  if (isFailure(context.email.auth.spf) || isFailure(context.email.auth.dkim)) return [];

  return [
    signal({
      id: 'authentication.unverified_sender',
      category: 'authentication',
      severity: 'medium',
      score: 20,
      title: 'Gmail could not verify that the sender is who they claim to be',
      description: `Gmail shows this message as coming from an unverified sender, which means it could not confirm that ${context.senderDomain === '' ? 'the sending domain' : context.senderDomain} authorised it.`,
    }),
  ];
}

/**
 * Everything passed. Emitted as an `info` signal worth zero points so the panel can say so
 * explicitly — a security tool that only ever lists problems teaches users to distrust its silence.
 */
function authenticationPassed(context: AnalysisContext): SecuritySignal[] {
  const auth = context.email.auth;
  if (auth === undefined) return [];
  const anyChecked = auth.spf !== undefined || auth.dkim !== undefined || auth.dmarc !== undefined;
  if (!anyChecked) return [];
  const anyFailed = isFailure(auth.spf) || isFailure(auth.dkim) || isFailure(auth.dmarc);
  if (anyFailed) return [];
  const passed = [
    auth.spf === 'pass' ? 'SPF' : null,
    auth.dkim === 'pass' ? 'DKIM' : null,
    auth.dmarc === 'pass' ? 'DMARC' : null,
  ].filter((v): v is string => v !== null);
  if (passed.length === 0) return [];

  return [
    signal({
      id: 'authentication.passed',
      category: 'authentication',
      severity: 'info',
      score: 0,
      title: `Sender authentication passed (${passed.join(', ')})`,
      description: `${passed.join(', ')} verified for ${context.senderDomain === '' ? 'the sending domain' : context.senderDomain}. This confirms the message really was sent by that domain — it does not confirm that the domain belongs to who it claims to be.`,
      evidence: { value: passed.join(', ') },
    }),
  ];
}

const authenticationDetectors: Detect[] = [
  authenticationFailure,
  signingDomainMismatch,
  sentViaUnrelatedHost,
  gmailOwnWarning,
  unauthenticatedSender,
  authenticationPassed,
] as const;

export function detectAuthenticationSignals(context: AnalysisContext): SecuritySignal[] {
  return authenticationDetectors.flatMap((detect) => detect(context));
}
