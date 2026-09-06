/**
 * End-to-end detection tests against fixtures.
 *
 * Runs the real pipeline — context building, every detector, refinement, aggregation, classification —
 * in plain Node with no Chrome and no Gmail.
 */
import { describe, expect, it } from 'vitest';
import { buildContext } from '../src/analysis/context.js';
import { analyzeDeterministic } from '../src/analysis/engine.js';
import { __testables as contentTestables } from '../src/analysis/rules/content.js';
import { __testables as adapterTestables } from '../src/gmail/dom-adapter.js';
import { isCaseScrambled, repeatedUnitCount } from '../src/analysis/rules/identity.js';
import { severityFloor } from '../src/analysis/scoring/aggregate.js';
import type { AnalysisResult, EmailMessage, SecuritySignal } from '../src/shared/types.js';
import { loadFixture, loadAllFixtures, toEmailLink } from './fixtures/load.js';

const LEGITIMATE_FIXTURES = [
  'legitimate',
  'legitimate-password-reset',
  'legitimate-newsletter',
  'legitimate-substack-newsletter',
  'legitimate-invoice',
];

const MALICIOUS_FIXTURES = [
  'paypal-phish',
  'microsoft-phish',
  'bec-gift-card',
  'payroll-change',
  'punycode-link',
  'ip-url',
  'executable-attachment',
  'mfa-code-request',
  'anchor-mismatch',
  'zip-attachment',
  'brand-spoof-leadgen',
];

const FIXED_NOW = 1_760_000_000_000;

function analyzeFixture(name: string): AnalysisResult {
  return analyzeDeterministic(loadFixture(name).email, { now: FIXED_NOW });
}

function ids(result: AnalysisResult): string[] {
  return result.signals.map((s) => s.id);
}

/** Matches exact ids and the `rule.name.<index>` form the per-link rules emit. */
function hasSignal(result: AnalysisResult, id: string): boolean {
  return result.signals.some((s) => s.id === id || s.id.startsWith(`${id}.`));
}

function signalFor(result: AnalysisResult, id: string): SecuritySignal | undefined {
  return result.signals.find((s) => s.id === id || s.id.startsWith(`${id}.`));
}

// ---------------------------------------------------------------------------
// Legitimate mail
// ---------------------------------------------------------------------------

describe('legitimate email', () => {
  const result = analyzeFixture('legitimate');

  it('scores low', () => {
    expect(result.score).toBeLessThan(25);
    expect(result.classification).toBe('low');
  });

  it('raises no identity, link, or content findings', () => {
    const scoring = result.signals.filter((s) => s.severity !== 'info');
    expect(scoring).toEqual([]);
  });

  it('still reports the positive authentication result for transparency', () => {
    expect(hasSignal(result, 'authentication.passed')).toBe(true);
    expect(signalFor(result, 'authentication.passed')?.score).toBe(0);
  });

  it('reports that the attachment is not suspicious rather than staying silent', () => {
    expect(hasSignal(result, 'attachment.none_suspicious')).toBe(true);
  });

  it('contributes nothing from the llm category', () => {
    expect(result.categoryScores.llm).toBe(0);
    expect(result.meta.semanticSource).toBe('none');
  });
});

describe('legitimate password reset (false-positive resistance)', () => {
  const result = analyzeFixture('legitimate-password-reset');

  it('scores low despite containing every credential-phishing keyword', () => {
    expect(result.score).toBeLessThan(25);
    expect(result.classification).toBe('low');
  });

  it('does not claim impersonation, because the sender really is PayPal', () => {
    expect(hasSignal(result, 'identity.display_name_impersonation')).toBe(false);
    expect(hasSignal(result, 'identity.lookalike_sender_domain')).toBe(false);
  });

  it('raises no link findings, because every link stays on paypal.com', () => {
    expect(result.categoryScores.link).toBe(0);
  });

  it('dampens rather than deletes the content observations', () => {
    // The wording *is* a credential-verification pattern; we say so, weighted down, rather than
    // pretending the pattern is absent. Users who cannot see why a score is low do not trust it.
    const content = result.signals.filter((s) => s.category === 'content' && s.severity !== 'info');
    expect(content.length).toBeGreaterThan(0);
    for (const s of content) {
      expect(s.description).toMatch(/[Ww]eighted down/u);
    }
  });

  it('scores dramatically lower than the identical wording from a lookalike domain', () => {
    // This is the real test of the dampening mechanism: hold the body constant and change only the
    // sender's domain and links. Nothing about the language differs.
    const genuine = loadFixture('legitimate-password-reset').email;
    const impostor = {
      ...genuine,
      senderEmail: 'service@paypal-account-recovery.com',
      links: genuine.links.map((l) => ({
        ...l,
        href: l.href.replace('www.paypal.com', 'paypal-account-recovery.com'),
        normalizedDomain: 'paypal-account-recovery.com',
      })),
    };
    const impostorResult = analyzeDeterministic(impostor, { now: FIXED_NOW });

    expect(impostorResult.score).toBeGreaterThan(result.score + 40);
    expect(impostorResult.categoryScores.content).toBeGreaterThan(result.categoryScores.content);
    expect(impostorResult.classification).toBe('high-risk');
  });
});

describe('legitimate newsletter with many links (false-positive resistance)', () => {
  const result = analyzeFixture('legitimate-newsletter');

  it('scores low', () => {
    expect(result.score).toBeLessThan(25);
    expect(result.classification).toBe('low');
  });

  it('does not fire the urgency heuristic on "last chance" / "ends tonight" marketing copy', () => {
    expect(hasSignal(result, 'content.urgency')).toBe(false);
  });

  it('does not treat 14 links as a link finding', () => {
    expect(result.categoryScores.link).toBe(0);
  });

  it('does not penalise the legitimate ESP relay', () => {
    const via = signalFor(result, 'authentication.via_unrelated_host');
    expect(via?.severity).not.toBe('high');
  });
});

describe('legitimate invoice (false-positive resistance)', () => {
  const result = analyzeFixture('legitimate-invoice');

  it('scores low', () => {
    expect(result.score).toBeLessThan(25);
    expect(result.classification).toBe('low');
  });

  it('does not flag the PDF attachment', () => {
    expect(hasSignal(result, 'attachment.executable')).toBe(false);
    expect(hasSignal(result, 'attachment.archive')).toBe(false);
    expect(hasSignal(result, 'attachment.none_suspicious')).toBe(true);
  });

  it('does not treat routine payment terms as payment fraud', () => {
    expect(hasSignal(result, 'content.payment_detail_change')).toBe(false);
    expect(hasSignal(result, 'content.wire_transfer')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Phishing
// ---------------------------------------------------------------------------

describe('obvious PayPal phishing', () => {
  const result = analyzeFixture('paypal-phish');

  it('scores high risk', () => {
    expect(result.score).toBeGreaterThanOrEqual(75);
    expect(result.classification).toBe('high-risk');
  });

  it('identifies the display-name impersonation', () => {
    expect(hasSignal(result, 'identity.display_name_impersonation')).toBe(true);
  });

  it('identifies the anchor text / destination mismatch', () => {
    expect(hasSignal(result, 'link.displayed_url_mismatch')).toBe(true);
  });

  it('identifies the Reply-To mismatch', () => {
    expect(hasSignal(result, 'identity.reply_to_mismatch')).toBe(true);
  });

  it('identifies the authentication failure', () => {
    expect(hasSignal(result, 'authentication.failure')).toBe(true);
  });

  it('identifies the account threat combined with a credential request', () => {
    expect(hasSignal(result, 'content.combo.threat_and_credential_request')).toBe(true);
  });

  it('reaches high risk on deterministic signals alone, with no llm contribution', () => {
    expect(result.categoryScores.llm).toBe(0);
    expect(result.classification).toBe('high-risk');
  });

  it('does not dampen anything, because technical findings are present', () => {
    for (const s of result.signals) {
      expect(s.description).not.toMatch(/[Ww]eighted down/u);
    }
  });
});

describe('Microsoft lookalike domain', () => {
  const result = analyzeFixture('microsoft-phish');

  it('scores high risk', () => {
    expect(result.score).toBeGreaterThanOrEqual(75);
    expect(result.classification).toBe('high-risk');
  });

  it('recognises rnicrosoft-online.com as imitating Microsoft', () => {
    const lookalike = signalFor(result, 'identity.lookalike_sender_domain');
    expect(lookalike).toBeDefined();
    expect(lookalike?.description).toContain('microsoft');
  });

  it('recognises microsoftonline.com placed in front of an unrelated domain', () => {
    expect(hasSignal(result, 'link.misleading_domain')).toBe(true);
    const misleading = signalFor(result, 'link.misleading_domain');
    expect(misleading?.evidence?.value).toContain('session-verify-portal.net');
  });

  it('explains that the controlling domain is the registrable one', () => {
    const misleading = signalFor(result, 'link.misleading_domain');
    expect(misleading?.description).toContain('session-verify-portal.net');
  });
});

describe('mismatched anchor URL in isolation', () => {
  const result = analyzeFixture('anchor-mismatch');

  it('fires the mismatch rule', () => {
    expect(hasSignal(result, 'link.displayed_url_mismatch')).toBe(true);
  });

  it('marks it critical because the displayed domain belongs to a real brand', () => {
    expect(signalFor(result, 'link.displayed_url_mismatch')?.severity).toBe('critical');
  });

  it('states both the shown and the actual destination', () => {
    const s = signalFor(result, 'link.displayed_url_mismatch');
    expect(s?.description).toContain('login.microsoftonline.com');
    expect(s?.description).toContain('account-verification.example');
  });

  it('carries the href as evidence so the UI can locate the link', () => {
    expect(signalFor(result, 'link.displayed_url_mismatch')?.evidence?.url).toBe(
      'https://account-verification.example/login?next=%2Fstatement',
    );
  });

  it('reaches at least suspicious on this single finding', () => {
    expect(result.score).toBeGreaterThanOrEqual(25);
  });
});

/**
 * Regression for a false positive seen in production. A Substack newsletter scored 50/100
 * "Suspicious": the platform rewrites every outbound link to its own redirector while leaving the
 * anchor text naming the destination site, which read as several `high` mismatches, maxed the link
 * category, and tripped the severity floor.
 *
 * The last test is the important one. The guard must not become a way to launder a brand claim by
 * pointing the link at your own domain, so it is asserted to yield when the *displayed* domain is a
 * brand's — the case where reputation is genuinely being borrowed.
 */
describe('click tracking on the sender own domain', () => {
  const result = analyzeFixture('legitimate-substack-newsletter');

  it('does not read the platform rewrite as a displayed/actual mismatch', () => {
    expect(hasSignal(result, 'link.displayed_url_mismatch')).toBe(false);
  });

  it('does not read the tracking wrapper as a concealed redirect', () => {
    expect(hasSignal(result, 'link.opaque_redirect')).toBe(false);
    expect(hasSignal(result, 'link.redirect_chain')).toBe(false);
  });

  it('stays low overall', () => {
    expect(result.classification).toBe('low');
  });

  /**
   * Isolates the guard from the tracker list. The platform here is deliberately unlisted, so the only
   * thing that can suppress the first case is `onSenderDomain` — and the second case, identical but
   * for the sender's domain, proves the rule still fires on the shape when nobody owns the redirector.
   */
  it('suppresses the rewrite only for the domain that sent the message', () => {
    const base = loadFixture('legitimate-substack-newsletter').email;
    const links = [
      toEmailLink({ text: 'sprudge.com', href: 'https://dripmail.example/redirect/9c1d4e2a' }),
      toEmailLink({ text: 'kestrelcoffee.co.uk', href: 'https://dripmail.example/redirect/3f8a1b90' }),
    ];

    const fromPlatform = analyzeDeterministic(
      { ...base, senderEmail: 'the-slow-drip@dripmail.example', links },
      { now: FIXED_NOW },
    );
    expect(hasSignal(fromPlatform, 'link.displayed_url_mismatch')).toBe(false);

    const fromElsewhere = analyzeDeterministic(
      { ...base, senderEmail: 'the-slow-drip@unrelated-sender.example', links },
      { now: FIXED_NOW },
    );
    expect(hasSignal(fromElsewhere, 'link.displayed_url_mismatch')).toBe(true);
    expect(signalFor(fromElsewhere, 'link.displayed_url_mismatch')?.severity).toBe('high');
  });

  it('still reports the mismatch when the displayed domain belongs to a brand', () => {
    const base = loadFixture('legitimate-substack-newsletter').email;
    const bait: EmailMessage = {
      ...base,
      senderName: 'Account Security',
      senderEmail: 'security@evil-example.com',
      subject: 'Unusual sign-in activity on your account',
      bodyText:
        'We detected an unusual sign-in attempt. Confirm your identity at login.microsoftonline.com within 24 hours or your account will be locked.',
      links: [
        toEmailLink({
          text: 'login.microsoftonline.com',
          href: 'https://evil-example.com/verify?id=8812',
        }),
      ],
    };

    const baited = analyzeDeterministic(bait, { now: FIXED_NOW });
    expect(hasSignal(baited, 'link.displayed_url_mismatch')).toBe(true);
    expect(signalFor(baited, 'link.displayed_url_mismatch')?.severity).toBe('critical');
  });
});

describe('punycode / homoglyph URL', () => {
  const result = analyzeFixture('punycode-link');

  it('flags the punycode link', () => {
    expect(hasSignal(result, 'link.punycode_domain')).toBe(true);
  });

  it('shows the rendered form alongside the real one', () => {
    const s = signalFor(result, 'link.punycode_domain');
    expect(s?.evidence?.value).toContain('xn--pypal-4ve.com');
    // Decoded form contains the Cyrillic а.
    expect(s?.evidence?.value).toMatch(/p\u0430ypal\.com/u);
  });

  it('also flags the punycode sender domain', () => {
    expect(hasSignal(result, 'identity.sender_punycode_domain')).toBe(true);
  });

  it('scores at least suspicious', () => {
    expect(result.score).toBeGreaterThanOrEqual(50);
  });
});

describe('IP-address URL', () => {
  const result = analyzeFixture('ip-url');

  it('flags the bare IP destination', () => {
    expect(hasSignal(result, 'link.ip_address_url')).toBe(true);
    expect(signalFor(result, 'link.ip_address_url')?.evidence?.value).toBe('185.234.219.14');
  });

  it('flags the unencrypted sign-in link', () => {
    expect(hasSignal(result, 'link.insecure_login')).toBe(true);
  });

  it('scores at least suspicious', () => {
    expect(result.score).toBeGreaterThanOrEqual(50);
  });
});

// ---------------------------------------------------------------------------
// Attachments
// ---------------------------------------------------------------------------

describe('suspicious ZIP attachment', () => {
  const result = analyzeFixture('zip-attachment');

  it('reports the archive', () => {
    expect(hasSignal(result, 'attachment.archive')).toBe(true);
  });

  it('escalates because a password for the archive is supplied in the body', () => {
    const s = signalFor(result, 'attachment.archive');
    expect(s?.severity).toBe('high');
    expect(s?.title).toContain('Password-protected');
  });

  it('does not let the attachment alone exceed the attachment category weight', () => {
    expect(result.categoryScores.attachment).toBeLessThanOrEqual(10);
  });

  it('does not reach high risk on an archive alone', () => {
    // A ZIP is a signal, not a verdict. The score here comes from the surrounding pretext too.
    expect(result.categoryScores.attachment).toBeLessThan(25);
  });
});

describe('executable attachments', () => {
  const result = analyzeFixture('executable-attachment');

  it('flags the double extension', () => {
    expect(hasSignal(result, 'attachment.double_extension')).toBe(true);
    expect(signalFor(result, 'attachment.double_extension')?.description).toContain('.exe');
  });

  it('flags the direction-override filename', () => {
    expect(hasSignal(result, 'attachment.filename_direction_override')).toBe(true);
  });

  it('flags the executables themselves', () => {
    expect(hasSignal(result, 'attachment.executable')).toBe(true);
  });

  it('scores high risk overall', () => {
    expect(result.classification).toBe('high-risk');
  });

  it('does not emit the "nothing suspicious" note', () => {
    expect(hasSignal(result, 'attachment.none_suspicious')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Social engineering
// ---------------------------------------------------------------------------

describe('executive gift-card scam', () => {
  const result = analyzeFixture('bec-gift-card');

  it('scores at least suspicious with no links and no attachments at all', () => {
    expect(result.score).toBeGreaterThanOrEqual(50);
    expect(result.categoryScores.link).toBe(0);
    expect(result.categoryScores.attachment).toBe(0);
  });

  it('recognises the gift-card request', () => {
    expect(hasSignal(result, 'content.gift_card')).toBe(true);
  });

  it('recognises the secrecy request', () => {
    expect(hasSignal(result, 'content.secrecy')).toBe(true);
  });

  it('recognises the combination as a single explained finding', () => {
    expect(hasSignal(result, 'content.combo.gift_card_with_secrecy')).toBe(true);
  });

  it('recognises the external executive claim', () => {
    expect(hasSignal(result, 'identity.external_executive_claim')).toBe(true);
  });

  it('recognises the availability probe and the channel steering', () => {
    expect(hasSignal(result, 'content.unusual_request_shape')).toBe(true);
    expect(hasSignal(result, 'content.process_bypass')).toBe(true);
  });
});

describe('fake payroll-change email', () => {
  const result = analyzeFixture('payroll-change');

  it('scores at least suspicious', () => {
    expect(result.score).toBeGreaterThanOrEqual(50);
  });

  it('recognises the payroll change request', () => {
    expect(hasSignal(result, 'content.payroll_change')).toBe(true);
  });

  it('recognises the request to change banking details', () => {
    expect(hasSignal(result, 'content.payment_detail_change')).toBe(true);
  });

  it('recognises the steer away from the HR portal', () => {
    expect(hasSignal(result, 'content.process_bypass')).toBe(true);
  });
});

describe('MFA code request', () => {
  const result = analyzeFixture('mfa-code-request');

  it('recognises the request for a verification code', () => {
    expect(hasSignal(result, 'content.mfa_request')).toBe(true);
  });

  it('recognises the pairing with a claimed security incident', () => {
    expect(hasSignal(result, 'content.combo.mfa_and_threat')).toBe(true);
  });

  it('recognises the sender domain as imitating the recipient’s own domain', () => {
    expect(hasSignal(result, 'identity.lookalike_of_recipient_domain')).toBe(true);
  });

  it('scores high risk', () => {
    expect(result.classification).toBe('high-risk');
  });
});

// ---------------------------------------------------------------------------
// Impersonation of organisations that are not in the brand table
// ---------------------------------------------------------------------------

/**
 * The regression this suite exists for.
 *
 * A real message impersonating Fidelity scored 24/100 — one point below `caution` — because every
 * identity detector was gated on the enumerated `BRANDS` table and Fidelity is not in it. No table
 * ever contains every insurer, bank, utility and agency, so identity detection cannot depend on one
 * being complete.
 */
describe('brand impersonation with no brand-table entry', () => {
  const result = analyzeFixture('brand-spoof-leadgen');

  it('scores at least suspicious', () => {
    expect(result.score).toBeGreaterThanOrEqual(50);
    expect(['suspicious', 'high-risk']).toContain(result.classification);
  });

  it('contributes identity findings without any brand-table entry', () => {
    expect(result.categoryScores.identity).toBeGreaterThan(0);
    expect(hasSignal(result, 'identity.display_name_impersonation')).toBe(false);
    expect(hasSignal(result, 'identity.unsupported_org_claim')).toBe(true);
  });

  it('explains the mismatch in terms of the name and the domain', () => {
    const s = signalFor(result, 'identity.unsupported_org_claim');
    expect(s?.description).toContain('Fidelity Life Offer');
    expect(s?.description).toContain('mt50sys.com');
  });

  it('flags the repeated fragment in the sender address', () => {
    expect(hasSignal(result, 'identity.implausible_local_part')).toBe(true);
    expect(signalFor(result, 'identity.implausible_local_part')?.description).toContain('4 times');
  });

  it('flags the evasion-formatted subject', () => {
    expect(hasSignal(result, 'content.subject_obfuscation')).toBe(true);
  });

  it('still reports the unencrypted links', () => {
    expect(hasSignal(result, 'link.insecure_http')).toBe(true);
  });

  /**
   * The score must come from more than one dimension. A single saturated category was exactly the
   * original failure: links alone reached 24/25 while everything else contributed nothing.
   */
  it('draws its score from identity and content, not links alone', () => {
    expect(result.categoryScores.link).toBeGreaterThan(0);
    expect(result.categoryScores.identity).toBeGreaterThan(0);
    expect(result.categoryScores.content).toBeGreaterThan(0);
    expect(result.score - result.categoryScores.link).toBeGreaterThanOrEqual(25);
  });
});

/**
 * Brand keywords are matched on separator-stripped text so `p-a-y-p-a-l` still reads as PayPal. The
 * cost is that a short keyword can hide inside an ordinary word once the spaces are gone: `irs` sits
 * in "first", `aws` in "laws". A claim invented that way is not cosmetic — it decides whether the
 * message is treated as presenting itself as that organisation.
 */
describe('short brand keywords inside ordinary words', () => {
  const claimsFor = (subject: string, bodyText: string, senderName = 'Dana Whitfield'): string[] =>
    buildContext({
      senderName,
      senderEmail: 'dana.whitfield@northwind-logistics.com',
      subject,
      bodyText,
      links: [],
      attachments: [],
    }).claims.map((claim) => claim.brand.id);

  it('does not read "first" in a subject as a claim to be the IRS', () => {
    expect(claimsFor('First quarter results', 'Figures for the first quarter are attached.')).toEqual(
      [],
    );
  });

  it('does not read "lawsuit" in a body as a claim to be AWS', () => {
    expect(claimsFor('Update', 'Counsel advised us on the lawsuit and its timeline.')).toEqual([]);
  });

  it('does not read "chairs" or "repairs" as an IRS mention', () => {
    expect(claimsFor('Office', 'The chairs need repairs before the stairs are refitted.')).toEqual([]);
  });

  it('still recognises a short keyword standing on its own', () => {
    expect(claimsFor('IRS notice CP2000', 'Reply with the details requested.')).toContain('irs');
  });

  it('still recognises a long keyword broken up with separators', () => {
    expect(claimsFor('Account review', 'Confirm your p-a-y-p-a-l details.')).toContain('paypal');
  });

  it('records a keyword in the display name as an identity claim, not a body mention', () => {
    const context = buildContext({
      senderName: 'PayPal Service',
      senderEmail: 'billing@mt50sys.com',
      subject: 'Invoice',
      bodyText: 'Paypal receipts are attached.',
      links: [],
      attachments: [],
    });
    expect(context.primaryClaim?.source).toBe('sender-name');
  });
});

/**
 * DKIM signatures from a sending platform are the norm for commercial mail. What matters is whether the
 * From domain is the brand's own: if it is, the mismatch says nothing, and reporting it at `medium` was
 * enough to suppress the dampening that keeps legitimate brand mail out of "caution".
 */
describe('confirmation wording that is not a credential ask', () => {
  const body = (bodyText: string): AnalysisResult =>
    analyzeDeterministic(
      {
        senderName: 'Harbour Coffee',
        senderEmail: 'orders@harbour-coffee-roasters.com',
        subject: 'Your order',
        bodyText,
        links: [],
        attachments: [],
      },
      { now: FIXED_NOW },
    );

  it('ignores a customer-service question phrased as a confirmation', () => {
    const result = body('Please confirm you are happy with your order and we will ship it today.');
    expect(hasSignal(result, 'content.credential_verification')).toBe(false);
  });

  it('still catches a confirmation of identity', () => {
    const result = body('Confirm this is really you to keep your account active.');
    expect(hasSignal(result, 'content.credential_verification')).toBe(true);
  });
});

describe('signatures from a sending platform', () => {
  const signedBy = (senderEmail: string, signer: string): AnalysisResult =>
    analyzeDeterministic(
      {
        senderName: 'PayPal',
        senderEmail,
        subject: 'Your password was changed',
        bodyText: 'You recently changed the password on your account. Sign in if this was not you.',
        links: [],
        attachments: [],
        auth: { spf: 'pass', dkim: 'pass', signedBy: signer },
      },
      { now: FIXED_NOW },
    );

  it('stays quiet when a brand own domain signs through a known platform', () => {
    const result = signedBy('service@paypal.com', 'sendgrid.net');
    expect(hasSignal(result, 'authentication.signing_domain_mismatch')).toBe(false);
  });

  it('still reports it when the From domain is not the brand at all', () => {
    const result = signedBy('service@paypal-secure-billing.com', 'sendgrid.net');
    expect(hasSignal(result, 'authentication.signing_domain_mismatch')).toBe(true);
  });

  it('still reports a signer that is neither the sender nor a known platform', () => {
    const result = signedBy('service@paypal.com', 'mt50sys.com');
    expect(hasSignal(result, 'authentication.signing_domain_mismatch')).toBe(true);
  });
});

describe('organisational-claim detector boundaries', () => {
  const base = loadFixture('brand-spoof-leadgen').email;

  const withSender = (name: string, email: string): AnalysisResult =>
    analyzeDeterministic({ ...base, senderName: name, senderEmail: email }, { now: FIXED_NOW });

  it('stays quiet when the display name shares a word with the domain', () => {
    const result = withSender('Kestrel Insurance Group', 'quotes@kestrelinsurance.com');
    expect(hasSignal(result, 'identity.unsupported_org_claim')).toBe(false);
  });

  it('stays quiet when the domain merely adds a suffix to the name', () => {
    const result = withSender('Northwind Benefits Team', 'no-reply@mail.northwind-hr.com');
    expect(hasSignal(result, 'identity.unsupported_org_claim')).toBe(false);
  });

  it('stays quiet for a personal name, which claims no institution', () => {
    const result = withSender('Priya Raman', 'priya@mt50sys.com');
    expect(hasSignal(result, 'identity.unsupported_org_claim')).toBe(false);
  });

  it('stays quiet for a recognised third-party sending service', () => {
    const result = withSender('Acme Payroll Support', 'no-reply@sendgrid.net');
    expect(hasSignal(result, 'identity.unsupported_org_claim')).toBe(false);
  });

  it('escalates when an institution claims to write from a consumer mailbox', () => {
    const result = withSender('Meridian Bank Security Team', 'meridian.alerts@gmail.com');
    expect(signalFor(result, 'identity.unsupported_org_claim')?.severity).toBe('high');
  });

  it('defers to the brand table when the claimed brand is a known one', () => {
    const result = withSender('PayPal Billing Team', 'service@mt50sys.com');
    expect(hasSignal(result, 'identity.unsupported_org_claim')).toBe(false);
    expect(hasSignal(result, 'identity.display_name_impersonation')).toBe(true);
  });
});

describe('repeated-fragment local parts', () => {
  it('counts separator-delimited repetition', () => {
    expect(repeatedUnitCount('donot.reply.donot.reply.donot.reply.donot.reply')).toBe(4);
  });

  it('counts unseparated repetition', () => {
    expect(repeatedUnitCount('donotreplydonotreplydonotreply')).toBe(3);
  });

  it('does not count an ordinary mailbox name', () => {
    expect(repeatedUnitCount('sam.okafor')).toBe(0);
    expect(repeatedUnitCount('first.last.first')).toBe(0);
  });

  /** ESP bounce addresses are long and opaque but not repetitive; length alone must not trigger. */
  it('does not count a long opaque ESP bounce address', () => {
    expect(repeatedUnitCount('bounces+124987-abcd-user=example.com')).toBe(0);
    expect(repeatedUnitCount('bounce-md_39481726.f8a2c410')).toBe(0);
  });
});

/**
 * Randomised case and subject padding are both destroyed by normalisation — the adapter case-folds the
 * address and collapses the subject's whitespace, because every comparison downstream depends on it.
 * `EmailMessage.raw` carries the originals so formatting detectors can still see them.
 */
describe('signals that survive only in the raw fields', () => {
  const fixture = loadFixture('brand-spoof-leadgen');

  it('carries the raw forms alongside the normalised ones', () => {
    expect(fixture.email.senderEmail).toBe('donot.reply.donot.reply.donot.reply.donot.reply@mt50sys.com');
    expect(fixture.email.raw?.senderEmail).toContain('DoNoT');
    expect(fixture.email.subject).not.toMatch(/ {2}/u);
    expect(fixture.email.raw?.subject).toMatch(/ {24}/u);
  });

  it('detects the randomised capitalisation', () => {
    const result = analyzeFixture('brand-spoof-leadgen');
    expect(hasSignal(result, 'identity.randomised_address_case')).toBe(true);
  });

  it('detects the padded subject', () => {
    const result = analyzeFixture('brand-spoof-leadgen');
    const s = signalFor(result, 'content.subject_padding');
    expect(s).toBeDefined();
    expect(s?.description).toMatch(/run of \d+ consecutive spaces/u);
  });

  it('reports nothing when the client gave no raw form', () => {
    const { raw: _raw, ...withoutRaw } = fixture.email;
    const result = analyzeDeterministic(withoutRaw, { now: FIXED_NOW });

    expect(hasSignal(result, 'identity.randomised_address_case')).toBe(false);
    expect(hasSignal(result, 'content.subject_padding')).toBe(false);
    // The brand-independent identity findings do not depend on raw fields, so they still stand.
    expect(hasSignal(result, 'identity.unsupported_org_claim')).toBe(true);
  });

  it('does not let the padded subject leak into the evidence shown to the user', () => {
    const result = analyzeFixture('brand-spoof-leadgen');
    for (const s of result.signals) {
      expect(s.evidence?.text ?? '').not.toMatch(/ {4}/u);
      expect(s.evidence?.value ?? '').not.toMatch(/ {4}/u);
    }
  });
});

describe('case-scrambling detection', () => {
  it('recognises alternating case', () => {
    expect(isCaseScrambled('DoNoT')).toBe(true);
    expect(isCaseScrambled('rEpLy')).toBe(true);
    expect(isCaseScrambled('aCcOuNt')).toBe(true);
  });

  /** Run length, not capital count, is what separates these from evasion. */
  it('does not flag CamelCase mailbox names', () => {
    expect(isCaseScrambled('JohnSmith')).toBe(false);
    expect(isCaseScrambled('MyCompanyName')).toBe(false);
    expect(isCaseScrambled('McDonald')).toBe(false);
    expect(isCaseScrambled('iPhoneSupport')).toBe(false);
  });

  it('does not flag single-case words', () => {
    expect(isCaseScrambled('donotreply')).toBe(false);
    expect(isCaseScrambled('NEWSLETTER')).toBe(false);
  });
});

describe('subject padding boundaries', () => {
  const base = loadFixture('legitimate-invoice').email;

  const withRawSubject = (subject: string): AnalysisResult =>
    analyzeDeterministic(
      { ...base, subject: subject.replace(/\s+/gu, ' ').trim(), raw: { subject } },
      { now: FIXED_NOW },
    );

  it('ignores ordinary double spaces', () => {
    expect(hasSignal(withRawSubject('Invoice 4471  attached'), 'content.subject_padding')).toBe(false);
  });

  it('ignores incidental whitespace from element boundaries', () => {
    expect(hasSignal(withRawSubject('Invoice 4471       attached'), 'content.subject_padding')).toBe(false);
  });

  it('flags a long padding run', () => {
    const padded = `Invoice 4471 attached${' '.repeat(40)}`;
    expect(hasSignal(withRawSubject(padded), 'content.subject_padding')).toBe(true);
  });

  it('does not treat newlines as padding', () => {
    expect(hasSignal(withRawSubject(`Invoice 4471\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\nattached`), 'content.subject_padding')).toBe(false);
  });
});

describe('subject formatting markers', () => {
  const { repeatedDecorativeChar } = contentTestables;

  it('treats a repeated dingbat as an ornament', () => {
    expect(repeatedDecorativeChar('WELCOME ❋ TO YOUR ❋ QUOTE')).toBe('❋');
  });

  it('does not treat bullet or dash separators as ornaments', () => {
    expect(repeatedDecorativeChar('News • Sports • Weather')).toBeNull();
    expect(repeatedDecorativeChar('Report – Q3 – Final')).toBeNull();
  });

  it('does not treat a single emoji as an ornament', () => {
    expect(repeatedDecorativeChar('🎉 Your order has shipped')).toBeNull();
    expect(repeatedDecorativeChar('✅ Payment received, thank you')).toBeNull();
  });

  it('needs more than one marker before reporting anything', () => {
    const base = loadFixture('legitimate-newsletter').email;
    const shouting = analyzeDeterministic(
      { ...base, subject: 'LAST CHANCE: 20% OFF SINGLE ORIGINS ENDS TONIGHT' },
      { now: FIXED_NOW },
    );
    expect(hasSignal(shouting, 'content.subject_obfuscation')).toBe(false);
  });
});

/**
 * A message's score must be a property of the message, not of where it is filed.
 *
 * Moving mail to Spam made Gmail render a banner, which the extractor read as a security verdict, which
 * (being `high` and in a floor-eligible category) dragged any message to at least 50. Two independent
 * corrections: placement notices are no longer read as verdicts, and Gmail's warning may no longer
 * establish a floor because it is not a finding this extension established.
 */
describe('Gmail banner: verdicts versus placement notices', () => {
  const { readGmailWarning } = adapterTestables;

  it('reads a genuine inbox warning as a verdict', () => {
    expect(
      readGmailWarning(
        "Be careful with this message. It contains content that's typically used to steal personal information.",
      ),
    ).toContain('Be careful');
    expect(readGmailWarning('This message seems dangerous. Many people marked similar messages as phishing scams.')).toBeDefined();
  });

  it('ignores the spam-folder placement notice', () => {
    expect(
      readGmailWarning(
        "Why is this message in spam? It's similar to messages that were detected by our spam filters.",
      ),
    ).toBeUndefined();
  });

  /** The frame matters: inside "why is this in spam", security wording is a filing rationale. */
  it('ignores a placement notice even when it contains security wording', () => {
    expect(
      readGmailWarning(
        "Why is this message in spam? It contains content that's typically used to steal personal information.",
      ),
    ).toBeUndefined();
  });

  it('ignores a notice reflecting the user’s own action', () => {
    expect(readGmailWarning('You marked this message as spam.')).toBeUndefined();
    expect(readGmailWarning('This message is in Spam. Not spam')).toBeUndefined();
  });

  it('ignores benign notices with no security wording', () => {
    expect(readGmailWarning('Images are not displayed. Display images below')).toBeUndefined();
    expect(readGmailWarning('')).toBeUndefined();
  });

  it('does not let Gmail’s warning alone establish a floor', () => {
    const warned: SecuritySignal[] = [
      {
        id: 'authentication.gmail_warning',
        category: 'authentication',
        severity: 'high',
        score: 30,
        title: 'Gmail displayed its own warning banner for this message',
        description: 'x',
      },
    ];
    expect(severityFloor(warned)).toBe(0);
  });

  it('still lets our own high-severity findings establish a floor', () => {
    const ours: SecuritySignal[] = [
      {
        id: 'identity.sender_ip_domain',
        category: 'authentication',
        severity: 'high',
        score: 28,
        title: 'x',
        description: 'x',
      },
    ];
    expect(severityFloor(ours)).toBe(50);
  });

  /** End to end: the same message must score the same with and without Gmail's banner attached. */
  it('keeps a legitimate message low when Gmail annotates it', () => {
    const base = loadFixture('legitimate').email;
    const plain = analyzeDeterministic(base, { now: FIXED_NOW });
    const annotated = analyzeDeterministic(
      {
        ...base,
        auth: {
          ...base.auth,
          gmailWarning: 'Be careful with this message. It looks suspicious.',
        },
      },
      { now: FIXED_NOW },
    );

    expect(plain.classification).toBe('low');
    // The warning is reported and adds weight, but cannot on its own make a clean message suspicious.
    expect(hasSignal(annotated, 'authentication.gmail_warning')).toBe(true);
    expect(annotated.score).toBeLessThan(50);
    expect(annotated.classification).not.toBe('suspicious');
  });
});

/**
 * Which message in a thread gets assessed.
 *
 * Taking the last expanded message assessed the user's own reply once they had replied to something —
 * scoring their own writing while the inbound message they might need warning about sat collapsed above
 * it. Skipping their own messages fixes that, but the obvious form of the skip ("ignore anything from my
 * address") would hand a free pass to mail forged to look like it came from the reader, which is a scam
 * genre in its own right and arrives in the inbox looking exactly like a sent message. The tests below
 * pin both halves: the reply is skipped, the forgery is not.
 */
describe('choosing the message to assess', () => {
  const { isOutboundMessage, selectReadableMessage, isOutboundLabel, accountAddressFromTitle } =
    adapterTestables;

  const ME = 'sam.okafor@northwind-logistics.com';
  const received = { sender: 'accounts@supplier.example', audience: [ME] };
  const myReply = { sender: ME, audience: ['accounts@supplier.example'] };

  describe('recognising a message the user sent', () => {
    it('treats a message from the account addressed to someone else as sent', () => {
      expect(isOutboundMessage(myReply, ME)).toBe(true);
    });

    it('does not treat inbound mail as sent', () => {
      expect(isOutboundMessage(received, ME)).toBe(false);
    });

    it('still assesses a forgery from the reader’s own address back to themselves', () => {
      // "I have access to your account" mail spoofs the recipient's own address. Suppressing on the
      // From address alone would exempt the entire genre.
      expect(isOutboundMessage({ sender: ME, audience: [ME] }, ME)).toBe(false);
    });

    it('still assesses a forgery that also copies in a third party', () => {
      // The account remaining among the recipients is what gives this away, which is why an
      // account-equal address in the audience must not be filtered out as redundant.
      expect(isOutboundMessage({ sender: ME, audience: [ME, 'attacker@evil.example'] }, ME)).toBe(
        false,
      );
    });

    it('assesses the message when the recipient row has not rendered', () => {
      // Unknown is not "nobody": failing towards assessing is the safe direction.
      expect(isOutboundMessage({ sender: ME, audience: null }, ME)).toBe(false);
      expect(isOutboundMessage({ sender: ME, audience: [] }, ME)).toBe(false);
    });

    it('assesses everything when the account address could not be read', () => {
      expect(isOutboundMessage(myReply, '')).toBe(false);
    });

    it('is unaffected by a sender that merely resembles the account', () => {
      expect(isOutboundMessage({ sender: 'sam.okafor@northwind.example', audience: ['x@y.example'] }, ME)).toBe(false);
    });
  });

  describe('selecting within a thread', () => {
    it('skips the user’s reply and lands on the message it answers', () => {
      expect(selectReadableMessage([received, myReply], ME, false)).toBe(0);
    });

    it('takes the newest inbound message when several are expanded', () => {
      const older = { sender: 'first@supplier.example', audience: [ME] };
      expect(selectReadableMessage([older, received, myReply], ME, false)).toBe(1);
    });

    it('takes the last message when none of them are the user’s', () => {
      expect(selectReadableMessage([received, received], ME, false)).toBe(1);
    });

    it('reports nothing to assess when the thread is only the user’s own mail', () => {
      expect(selectReadableMessage([myReply], ME, false)).toBeNull();
      expect(selectReadableMessage([], ME, false)).toBeNull();
    });

    it('reports nothing in Sent, whatever the headers say', () => {
      // The route is the one signal here a sender cannot influence: nothing a phisher does files their
      // message under `#sent`, so this may suppress unconditionally.
      expect(selectReadableMessage([received], ME, true)).toBeNull();
    });
  });

  describe('reading the route label', () => {
    it.each([
      ['#sent/FMfcgzQbcd1234567890', true],
      ['#drafts?compose=new', true],
      ['#sent', true],
      ['#inbox/FMfcgzQbcd1234567890', false],
      ['#label/Suppliers/FMfcgzQbcd1234567890', false],
      ['#search/sent/FMfcgzQbcd1234567890', false],
      ['', false],
    ])('%s → outbound view: %s', (hash, expected) => {
      expect(isOutboundLabel(hash)).toBe(expected);
    });
  });

  describe('reading the account address from the title', () => {
    it('takes the account segment, not the first address in the string', () => {
      // A subject can contain an address; taking the first match would read the wrong mailbox and make
      // the reader's own replies look like someone else's mail.
      expect(accountAddressFromTitle('Re: invoice from billing@supplier.example - sam@northwind.example - Gmail'))
        .toBe('sam@northwind.example');
    });

    it('handles a subject containing the separator', () => {
      expect(accountAddressFromTitle('Q3 - final - sam@northwind.example - Gmail')).toBe(
        'sam@northwind.example',
      );
    });

    it('returns nothing rather than guessing', () => {
      expect(accountAddressFromTitle('Gmail')).toBeUndefined();
      expect(accountAddressFromTitle('Inbox - Gmail')).toBeUndefined();
      expect(accountAddressFromTitle('')).toBeUndefined();
    });
  });
});

// ---------------------------------------------------------------------------
// Invariants that must hold for every fixture
// ---------------------------------------------------------------------------

describe('invariants across all fixtures', () => {
  const fixtures = loadAllFixtures();

  it('loads every fixture', () => {
    expect(fixtures.length).toBeGreaterThanOrEqual(12);
  });

  for (const fixture of fixtures) {
    describe(fixture.name, () => {
      const result = analyzeDeterministic(fixture.email, { now: FIXED_NOW });

      it('produces an integer score in [0, 100]', () => {
        expect(Number.isInteger(result.score)).toBe(true);
        expect(result.score).toBeGreaterThanOrEqual(0);
        expect(result.score).toBeLessThanOrEqual(100);
      });

      it('score is the additive subtotal raised to any applicable severity floor', () => {
        const sum = Math.min(100, Math.round(Object.values(result.categoryScores).reduce((a, b) => a + b, 0)));
        const floor = severityFloor(result.signals);
        expect(result.score).toBe(Math.max(sum, floor));
        expect(result.score).toBeGreaterThanOrEqual(sum);
      });

      it('emits no duplicate signal ids', () => {
        const seen = ids(result);
        expect(new Set(seen).size).toBe(seen.length);
      });

      it('gives every signal a non-empty title and description', () => {
        for (const s of result.signals) {
          expect(s.title.length).toBeGreaterThan(0);
          expect(s.description.length).toBeGreaterThan(0);
        }
      });

      it('bounds every piece of evidence', () => {
        for (const s of result.signals) {
          expect(s.evidence?.text?.length ?? 0).toBeLessThanOrEqual(161);
          expect(s.evidence?.value?.length ?? 0).toBeLessThanOrEqual(161);
          expect(s.evidence?.url?.length ?? 0).toBeLessThanOrEqual(2048);
        }
      });

      it('contributes zero from the llm category when no analyzer ran', () => {
        expect(result.categoryScores.llm).toBe(0);
      });

      it('is deterministic — identical input gives an identical result', () => {
        const again = analyzeDeterministic(fixture.email, { now: FIXED_NOW });
        expect(JSON.stringify(again.signals)).toBe(JSON.stringify(result.signals));
        expect(again.score).toBe(result.score);
      });

      it('does not mutate the input message', () => {
        const before = JSON.stringify(fixture.email);
        analyzeDeterministic(fixture.email, { now: FIXED_NOW });
        expect(JSON.stringify(fixture.email)).toBe(before);
      });
    });
  }
});

describe('ranking sanity: phishing must outscore legitimate mail', () => {
  const score = (name: string): number => analyzeFixture(name).score;

  it('every malicious fixture outscores every legitimate fixture', () => {
    const legitimate = LEGITIMATE_FIXTURES.map(score);
    const malicious = MALICIOUS_FIXTURES.map(score);
    expect(Math.max(...legitimate)).toBeLessThan(Math.min(...malicious));
  });

  it('every legitimate fixture classifies as low', () => {
    for (const name of LEGITIMATE_FIXTURES) {
      expect(analyzeFixture(name).classification, name).toBe('low');
    }
  });

  it('every malicious fixture classifies at least as suspicious', () => {
    for (const name of MALICIOUS_FIXTURES) {
      const result = analyzeFixture(name);
      expect(['suspicious', 'high-risk'], name).toContain(result.classification);
    }
  });
});

/**
 * The severity floors in `scoring/config.ts` are only safe if legitimate mail never produces a `high`
 * or `critical` deterministic signal. That is a load-bearing assumption, so it is asserted directly
 * rather than left implicit — if a future detector starts flagging real mail as `high`, this fails
 * here rather than silently marking every newsletter as suspicious in production.
 */
describe('severity floor safety', () => {
  for (const name of LEGITIMATE_FIXTURES) {
    it(`${name} produces no high or critical deterministic signal`, () => {
      const result = analyzeFixture(name);
      const offenders = result.signals.filter(
        (s) => s.category !== 'llm' && (s.severity === 'high' || s.severity === 'critical') && s.score > 0,
      );
      expect(offenders.map((s) => `${s.id} (${s.severity})`)).toEqual([]);
      expect(severityFloor(result.signals)).toBe(0);
    });
  }

  it('an informational signal never establishes a floor', () => {
    const result = analyzeFixture('legitimate');
    expect(result.signals.some((s) => s.severity === 'info')).toBe(true);
    expect(severityFloor(result.signals)).toBe(0);
  });
});
