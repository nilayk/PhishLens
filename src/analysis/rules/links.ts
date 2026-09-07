/**
 * Link detectors.
 *
 * Everything here compares *what the user sees* against *where the click goes*. That comparison is
 * only sound because `buildContext` already normalised both sides through the platform URL parser
 * and unwrapped redirect wrappers — a raw string comparison would be trivially defeated by
 * `HTTPS://EVIL.EXAMPLE./x` versus `https://evil.example/x`.
 *
 * No detector in this file resolves DNS, issues a request, or follows a redirect over the network.
 * All redirect analysis is textual.
 */
import { brandOwningDomain, BRANDS } from '../../shared/brands.js';
import type { SecuritySignal } from '../../shared/types.js';
import { describeUrl, registrableDomain } from '../../shared/url.js';
import { decodeIdnHost, hasSuspiciousScriptMixing, scriptsUsed, skeleton } from '../../shared/unicode.js';
import type { AnalysisContext } from '../context.js';
import { DETECTION_TUNING } from '../scoring/config.js';
import { findLookalike } from './identity.js';
import { signal } from './types.js';
import type { Detect } from './types.js';

/** Words that mean "this link leads to a login form". */
const CREDENTIAL_LINK_TERMS =
  /\b(sign\s?in|signon|log\s?in|logon|log-on|password|passwd|credential|authenticate|authentication|verify|verification|validate|confirm|secure\s?access|account\s?access|mfa|2fa|otp|sso|webmail|owa|portal|unlock|reactivate|re-?activate)\b/u;

/** Take only the first N of a repeated finding so one hostile message cannot flood the panel. */
function limit<T>(items: T[]): T[] {
  return items.slice(0, DETECTION_TUNING.maxLinkSignalsPerRule);
}

/**
 * The anchor text reads as one URL, the href goes somewhere else.
 *
 * The highest-confidence link signal there is, and the reason the product exists: nothing about a
 * legitimate message needs the visible URL to disagree with the destination.
 */
function displayedUrlMismatch(context: AnalysisContext): SecuritySignal[] {
  const findings: SecuritySignal[] = [];

  for (const link of context.links) {
    const { displayed, target } = link;
    if (displayed === null || target === null) continue;
    if (link.displayedRegistrable === '' || link.registrable === '') continue;
    if (link.displayedRegistrable === link.registrable) continue;
    // Mail platforms legitimately rewrite hrefs to their own click-tracking host while leaving the
    // anchor text as the sender wrote it, so a "mismatch" here is the expected state, not a finding.
    if (link.wrappedByKnownTracker) continue;

    const displayedHost = decodeIdnHost(displayed.hostname);
    const brand = brandOwningDomain(link.displayedRegistrable);
    const impersonatesBrand = brand !== undefined;

    // The same rewrite, done by a platform we have not listed: the href points back at the sender's
    // own domain. Newsletter platforms (Substack, beehiiv, Kit) send from and redirect through one
    // domain, so every outbound link in a newsletter reads as a mismatch — the observed false
    // positive this guard exists to remove.
    //
    // Suppressed rather than downgraded because there is nothing here to report: the sender is not
    // borrowing anyone's reputation, only its own. When the anchor text *is* a brand's domain the
    // borrowing is real and the finding stands, which is why this yields to `impersonatesBrand`.
    if (link.onSenderDomain && !impersonatesBrand) continue;

    findings.push(
      signal({
        id: `link.displayed_url_mismatch.${String(link.index)}`,
        category: 'link',
        severity: impersonatesBrand ? 'critical' : 'high',
        score: impersonatesBrand ? 45 : 32,
        title: 'Displayed link address differs from its actual destination',
        description: `The link is shown as "${displayedHost}" but clicking it goes to ${describeUrl(target)}.${impersonatesBrand ? ` The displayed address belongs to ${brand.label}; the real destination does not.` : ''}`,
        evidence: {
          text: link.link.text,
          url: link.link.href,
          value: `shown: ${displayedHost} → actual: ${link.hostname}`,
        },
      }),
    );
  }

  return limit(findings);
}

/**
 * The link text names a brand (not as a URL) while the destination is unrelated:
 * `<a href="https://evil.example">Microsoft 365 sign-in</a>`.
 *
 * Separate from `displayedUrlMismatch` because the anchor text here is prose, not a URL, so it needs
 * brand-claim logic rather than URL comparison.
 */
function anchorTextBrandMismatch(context: AnalysisContext): SecuritySignal[] {
  const findings: SecuritySignal[] = [];

  for (const link of context.webLinks) {
    if (link.registrable === '') continue;
    if (link.displayed !== null) continue; // handled by displayedUrlMismatch
    if (link.wrappedByKnownTracker) continue;

    const folded = skeleton(link.anchorText);
    if (folded.length < 4) continue;

    for (const brand of BRANDS) {
      const hit = brand.keywords.find((k) => {
        const f = skeleton(k);
        return f.length >= 5 && folded.includes(f);
      });
      if (hit === undefined) continue;
      if (brand.domains.includes(link.registrable)) break;
      // The destination is a lookalike of this brand — reported by the lookalike rule instead.
      if (brandOwningDomain(link.registrable)?.id === brand.id) break;

      findings.push(
        signal({
          id: `link.anchor_brand_mismatch.${String(link.index)}`,
          category: 'link',
          severity: 'high',
          score: 28,
          title: `Link labelled as ${brand.label} points to an unrelated domain`,
          description: `The link text refers to ${brand.label}, but the destination is ${link.hostname}, which ${brand.label} does not own.`,
          evidence: { text: link.link.text, url: link.link.href, value: link.hostname },
        }),
      );
      break;
    }
  }
  return limit(findings);
}

/** A destination that is a raw IP address. Effectively never legitimate in commercial mail. */
function ipAddressLinks(context: AnalysisContext): SecuritySignal[] {
  const ipLinks = context.webLinks.filter((l) => l.isIp);
  const [first] = ipLinks;
  if (first === undefined) return [];

  return [
    signal({
      id: 'link.ip_address_url',
      category: 'link',
      severity: 'critical',
      score: 40,
      title: 'Link points directly to an IP address',
      description: `${ipLinks.length === 1 ? 'A link goes' : `${String(ipLinks.length)} links go`} to the bare address ${first.hostname} instead of a domain name. Legitimate services publish hostnames; bare IPs are used to avoid registering a domain that could be taken down.`,
      evidence: { url: first.link.href, value: first.hostname },
    }),
  ];
}

/** Punycode / mixed-script hostnames in link destinations. */
function unicodeSpoofedLinks(context: AnalysisContext): SecuritySignal[] {
  const findings: SecuritySignal[] = [];

  for (const link of context.webLinks) {
    if (!link.isPunycode) continue;
    const rendered = link.displayHost;
    const labels = rendered.split('.');
    const mixed = labels.some((l) => hasSuspiciousScriptMixing(l));
    const imitates = findLookalike(link.registrable);

    findings.push(
      signal({
        id: `link.punycode_domain.${String(link.index)}`,
        category: 'link',
        severity: mixed || imitates !== null ? 'critical' : 'medium',
        score: mixed || imitates !== null ? 40 : 18,
        title: 'Link uses an internationalised domain that renders as familiar text',
        description: imitates !== null
          ? `The link's host is ${link.hostname}, which renders as "${rendered}" — visually indistinguishable from ${imitates.target}, but a different domain entirely.`
          : mixed
            ? `The link's host is ${link.hostname}, which renders as "${rendered}" using a mix of ${scriptsUsed(rendered).join(' and ')} characters. Mixed scripts inside one name are how a domain is made to look like something it is not.`
            : `The link's host is ${link.hostname}, which renders as "${rendered}". Internationalised domains are legitimate but are commonly used to imitate familiar names.`,
        evidence: { url: link.link.href, value: `${rendered} (${link.hostname})` },
      }),
    );
  }
  return limit(findings);
}

/** A link destination that imitates a brand domain without being one. */
function lookalikeLinkDomains(context: AnalysisContext): SecuritySignal[] {
  const findings: SecuritySignal[] = [];
  const reported = new Set<string>();

  for (const link of context.webLinks) {
    if (link.registrable === '' || reported.has(link.registrable)) continue;
    if (link.isPunycode) continue; // reported by unicodeSpoofedLinks with better wording
    const match = findLookalike(link.registrable);
    if (match === null) continue;
    reported.add(link.registrable);

    findings.push(
      signal({
        id: `link.lookalike_domain.${String(link.index)}`,
        category: 'link',
        severity: 'critical',
        score: 40,
        title: `Link destination imitates ${match.brandLabel}`,
        description: `The link goes to ${link.registrable}, a near-identical imitation of ${match.target}. It is not operated by ${match.brandLabel}.`,
        evidence: { url: link.link.href, value: `${link.registrable} vs ${match.target}` },
      }),
    );
  }
  return limit(findings);
}

/**
 * A brand's real domain appearing as a *prefix* of an unrelated domain:
 * `microsoft.com.evil-example.com`, `paypal.security-login.example`.
 *
 * A reader scanning left to right sees the brand and stops. The registrable domain is what matters.
 */
function misleadingDomainComposition(context: AnalysisContext): SecuritySignal[] {
  const findings: SecuritySignal[] = [];
  const reported = new Set<string>();

  for (const link of context.webLinks) {
    if (link.registrable === '' || reported.has(link.hostname)) continue;
    if (brandOwningDomain(link.registrable) !== undefined) continue;

    const beforeRegistrable = link.subdomain;
    if (beforeRegistrable === '') continue;
    const foldedPrefix = skeleton(beforeRegistrable);

    for (const brand of BRANDS) {
      // Match a full brand domain in the subdomain (`microsoft.com.evil.example`) or a distinctive
      // brand token (`paypal.security-login.example`).
      const domainHit = brand.domains.find((d) => {
        const f = skeleton(d);
        return f.length >= 6 && foldedPrefix.includes(f);
      });
      const tokenHit =
        domainHit === undefined
          ? brand.lookalikeTargets.find((t) => {
              const core = skeleton(t.split('.')[0] ?? '');
              return core.length >= 5 && foldedPrefix.includes(core);
            })
          : undefined;

      if (domainHit === undefined && tokenHit === undefined) continue;
      reported.add(link.hostname);

      findings.push(
        signal({
          id: `link.misleading_domain.${String(link.index)}`,
          category: 'link',
          severity: 'critical',
          score: 42,
          title: `Link places ${brand.label}'s name in front of an unrelated domain`,
          description: `The link reads as ${brand.label} at a glance, but the part of the address that determines where it actually goes is ${link.registrable}. Everything to the left of that — including "${beforeRegistrable}" — is chosen freely by whoever controls ${link.registrable}.`,
          evidence: { url: link.link.href, value: link.hostname },
        }),
      );
      break;
    }
  }
  return limit(findings);
}

/** URL shorteners hide the destination, so the mismatch checks above cannot run at all. */
function shortenedLinks(context: AnalysisContext): SecuritySignal[] {
  const shortened = context.webLinks.filter((l) => l.isShortener);
  const [first] = shortened;
  if (first === undefined) return [];
  const credentialContext = CREDENTIAL_LINK_TERMS.test(context.matchText);

  return [
    signal({
      id: 'link.url_shortener',
      category: 'link',
      severity: credentialContext ? 'medium' : 'low',
      score: credentialContext ? 20 : 10,
      title: 'Link is hidden behind a URL shortener',
      description: `${shortened.length === 1 ? 'A link uses' : `${String(shortened.length)} links use`} the shortener ${first.registrable}, so the real destination cannot be seen before clicking.${credentialContext ? ' The message also asks the recipient to sign in or verify something, which is when a concealed destination matters most.' : ''}`,
      evidence: { url: first.link.href, value: first.registrable },
    }),
  ];
}

/**
 * Redirect-shaped links whose destination we cannot see, and redirect chains through hosts that are
 * not known mail trackers.
 */
function suspiciousRedirects(context: AnalysisContext): SecuritySignal[] {
  const findings: SecuritySignal[] = [];

  for (const link of context.webLinks) {
    if (link.wrappedByKnownTracker) continue;
    // A redirector on the sender's own domain is not laundering a destination behind a domain the
    // recipient recognises, which is the deception described below: it *is* the domain that sent the
    // mail. Click tracking is built this way, so flagging it reports infrastructure, not intent.
    if (link.onSenderDomain) continue;

    if (link.opaqueRedirect) {
      findings.push(
        signal({
          id: `link.opaque_redirect.${String(link.index)}`,
          category: 'link',
          severity: 'medium',
          score: 20,
          title: 'Link is built as a redirector with a hidden target',
          description: `The link to ${link.hostname} carries a redirect parameter whose destination is encoded so that it cannot be read. Redirect chains are used to launder a malicious destination behind a domain the recipient recognises.`,
          evidence: { url: link.link.href, value: link.hostname },
        }),
      );
      continue;
    }

    if (link.redirectHops > 0 && link.redirectChain.length > 1) {
      const entry = link.redirectChain[0] ?? '';
      const exit = link.registrable;
      if (registrableDomain(entry) === exit) continue;

      findings.push(
        signal({
          id: `link.redirect_chain.${String(link.index)}`,
          category: 'link',
          severity: 'medium',
          score: 18,
          title: 'Link redirects through one domain to reach another',
          description: `The link starts at ${entry} but redirects to ${exit}. The domain the recipient sees is not the domain that serves the page.`,
          evidence: { url: link.link.href, value: link.redirectChain.join(' → ') },
        }),
      );
    }
  }
  return limit(findings);
}

/** Non-HTTPS destination for a page that will ask for credentials. */
function insecureCredentialLinks(context: AnalysisContext): SecuritySignal[] {
  const findings: SecuritySignal[] = [];

  for (const link of context.webLinks) {
    if (link.isHttps) continue;
    const looksLikeLogin =
      CREDENTIAL_LINK_TERMS.test(link.anchorText) ||
      CREDENTIAL_LINK_TERMS.test(`${link.target?.pathname ?? ''} ${link.target?.search ?? ''}`);

    findings.push(
      signal({
        id: `link.insecure_${looksLikeLogin ? 'login' : 'http'}.${String(link.index)}`,
        category: 'link',
        severity: looksLikeLogin ? 'high' : 'low',
        score: looksLikeLogin ? 26 : 8,
        title: looksLikeLogin
          ? 'Sign-in link uses unencrypted HTTP'
          : 'Link uses unencrypted HTTP',
        description: looksLikeLogin
          ? `The link to ${link.hostname} appears to lead to a sign-in page but uses plain HTTP. No legitimate service accepts credentials over an unencrypted connection.`
          : `The link to ${link.hostname} uses plain HTTP rather than HTTPS.`,
        evidence: { url: link.link.href, value: link.hostname },
      }),
    );
  }
  return limit(findings);
}

/** `javascript:`, `data:`, and other schemes that should never appear as a link in mail. */
function dangerousSchemeLinks(context: AnalysisContext): SecuritySignal[] {
  const dangerous = context.links.filter((l) => l.isDangerousScheme);
  const [first] = dangerous;
  if (first === undefined) return [];
  const scheme = first.raw?.protocol ?? '';

  return [
    signal({
      id: 'link.dangerous_scheme',
      category: 'link',
      severity: 'critical',
      score: 45,
      title: `Link uses the ${scheme} scheme`,
      description: `A link uses "${scheme}" rather than http or https. Schemes like this execute code or open local resources instead of loading a web page, and have no legitimate use in an email link.`,
      evidence: { value: scheme, url: first.link.href },
    }),
  ];
}

/** Malformed hosts, and hrefs that are not absolute URLs at all. */
function malformedLinks(context: AnalysisContext): SecuritySignal[] {
  const malformed = context.links.filter(
    (l) => l.isMalformed && !l.isNonNavigation && !l.isDangerousScheme && l.link.href.trim() !== '',
  );
  const [first] = malformed;
  if (first === undefined) return [];

  return [
    signal({
      id: 'link.malformed_url',
      category: 'link',
      severity: 'low',
      score: 10,
      title: 'Message contains a malformed link',
      description: `${malformed.length === 1 ? 'A link' : `${String(malformed.length)} links`} could not be resolved to a valid web address. This is often a broken phishing template, and occasionally a parser-confusion attempt.`,
      evidence: { value: first.link.href.slice(0, 120) },
    }),
  ];
}

/** Excessive subdomain nesting used to push recognisable words into view. */
function excessiveSubdomains(context: AnalysisContext): SecuritySignal[] {
  const deep = context.webLinks.filter(
    (l) => l.subdomainLabelCount > DETECTION_TUNING.maxReasonableSubdomainLabels && !l.isIp,
  );
  const [first] = deep;
  if (first === undefined) return [];

  return [
    signal({
      id: 'link.excessive_subdomains',
      category: 'link',
      severity: 'medium',
      score: 16,
      title: 'Link host has an unusually deep subdomain structure',
      description: `The link's host has ${String(first.subdomainLabelCount)} subdomain levels beneath ${first.registrable}. Long chains of labels are used to fill the visible part of an address with reassuring words while the controlling domain stays out of sight.`,
      evidence: { url: first.link.href, value: first.hostname },
    }),
  ];
}

/**
 * A credential-related destination on a domain that has nothing to do with the claimed brand — the
 * cross-signal case the brief calls out: "credentials/login terminology combined with unrelated
 * domains".
 */
function credentialTermsOnUnrelatedDomain(context: AnalysisContext): SecuritySignal[] {
  const claim = context.primaryClaim;
  const findings: SecuritySignal[] = [];

  for (const link of context.webLinks) {
    if (link.registrable === '') continue;

    const pathAndQuery = `${link.target?.pathname ?? ''} ${link.target?.search ?? ''}`;
    const loginish =
      CREDENTIAL_LINK_TERMS.test(link.anchorText) || CREDENTIAL_LINK_TERMS.test(pathAndQuery);
    if (!loginish) continue;

    if (claim?.brand.domains.includes(link.registrable) === true) continue;

    const openHosting = link.openHosting;

    if (claim !== undefined && brandOwningDomain(link.registrable) === undefined) {
      findings.push(
        signal({
          id: `link.credential_link_unrelated_domain.${String(link.index)}`,
          category: 'link',
          severity: 'high',
          score: 30,
          title: `Sign-in link for ${claim.brand.label} leads to a domain ${claim.brand.label} does not own`,
          description: `The message presents itself as ${claim.brand.label} and the link leads to a sign-in or verification page, but the page is hosted at ${link.registrable}. Credentials entered there would go to whoever controls that domain.`,
          evidence: { url: link.link.href, value: link.registrable, text: link.link.text },
        }),
      );
      continue;
    }

    if (openHosting !== null) {
      findings.push(
        signal({
          id: `link.credential_link_open_hosting.${String(link.index)}`,
          category: 'link',
          severity: 'high',
          score: 26,
          title: 'Sign-in link is hosted on a free hosting service',
          description: `The link leads to a sign-in or verification page ${describeOpenHost(link.hostname, openHosting)}. Anyone can publish there in seconds, so the address carries no indication of who is actually behind the page.`,
          evidence: { url: link.link.href, value: link.hostname },
        }),
      );
    }
  }
  return limit(findings);
}

/**
 * Wording for an open host, which is either a tenant subdomain or the storage service itself.
 *
 * Worth branching on: calling `storage.googleapis.com` "a subdomain of storage.googleapis.com" is the
 * kind of sentence that makes a reader stop trusting the whole explanation.
 */
function describeOpenHost(hostname: string, openHosting: string): string {
  return hostname === openHosting
    ? `on ${openHosting}, where the page is stored as a file`
    : `at ${hostname}, a subdomain of ${openHosting}`;
}

/**
 * The link opens a web page that is a **file in a public storage bucket** rather than a page on
 * anybody's website.
 *
 * This is the shape that defeats every other link rule at once, and it is now the common one. The
 * destination is `storage.googleapis.com`, `s3.amazonaws.com` or a sibling: a real domain, owned by
 * Google or Amazon, with valid HTTPS and no lookalike spelling, no shortener, no redirect and no
 * punycode. Nothing about the *host* is wrong. What is wrong is that the host identifies the storage
 * provider and not the author — anyone with an account can upload `page.html` and serve it from an
 * address that reads as impeccable, which is precisely why phishing kits are hosted this way.
 *
 * Two conditions keep it off ordinary mail. The path must name an **HTML document**, because that is what
 * separates a page pretending to be a website from the legitimate uses of object storage, which are
 * images, PDFs and downloads. And the escalation to `high` requires the *message* to be asking for
 * something — a sign-in, an unlock, a renewal, a payment — since a bare link to a hosted document is
 * unremarkable while the same link under "your account will be deleted" is the whole attack.
 */
function pageServedFromOpenStorage(context: AnalysisContext): SecuritySignal[] {
  const findings: SecuritySignal[] = [];
  const asking =
    CREDENTIAL_LINK_TERMS.test(context.matchText) || ACCOUNT_ACTION_TERMS.test(context.matchText);

  for (const link of context.webLinks) {
    const openHosting = link.openHosting;
    if (openHosting === null || link.onSenderDomain) continue;
    if (!HTML_DOCUMENT_PATH.test(link.target?.pathname ?? '')) continue;

    // A sign-in page on an open host is the same link described better by
    // `credentialTermsOnUnrelatedDomain`, which can say what the page asks for. Two findings about one
    // link, differing only in wording, spend the reader's attention twice for one fact.
    const pathAndQuery = `${link.target?.pathname ?? ''} ${link.target?.search ?? ''}`;
    if (
      CREDENTIAL_LINK_TERMS.test(link.anchorText) ||
      CREDENTIAL_LINK_TERMS.test(pathAndQuery)
    ) {
      continue;
    }

    findings.push(
      signal({
        id: `link.page_in_open_storage.${String(link.index)}`,
        category: 'link',
        severity: asking ? 'high' : 'medium',
        score: asking ? 26 : 16,
        title: 'Link opens a page stored as a file on a public hosting service',
        description: `The link goes to a web page held as a file on ${openHosting}. The address belongs to the storage provider, not to whoever wrote the page: anyone with an account can upload a file there and it will be served from that domain. A real organisation publishes pages on its own site${asking ? ', and this message is asking you to act on one' : ''}.`,
        evidence: { url: link.link.href, value: link.hostname, text: link.link.text },
      }),
    );
  }
  return limit(findings);
}

/** A path whose last segment is an HTML document, i.e. a page rather than an asset or a download. */
const HTML_DOCUMENT_PATH = /\.(html?|shtml|xhtml|php|asp|aspx|jsp)$/iu;

/**
 * Wording that makes a message a demand for action on an account, beyond the credential vocabulary in
 * `CREDENTIAL_LINK_TERMS`. Subscription and billing language belongs here rather than there: "renew your
 * subscription" is not a sign-in request, and it puts the same pressure behind the same click.
 */
const ACCOUNT_ACTION_TERMS =
  /\b(renew|renewal|reactivate|upgrade|subscription|billing|invoice|payment (declined|failed|method)|past due|storage (is )?(full|limit)|out of (storage|space)|will be (deleted|removed|suspended|closed)|update your (payment|billing|card))\b/u;

/**
 * A destination whose TLD is also a common file extension, so the address reads as a filename.
 *
 * Reported on its own merits rather than only alongside a credential ask: the confusion is the whole
 * point of `payroll-2024.zip` being a *website*, and a reader who mistakes it for an attachment has
 * already been deceived regardless of what the page then asks for.
 */
function filenameLookalikeTldLinks(context: AnalysisContext): SecuritySignal[] {
  const risky = context.webLinks.filter((l) => {
    if (l.registrable === '' || brandOwningDomain(l.registrable) !== undefined) return false;
    return l.tld === 'zip' || l.tld === 'mov';
  });
  const [first] = risky;
  if (first === undefined) return [];

  return [
    signal({
      id: 'link.filename_lookalike_tld',
      category: 'link',
      severity: 'medium',
      score: 16,
      title: `Link uses the .${first.tld} top-level domain, which looks like a filename`,
      description: `The link goes to ${first.hostname}. Because ".${first.tld}" is also a common file extension, text like this is frequently mistaken for an attachment name rather than a web address.`,
      evidence: { url: first.link.href, value: first.hostname },
    }),
  ];
}

/**
 * Attacker-controlled destination for a message that also carries no readable text — a bare
 * "click here" body, which exists only to get the click.
 */
function linkOnlyBody(context: AnalysisContext): SecuritySignal[] {
  if (context.webLinks.length === 0) return [];
  if (context.bodyText.trim().length >= DETECTION_TUNING.minimalBodyChars) return [];
  const [first] = context.webLinks.filter(
    (l) => l.registrable !== '' && l.registrable !== context.senderRegistrable,
  );
  if (first === undefined) return [];

  return [
    signal({
      id: 'link.link_only_body',
      category: 'link',
      severity: 'low',
      score: 10,
      title: 'Message body is almost entirely a link',
      description: `The message contains very little readable text (${String(context.bodyText.trim().length)} characters) but does contain links to other domains. Minimal-context messages avoid saying anything that could be checked.`,
      evidence: { url: first.link.href },
    }),
  ];
}

const linkDetectors: Detect[] = [
  displayedUrlMismatch,
  anchorTextBrandMismatch,
  ipAddressLinks,
  unicodeSpoofedLinks,
  lookalikeLinkDomains,
  misleadingDomainComposition,
  shortenedLinks,
  suspiciousRedirects,
  insecureCredentialLinks,
  dangerousSchemeLinks,
  malformedLinks,
  excessiveSubdomains,
  credentialTermsOnUnrelatedDomain,
  pageServedFromOpenStorage,
  filenameLookalikeTldLinks,
  linkOnlyBody,
] as const;

export function detectLinkSignals(context: AnalysisContext): SecuritySignal[] {
  return linkDetectors.flatMap((detect) => detect(context));
}
