/**
 * URL and domain primitives.
 *
 * Every function here receives attacker-chosen input, and the detectors above them are only as correct
 * as these are. The cases are therefore adversarial rather than illustrative: obfuscated IP forms,
 * forged suffix boundaries, redirect chains designed to loop, and hostnames that `new URL()` accepts
 * but that cannot exist on the public internet.
 */
import { describe, expect, it } from 'vitest';
import {
  countSubdomainLabels,
  domainLabels,
  hasPunycode,
  hasRedirectParam,
  hasUnknownTld,
  isDangerousScheme,
  isIpHost,
  isKnownTrackingRedirector,
  isMalformedHost,
  isNonNavigationScheme,
  isShortener,
  isWebUrl,
  normalizeDomain,
  openHostingSuffix,
  parseDisplayedUrl,
  parseUrl,
  registrableDomain,
  sameRegistrableDomain,
  subdomainOf,
  tldOf,
  unwrapRedirects,
} from '../src/shared/url.js';

describe('parseUrl', () => {
  it('never throws, whatever it is given', () => {
    const hostile = [
      '',
      '   ',
      'not a url',
      'http://',
      'https://[',
      '://missing-scheme',
      'javascript:alert(1)',
      `https://example.com/${'a'.repeat(50_000)}`,
      '\u0000\u0001',
      'http://\u202Eevil.example',
    ];
    for (const input of hostile) {
      expect(() => parseUrl(input)).not.toThrow();
    }
  });

  it('refuses to resolve relative hrefs against the current page', () => {
    // Resolving `/login` while running on mail.google.com would invent a Google destination that does
    // not exist, turning a broken template into an apparently legitimate link.
    expect(parseUrl('/login')).toBeNull();
    expect(parseUrl('login.php')).toBeNull();
    expect(parseUrl('//evil.example/login')).toBeNull();
  });
});

describe('normalizeDomain', () => {
  it.each([
    ['EXAMPLE.COM', 'example.com'],
    ['example.com.', 'example.com'],
    ['example.com...', 'example.com'],
    ['www.example.com', 'example.com'],
    ['  Example.Com  ', 'example.com'],
    ['WWW.EXAMPLE.COM.', 'example.com'],
  ])('normalizes %s to %s', (input, expected) => {
    expect(normalizeDomain(input)).toBe(expected);
  });

  it('leaves an IPv6 literal intact', () => {
    expect(normalizeDomain('[::1]')).toBe('[::1]');
  });

  it('strips only a leading www., not an interior one', () => {
    expect(normalizeDomain('login.www.example.com')).toBe('login.www.example.com');
  });
});

describe('registrableDomain', () => {
  it.each([
    ['example.com', 'example.com'],
    ['login.example.com', 'example.com'],
    ['a.b.c.d.example.com', 'example.com'],
    // Multi-label public suffixes: the boundary is two labels deep, not one.
    ['example.co.uk', 'example.co.uk'],
    ['login.example.co.uk', 'example.co.uk'],
    ['example.com.au', 'example.com.au'],
    ['shop.example.com.br', 'example.com.br'],
  ])('resolves %s to %s', (input, expected) => {
    expect(registrableDomain(input)).toBe(expected);
  });

  it('is not fooled by a suffix appearing as a subdomain', () => {
    // The whole point of the misleading-composition attack.
    expect(registrableDomain('microsoft.com.evil-example.com')).toBe('evil-example.com');
    expect(registrableDomain('paypal.co.uk.evil.example')).toBe('evil.example');
  });

  it('returns IP literals unchanged', () => {
    expect(registrableDomain('192.168.1.1')).toBe('192.168.1.1');
    expect(registrableDomain('[::1]')).toBe('[::1]');
  });
});

describe('subdomainOf / tldOf / countSubdomainLabels', () => {
  it('splits host into subdomain and registrable parts', () => {
    expect(subdomainOf('login.secure.example.com')).toBe('login.secure');
    expect(subdomainOf('example.com')).toBe('');
    expect(subdomainOf('login.example.co.uk')).toBe('login');
  });

  it('reports the effective TLD label', () => {
    expect(tldOf('example.com')).toBe('com');
    expect(tldOf('example.co.uk')).toBe('uk');
    expect(tldOf('192.168.1.1')).toBe('');
  });

  it('counts subdomain depth, which is what "excessive nesting" measures', () => {
    expect(countSubdomainLabels('example.com')).toBe(0);
    expect(countSubdomainLabels('a.example.com')).toBe(1);
    expect(countSubdomainLabels('secure.login.account.verify.example.com')).toBe(4);
  });
});

describe('isIpHost', () => {
  it.each([
    ['192.168.1.1', true],
    ['8.8.8.8', true],
    ['[::1]', true],
    ['[2001:db8::1]', true],
    // Obfuscated forms the WHATWG parser canonicalises, and that users do not read as IPs.
    ['3232235777', true],
    ['0xc0a80001', true],
    ['0300.0250.0.1', true],
    ['example.com', false],
    ['', false],
    ['v4.example.com', false],
    ['123abc.example.com', false],
  ])('classifies %s as ip=%s', (input, expected) => {
    expect(isIpHost(input)).toBe(expected);
  });

  it('agrees with the platform parser on decimal IP forms', () => {
    const parsed = parseUrl('http://3232235777/login');
    expect(parsed?.hostname).toBe('192.168.1.1');
    expect(isIpHost(parsed?.hostname ?? '')).toBe(true);
  });
});

describe('isMalformedHost', () => {
  it.each([
    ['example.com', false],
    ['login.example.co.uk', false],
    ['192.168.1.1', false],
    ['[::1]', false],
    ['xn--80ak6aa92e.com', false],
    // `new URL()` accepts all of these.
    ['localhost', true],
    ['intranet', true],
    ['a..b.com', true],
    ['-example.com', true],
    ['example-.com', true],
    ['example.c', true],
    ['example.123', true],
    ['', true],
  ])('classifies %s as malformed=%s', (input, expected) => {
    expect(isMalformedHost(input)).toBe(expected);
  });

  it('rejects an over-long label', () => {
    expect(isMalformedHost(`${'a'.repeat(64)}.example.com`)).toBe(true);
    expect(isMalformedHost(`${'a'.repeat(63)}.example.com`)).toBe(false);
  });
});

describe('scheme classification', () => {
  it('treats only http(s) as web navigation', () => {
    expect(isWebUrl(new URL('https://example.com'))).toBe(true);
    expect(isWebUrl(new URL('http://example.com'))).toBe(true);
    expect(isWebUrl(new URL('ftp://example.com'))).toBe(false);
    expect(isWebUrl(new URL('mailto:a@example.com'))).toBe(false);
  });

  it.each(['javascript:alert(1)', 'data:text/html,<script>', 'vbscript:msgbox', 'file:///etc/passwd'])(
    'flags %s as dangerous',
    (href) => {
      const url = parseUrl(href);
      expect(url).not.toBeNull();
      expect(isDangerousScheme(url!)).toBe(true);
    },
  );

  it('separates benign non-navigations from dangerous schemes', () => {
    const mailto = new URL('mailto:someone@example.com');
    expect(isNonNavigationScheme(mailto)).toBe(true);
    expect(isDangerousScheme(mailto)).toBe(false);
  });
});

describe('domain reputation lists', () => {
  it('recognises shorteners at both host and registrable level', () => {
    expect(isShortener('bit.ly')).toBe(true);
    expect(isShortener('www.bit.ly')).toBe(true);
    expect(isShortener('example.com')).toBe(false);
  });

  it('recognises tracking redirectors including their subdomains', () => {
    expect(isKnownTrackingRedirector('click.sendgrid.net')).toBe(true);
    expect(isKnownTrackingRedirector('evil.example')).toBe(false);
  });

  it('identifies open hosting suffixes, which anyone can get a subdomain on', () => {
    expect(openHostingSuffix('phish.web.app')).toBe('web.app');
    expect(openHostingSuffix('example.com')).toBeNull();
  });

  /**
   * Object stores are open hosting where the tenant is a *path* segment, so the hostname is the suffix
   * rather than something under it. Missing this is how a phishing page on `storage.googleapis.com`
   * reads as a Google URL: the domain is genuinely Google's, and only the bucket is the stranger's.
   */
  it('identifies object stores, where the host itself is the open one', () => {
    expect(openHostingSuffix('storage.googleapis.com')).toBe('storage.googleapis.com');
    expect(openHostingSuffix('my-bucket.s3.amazonaws.com')).toBe('s3.amazonaws.com');
    expect(openHostingSuffix('raw.githubusercontent.com')).toBe('githubusercontent.com');
  });

  it('does not mistake the rest of a provider for its object store', () => {
    expect(openHostingSuffix('googleapis.com')).toBeNull();
    expect(openHostingSuffix('accounts.google.com')).toBeNull();
    expect(openHostingSuffix('console.aws.amazon.com')).toBeNull();
  });
});

/**
 * `isMalformedHost` asks whether a TLD is *shaped* like one; this asks whether it exists. The distinction
 * earns its keep on names an attacker picks precisely because they look unremarkable — `.ldk` passes
 * every structural test there is and has simply never been delegated to anyone.
 */
describe('hasUnknownTld', () => {
  it('recognises the TLDs mail actually arrives from', () => {
    for (const host of [
      'example.com', 'bbc.co.uk', 'mail.gov.au', 'shop.berlin', 'a.museum', 'x.io',
      'köln.de', 'президент.рф', 'xn--80akhbyknj4f.xn--p1ai',
    ]) {
      expect(hasUnknownTld(host), host).toBe(false);
    }
  });

  it('rejects TLDs that were never delegated', () => {
    for (const host of ['qmbvx.ldk', 'mail.corp', 'server.local', 'thing.zzz', 'a.xn--zzzzzz']) {
      expect(hasUnknownTld(host), host).toBe(true);
    }
  });

  /**
   * A bare hostname has no TLD to judge, and an address literal has no TLD at all. Both must be someone
   * else's finding, or every internal relay in existence becomes a fabricated sender.
   */
  it('declines to judge what has no TLD', () => {
    for (const host of ['localhost', 'mailserver', '', '192.168.1.1', '[::1]']) {
      expect(hasUnknownTld(host), host).toBe(false);
    }
  });
});

describe('unwrapRedirects', () => {
  it('peels a Google/Gmail wrapper to the real destination', () => {
    const wrapped = new URL('https://www.google.com/url?q=https%3A%2F%2Fevil.example%2Flogin');
    const result = unwrapRedirects(wrapped);
    expect(result.url.hostname).toBe('evil.example');
    expect(result.hops).toBe(1);
    expect(result.chain).toEqual(['google.com', 'evil.example']);
  });

  it('peels a chain but stops at the hop limit, so a loop cannot hang the analysis', () => {
    // A self-referential redirector: unbounded unwrapping would spin here.
    const loop = new URL('https://a.example/r?url=https://a.example/r%3Furl%3Dhttps://a.example/r');
    const result = unwrapRedirects(loop, 3);
    expect(result.hops).toBeLessThanOrEqual(3);
  });

  it('marks a redirect whose destination it cannot resolve', () => {
    const opaque = new URL('https://tracker.example/click?url=https%3A%2F%2F');
    const result = unwrapRedirects(opaque);
    expect(result.opaqueRedirect).toBe(true);
  });

  it('finds a destination embedded in the path', () => {
    const embedded = new URL('https://redir.example/go/https://evil.example/login');
    expect(unwrapRedirects(embedded).url.hostname).toBe('evil.example');
  });

  /**
   * Parameters are tried in a fixed order, so an unresolvable one early in that order must not end the
   * search — otherwise adding `?q=//` is enough to hide the destination from every comparison that
   * depends on it.
   */
  it('keeps looking past a decoy parameter that leads nowhere', () => {
    const decoyed = new URL('https://tracker.example/click?q=%2F%2F&url=https%3A%2F%2Fevil.example');
    const result = unwrapRedirects(decoyed);
    expect(result.url.hostname).toBe('evil.example');
    expect(result.opaqueRedirect).toBe(false);
  });

  it('does not treat an ordinary search query as a redirect', () => {
    const search = new URL('https://example.com/search?q=invoice+2024');
    const result = unwrapRedirects(search);
    expect(result.hops).toBe(0);
    expect(result.url.hostname).toBe('example.com');
  });

  it('refuses to unwrap into a non-web scheme', () => {
    const nasty = new URL('https://redir.example/?url=javascript%3Aalert(1)');
    const result = unwrapRedirects(nasty);
    expect(result.url.protocol).toBe('https:');
  });

  it('detects a redirect parameter even when the target is unreadable', () => {
    expect(hasRedirectParam(new URL('https://x.example/?url=https%3A%2F%2Fy.example'))).toBe(true);
    expect(hasRedirectParam(new URL('https://x.example/?q=hello'))).toBe(false);
  });
});

describe('parseDisplayedUrl', () => {
  it('reads anchor text that a human would read as a URL', () => {
    expect(parseDisplayedUrl('https://login.microsoftonline.com')?.hostname).toBe(
      'login.microsoftonline.com',
    );
    expect(parseDisplayedUrl('login.microsoftonline.com/verify')?.hostname).toBe(
      'login.microsoftonline.com',
    );
    expect(parseDisplayedUrl('  paypal.com  ')?.hostname).toBe('paypal.com');
  });

  it('strips trailing sentence punctuation', () => {
    expect(parseDisplayedUrl('Visit example.com.')).toBeNull();
    expect(parseDisplayedUrl('example.com.')?.hostname).toBe('example.com');
  });

  it.each([
    'Click here to sign in',
    'Sign in',
    '',
    'read more',
    'Verify your account now',
    'invoice 2024',
  ])('does not read ordinary link text like %o as a URL', (text) => {
    // This strictness is what keeps "displayed URL differs from destination" from firing on every
    // legitimate email that has a "Sign in" button.
    expect(parseDisplayedUrl(text)).toBeNull();
  });

  it('ignores absurdly long text rather than parsing it', () => {
    expect(parseDisplayedUrl(`https://example.com/${'a'.repeat(4000)}`)).toBeNull();
  });
});

describe('sameRegistrableDomain', () => {
  it('compares at the registrable boundary, not by string equality', () => {
    expect(sameRegistrableDomain('login.example.com', 'mail.example.com')).toBe(true);
    expect(sameRegistrableDomain('example.co.uk', 'login.example.co.uk')).toBe(true);
    expect(sameRegistrableDomain('example.com', 'example.net')).toBe(false);
  });

  it('treats empty input as not matching, so a missing value never reads as agreement', () => {
    expect(sameRegistrableDomain('', '')).toBe(false);
    expect(sameRegistrableDomain('example.com', '')).toBe(false);
  });
});

describe('domainLabels', () => {
  it('returns labels for names and nothing for IP literals', () => {
    expect(domainLabels('a.b.example.com')).toEqual(['a', 'b', 'example', 'com']);
    expect(domainLabels('192.168.1.1')).toEqual([]);
  });
});

describe('hasPunycode', () => {
  it('detects an encoded label anywhere in the host', () => {
    expect(hasPunycode('xn--80ak6aa92e.com')).toBe(true);
    expect(hasPunycode('login.xn--e1awd7f.example')).toBe(true);
    expect(hasPunycode('example.com')).toBe(false);
  });

  it('sees punycode where the platform parser produced it from Unicode input', () => {
    const parsed = parseUrl('https://аpple.com/login');
    expect(hasPunycode(parsed?.hostname ?? '')).toBe(true);
  });
});
