/**
 * The privacy boundary.
 *
 * Two things are tested here, and they are the two places where a mistake would leak mailbox content:
 *
 *  1. **Settings validation.** The defaults must favour local processing, and a value read back from
 *     storage — possibly written by an older build — must never be able to turn the cloud path on or
 *     point it somewhere unintended.
 *  2. **Redaction.** `buildCloudPayload` is the *only* function whose output would ever leave the
 *     browser. These tests assert what it drops, not just what it keeps, because a field silently
 *     added to it later is exactly the regression worth catching.
 */
import { describe, expect, it } from 'vitest';
import { buildCloudPayload, describeNameShape, redactAddresses } from '../src/analysis/llm/redact.js';
import {
  DEFAULT_SETTINGS,
  isCloudConfigured,
  normalizeBackendUrl,
  normalizeSettings,
} from '../src/shared/settings.js';
import type { EmailMessage } from '../src/shared/types.js';
import { loadFixture } from './fixtures/load.js';

describe('default settings', () => {
  it('processes locally and requires no backend', () => {
    expect(DEFAULT_SETTINGS.aiMode).toBe('local');
    expect(DEFAULT_SETTINGS.backendBaseUrl).toBe('');
    expect(isCloudConfigured(DEFAULT_SETTINGS)).toBe(false);
  });

  it('is not cloud-capable out of the box under any reading of the defaults', () => {
    // Belt and braces: cloud mode requires *both* an explicit choice and a URL, so a single mistaken
    // default cannot start sending content anywhere.
    expect(isCloudConfigured({ ...DEFAULT_SETTINGS, aiMode: 'cloud' })).toBe(false);
    expect(isCloudConfigured({ ...DEFAULT_SETTINGS, backendBaseUrl: 'https://x.example' })).toBe(false);
  });
});

describe('normalizeSettings', () => {
  it.each([
    ['null', null],
    ['undefined', undefined],
    ['a string', 'aiMode=cloud'],
    ['a number', 42],
    ['an array', []],
  ])('falls back to defaults for %s', (_label, raw) => {
    expect(normalizeSettings(raw)).toEqual(DEFAULT_SETTINGS);
  });

  it('rejects an unrecognised AI mode rather than passing it through', () => {
    expect(normalizeSettings({ aiMode: 'remote' }).aiMode).toBe('local');
    expect(normalizeSettings({ aiMode: 42 }).aiMode).toBe('local');
    expect(normalizeSettings({ aiMode: null }).aiMode).toBe('local');
  });

  it('preserves valid choices', () => {
    expect(normalizeSettings({ aiMode: 'off' }).aiMode).toBe('off');
    expect(normalizeSettings({ aiMode: 'cloud' }).aiMode).toBe('cloud');
    expect(normalizeSettings({ highlightEnabled: false }).highlightEnabled).toBe(false);
    expect(normalizeSettings({ showBadgeWhenLow: false }).showBadgeWhenLow).toBe(false);
  });

  it('ignores unknown keys instead of carrying them forward', () => {
    const normalized = normalizeSettings({ aiMode: 'off', apiKey: 'sk-secret', debug: true });
    expect(Object.keys(normalized).sort()).toEqual(
      ['aiMode', 'backendBaseUrl', 'highlightEnabled', 'showBadgeWhenLow'].sort(),
    );
  });
});

describe('normalizeBackendUrl', () => {
  it('keeps an https origin and path prefix', () => {
    expect(normalizeBackendUrl('https://phishlens.example.com')).toBe('https://phishlens.example.com');
    expect(normalizeBackendUrl('https://example.com/api/v1')).toBe('https://example.com/api/v1');
    expect(normalizeBackendUrl('  https://example.com/  ')).toBe('https://example.com');
  });

  it.each([
    ['plain http, which would send content in the clear', 'http://example.com'],
    ['a javascript: URL', 'javascript:alert(1)'],
    ['a data: URL', 'data:text/plain,hi'],
    ['a file: URL', 'file:///etc/passwd'],
    ['a chrome-extension: URL', 'chrome-extension://abc/page.html'],
    ['a bare hostname with no scheme', 'example.com'],
    ['an empty string', ''],
    ['whitespace', '   '],
    ['nonsense', 'not a url at all'],
    ['a non-string', 42],
    ['null', null],
  ])('refuses %s', (_label, input) => {
    expect(normalizeBackendUrl(input)).toBe('');
  });

  it('discards query and fragment, so a configured URL cannot smuggle parameters', () => {
    expect(normalizeBackendUrl('https://example.com/api?key=secret#frag')).toBe('https://example.com/api');
  });

  it('cannot be pointed at a model vendor by editing storage without also choosing cloud mode', () => {
    const settings = normalizeSettings({ backendBaseUrl: 'https://api.openai.com' });
    expect(settings.aiMode).toBe('local');
    expect(isCloudConfigured(settings)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

const RICH_EMAIL: EmailMessage = {
  senderName: 'Microsoft Account Team',
  senderEmail: 'security-noreply@rnicrosoft-online.com',
  replyTo: 'collect@mailbox-relay.example',
  recipientEmail: 'jane.okonkwo@northwind-logistics.com',
  subject: 'Unusual sign-in activity on your account',
  bodyText:
    'Hello jane.okonkwo@northwind-logistics.com, we detected a sign-in. Contact us at help@rnicrosoft-online.com immediately.',
  links: [
    {
      text: 'Verify now',
      href: 'https://account-verify.example/login?uid=8f3a9c2b-jane-okonkwo&campaign=q4',
      normalizedDomain: 'account-verify.example',
    },
  ],
  attachments: [
    { filename: 'Northwind_Payroll_Q4_Okonkwo.xlsx', extension: 'xlsx' },
  ],
};

describe('buildCloudPayload: what is dropped', () => {
  const payload = buildCloudPayload(RICH_EMAIL, ['identity.lookalike_sender_domain']);
  const serialized = JSON.stringify(payload);

  it('never includes the recipient address', () => {
    expect(serialized).not.toContain('jane.okonkwo@northwind-logistics.com');
    expect(payload).not.toHaveProperty('recipientEmail');
  });

  it('reduces the sender to a domain, dropping the local part', () => {
    expect(payload.senderDomain).toBe('rnicrosoft-online.com');
    expect(serialized).not.toContain('security-noreply');
  });

  it('describes the display name by shape rather than including it', () => {
    expect(serialized).not.toContain('Microsoft Account Team');
    expect(payload.senderNameShape).toContain('three-words');
  });

  it('reduces links to registrable domains, dropping paths that carry recipient identifiers', () => {
    expect(payload.linkDomains).toEqual(['account-verify.example']);
    expect(serialized).not.toContain('8f3a9c2b');
    expect(serialized).not.toContain('uid=');
  });

  it('reduces attachments to extensions, dropping filenames that name people and cases', () => {
    expect(payload.attachmentExtensions).toEqual(['xlsx']);
    expect(serialized).not.toContain('Okonkwo');
    expect(serialized).not.toContain('Northwind_Payroll');
  });

  it('redacts addresses that appear inside the body, keeping only their domains', () => {
    expect(payload.bodyExcerpt).not.toContain('jane.okonkwo@');
    expect(payload.bodyExcerpt).not.toContain('help@');
    expect(payload.bodyExcerpt).toContain('<address@northwind-logistics.com>');
  });

  it('keeps the Reply-To domain, which is load-bearing for the analysis', () => {
    expect(payload.replyToDomain).toBe('mailbox-relay.example');
  });

  it('carries no identifiers that would let a backend correlate a mailbox across requests', () => {
    for (const forbidden of ['messageId', 'threadId', 'recipientEmail', 'senderEmail', 'senderName']) {
      expect(payload).not.toHaveProperty(forbidden);
    }
  });

  it('bounds every field, so payload size does not scale with message size', () => {
    const huge = buildCloudPayload(
      {
        senderEmail: 'a@example.com',
        subject: 'x'.repeat(5000),
        bodyText: 'y'.repeat(500_000),
        links: Array.from({ length: 400 }, (_v, i) => ({
          text: 't',
          href: `https://d${String(i)}.example/`,
          normalizedDomain: `d${String(i)}.example`,
        })),
        attachments: Array.from({ length: 100 }, (_v, i) => ({
          filename: `f${String(i)}.pdf`,
          extension: `ext${String(i)}`,
        })),
      },
      Array.from({ length: 200 }, (_v, i) => `signal.${String(i)}`),
    );

    expect(huge.subject.length).toBeLessThanOrEqual(300);
    expect(huge.bodyExcerpt.length).toBeLessThanOrEqual(4200);
    expect(huge.linkDomains.length).toBeLessThanOrEqual(25);
    expect(huge.attachmentExtensions.length).toBeLessThanOrEqual(15);
    expect(huge.deterministicSignalIds.length).toBeLessThanOrEqual(40);
  });

  it('produces a payload whose every field is inspectable in the options UI wording', () => {
    // The options page promises "subject, a body excerpt, and domains". Assert the shape matches the
    // promise, so the two cannot drift apart.
    expect(Object.keys(payload).sort()).toEqual(
      [
        'attachmentExtensions',
        'bodyExcerpt',
        'deterministicSignalIds',
        'linkDomains',
        'replyToDomain',
        'senderDomain',
        'senderNameShape',
        'subject',
      ].sort(),
    );
  });
});

/**
 * `EmailMessage.raw` holds un-normalised header values so that formatting detectors can see evidence
 * normalisation destroys. It is the least redacted data in the message, so it must never reach the
 * payload. `buildCloudPayload` uses an explicit allowlist, which is what makes this hold — these tests
 * exist so that a future refactor to spreading the email fails here.
 */
describe('buildCloudPayload never forwards raw header values', () => {
  const email = {
    senderName: 'Fidelity Life Offer',
    senderEmail: 'donot.reply.donot.reply@mt50sys.com',
    subject: 'YOUR QUOTE IS READY',
    bodyText: 'Body text.',
    links: [],
    attachments: [],
    raw: {
      senderEmail: 'DoNoT.rEpLy.DoNoT.rEpLy@mt50sys.com',
      subject: `YOUR QUOTE IS READY${' '.repeat(40)}`,
    },
  };
  const payload = buildCloudPayload(email, []);
  const serialized = JSON.stringify(payload);

  it('omits the raw slot entirely', () => {
    expect(payload).not.toHaveProperty('raw');
    expect(serialized).not.toContain('DoNoT');
  });

  it('forwards no padding, only the collapsed subject', () => {
    expect(serialized).not.toMatch(/ {4}/u);
  });

  it('still forwards the fields it is supposed to', () => {
    expect(payload.senderDomain).toBe('mt50sys.com');
    expect(payload.subject).toBe('YOUR QUOTE IS READY');
  });
});

describe('redactAddresses', () => {
  it('keeps the domain and drops the local part', () => {
    expect(redactAddresses('Write to alice.smith+tag@example.co.uk today')).toBe(
      'Write to <address@example.co.uk> today',
    );
  });

  it('redacts every occurrence, not just the first', () => {
    const redacted = redactAddresses('a@x.example and b@y.example and c@x.example');
    expect(redacted).not.toMatch(/\ba@|\bb@|\bc@/u);
    expect(redacted).toContain('<address@x.example>');
    expect(redacted).toContain('<address@y.example>');
  });

  it('leaves text without addresses untouched', () => {
    expect(redactAddresses('No addresses here at all.')).toBe('No addresses here at all.');
  });
});

describe('describeNameShape', () => {
  it.each([
    ['', 'empty'],
    ['Jane', 'one-word'],
    ['Jane Okonkwo', 'two-words'],
  ])('describes %o as %s', (input, expected) => {
    expect(describeNameShape(input)).toBe(expected);
  });

  it('notes impersonation-relevant shape without revealing the name', () => {
    const shape = describeNameShape('Microsoft Account Team');
    expect(shape).toContain('role-account');
    expect(shape).not.toContain('Microsoft');
  });

  it('notes an address embedded in a display name, a common spoofing trick', () => {
    expect(describeNameShape('security@microsoft.com')).toContain('contains-address');
  });

  it('notes non-ASCII characters, which is where homoglyph names live', () => {
    expect(describeNameShape('Аpple Support')).toContain('non-ascii');
  });

  it('collapses an unbounded name to a bounded description', () => {
    expect(describeNameShape('word '.repeat(1000)).length).toBeLessThan(60);
  });
});

describe('redaction against real fixtures', () => {
  it.each(['legitimate', 'microsoft-phish', 'bec-gift-card', 'legitimate-invoice'])(
    'leaks no full email address for %s',
    (name) => {
      const email = loadFixture(name).email;
      const serialized = JSON.stringify(buildCloudPayload(email, []));

      // Placeholders are removed first, since `<address@example.com>` is the redacted form and would
      // otherwise match the pattern we are looking for.
      const withoutPlaceholders = serialized.replace(/<address@[\w.-]+>/gu, '');
      expect(withoutPlaceholders).not.toMatch(/[\w.+-]+@[\w-]+\.[\w.-]+/u);
      if (email.senderEmail !== undefined) {
        expect(serialized).not.toContain(email.senderEmail);
      }
    },
  );
});
