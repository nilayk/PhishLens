/**
 * Tests for the extraction-gap rule: when the adapter cannot read a message, nothing is scored.
 *
 * The failure this guards against is the only one in the project that points the wrong way. Every other
 * degradation loses a finding, which understates risk by a knowable amount; this one produces a
 * *confident* verdict from an almost empty message, and the verdict it produces is "Low Risk". A user
 * who has learned to trust a green badge is worse off than one with no extension at all.
 *
 * So the first test here does not test the guard — it demonstrates the danger, by scoring a phishing
 * message with its sender removed and showing what comes back. If a later change makes that message
 * score high on its own, this file should be revisited rather than deleted: the guard would then be
 * unnecessary, and a test asserting a near-zero score would be asserting the bug.
 */
import { describe, expect, it } from 'vitest';

import { analyzeDeterministic } from '../src/analysis/engine.js';
import { isScorable } from '../src/gmail/adapter.js';
import { browserVersion, formatDiagnostic, type SelectorProbe } from '../src/gmail/diagnostics.js';
import type { EmailMessage, MessagePart } from '../src/shared/types.js';
import { unreadableNotes } from '../src/ui/format.js';
import { UNREADABLE_LABEL } from '../src/ui/labels.js';
import { loadFixture } from './fixtures/load.js';

/** The extraction a broken sender selector produces: everything else intact, no address. */
function withoutSender(email: EmailMessage): EmailMessage {
  const { senderEmail: _address, senderName: _name, raw: _raw, ...rest } = email;
  return rest;
}

describe('why the guard exists', () => {
  /**
   * A thread hijack is the clearest case because it is *entirely* an identity attack: an outsider
   * replying into a real conversation, detectable only by comparing who they are against who has been
   * in it. Take the sender away and there is nothing left to detect — no bad link, no attachment, no
   * alarming wording — so the engine correctly reports a message with no findings, and the badge that
   * reports it says Low Risk.
   */
  it.each(['thread-hijack-lookalike', 'thread-hijack-name-reuse'])(
    'scores %s as low risk once its sender cannot be read',
    (name) => {
      const phish = loadFixture(name).email;

      const whole = analyzeDeterministic(phish);
      const blinded = analyzeDeterministic(withoutSender(phish));

      // Nothing about the message changed in any way a reader would notice; only our view of it did.
      expect(whole.classification).not.toBe('low');
      expect(blinded.classification).toBe('low');
    },
  );

  /**
   * Recorded so the guard is not mistaken for a fix. Phishing that carries its payload in the body is
   * still caught with no sender at all, which is why the extension keeps working through a partial
   * breakage rather than switching itself off — and why the gap is reported on the message it affects
   * instead of disabling the extension globally.
   */
  it('still catches a phish whose evidence is in the body', () => {
    const phish = loadFixture('microsoft-phish').email;
    expect(analyzeDeterministic(withoutSender(phish)).classification).toBe('high-risk');
  });

  it('leaves a message scoreable when only its subject is unread', () => {
    const phish = loadFixture('thread-hijack-lookalike').email;
    const { subject: _subject, ...noSubject } = phish;

    // Not a claim that the score is unchanged — some wording checks read the subject — only that what
    // remains is a real assessment of a real sender, which is why a subject is not load-bearing.
    expect(analyzeDeterministic({ ...noSubject, subject: '' }).classification).not.toBe('low');
  });
});

describe('isScorable', () => {
  it('accepts a complete extraction', () => {
    expect(isScorable([])).toBe(true);
  });

  it('refuses one with no sender, whatever else was read', () => {
    expect(isScorable(['sender'])).toBe(false);
    expect(isScorable(['sender', 'subject'])).toBe(false);
  });

  it('refuses one with no body', () => {
    expect(isScorable(['body'])).toBe(false);
  });

  it('accepts one missing only the subject, which costs detail rather than meaning', () => {
    expect(isScorable(['subject'])).toBe(true);
  });
});

describe('what the card says when nothing was checked', () => {
  const parts: MessagePart[] = ['sender', 'subject', 'body'];

  it('names a cause for every part, so a new one cannot ship unworded', () => {
    for (const part of parts) {
      expect(unreadableNotes([part])[0]?.text).toContain('PhishLens could not read');
    }

    // Distinct wording per part, or the card would say the same thing about different failures.
    const firsts = new Set(parts.map((part) => unreadableNotes([part])[0]?.text));
    expect(firsts.size).toBe(parts.length);
  });

  /**
   * Asserted by *finding* the emphatic note rather than by position. The card marked one paragraph
   * emphatic by index, which silently moved onto a cause line as soon as two parts were unread — the
   * sentence that carries the whole point of this state, unemphasised.
   */
  it.each([[['sender']], [['sender', 'subject']], [[]]] as MessagePart[][][])(
    'emphasises exactly the safety disclaimer for %j',
    (missing) => {
      const emphatic = unreadableNotes(missing).filter((note) => note.emphatic);

      expect(emphatic).toHaveLength(1);
      expect(emphatic[0]?.text).toContain('not a judgement that the message is safe');
      expect(emphatic[0]?.text).toContain('Nothing was checked');
    },
  );

  /**
   * The property that matters most and is easiest to break by editing copy: nothing on this card may
   * read as reassurance. A future author softening the tone is exactly how "not checked" starts sounding
   * like "nothing found".
   */
  it('never reassures the reader', () => {
    const text = [UNREADABLE_LABEL, ...unreadableNotes(['sender', 'subject']).map((n) => n.text)]
      .join(' ')
      .toLowerCase();

    for (const reassurance of [
      'low risk',
      'looks fine',
      'looks safe',
      'appears safe',
      'no threats',
      'nothing suspicious',
      'no problems',
    ]) {
      expect(text).not.toContain(reassurance);
    }
  });

  it('still explains itself when the missing list is empty, rather than rendering a blank card', () => {
    expect(unreadableNotes([]).map((note) => note.text).join(' ')).toContain('could not read');
  });
});

describe('the diagnostic report', () => {
  const probes: SelectorProbe[] = [
    { group: 'messageContainer', scope: 'message', candidate: 0 },
    { group: 'senderSpan', scope: 'none', candidate: -1 },
    { group: 'subject', scope: 'document', candidate: 1 },
  ];

  const report = formatDiagnostic({
    adapter: 'gmail-dom',
    version: '0.3.0',
    browser: 'Chrome/139.0.0.0',
    missing: ['sender'],
    probes,
  });

  it('names the group that found nothing, which is the actionable part', () => {
    expect(report).toContain('senderSpan');
    expect(report).toMatch(/senderSpan\s+NO MATCH/u);
  });

  it('shows which candidate matched, so a decaying list is visible before it breaks', () => {
    // `subject` fell through to its second candidate: still working, worth knowing.
    expect(report).toMatch(/subject\s+document #1 h2\.hP/u);
  });

  it('records the versions a bug report needs', () => {
    expect(report).toContain('0.3.0');
    expect(report).toContain('Chrome/139.0.0.0');
    expect(report).toContain('gmail-dom');
    expect(report).toContain('missing:  sender');
  });

  it('reduces a user agent to the browser version alone', () => {
    expect(
      browserVersion(
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.7258.67 Safari/537.36',
      ),
    ).toBe('Chrome/139.0.7258.67');
    expect(browserVersion('something else entirely')).toBe('unknown');
  });

  /**
   * The privacy claim the card makes about the report, tested where it can be: no field of the input
   * carries message content, so no output can. A future author who adds `subject` or a body length to
   * `DiagnosticInput` to make debugging easier will not be caught by this — hence the file header on
   * `diagnostics.ts` listing what was excluded and why.
   */
  it('carries nothing from the message', () => {
    const phish = loadFixture('microsoft-phish').email;
    for (const secret of [phish.senderEmail, phish.subject, phish.bodyText.slice(0, 40)]) {
      if (secret === undefined || secret === '') continue;
      expect(report).not.toContain(secret);
    }
  });
});
