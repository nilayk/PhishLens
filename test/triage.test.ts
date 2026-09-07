/**
 * Inbox-list triage.
 *
 * A marker on a list row is the extension's least-evidenced statement — a sender line and nothing else —
 * so the tests here are mostly about what it must *not* say. Two properties matter more than any
 * detection: it never marks a row as safe, and it never fires on ordinary mail, because a marker a user
 * learns to ignore is worse than no marker and one they trust as an all-clear is worse still.
 */
import { describe, expect, it } from 'vitest';
import { analyzeDeterministic } from '../src/analysis/engine.js';
import { triageSender, __testables } from '../src/analysis/triage.js';
import { loadAllFixtures } from './fixtures/load.js';

const FIXED_NOW = 1_760_000_000_000;

describe('triageSender', () => {
  it('warns about a display name impersonating a brand it does not send from', () => {
    const verdict = triageSender({
      senderName: 'Microsoft Account Team',
      senderEmail: 'security@microsoft-account-verify.com',
    });
    expect(verdict).not.toBeNull();
    expect(verdict?.title).not.toBe('');
  });

  it('warns about a lookalike of a real domain', () => {
    expect(triageSender({ senderName: 'PayPal', senderEmail: 'service@paypa1.com' })).not.toBeNull();
  });

  it('says nothing about ordinary mail', () => {
    const ordinary = [
      { senderName: 'Tom Adeyemi', senderEmail: 'accounts@brightline-supplies.co.uk' },
      { senderName: 'Sam Okafor', senderEmail: 'sam.okafor@northwind-logistics.com' },
      { senderName: '', senderEmail: 'no-reply@github.com' },
      { senderName: 'Kestrel Coffee Roasters', senderEmail: 'hello@kestrelcoffee.co.uk' },
      // A department, not an organisation claim. This one is the reason the marker's floor is `high`:
      // the name shares no word with the domain, so the softer half of `unsupported_org_claim` fires,
      // and being told only that about a supplier's invoice would be a marker worth switching off.
      { senderName: 'Accounts Receivable', senderEmail: 'ar@brightline-supplies.co.uk' },
    ];
    for (const sender of ordinary) {
      expect(triageSender(sender), sender.senderEmail).toBeNull();
    }
  });

  it('says nothing when there is no sender to look at', () => {
    // The row equivalent of an unreadable message. Silence is right here precisely because it is not an
    // all-clear: nothing on this row claims the message was checked.
    expect(triageSender({ senderName: 'Someone', senderEmail: '' })).toBeNull();
    expect(triageSender({ senderName: '', senderEmail: '   ' })).toBeNull();
  });

  it('has no verdict that could read as an all-clear', () => {
    // Every possible output is either null or a warning. Asserted over the corpus rather than argued,
    // since the whole design rests on it.
    for (const fixture of loadAllFixtures()) {
      const verdict = triageSender({
        senderName: fixture.email.senderName ?? '',
        senderEmail: fixture.email.senderEmail ?? '',
        ...(fixture.email.recipientEmail === undefined
          ? {}
          : { recipientEmail: fixture.email.recipientEmail }),
      });
      if (verdict === null) continue;
      expect(verdict.severity, fixture.name).not.toBe('info');
      expect(verdict.title, fixture.name).not.toMatch(/no |clean|safe|passed/i);
    }
  });

  it('marks no legitimate fixture', () => {
    for (const fixture of loadAllFixtures()) {
      const full = analyzeDeterministic(fixture.email, { now: FIXED_NOW });
      if (full.classification !== 'low') continue;

      const verdict = triageSender({
        senderName: fixture.email.senderName ?? '',
        senderEmail: fixture.email.senderEmail ?? '',
        ...(fixture.email.recipientEmail === undefined
          ? {}
          : { recipientEmail: fixture.email.recipientEmail }),
      });
      expect(verdict, `${fixture.name} scored low but was marked in the list`).toBeNull();
    }
  });

  it('ignores the subject and snippet entirely', () => {
    // A row's snippet length depends on the window width. A verdict that moved with it would differ
    // between two people looking at the same inbox.
    const sender = { senderName: 'Accounts', senderEmail: 'billing@northwind-logistics.com' };
    expect(triageSender(sender)).toBeNull();
  });
});

/**
 * The guard on the allowlist.
 *
 * A new identity rule is invisible to triage until someone lists it, which is the safe default but a
 * silent one. This makes the omission loud: every identity rule the corpus exercises has to be either
 * allowed or deliberately excluded, so adding one forces the decision.
 */
describe('the sender-only allowlist', () => {
  it('classifies every identity rule the corpus produces', () => {
    const produced = new Set<string>();
    for (const fixture of loadAllFixtures()) {
      for (const signal of analyzeDeterministic(fixture.email, { now: FIXED_NOW }).signals) {
        if (signal.category === 'identity') produced.add(__testables.baseId(signal.id));
      }
    }

    const unclassified = [...produced].filter(
      (id) =>
        !__testables.SENDER_ONLY_RULES.has(id) && !__testables.NEEDS_MORE_THAN_SENDER.has(id),
    );
    expect(unclassified).toEqual([]);
  });

  it('lists nothing in both sets', () => {
    const both = [...__testables.SENDER_ONLY_RULES].filter((id) =>
      __testables.NEEDS_MORE_THAN_SENDER.has(id),
    );
    expect(both).toEqual([]);
  });
});
