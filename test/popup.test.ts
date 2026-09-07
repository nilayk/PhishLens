/**
 * The popup's wording.
 *
 * Worth asserting rather than eyeballing because the popup is consulted when something looks wrong, and
 * the two sentences it must never confuse — "nothing was found" and "nothing was checked" — are one
 * careless edit apart.
 */
import { describe, expect, it } from 'vitest';
import { aiRow, cardButtonLabel, findingsLine, headline } from '../src/popup/present.js';
import type { PopupState } from '../src/popup/present.js';
import { DEFAULT_SETTINGS } from '../src/shared/settings.js';
import type { SemanticStatus, Settings } from '../src/shared/types.js';

const scored = (over: Partial<Extract<PopupState, { kind: 'scored' }>> = {}): PopupState => ({
  kind: 'scored',
  score: 58,
  classification: 'suspicious',
  findings: 4,
  headlines: ['Display name does not match the sending domain'],
  semantic: 'ready',
  ...over,
});

const settings = (over: Partial<Settings> = {}): Settings => ({ ...DEFAULT_SETTINGS, ...over });

describe('headline', () => {
  it('shows the score and classification for a scored message', () => {
    const head = headline(scored());
    expect(head.label).toBe('Suspicious');
    expect(head.score).toBe('58/100');
    expect(head.tone).toBe('suspicious');
  });

  it('never presents an unreadable message as a clean one', () => {
    const head = headline({ kind: 'unreadable', missing: ['sender'] });
    expect(head.score).toBe('');
    expect(head.tone).toBe('unknown');
    expect(head.label).not.toMatch(/low|safe|clean/i);
    // The load-bearing sentence. Its absence is the failure this project refuses.
    expect(head.note).toMatch(/not a judgement that the message is safe/i);
  });

  it('names every unread part in the explanation', () => {
    const head = headline({ kind: 'unreadable', missing: ['sender', 'body'] });
    expect(head.note).toContain('who it is from');
    expect(head.note).toContain('its text');
  });

  it('distinguishes a clean message from an unchecked one', () => {
    const clean = headline(scored({ score: 0, classification: 'low', findings: 0 }));
    const unchecked = headline({ kind: 'unreadable', missing: ['sender'] });
    expect(clean.note).not.toBe(unchecked.note);
    expect(clean.note).toMatch(/checks found (nothing|anything)/i);
  });

  it('tells a tab that predates the extension to reload', () => {
    expect(headline({ kind: 'unreachable' }).note).toMatch(/reload/i);
  });

  it('offers no verdict glyph where there is no verdict', () => {
    for (const kind of ['not-gmail', 'no-message', 'pending'] as const) {
      expect(headline({ kind }).glyph).toBe('');
      expect(headline({ kind }).score).toBe('');
    }
  });
});

describe('findingsLine', () => {
  it('counts findings, singular and plural', () => {
    expect(findingsLine(scored({ findings: 1 }))).toBe('1 finding');
    expect(findingsLine(scored({ findings: 4 }))).toBe('4 findings');
    expect(findingsLine(scored({ findings: 0 }))).toBe('No findings');
  });

  it('counts nothing when nothing was scored', () => {
    expect(findingsLine({ kind: 'unreadable', missing: ['body'] })).toBeNull();
    expect(findingsLine({ kind: 'not-gmail' })).toBeNull();
  });
});

describe('cardButtonLabel', () => {
  it('offers the card exactly when the tab has one to show', () => {
    expect(cardButtonLabel(scored())).not.toBeNull();
    expect(cardButtonLabel({ kind: 'unreadable', missing: ['sender'] })).not.toBeNull();
    expect(cardButtonLabel({ kind: 'pending' })).toBeNull();
    expect(cardButtonLabel({ kind: 'no-message' })).toBeNull();
    expect(cardButtonLabel({ kind: 'not-gmail' })).toBeNull();
  });

  it('does not promise an assessment for a message that was never assessed', () => {
    expect(cardButtonLabel({ kind: 'unreadable', missing: ['sender'] })).not.toMatch(/assessment/i);
  });
});

describe('aiRow', () => {
  it('reports the mode by what it is, not by its stored value', () => {
    expect(aiRow(settings({ aiMode: 'local' }), scored()).label).toBe('On-device model');
    expect(aiRow(settings({ aiMode: 'server' }), scored()).label).toBe('Your model server');
  });

  it('says analysis is off without implying a failure', () => {
    const row = aiRow(settings({ aiMode: 'off' }), scored({ semantic: 'off' }));
    expect(row.detail).toMatch(/switched off/i);
    expect(row.fix).toBeNull();
    expect(row.testable).toBe(false);
  });

  it('has wording for every semantic status', () => {
    const statuses: SemanticStatus[] = [
      'ready',
      'pending',
      'off',
      'unavailable',
      'no-output',
      'error',
      'cancelled',
    ];
    for (const semantic of statuses) {
      const row = aiRow(settings({ aiMode: 'local' }), scored({ semantic }));
      expect(row.detail).not.toBe('');
    }
  });

  it('points a failing model server at the connection test', () => {
    const configured = settings({
      aiMode: 'server',
      modelBaseUrl: 'http://localhost:11434/v1',
      modelName: 'qwen2.5:7b',
    });
    for (const semantic of ['no-output', 'error'] as const) {
      const row = aiRow(configured, scored({ semantic }));
      expect(row.testable).toBe(true);
      expect(row.fix).toMatch(/test the connection/i);
    }
  });

  it('asks for the missing settings rather than offering a test that cannot work', () => {
    const row = aiRow(settings({ aiMode: 'server' }), scored());
    expect(row.testable).toBe(false);
    expect(row.fix).toMatch(/settings/i);
  });

  it('does not offer a connection test for the on-device model', () => {
    expect(aiRow(settings({ aiMode: 'local' }), scored({ semantic: 'unavailable' })).testable).toBe(
      false,
    );
  });

  it('does not claim to be waiting for a message that is already open', () => {
    const row = aiRow(settings({ aiMode: 'local' }), { kind: 'unreadable', missing: ['sender'] });
    expect(row.detail).toMatch(/not used/i);
  });

  it('reports configuration, not a verdict, before a message is open', () => {
    const row = aiRow(settings({ aiMode: 'local' }), { kind: 'no-message' });
    expect(row.detail).not.toMatch(/unavailable/i);
    expect(row.fix).toBeNull();
  });

  it('explains an absent on-device model without implying the checks failed', () => {
    const row = aiRow(settings({ aiMode: 'local' }), scored({ semantic: 'unavailable' }));
    expect(row.fix).toMatch(/technical checks are unaffected/i);
  });
});
