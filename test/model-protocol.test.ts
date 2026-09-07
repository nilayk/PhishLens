/**
 * What we ask a model server for, and how we read its reply.
 *
 * Every case here comes from a runner actually behaving this way, because none of it can be reasoned out
 * from a specification: "OpenAI-compatible" is a family resemblance, and the fields that differ between
 * members are exactly the ones this file pins down. The failure these guard against is the worst kind to
 * receive — HTTP 200, a model plainly loaded and running, and a card saying it returned nothing usable.
 */
import { describe, expect, it } from 'vitest';

import {
  MAX_TOKENS,
  REQUEST_VARIANTS,
  completionText,
  describeHttpFailure,
  describeUnusable,
  isShapeRejection,
} from '../src/background/model-protocol.js';

/** A reply in the shape Ollama returns, reduced to the fields anything reads. */
function reply(
  message: Record<string, unknown>,
  finishReason = 'stop',
): Record<string, unknown> {
  return { choices: [{ index: 0, message, finish_reason: finishReason }] };
}

describe('the request ladder', () => {
  it('asks for the strongest guarantees first', () => {
    const [strictest] = REQUEST_VARIANTS;
    expect((strictest?.['response_format'] as { type?: string } | undefined)?.type).toBe('json_schema');
    expect(strictest?.['reasoning_effort']).toBe('none');
  });

  it('gives up one guarantee at a time, ending with a plain request', () => {
    expect(REQUEST_VARIANTS.map((v) => Object.keys(v).sort().join('+'))).toEqual([
      'reasoning_effort+response_format',
      'reasoning_effort+response_format',
      'response_format',
      '',
    ]);
    expect(REQUEST_VARIANTS.at(-1)).toEqual({});
  });

  /**
   * The ladder exists because a server that does not know a field rejects the whole request rather than
   * ignoring it, so both optional fields have to be droppable — including `reasoning_effort`, which is
   * newer than `response_format` and the more likely of the two to be unknown.
   */
  it('can reach a working request even if reasoning_effort is what was refused', () => {
    const withoutReasoning = REQUEST_VARIANTS.filter((v) => !('reasoning_effort' in v));
    expect(withoutReasoning.length).toBeGreaterThanOrEqual(2);
  });

  it('retries only a rejection of the request shape', () => {
    expect(isShapeRejection(400)).toBe(true);
    expect(isShapeRejection(422)).toBe(true);
    // Retrying these would make the reader wait several times as long to be told the same thing.
    for (const status of [401, 403, 404, 500, 502, 503]) {
      expect(isShapeRejection(status), String(status)).toBe(false);
    }
  });

  /**
   * The budget has to hold a reasoning model's thinking *and* the answer, because runners count thinking
   * against it and `reasoning_effort` is not honoured everywhere. A 9B Qwen3-class model spent 430 tokens
   * thinking before answering, which is what made 500 too small.
   */
  it('leaves room for a model that thinks before answering', () => {
    expect(MAX_TOKENS).toBeGreaterThanOrEqual(1500);
  });
});

describe('describeHttpFailure', () => {
  /**
   * The most common first experience of this feature, and the one where a bare status code sends the
   * reader to look for a fault that is not there: the address, the port and the permission grant are all
   * correct, and the server simply was not told to expect an extension origin.
   */
  it('explains a refusal as the origin policy it is, and names the setting', () => {
    for (const status of [401, 403]) {
      const message = describeHttpFailure(status);
      expect(message).toContain(String(status));
      expect(message).toContain('browser extensions');
      expect(message).toContain('OLLAMA_ORIGINS');
    }
  });

  it('reads a 404 as the wrong path rather than a missing server', () => {
    expect(describeHttpFailure(404)).toContain('/v1');
  });

  it('says only what it knows about anything else', () => {
    expect(describeHttpFailure(500)).toBe('model server returned 500');
  });
});

describe('completionText', () => {
  it('reads the assistant text from a normal reply', () => {
    expect(completionText(reply({ role: 'assistant', content: '{"risk": 40}' }))).toBe('{"risk": 40}');
  });

  /**
   * A runner that separates thinking from the answer often has an *earlier draft* of the same JSON in the
   * thinking, with different numbers in it. Reading that would show a verdict the model discarded, so an
   * answer that is only thinking counts as no answer.
   */
  it('never reads a reply out of the model\'s thinking', () => {
    const thinkingOnly = reply({
      role: 'assistant',
      content: '',
      reasoning: 'Let me consider. Maybe {"risk": 90}. Actually no.',
    });
    expect(completionText(thinkingOnly)).toBeNull();
  });

  it('treats whitespace as nothing said', () => {
    expect(completionText(reply({ role: 'assistant', content: '   \n ' }))).toBeNull();
  });

  it('survives every shape a reply might not have', () => {
    for (const body of [
      null,
      undefined,
      'not json',
      42,
      {},
      { choices: [] },
      { choices: 'no' },
      { choices: [{}] },
      { choices: [{ message: null }] },
      { choices: [{ message: { content: 42 } }] },
    ]) {
      expect(completionText(body), JSON.stringify(body ?? null)).toBeNull();
    }
  });
});

describe('describeUnusable', () => {
  /**
   * The diagnosis that took the longest to reach without it: the model answered, in valid JSON, and the
   * budget ended mid-string. Every other parse failure looks identical from the card, so the shape of the
   * reply is what separates raising a limit from changing a prompt.
   */
  it('recognises an answer cut off by the token budget', () => {
    const truncated = describeUnusable(
      reply(
        { role: 'assistant', content: '{"risk": 48, "reasons": ["Uses time pressure', reasoning: 'x'.repeat(1700) },
        'length',
      ),
      '{"risk": 48, "reasons": ["Uses time pressure',
    );

    expect(truncated.truncated).toBe(true);
    expect(truncated.finish).toBe('length');
    expect(truncated.thoughtChars).toBe(1700);
    expect(truncated.contentChars).toBeGreaterThan(0);
  });

  it('distinguishes prose the parser refused from an answer that never came', () => {
    const prose = describeUnusable(reply({ role: 'assistant', content: 'I cannot help with that.' }), 'I cannot help with that.');
    expect(prose).toEqual({ finish: 'stop', contentChars: 24, thoughtChars: 0, truncated: false });

    const nothing = describeUnusable(reply({ role: 'assistant', content: '' }), null);
    expect(nothing.contentChars).toBe(0);
    expect(nothing.truncated).toBe(false);
  });

  it('reads the other spelling of the thinking field', () => {
    const body = reply({ role: 'assistant', content: '', reasoning_content: 'thinking' });
    expect(describeUnusable(body, null).thoughtChars).toBe(8);
  });

  it('describes a reply it cannot understand at all without throwing', () => {
    for (const body of [null, undefined, {}, { choices: [] }, 'text']) {
      expect(describeUnusable(body, null).finish).toBe('unknown');
    }
  });
});
