/**
 * The on-device adapter's fail-closed behaviour.
 *
 * The Chrome Prompt API has moved between `window.ai.languageModel`, `chrome.aiOriginTrial.
 * languageModel`, and the bare `LanguageModel` global, and has reported availability through two
 * different method names with two different vocabularies. We cannot test against a real model in CI,
 * so what is tested here is the thing that actually matters: **every deviation from the shape we hope
 * for resolves to "unavailable" rather than throwing, hanging, or inventing a verdict.**
 *
 * Each case installs a fake global, so these run in plain Node with no browser. The fakes must match
 * the browser's *shape*, not merely its interface: the modern global is a class, and fakes that were
 * plain objects let a probe bug through that disabled on-device analysis in every real browser.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ChromePromptAnalyzer } from '../src/analysis/llm/chrome-prompt.js';
import { SYSTEM_PROMPT } from '../src/analysis/llm/prompt.js';
import type { EmailMessage } from '../src/shared/types.js';

const EMAIL: EmailMessage = {
  senderName: 'Microsoft Account Team',
  senderEmail: 'security@rnicrosoft-online.com',
  subject: 'Unusual sign-in activity',
  bodyText: 'Verify your account immediately or it will be suspended.',
  links: [],
  attachments: [],
};

const VALID_JSON = JSON.stringify({
  risk: 78,
  categories: ['credential_phishing'],
  reasons: ['The message demands immediate account verification.'],
  confidence: 0.82,
});

type Globals = Record<string, unknown>;

const INSTALLED_KEYS = ['LanguageModel', 'ai', 'chrome'] as const;

/** Installs fake globals for one test and records them for teardown. */
function install(globals: Globals): void {
  for (const [key, value] of Object.entries(globals)) {
    (globalThis as unknown as Globals)[key] = value;
  }
}

afterEach(() => {
  for (const key of INSTALLED_KEYS) {
    Reflect.deleteProperty(globalThis, key);
  }
  vi.restoreAllMocks();
});

/**
 * A factory in the modern shape: static `availability()` + `create()`.
 *
 * Returned as a **class**, because that is what the browser exposes. This matters more than it
 * looks: an earlier version of this suite used an object literal here, which passed happily while
 * the adapter rejected every real browser, since `typeof LanguageModel === 'function'` and the
 * probe was guarding on `typeof === 'object'`. A fake in the wrong shape tests nothing.
 */
function modernFactory(options: { availability?: string; promptResult?: unknown } = {}) {
  const prompt = vi.fn((_input: string, _promptOptions?: unknown) =>
    Promise.resolve(options.promptResult ?? VALID_JSON),
  );
  const destroy = vi.fn();
  const create = vi.fn((_createOptions?: unknown) => Promise.resolve({ prompt, destroy }));
  const availability = vi.fn(() => Promise.resolve(options.availability ?? 'available'));

  // A class is a function carrying static properties, which is what this builds. The adapter must
  // never invoke it as a constructor, so doing so fails loudly rather than silently succeeding.
  function LanguageModelFake(): never {
    throw new TypeError('the Prompt API entry point is not constructed by the adapter');
  }

  const factory = Object.assign(LanguageModelFake, { availability, create });
  return { factory, prompt, destroy, create, availability };
}

/** The same contract as `modernFactory`, but as a plain namespace object (pre-class builds). */
function objectFactory(options: { availability?: string } = {}) {
  return {
    availability: () => Promise.resolve(options.availability ?? 'available'),
    create: () => Promise.resolve({ prompt: () => Promise.resolve(VALID_JSON) }),
  };
}

describe('on-device adapter: availability', () => {
  it('reports unavailable when no factory global exists at all', async () => {
    const analyzer = new ChromePromptAnalyzer();
    await expect(analyzer.isAvailable()).resolves.toBe(false);
    await expect(analyzer.analyze(EMAIL)).resolves.toBeNull();
  });

  it('finds the bare LanguageModel global when it is a class, as browsers ship it', async () => {
    const { factory } = modernFactory();
    // Regression: the probe once required `typeof === 'object'`, so this returned false on every
    // browser that had a working model. Keep the fake function-typed.
    expect(typeof factory).toBe('function');

    install({ LanguageModel: factory });
    await expect(new ChromePromptAnalyzer().isAvailable()).resolves.toBe(true);
  });

  it('also accepts an object-shaped bare global', async () => {
    install({ LanguageModel: objectFactory() });
    await expect(new ChromePromptAnalyzer().isAvailable()).resolves.toBe(true);
  });

  it('finds the older window.ai.languageModel shape', async () => {
    install({ ai: { languageModel: objectFactory() } });
    await expect(new ChromePromptAnalyzer().isAvailable()).resolves.toBe(true);
  });

  it('finds the origin-trial chrome.aiOriginTrial.languageModel shape', async () => {
    install({ chrome: { aiOriginTrial: { languageModel: objectFactory() } } });
    await expect(new ChromePromptAnalyzer().isAvailable()).resolves.toBe(true);
  });

  it('accepts the legacy capabilities().available vocabulary', async () => {
    install({
      LanguageModel: {
        capabilities: () => Promise.resolve({ available: 'readily' }),
        create: () => Promise.resolve({ prompt: () => Promise.resolve(VALID_JSON) }),
      },
    });
    await expect(new ChromePromptAnalyzer().isAvailable()).resolves.toBe(true);
  });

  it.each([
    ['downloadable', 'the model is not on disk yet'],
    ['downloading', 'the model is still downloading'],
  ])('treats "%s" as unavailable, because %s', async (availability) => {
    install({ LanguageModel: modernFactory({ availability }).factory });
    // Deliberate: opening an email must never kick off a multi-hundred-megabyte download.
    await expect(new ChromePromptAnalyzer().isAvailable()).resolves.toBe(false);
  });

  it.each([
    ['a factory with create() but no availability probe', { create: () => Promise.resolve({}) }],
    ['availability() returning an unknown string', {
      availability: () => Promise.resolve('perhaps'),
      create: () => Promise.resolve({}),
    }],
    ['availability() returning a non-string', {
      availability: () => Promise.resolve(42),
      create: () => Promise.resolve({}),
    }],
    ['capabilities() returning an unknown verdict', {
      capabilities: () => Promise.resolve({ available: 'maybe' }),
      create: () => Promise.resolve({}),
    }],
    ['a factory whose create is not callable', { availability: () => Promise.resolve('available'), create: 42 }],
    ['a non-object global', 'LanguageModel'],
    ['a null global', null],
    // Broadening the guard to accept function-typed hosts must not accept *any* function.
    ['a function global with no create', () => undefined],
  ])('fails closed on %s', async (_label, fake) => {
    install({ LanguageModel: fake });
    await expect(new ChromePromptAnalyzer().isAvailable()).resolves.toBe(false);
  });

  it.each([
    ['availability() throws', () => {
      throw new Error('NotAllowedError: origin trial token missing');
    }],
    ['availability() rejects', () => Promise.reject(new Error('internal error'))],
  ])('never propagates a rejection when %s', async (_label, availability) => {
    install({ LanguageModel: { availability, create: () => Promise.resolve({}) } });
    const analyzer = new ChromePromptAnalyzer();
    // The contract is `Promise<boolean>`, not `Promise<boolean> | throws`.
    await expect(analyzer.isAvailable()).resolves.toBe(false);
    await expect(analyzer.analyze(EMAIL)).resolves.toBeNull();
  });

  it('probes once and caches the verdict across messages', async () => {
    const { factory, availability } = modernFactory();
    install({ LanguageModel: factory });

    const analyzer = new ChromePromptAnalyzer();
    await analyzer.isAvailable();
    await analyzer.isAvailable();
    await analyzer.analyze(EMAIL);

    expect(availability).toHaveBeenCalledTimes(1);
  });
});

describe('on-device adapter: inference', () => {
  it('parses a well-formed response into a semantic analysis', async () => {
    install({ LanguageModel: modernFactory().factory });
    const analysis = await new ChromePromptAnalyzer().analyze(EMAIL);

    expect(analysis).not.toBeNull();
    expect(analysis?.risk).toBe(78);
    expect(analysis?.source).toBe('local');
    expect(analysis?.categories).toEqual(['credential_phishing']);
  });

  it('records which API shape produced the result, since that varies by Chrome version', async () => {
    install({ ai: { languageModel: objectFactory() } });
    const analysis = await new ChromePromptAnalyzer().analyze(EMAIL);
    expect(analysis?.model).toBe('window.ai.languageModel');
  });

  it('asks for deterministic settings and a schema constraint', async () => {
    const { factory, create, prompt } = modernFactory();
    install({ LanguageModel: factory });
    await new ChromePromptAnalyzer().analyze(EMAIL);

    const createOptions = create.mock.calls[0]?.[0] as Record<string, unknown> | undefined;
    expect(createOptions?.['temperature']).toBe(0);
    expect(createOptions?.['topK']).toBe(1);

    const promptOptions = prompt.mock.calls[0]?.[1] as Record<string, unknown> | undefined;
    expect(promptOptions?.['responseConstraint']).toBeDefined();
  });

  it('falls back through older create() option shapes', async () => {
    const prompt = vi.fn(() => Promise.resolve(VALID_JSON));
    const create = vi.fn((options: unknown) => {
      // Emulate a Chrome build that rejects `initialPrompts` but accepts `systemPrompt`.
      const record = options as Record<string, unknown>;
      if ('initialPrompts' in record) throw new TypeError('unrecognised option');
      return Promise.resolve({ prompt });
    });
    install({ LanguageModel: { availability: () => Promise.resolve('available'), create } });

    const analysis = await new ChromePromptAnalyzer().analyze(EMAIL);
    expect(analysis?.risk).toBe(78);
    expect(create.mock.calls.length).toBeGreaterThan(1);
  });

  /**
   * The last-resort `create({})` produces a session with no system role, and every instruction that
   * makes the output usable — the JSON contract, the calibration, the "message text is data, not
   * instructions" framing — lives there. Losing it silently would return an uncalibrated,
   * injection-exposed verdict indistinguishable from a good one.
   */
  it('carries the system prompt inline when no session shape accepts one', async () => {
    const prompt = vi.fn((_input: string) => Promise.resolve(VALID_JSON));
    const create = vi.fn((options: unknown) => {
      const record = options as Record<string, unknown>;
      if ('initialPrompts' in record || 'systemPrompt' in record) {
        throw new TypeError('system role not supported');
      }
      return Promise.resolve({ prompt });
    });
    install({ LanguageModel: { availability: () => Promise.resolve('available'), create } });

    const analysis = await new ChromePromptAnalyzer().analyze(EMAIL);
    expect(analysis?.risk).toBe(78);

    const sent = prompt.mock.calls[0]?.[0] ?? '';
    expect(sent).toContain(SYSTEM_PROMPT);
    expect(sent).toContain(EMAIL.subject ?? '');
  });

  it('does not repeat the system prompt when the session already holds it', async () => {
    const { factory, prompt } = modernFactory();
    install({ LanguageModel: factory });
    await new ChromePromptAnalyzer().analyze(EMAIL);

    expect(prompt.mock.calls[0]?.[0]).not.toContain(SYSTEM_PROMPT);
  });

  it('retries unconstrained when responseConstraint is unsupported', async () => {
    const prompt = vi.fn((_input: string, options?: unknown) => {
      if (options !== undefined) return Promise.reject(new TypeError('responseConstraint not supported'));
      return Promise.resolve(VALID_JSON);
    });
    install({
      LanguageModel: {
        availability: () => Promise.resolve('available'),
        create: () => Promise.resolve({ prompt }),
      },
    });

    const analysis = await new ChromePromptAnalyzer().analyze(EMAIL);
    expect(analysis?.risk).toBe(78);
  });

  it.each([
    ['prose instead of JSON', 'I think this is probably phishing, be careful!'],
    ['an empty response', ''],
    ['whitespace only', '   \n  '],
    ['a non-string response', { risk: 50 }],
    ['JSON missing required fields', '{"risk": 50}'],
  ])('returns null on %s rather than guessing', async (_label, promptResult) => {
    install({ LanguageModel: modernFactory({ promptResult }).factory });
    await expect(new ChromePromptAnalyzer().analyze(EMAIL)).resolves.toBeNull();
  });

  it('returns null when the session cannot be created at all', async () => {
    install({
      LanguageModel: {
        availability: () => Promise.resolve('available'),
        create: () => Promise.resolve({ notAPrompt: true }),
      },
    });
    await expect(new ChromePromptAnalyzer().analyze(EMAIL)).resolves.toBeNull();
  });

  it('returns null, not a rejection, when prompt() throws synchronously', async () => {
    install({
      LanguageModel: {
        availability: () => Promise.resolve('available'),
        create: () => Promise.resolve({
          prompt: () => {
            throw new Error('session destroyed');
          },
        }),
      },
    });
    await expect(new ChromePromptAnalyzer().analyze(EMAIL)).resolves.toBeNull();
  });

  it('abandons a hung inference instead of blocking the pipeline', async () => {
    vi.useFakeTimers();
    try {
      install({
        LanguageModel: {
          availability: () => Promise.resolve('available'),
          create: () => Promise.resolve({ prompt: () => new Promise(() => undefined) }),
        },
      });

      const pending = new ChromePromptAnalyzer().analyze(EMAIL);
      await vi.advanceTimersByTimeAsync(25_000);
      await expect(pending).resolves.toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  it('reuses one session across messages, then releases it on dispose', async () => {
    const { factory, create, destroy } = modernFactory();
    install({ LanguageModel: factory });

    const analyzer = new ChromePromptAnalyzer();
    await analyzer.analyze(EMAIL);
    await analyzer.analyze(EMAIL);
    // Session caching is why this adapter lives in the content script and not the service worker,
    // which MV3 would terminate between messages.
    expect(create).toHaveBeenCalledTimes(1);

    analyzer.dispose();
    expect(destroy).toHaveBeenCalledTimes(1);
  });

  it('survives a session that refuses to be destroyed', async () => {
    install({
      LanguageModel: {
        availability: () => Promise.resolve('available'),
        create: () => Promise.resolve({
          prompt: () => Promise.resolve(VALID_JSON),
          destroy: () => {
            throw new Error('already destroyed');
          },
        }),
      },
    });
    const analyzer = new ChromePromptAnalyzer();
    await analyzer.analyze(EMAIL);
    expect(() => {
      analyzer.dispose();
    }).not.toThrow();
  });

  it('does not send the recipient address to the model', async () => {
    const { factory, prompt } = modernFactory();
    install({ LanguageModel: factory });

    await new ChromePromptAnalyzer().analyze({ ...EMAIL, recipientEmail: 'victim@northwind.example' });
    const sent = prompt.mock.calls[0]?.[0] ?? '';
    expect(sent).not.toContain('victim@northwind.example');
    expect(sent).toContain('Unusual sign-in activity');
  });
});

/**
 * A session that behaves like the real one: it refuses a prompt while another is outstanding.
 *
 * This is the fake that reproduces the "no AI assessment on the first email after opening Gmail" bug.
 * Gmail renders a thread in stages, so the observer legitimately reports the same first message two or
 * three times as the body fills in; each report started an inference, the later ones were rejected, and
 * the adapter's rejection handler destroyed the session out from under the first — so all of them
 * failed. Later messages arrive in one render, never collide, and always worked.
 */
function singleFlightFactory() {
  let inFlight = 0;
  let maxConcurrent = 0;

  const prompt = vi.fn(async (_input: string, _options?: unknown) => {
    if (inFlight > 0) throw new DOMException('a prompt is already in progress', 'InvalidStateError');
    inFlight += 1;
    maxConcurrent = Math.max(maxConcurrent, inFlight);
    try {
      await Promise.resolve();
      return VALID_JSON;
    } finally {
      inFlight -= 1;
    }
  });

  const create = vi.fn(() => Promise.resolve({ prompt, destroy: vi.fn() }));
  const factory = Object.assign(function LanguageModelFake(): never {
    throw new TypeError('not constructed');
  }, { availability: () => Promise.resolve('available'), create });

  return { factory, prompt, create, peak: () => maxConcurrent };
}

describe('on-device adapter: one request at a time', () => {
  it('serialises concurrent analyses instead of letting them collide', async () => {
    const { factory, peak } = singleFlightFactory();
    install({ LanguageModel: factory });
    const analyzer = new ChromePromptAnalyzer();

    // Three overlapping calls, as a staged Gmail render produces.
    const results = await Promise.all([
      analyzer.analyze(EMAIL),
      analyzer.analyze(EMAIL),
      analyzer.analyze(EMAIL),
    ]);

    // Every one succeeds. Unserialised, the last two are rejected and the first loses its session.
    expect(results.map((r) => r?.risk)).toEqual([78, 78, 78]);
    expect(peak()).toBe(1);
  });

  it('keeps serving later messages after one inference fails', async () => {
    // Three rejections, because one `analyze()` legitimately tries three option shapes before giving
    // up. Failing all of them is what makes the *call* fail, which is the case under test.
    let call = 0;
    const prompt = vi.fn(() => {
      call += 1;
      return call <= 3 ? Promise.reject(new Error('session lost')) : Promise.resolve(VALID_JSON);
    });
    install({
      LanguageModel: {
        availability: () => Promise.resolve('available'),
        create: () => Promise.resolve({ prompt }),
      },
    });
    const analyzer = new ChromePromptAnalyzer();

    // A rejection must not poison the queue for everything behind it.
    const [first, second] = await Promise.all([analyzer.analyze(EMAIL), analyzer.analyze(EMAIL)]);
    expect(first).toBeNull();
    expect(second?.risk).toBe(78);
  });

  it('builds the session during warm-up so the first message does not pay for it', async () => {
    const { factory, create, prompt } = modernFactory();
    install({ LanguageModel: factory });
    const analyzer = new ChromePromptAnalyzer();

    await analyzer.warmUp();
    expect(create).toHaveBeenCalledTimes(1);
    // Warming loads the model; it must not put a message through it.
    expect(prompt).not.toHaveBeenCalled();

    await analyzer.analyze(EMAIL);
    expect(create).toHaveBeenCalledTimes(1);
  });

  it('warming a browser without a ready model touches nothing', async () => {
    // `create()` on a downloadable model starts a multi-hundred-megabyte download. Warm-up must not be
    // the thing that triggers it.
    const { factory, create } = modernFactory({ availability: 'downloadable' });
    install({ LanguageModel: factory });

    await new ChromePromptAnalyzer().warmUp();
    expect(create).not.toHaveBeenCalled();
  });

  it('warm-up never throws, whatever the API does', async () => {
    install({
      LanguageModel: {
        availability: () => Promise.resolve('available'),
        create: () => Promise.reject(new Error('model failed to load')),
      },
    });
    await expect(new ChromePromptAnalyzer().warmUp()).resolves.toBeUndefined();
  });
});

describe('on-device adapter: cancellation', () => {
  it('does not run a queued analysis whose message is already gone', async () => {
    const { factory, prompt } = modernFactory();
    install({ LanguageModel: factory });

    const controller = new AbortController();
    controller.abort();

    await expect(new ChromePromptAnalyzer().analyze(EMAIL, { signal: controller.signal })).resolves.toBeNull();
    expect(prompt).not.toHaveBeenCalled();
  });

  it('passes the signal to the model so work already running can stop', async () => {
    const { factory, prompt } = modernFactory();
    install({ LanguageModel: factory });

    const controller = new AbortController();
    await new ChromePromptAnalyzer().analyze(EMAIL, { signal: controller.signal });

    const options = prompt.mock.calls[0]?.[1] as Record<string, unknown> | undefined;
    expect(options?.['signal']).toBe(controller.signal);
  });

  it('treats an abort as final rather than trying the next option shape', async () => {
    const controller = new AbortController();
    const prompt = vi.fn(() => {
      controller.abort();
      return Promise.reject(new DOMException('aborted', 'AbortError'));
    });
    install({
      LanguageModel: {
        availability: () => Promise.resolve('available'),
        create: () => Promise.resolve({ prompt }),
      },
    });

    const result = await new ChromePromptAnalyzer().analyze(EMAIL, { signal: controller.signal });
    expect(result).toBeNull();
    // The retry loop exists to survive unsupported option shapes. An abort is not one of those, and
    // must not spend two more inferences discovering that.
    expect(prompt).toHaveBeenCalledTimes(1);
  });

  it('cancelling one message lets the next one straight through', async () => {
    const { factory } = singleFlightFactory();
    install({ LanguageModel: factory });
    const analyzer = new ChromePromptAnalyzer();

    const abandoned = new AbortController();
    abandoned.abort();

    const [stale, current] = await Promise.all([
      analyzer.analyze(EMAIL, { signal: abandoned.signal }),
      analyzer.analyze(EMAIL),
    ]);

    expect(stale).toBeNull();
    expect(current?.risk).toBe(78);
  });
});
