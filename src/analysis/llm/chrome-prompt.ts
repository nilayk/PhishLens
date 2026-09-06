/**
 * Chrome on-device model adapter (the Prompt API / built-in AI).
 *
 * The API surface is unstable: the entry point, the availability method, and the values it returns have
 * all differed between Chrome versions, and the feature is often behind a flag the user never enabled.
 * Every shape this file knows about is therefore probed rather than assumed, and anything unexpected
 * resolves to "unavailable" instead of throwing. `analyze()` returns `null` for both "no model" and
 * "nothing usable came back", so the pipeline needs no special case for either.
 *
 * Two structural constraints shape the class:
 *  - The session is expensive, so it is cached. That is only sound in the content script, which lives
 *    as long as the tab; the service worker MV3 terminates when idle must never load this module.
 *  - A session takes one prompt at a time, so all model work is serialised through `#enqueue`.
 */
import { isAborted } from '../../shared/abort.js';
import { logger } from '../../shared/logger.js';
import type {
  EmailMessage,
  SemanticAnalysis,
  SemanticAnalyzeOptions,
  SemanticAnalyzer,
} from '../../shared/types.js';
import { parseSemanticAnalysis } from './parse.js';
import { RESPONSE_SCHEMA, SYSTEM_PROMPT, buildUserPrompt, describePromptShape } from './prompt.js';

/** Milliseconds before a single on-device inference is abandoned. */
const INFERENCE_TIMEOUT_MS = 20_000;

/** Deterministic settings where the API supports them. */
const DETERMINISTIC_OPTIONS = { temperature: 0, topK: 1 };

// ---------------------------------------------------------------------------
// Structural probing (no `any`, no optimistic casts)
// ---------------------------------------------------------------------------

type UnknownRecord = Record<string, unknown>;

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === 'object' && value !== null;
}

/**
 * Whether properties can be read off `value`.
 *
 * Broader than `isRecord` on purpose: the current entry point is a class, so it is function-typed and
 * an object-only check rejects the real API. Availability *results* still use `isRecord`, since a
 * function there would mean something is wrong.
 */
function isPropertyHost(value: unknown): value is UnknownRecord {
  return value !== null && (typeof value === 'object' || typeof value === 'function');
}

function fn(host: unknown, name: string): ((...args: unknown[]) => unknown) | null {
  if (!isPropertyHost(host)) return null;
  const candidate = host[name];
  return typeof candidate === 'function' ? (candidate as (...args: unknown[]) => unknown) : null;
}

/**
 * Locates the language-model factory across the shapes this API has shipped as.
 * Returns the object that exposes `create()`, or `null`.
 */
function findFactory(): { host: UnknownRecord; label: string } | null {
  const g = globalThis as unknown as UnknownRecord;

  // Current: bare `LanguageModel` global (Chrome 138+ in extensions, 148+ on the web). This is a
  // class, so it is function-typed — see `isPropertyHost`.
  const bare = g['LanguageModel'];
  if (isPropertyHost(bare) && fn(bare, 'create') !== null) {
    return { host: bare, label: 'LanguageModel' };
  }

  // Earlier: `window.ai.languageModel`.
  const ai = g['ai'];
  if (isPropertyHost(ai)) {
    const languageModel = ai['languageModel'];
    if (isPropertyHost(languageModel) && fn(languageModel, 'create') !== null) {
      return { host: languageModel, label: 'window.ai.languageModel' };
    }
  }

  // Origin-trial era: `chrome.aiOriginTrial.languageModel`.
  const chromeNs = g['chrome'];
  if (isPropertyHost(chromeNs)) {
    const trial = chromeNs['aiOriginTrial'];
    if (isPropertyHost(trial)) {
      const languageModel = trial['languageModel'];
      if (isPropertyHost(languageModel) && fn(languageModel, 'create') !== null) {
        return { host: languageModel, label: 'chrome.aiOriginTrial.languageModel' };
      }
    }
  }
  return null;
}

/** Normalises the two historical availability reporting shapes to a single verdict. */
async function probeAvailability(host: UnknownRecord): Promise<'ready' | 'needs-download' | 'no'> {
  const availability = fn(host, 'availability');
  if (availability !== null) {
    const result: unknown = await availability.call(host);
    if (typeof result === 'string') {
      if (result === 'available') return 'ready';
      if (result === 'downloadable' || result === 'downloading') return 'needs-download';
      return 'no';
    }
  }

  const capabilities = fn(host, 'capabilities');
  if (capabilities !== null) {
    const result: unknown = await capabilities.call(host);
    if (isRecord(result)) {
      const available = result['available'];
      if (available === 'readily') return 'ready';
      if (available === 'after-download') return 'needs-download';
    }
    return 'no';
  }

  // A factory that exposes `create()` but no availability probe at all. Assume unavailable rather
  // than triggering a model download as a side effect of a feature check.
  return 'no';
}

interface Session {
  prompt(input: string, options?: UnknownRecord): Promise<unknown>;
  destroy?: () => void;
}

function asSession(value: unknown): Session | null {
  if (!isRecord(value)) return null;
  const prompt = fn(value, 'prompt');
  if (prompt === null) return null;
  return {
    prompt: async (input: string, options?: UnknownRecord) => {
      const result: unknown = options === undefined
        ? await prompt.call(value, input)
        : await prompt.call(value, input, options);
      return result;
    },
    ...(fn(value, 'destroy') !== null
      ? {
          destroy: () => {
            try {
              fn(value, 'destroy')?.call(value);
            } catch {
              // A session that will not close is not worth reporting.
            }
          },
        }
      : {}),
  };
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

export class ChromePromptAnalyzer implements SemanticAnalyzer {
  readonly id = 'chrome-on-device';

  /** Cached session. Valid only in a long-lived context (the content script). */
  #session: Session | null = null;
  /**
   * Whether the cached session was created with the system prompt attached.
   *
   * False only on the last-resort bare `create({})`. Every instruction that makes the output usable
   * lives in `SYSTEM_PROMPT` — the JSON contract, the calibration against over-flagging, and the
   * framing of message text as data rather than instructions — so a session without it must be given
   * the same text inline instead. Running without it at all would quietly produce an uncalibrated,
   * injection-exposed verdict that looks exactly like a normal one.
   */
  #sessionHasSystemPrompt = false;
  #factoryLabel = '';
  /** Set once availability has been determined, to avoid re-probing on every message. */
  #availability: 'ready' | 'needs-download' | 'no' | 'unknown' = 'unknown';

  /**
   * Tail of the queue of pending model work. Every use of the session goes through `#enqueue`.
   *
   * A session accepts one prompt at a time and rejects a second while the first is outstanding. Since a
   * rejected inference is treated as a poisoned session and destroys it, concurrent calls do not merely
   * queue badly — they lose each other's results. Gmail renders a thread in stages and each stage looks
   * like a new message to the observer, so concurrency here is the normal case, not an edge one.
   */
  #chain: Promise<unknown> = Promise.resolve();

  async isAvailable(): Promise<boolean> {
    try {
      if (this.#availability === 'unknown') {
        const factory = findFactory();
        if (factory === null) {
          this.#availability = 'no';
          logger.debug('on-device model: no factory global present');
          return false;
        }
        this.#factoryLabel = factory.label;
        this.#availability = await probeAvailability(factory.host);
        logger.debug('on-device model probe', {
          factory: factory.label,
          availability: this.#availability,
        });
      }
      // `needs-download` is deliberately not treated as available: triggering a multi-hundred-
      // megabyte download because a user opened an email would be an unacceptable surprise.
      return this.#availability === 'ready';
    } catch (error) {
      // Any unexpected shape or thrown error resolves to false. Never propagate.
      this.#availability = 'no';
      logger.debug('on-device model probe failed', error);
      return false;
    }
  }

  /**
   * Loads the model and builds the session ahead of first use.
   *
   * Called at content-script startup so the several seconds of session creation are spent while the
   * user is still looking at their inbox, rather than after they open the first message. Never
   * downloads: `isAvailable()` is false unless the model is already on disk, so a cold browser warms
   * nothing and costs nothing.
   */
  async warmUp(): Promise<void> {
    try {
      if (!(await this.isAvailable())) return;
      const session = await this.#enqueue(() => this.#ensureSession());
      logger.debug('on-device model warm-up', { session: session !== null });
    } catch (error) {
      logger.debug('on-device model warm-up failed', error);
    }
  }

  async analyze(
    email: EmailMessage,
    options: SemanticAnalyzeOptions = {},
  ): Promise<SemanticAnalysis | null> {
    if (!(await this.isAvailable())) return null;
    return this.#enqueue(() => this.#analyzeOne(email, options));
  }

  async #analyzeOne(
    email: EmailMessage,
    options: SemanticAnalyzeOptions,
  ): Promise<SemanticAnalysis | null> {
    // Reached the front of the queue only to find the reader has moved on. Whatever is on screen now
    // is not this message, so the cheapest correct thing is to not run at all.
    if (isAborted(options.signal)) return null;

    try {
      const session = await this.#ensureSession();
      if (session === null) return null;

      const user = buildUserPrompt(email);
      const prompt = this.#sessionHasSystemPrompt ? user : `${SYSTEM_PROMPT}\n\n${user}`;
      logger.debug('on-device inference starting', { shape: describePromptShape(email) });

      const raw = await this.#promptWithTimeout(session, prompt, options.signal);
      if (raw === null) return null;

      const analysis = parseSemanticAnalysis(raw, 'local', this.#factoryLabel);
      if (analysis === null) {
        logger.debug('on-device output rejected by schema validation');
      }
      return analysis;
    } catch (error) {
      // A failed session is assumed poisoned; the next call rebuilds it.
      this.#discardSession();
      logger.debug('on-device inference failed', error);
      return null;
    }
  }

  /**
   * Runs `job` after all previously queued model work has finished.
   *
   * The queue tail is kept as a promise that never rejects, so one failed inference cannot break the
   * chain for every subsequent message.
   */
  #enqueue<T>(job: () => Promise<T>): Promise<T> {
    const run = this.#chain.then(job);
    this.#chain = run.catch(() => undefined);
    return run;
  }

  /**
   * Creates a session, reusing the cached one when present.
   *
   * Tries the modern `initialPrompts` system-role shape first, then the older `systemPrompt` option,
   * then a bare create — each historically valid, none guaranteed.
   */
  async #ensureSession(): Promise<Session | null> {
    if (this.#session !== null) return this.#session;

    const factory = findFactory();
    if (factory === null) return null;
    const create = fn(factory.host, 'create');
    if (create === null) return null;

    const attempts: { options: UnknownRecord; system: boolean }[] = [
      {
        options: {
          ...DETERMINISTIC_OPTIONS,
          initialPrompts: [{ role: 'system', content: SYSTEM_PROMPT }],
        },
        system: true,
      },
      { options: { ...DETERMINISTIC_OPTIONS, systemPrompt: SYSTEM_PROMPT }, system: true },
      { options: { initialPrompts: [{ role: 'system', content: SYSTEM_PROMPT }] }, system: true },
      { options: {}, system: false },
    ];

    for (const attempt of attempts) {
      try {
        const session = asSession(await create.call(factory.host, attempt.options));
        if (session !== null) {
          this.#session = session;
          this.#sessionHasSystemPrompt = attempt.system;
          return session;
        }
      } catch {
        // Options rejected by this Chrome version; try the next shape.
      }
    }
    logger.debug('on-device session could not be created with any known option shape');
    return null;
  }

  /**
   * Runs one inference with a timeout, requesting a JSON-schema constraint when the version supports
   * it and retrying unconstrained when it does not.
   *
   * The retry loop is why abort needs explicit handling. Its `catch` exists to swallow "this Chrome
   * version rejected that option shape" and try the next one, and an abort arrives as a rejection too
   * — so without the check below, cancelling would silently run all three attempts instead of none.
   */
  async #promptWithTimeout(
    session: Session,
    prompt: string,
    signal?: AbortSignal,
  ): Promise<string | null> {
    const attempts: (UnknownRecord | undefined)[] = [
      { responseConstraint: RESPONSE_SCHEMA, omitResponseConstraintInput: true },
      { responseConstraint: RESPONSE_SCHEMA },
      undefined,
    ];

    for (const options of attempts) {
      if (isAborted(signal)) return null;
      // Passed to the API as well as checked here: the API can stop work already in progress, which
      // this loop cannot.
      const withSignal = signal === undefined ? options : { ...options, signal };

      try {
        const result = await withTimeout(session.prompt(prompt, withSignal), INFERENCE_TIMEOUT_MS);
        if (typeof result === 'string' && result.trim() !== '') return result;
      } catch (error) {
        if (isAborted(signal)) return null;
        if (error instanceof TimeoutError) {
          this.#discardSession();
          return null;
        }
        // Unsupported option shape; fall through to the next attempt.
      }
    }
    return null;
  }

  #discardSession(): void {
    this.#session?.destroy?.();
    this.#session = null;
    this.#sessionHasSystemPrompt = false;
  }

  /** Releases the on-device session. Called when the content script tears down. */
  dispose(): void {
    this.#discardSession();
  }
}

class TimeoutError extends Error {
  constructor() {
    super('inference timed out');
    this.name = 'TimeoutError';
  }
}

async function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => {
          reject(new TimeoutError());
        }, ms);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}