/**
 * Service worker.
 *
 * **This file is intentionally stateless.** MV3 terminates the worker after ~30 s idle, so any
 * module-level cache here would be a correctness bug that only shows up under real usage. There is no
 * `let cache = …`, no model session, no analysis state; every handler re-reads `chrome.storage` from
 * scratch and every message is self-contained. See docs/ARCHITECTURE.md §2.
 *
 * It does exactly three things, all of which are safe to lose at any instant:
 *   1. settings read/write
 *   2. the only place the extension opens a socket — the inert cloud path, and a model server the user
 *      runs themselves
 *   3. seeding defaults on install
 *
 * Egress lives here rather than in the content script so that there is one file to audit for it, and so
 * that a Gmail page's execution context never holds the ability to make requests. Every endpoint is
 * composed from a URL that has already passed validation in `shared/settings.ts`; none is ever taken
 * from a message.
 *
 * It deliberately does **not** import the analysis engine or the on-device model adapter. Analysis
 * runs in the content script, where the execution context lives as long as the tab.
 */
import { logger } from '../shared/logger.js';
import {
  isExtensionRequest,
  type CloudAnalyzeRequest,
  type ExtensionRequest,
  type ExtensionResponse,
  type ModelServerAnalyzeRequest,
} from '../shared/messaging.js';
import {
  DEFAULT_SETTINGS,
  STORAGE_KEY,
  isCloudConfigured,
  isModelServerConfigured,
  normalizeSettings,
} from '../shared/settings.js';
import type { Settings } from '../shared/types.js';
import { parseSemanticAnalysis } from '../analysis/llm/parse.js';
import { RESPONSE_SCHEMA } from '../analysis/llm/prompt.js';

/** Cloud request timeout. Bounded so a hung backend cannot keep a worker alive indefinitely. */
const CLOUD_TIMEOUT_MS = 12_000;
/**
 * Model-server timeout, far longer than the cloud one because the work happens on the user's own
 * hardware: a 7B model on a CPU can take most of a minute on a long message. Still bounded, and the
 * card shows `pending` throughout, so the cost of the wait is visible rather than mysterious.
 */
const MODEL_SERVER_TIMEOUT_MS = 45_000;
/** Listing models runs no inference, so a server that cannot answer promptly is not reachable. */
const MODEL_LIST_TIMEOUT_MS = 8_000;
/** The schema output is a few hundred bytes; this stops a runaway model streaming indefinitely. */
const MODEL_SERVER_MAX_TOKENS = 500;

async function readSettings(): Promise<Settings> {
  try {
    const stored = await chrome.storage.sync.get(STORAGE_KEY);
    return normalizeSettings(stored[STORAGE_KEY]);
  } catch (error) {
    logger.debug('settings read failed; using defaults', error);
    return { ...DEFAULT_SETTINGS };
  }
}

async function writeSettings(patch: Partial<Settings>): Promise<Settings> {
  const current = await readSettings();
  const next = normalizeSettings({ ...current, ...patch });
  await chrome.storage.sync.set({ [STORAGE_KEY]: next });
  return next;
}

/**
 * The single egress point.
 *
 * Inert in the MVP: without `aiMode: 'cloud'` *and* a configured `backendBaseUrl` this returns an
 * error without touching the network, and there is no default backend URL. When it is enabled it
 * talks only to our own backend — never to a model vendor — and carries no API key, because an API
 * key shipped inside an extension is a public API key.
 */
async function cloudAnalyze(request: CloudAnalyzeRequest): Promise<ExtensionResponse> {
  const settings = await readSettings();
  if (!isCloudConfigured(settings)) {
    return { ok: false, error: 'cloud analysis is not enabled' };
  }

  const endpoint = `${settings.backendBaseUrl}/api/analyze`;
  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort();
  }, CLOUD_TIMEOUT_MS);

  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify(request.payload),
      signal: controller.signal,
      // No cookies or cached credentials are attached: this is an anonymous call to our own API, and
      // it must not become a way to correlate a browsing identity with mailbox content.
      credentials: 'omit',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      // A cross-origin redirect would move the payload to an origin the user never approved.
      redirect: 'error',
    });

    if (!response.ok) {
      return { ok: false, error: `analysis service returned ${String(response.status)}` };
    }

    const body: unknown = await response.json();
    const analysis = parseSemanticAnalysis(body, 'cloud');
    return { ok: true, type: 'SEMANTIC', analysis };
  } catch (error) {
    logger.debug('cloud analysis request failed', error);
    return { ok: false, error: 'analysis service unreachable' };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * The other egress point: an OpenAI-compatible model server the user runs.
 *
 * One request shape serves Ollama, LM Studio, Docker Model Runner, llama.cpp and vLLM, because they all
 * expose `/chat/completions`. The endpoint is composed from a URL that has already been through
 * `normalizeModelBaseUrl`, so it is either loopback or https, and it is read from settings rather than
 * taken from the message.
 *
 * No `Authorization` header is sent. Local runners ignore credentials, and the moment this function
 * grew a key field it would become a way to call a hosted vendor with a key stored in an extension.
 */
async function modelServerAnalyze(request: ModelServerAnalyzeRequest): Promise<ExtensionResponse> {
  const settings = await readSettings();
  if (!isModelServerConfigured(settings)) {
    return { ok: false, error: 'no model server is configured' };
  }

  const messages = [
    { role: 'system', content: request.payload.system },
    { role: 'user', content: request.payload.user },
  ];

  // Structured output is requested in descending order of strictness, because coverage differs by
  // runner and version, and a server that does not recognise a `response_format` rejects the request
  // outright rather than ignoring the field. Each retry is a rejected request, not a wasted
  // generation, so this costs a round trip on old servers and nothing on current ones. The parser
  // tolerates fenced or prose-wrapped JSON regardless, which is what makes the last rung viable.
  const formats: (Record<string, unknown> | null)[] = [
    { type: 'json_schema', json_schema: { name: 'assessment', strict: true, schema: RESPONSE_SCHEMA } },
    { type: 'json_object' },
    null,
  ];

  for (const [index, format] of formats.entries()) {
    const result = await postCompletion(settings, messages, format);
    if (result.retryable && index < formats.length - 1) {
      logger.debug('model server rejected the response format; retrying with a looser one');
      continue;
    }
    return result.response;
  }

  return { ok: false, error: 'model server did not accept any supported request shape' };
}

/**
 * `retryable` is true only for a 400-class rejection of the request *shape*, which is the one failure
 * worth trying a different way. A connection error, a timeout or a 500 mean the next attempt would fail
 * identically and the reader would wait three times as long to be told so.
 */
async function postCompletion(
  settings: Settings,
  messages: readonly { role: string; content: string }[],
  responseFormat: Record<string, unknown> | null,
): Promise<{ response: ExtensionResponse; retryable: boolean }> {
  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort();
  }, MODEL_SERVER_TIMEOUT_MS);

  try {
    const response = await fetch(`${settings.modelBaseUrl}/chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({
        model: settings.modelName,
        messages,
        // Deterministic: the same message should not score differently on a second reading.
        temperature: 0,
        max_tokens: MODEL_SERVER_MAX_TOKENS,
        stream: false,
        ...(responseFormat === null ? {} : { response_format: responseFormat }),
      }),
      signal: controller.signal,
      credentials: 'omit',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      // A redirect would move message content to an origin the user never approved — and, for a
      // loopback server, potentially off the machine entirely.
      redirect: 'error',
    });

    if (!response.ok) {
      return {
        response: { ok: false, error: `model server returned ${String(response.status)}` },
        retryable: response.status === 400 || response.status === 422,
      };
    }

    const body: unknown = await response.json();
    const content = completionText(body);
    if (content === null) {
      return { response: { ok: true, type: 'SEMANTIC', analysis: null }, retryable: false };
    }

    return {
      response: {
        ok: true,
        type: 'SEMANTIC',
        analysis: parseSemanticAnalysis(content, 'server', settings.modelName),
      },
      retryable: false,
    };
  } catch (error) {
    logger.debug('model server request failed', error);
    return {
      response: {
        ok: false,
        error: controller.signal.aborted ? 'model server timed out' : 'model server unreachable',
      },
      retryable: false,
    };
  } finally {
    clearTimeout(timer);
  }
}

/** Pulls the assistant text out of a chat-completions envelope without trusting its shape. */
function completionText(body: unknown): string | null {
  if (body === null || typeof body !== 'object') return null;
  const choices = (body as { choices?: unknown }).choices;
  if (!Array.isArray(choices) || choices.length === 0) return null;
  const message = (choices[0] as { message?: unknown }).message;
  if (message === null || typeof message !== 'object') return null;
  const content = (message as { content?: unknown }).content;
  return typeof content === 'string' && content.trim() !== '' ? content : null;
}

/**
 * `GET /models` on the configured server, so the options page can offer what is actually loaded rather
 * than asking the user to type a name from memory. Also the connection test: reaching this means the
 * URL, the port, the permission grant and the server's origin policy are all correct.
 */
async function listModels(): Promise<ExtensionResponse> {
  const settings = await readSettings();
  if (settings.modelBaseUrl === '') return { ok: false, error: 'no model server URL is set' };

  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort();
  }, MODEL_LIST_TIMEOUT_MS);

  try {
    const response = await fetch(`${settings.modelBaseUrl}/models`, {
      headers: { accept: 'application/json' },
      signal: controller.signal,
      credentials: 'omit',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      redirect: 'error',
    });
    if (!response.ok) return { ok: false, error: `server returned ${String(response.status)}` };

    const body: unknown = await response.json();
    const data = (body as { data?: unknown }).data;
    if (!Array.isArray(data)) return { ok: false, error: 'server did not return a model list' };

    const models = data
      .map((entry) => (entry as { id?: unknown }).id)
      .filter((id): id is string => typeof id === 'string' && id !== '')
      .slice(0, 200);
    return { ok: true, type: 'MODELS', models };
  } catch (error) {
    logger.debug('model list request failed', error);
    return { ok: false, error: 'could not reach the model server' };
  } finally {
    clearTimeout(timer);
  }
}

async function handle(request: ExtensionRequest): Promise<ExtensionResponse> {
  switch (request.type) {
    case 'GET_SETTINGS':
      return { ok: true, type: 'SETTINGS', settings: await readSettings() };
    case 'SET_SETTINGS':
      return { ok: true, type: 'SETTINGS', settings: await writeSettings(request.patch) };
    case 'CLOUD_ANALYZE':
      return cloudAnalyze(request);
    case 'MODEL_SERVER_ANALYZE':
      return modelServerAnalyze(request);
    case 'LIST_MODELS':
      return listModels();
  }
}

chrome.runtime.onMessage.addListener((message: unknown, sender, sendResponse): boolean => {
  if (!isExtensionRequest(message)) {
    sendResponse({ ok: false, error: 'unrecognised request' } satisfies ExtensionResponse);
    return false;
  }

  // Only accept messages from our own extension's contexts. `sender.id` is set by Chrome and cannot
  // be forged by a web page, so this rejects anything originating outside the extension.
  if (sender.id !== chrome.runtime.id) {
    sendResponse({ ok: false, error: 'unauthorised sender' } satisfies ExtensionResponse);
    return false;
  }

  handle(message).then(sendResponse, (error: unknown) => {
    logger.debug('handler threw', error);
    sendResponse({ ok: false, error: 'internal error' } satisfies ExtensionResponse);
  });

  // Keeps the message channel open for the async response.
  return true;
});

chrome.runtime.onInstalled.addListener((details) => {
  void (async () => {
    // Seed defaults without overwriting anything the user has already chosen.
    const settings = await readSettings();
    await chrome.storage.sync.set({ [STORAGE_KEY]: settings });
    logger.info('installed', { reason: details.reason, aiMode: settings.aiMode });
  })();
});
