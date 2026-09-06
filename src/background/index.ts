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
 *   2. the single future egress point for cloud analysis
 *   3. seeding defaults on install
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
} from '../shared/messaging.js';
import { DEFAULT_SETTINGS, STORAGE_KEY, isCloudConfigured, normalizeSettings } from '../shared/settings.js';
import type { Settings } from '../shared/types.js';
import { parseSemanticAnalysis } from '../analysis/llm/parse.js';

/** Cloud request timeout. Bounded so a hung backend cannot keep a worker alive indefinitely. */
const CLOUD_TIMEOUT_MS = 12_000;

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

async function handle(request: ExtensionRequest): Promise<ExtensionResponse> {
  switch (request.type) {
    case 'GET_SETTINGS':
      return { ok: true, type: 'SETTINGS', settings: await readSettings() };
    case 'SET_SETTINGS':
      return { ok: true, type: 'SETTINGS', settings: await writeSettings(request.patch) };
    case 'CLOUD_ANALYZE':
      return cloudAnalyze(request);
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
