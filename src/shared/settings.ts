import type { AiMode, Settings } from './types.js';

/**
 * Defaults favour local processing: AI analysis, if it runs at all, runs on-device. Cloud is opt-in
 * and additionally requires a backend URL, so there is no configuration in which the MVP sends
 * message content off the machine.
 */
export const DEFAULT_SETTINGS: Readonly<Settings> = Object.freeze({
  aiMode: 'local',
  highlightEnabled: true,
  showBadgeWhenLow: true,
  backendBaseUrl: '',
  modelBaseUrl: '',
  modelName: '',
});

export const STORAGE_KEY = 'phishlens.settings.v1';

const AI_MODES: readonly AiMode[] = ['off', 'local', 'cloud', 'server'];

function isAiMode(value: unknown): value is AiMode {
  return typeof value === 'string' && (AI_MODES as readonly string[]).includes(value);
}

/**
 * Coerces whatever is in storage into a valid `Settings`.
 *
 * Storage is not attacker-controlled in the usual sense, but it *is* persisted state from a possibly
 * older version of the extension, so it is validated rather than trusted.
 */
export function normalizeSettings(raw: unknown): Settings {
  if (raw === null || typeof raw !== 'object') return { ...DEFAULT_SETTINGS };
  const source = raw as Record<string, unknown>;

  return {
    aiMode: isAiMode(source['aiMode']) ? source['aiMode'] : DEFAULT_SETTINGS.aiMode,
    highlightEnabled:
      typeof source['highlightEnabled'] === 'boolean'
        ? source['highlightEnabled']
        : DEFAULT_SETTINGS.highlightEnabled,
    showBadgeWhenLow:
      typeof source['showBadgeWhenLow'] === 'boolean'
        ? source['showBadgeWhenLow']
        : DEFAULT_SETTINGS.showBadgeWhenLow,
    backendBaseUrl: normalizeBackendUrl(source['backendBaseUrl']),
    modelBaseUrl: normalizeModelBaseUrl(source['modelBaseUrl']),
    modelName: normalizeModelName(source['modelName']),
  };
}

/**
 * Only `https://` origins are accepted, and only as an origin + optional path prefix. Rejecting
 * anything else here means the cloud adapter cannot be pointed at `http://`, at a `javascript:` URL,
 * or at a vendor endpoint by editing storage.
 */
export function normalizeBackendUrl(value: unknown): string {
  if (typeof value !== 'string' || value.trim() === '') return '';
  try {
    const url = new URL(value.trim());
    if (url.protocol !== 'https:') return '';
    const path = url.pathname.replace(/\/+$/u, '');
    return `${url.origin}${path}`;
  } catch {
    return '';
  }
}

/** True when the user has both chosen cloud mode and supplied our backend's URL. */
export function isCloudConfigured(settings: Settings): boolean {
  return settings.aiMode === 'cloud' && settings.backendBaseUrl !== '';
}

/**
 * Hosts for which plaintext HTTP is acceptable, because the request never reaches a network.
 *
 * `localhost` is included despite resolving through the OS, so a hosts file or a DNS answer could in
 * principle send it elsewhere. Excluding it would be the stricter choice and the wrong one: every model
 * runner's documentation gives `http://localhost:…`, so a rejection here reads as the feature being
 * broken, and a user who can edit their own hosts file can also simply type the address they were
 * redirected to. The protection that matters is that anything *not* on this list must use TLS.
 */
const LOOPBACK_HOSTS: ReadonlySet<string> = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

export function isLoopbackHost(hostname: string): boolean {
  return LOOPBACK_HOSTS.has(hostname.toLowerCase());
}

/**
 * Normalises the base URL of a user-run model server to an origin plus optional path prefix.
 *
 * Unlike `normalizeBackendUrl` this accepts `http:` — but only for loopback, where there is no wire to
 * intercept. Off the machine, TLS is required: the request carries the subject and body of the message
 * being read, and sending that in plaintext across a LAN would be a worse leak than any this extension
 * is meant to warn about. Everything else is rejected exactly as it is for the backend URL, so
 * `javascript:`, `file:`, `data:` and a bare hostname cannot become an endpoint by editing storage.
 *
 * The path prefix is kept because runners differ: Ollama serves `/v1`, Docker Model Runner
 * `/engines/v1`. Users paste what their own documentation told them.
 */
export function normalizeModelBaseUrl(value: unknown): string {
  if (typeof value !== 'string' || value.trim() === '') return '';
  try {
    const url = new URL(value.trim());
    const loopback = isLoopbackHost(url.hostname);
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) return '';
    // Credentials in the URL would be sent to the server and shown in the options field; a model
    // server needing them is not a case worth supporting silently.
    if (url.username !== '' || url.password !== '') return '';
    const path = url.pathname.replace(/\/+$/u, '');
    return `${url.origin}${path}`;
  } catch {
    return '';
  }
}

/**
 * A model name is interpolated into a JSON request body, so it is bounded and stripped of control
 * characters. It is not otherwise constrained: runners name models as they please
 * (`qwen2.5:7b`, `ai/smollm2`, `hf.co/user/repo:Q4_K_M`).
 */
export function normalizeModelName(value: unknown): string {
  if (typeof value !== 'string') return '';
  return value
    .replace(/[\u0000-\u001f\u007f]/gu, '')
    .trim()
    .slice(0, 200);
}

/**
 * True when the user has chosen their own model server and given both the pieces needed to call it.
 *
 * The model name counts: these servers reject or silently substitute an unknown model, and a mode that
 * looks enabled while every request fails is worse than one that is plainly not configured yet.
 */
export function isModelServerConfigured(settings: Settings): boolean {
  return settings.aiMode === 'server' && settings.modelBaseUrl !== '' && settings.modelName !== '';
}

/** True when a configured model server is off this machine, and message content crosses a network. */
export function isModelServerRemote(settings: Settings): boolean {
  if (settings.modelBaseUrl === '') return false;
  try {
    return !isLoopbackHost(new URL(settings.modelBaseUrl).hostname);
  } catch {
    return false;
  }
}
