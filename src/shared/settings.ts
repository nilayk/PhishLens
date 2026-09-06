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
});

export const STORAGE_KEY = 'phishlens.settings.v1';

const AI_MODES: readonly AiMode[] = ['off', 'local', 'cloud'];

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
