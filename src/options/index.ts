/**
 * Options page.
 *
 * Reads and writes settings through the service worker rather than touching `chrome.storage` directly,
 * so validation (`normalizeSettings`, `normalizeBackendUrl`) happens in exactly one place. The content
 * script picks changes up via `chrome.storage.onChanged`; there is no reload needed and no separate
 * "apply" step.
 *
 * The page's markup is static and ships with the extension, so it is written in `options.html`. Nothing
 * here interpolates message-derived content — the only user-supplied string is the backend URL, which
 * is set via `value`, never parsed as HTML.
 */
import { sendMessage } from '../shared/messaging.js';
import { DEFAULT_SETTINGS, normalizeBackendUrl } from '../shared/settings.js';
import type { AiMode, Settings } from '../shared/types.js';

declare const __PHISHLENS_VERSION__: string;

const STATUS_MS = 1600;

function requireElement<T extends HTMLElement>(id: string, ctor: new () => T): T {
  const element = document.getElementById(id);
  if (!(element instanceof ctor)) throw new Error(`missing #${id}`);
  return element;
}

function parseAiMode(value: string): AiMode | null {
  return value === 'off' || value === 'local' || value === 'cloud' ? value : null;
}

class OptionsPage {
  readonly #modeInputs = [...document.querySelectorAll<HTMLInputElement>('input[name="aiMode"]')];
  readonly #backendField = requireElement('backendField', HTMLDivElement);
  readonly #backendInput = requireElement('backendBaseUrl', HTMLInputElement);
  readonly #backendError = requireElement('backendError', HTMLParagraphElement);
  readonly #showBadgeWhenLow = requireElement('showBadgeWhenLow', HTMLInputElement);
  readonly #highlightEnabled = requireElement('highlightEnabled', HTMLInputElement);
  readonly #status = requireElement('status', HTMLDivElement);
  readonly #version = requireElement('version', HTMLSpanElement);

  #statusTimer: ReturnType<typeof setTimeout> | null = null;

  async init(): Promise<void> {
    this.#version.textContent = `Version ${typeof __PHISHLENS_VERSION__ === 'undefined' ? 'dev' : __PHISHLENS_VERSION__}`;

    const response = await sendMessage({ type: 'GET_SETTINGS' });
    const settings =
      response !== null && response.ok && response.type === 'SETTINGS'
        ? response.settings
        : { ...DEFAULT_SETTINGS };
    this.#render(settings);

    for (const input of this.#modeInputs) {
      input.addEventListener('change', () => {
        if (!input.checked) return;
        const mode = parseAiMode(input.value);
        if (mode === null) return;
        void this.#save({ aiMode: mode });
      });
    }

    this.#showBadgeWhenLow.addEventListener('change', () => {
      void this.#save({ showBadgeWhenLow: this.#showBadgeWhenLow.checked });
    });

    this.#highlightEnabled.addEventListener('change', () => {
      void this.#save({ highlightEnabled: this.#highlightEnabled.checked });
    });

    // Committed on blur/Enter rather than per keystroke: a partially-typed URL is not a valid one, and
    // `normalizeBackendUrl` would reject it and silently discard what was typed so far.
    this.#backendInput.addEventListener('change', () => {
      void this.#saveBackendUrl();
    });
  }

  #render(settings: Settings): void {
    for (const input of this.#modeInputs) input.checked = input.value === settings.aiMode;
    this.#backendField.hidden = settings.aiMode !== 'cloud';
    this.#backendInput.value = settings.backendBaseUrl;
    this.#showBadgeWhenLow.checked = settings.showBadgeWhenLow;
    this.#highlightEnabled.checked = settings.highlightEnabled;
    this.#backendError.textContent =
      settings.aiMode === 'cloud' && settings.backendBaseUrl === ''
        ? 'Cloud analysis stays inactive until a valid https:// URL is set.'
        : '';
  }

  async #saveBackendUrl(): Promise<void> {
    const raw = this.#backendInput.value.trim();
    const normalized = normalizeBackendUrl(raw);

    if (raw !== '' && normalized === '') {
      this.#backendError.textContent = 'Enter a full https:// URL, for example https://phishlens.example.com';
      return;
    }
    await this.#save({ backendBaseUrl: normalized });
  }

  async #save(patch: Partial<Settings>): Promise<void> {
    const response = await sendMessage({ type: 'SET_SETTINGS', patch });
    if (response === null || !response.ok || response.type !== 'SETTINGS') {
      this.#showStatus('Could not save. Try again.');
      return;
    }
    this.#render(response.settings);
    this.#showStatus('Saved');
  }

  #showStatus(text: string): void {
    this.#status.textContent = text;
    this.#status.dataset['visible'] = 'true';
    if (this.#statusTimer !== null) clearTimeout(this.#statusTimer);
    this.#statusTimer = setTimeout(() => {
      this.#status.dataset['visible'] = 'false';
    }, STATUS_MS);
  }
}

void new OptionsPage().init();
