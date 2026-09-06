/**
 * Cloud semantic analyzer — designed, wired, and inert.
 *
 * Disabled with no default backend URL, so no configuration of the shipped extension sends message
 * content off the machine. It exists so that enabling cloud analysis later is configuration plus a
 * manifest `host_permissions` entry rather than a redesign. Four properties hold by construction:
 *
 *  - **No vendor API key.** There is no field for one and no path that authenticates to a model host.
 *    The extension talks to our backend, which holds the provider credential; a key shipped inside an
 *    extension is public the moment someone unpacks the `.crx`.
 *  - **Egress happens in the service worker.** This class hands a payload to `sendMessage` and the
 *    worker fetches, so there is one place to audit and the content script never opens a socket.
 *  - **Only a minimised payload leaves**, built by `redact.ts`.
 *  - **HTTPS origins only**, enforced by `normalizeBackendUrl` in `settings.ts`.
 */
import { isAborted } from '../../shared/abort.js';
import { logger } from '../../shared/logger.js';
import { sendMessage } from '../../shared/messaging.js';
import type {
  EmailMessage,
  SemanticAnalysis,
  SemanticAnalyzeOptions,
  SemanticAnalyzer,
  Settings,
} from '../../shared/types.js';
import { isCloudConfigured } from '../../shared/settings.js';
import { buildCloudPayload } from './redact.js';

export class CloudAnalyzer implements SemanticAnalyzer {
  readonly id = 'cloud-backend';

  readonly #settings: Settings;
  /** Deterministic signal ids, so the backend need not re-derive what we already know. */
  readonly #deterministicSignalIds: readonly string[];

  constructor(settings: Settings, deterministicSignalIds: readonly string[] = []) {
    this.#settings = settings;
    this.#deterministicSignalIds = deterministicSignalIds;
  }

  /**
   * Requires *both* an explicit `cloud` choice and a configured backend. Absent either, this
   * analyzer does nothing — which is the MVP's state.
   */
  isAvailable(): Promise<boolean> {
    return Promise.resolve(isCloudConfigured(this.#settings));
  }

  /**
   * `options.signal` is honoured either side of the round trip but cannot cancel it: the request is
   * performed by the service worker (see the header), and reaching into it would mean plumbing
   * cancellation through the message protocol. Checking before and after is enough to stop a
   * superseded result being applied and to avoid paying for a request the reader has navigated past.
   */
  async analyze(
    email: EmailMessage,
    options: SemanticAnalyzeOptions = {},
  ): Promise<SemanticAnalysis | null> {
    if (!isCloudConfigured(this.#settings)) return null;
    if (isAborted(options.signal)) return null;

    const payload = buildCloudPayload(email, this.#deterministicSignalIds);
    logger.debug('requesting cloud analysis', {
      linkDomains: payload.linkDomains.length,
      bodyChars: payload.bodyExcerpt.length,
    });

    const response = await sendMessage({ type: 'CLOUD_ANALYZE', payload });
    if (isAborted(options.signal)) return null;
    if (response?.ok !== true) {
      logger.debug('cloud analysis unavailable', response === null ? 'no response' : response.error);
      return null;
    }
    if (response.type !== 'SEMANTIC') return null;
    return response.analysis;
  }
}
