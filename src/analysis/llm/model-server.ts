/**
 * Adapter for an OpenAI-compatible model server the user runs — Ollama, LM Studio, Docker Model Runner,
 * llama.cpp, vLLM.
 *
 * This is the same trade as the on-device path, made with a better model: the user supplies the compute
 * and gets sharper reasons, and in exchange the content of the open message leaves the extension
 * process. Four things keep that trade honest:
 *
 *  - **The prompt is the on-device prompt.** No separate wording, no extra fields. What a self-hosted
 *    model is asked is exactly what Chrome's built-in model is asked, so the two modes are comparable
 *    and there is one prompt to reason about rather than two. In particular it still withholds the
 *    sending domain, the link destinations and the attachment types, which are judged deterministically.
 *  - **Egress stays in the service worker.** This class hands over two strings; the worker holds the
 *    URL, composes the request and opens the socket.
 *  - **The address is validated, not supplied.** `normalizeModelBaseUrl` has already reduced it to a
 *    loopback origin or an https one before it reaches storage.
 *  - **The cap does not move.** A 70B model on the user's own GPU is still bound by the `llm` category
 *    ceiling and still scores zero uncorroborated. What a better model buys is a better *explanation*,
 *    not a louder vote — configuration must not be able to weaken an invariant.
 */
import { isAborted } from '../../shared/abort.js';
import { logger } from '../../shared/logger.js';
import { sendMessage } from '../../shared/messaging.js';
import { isModelServerConfigured } from '../../shared/settings.js';
import type {
  EmailMessage,
  SemanticAnalysis,
  SemanticAnalyzeOptions,
  SemanticAnalyzer,
  Settings,
} from '../../shared/types.js';
import { SYSTEM_PROMPT, buildUserPrompt, describePromptShape } from './prompt.js';

export class ModelServerAnalyzer implements SemanticAnalyzer {
  readonly id = 'model-server';

  readonly #settings: Settings;

  constructor(settings: Settings) {
    this.#settings = settings;
  }

  /** Requires the mode, a validated URL and a model name; anything less does nothing at all. */
  isAvailable(): Promise<boolean> {
    return Promise.resolve(isModelServerConfigured(this.#settings));
  }

  /**
   * `options.signal` is checked either side of the round trip but cannot cancel it, exactly as in the
   * cloud adapter: the request belongs to the worker. Checking is enough to stop a superseded result
   * being applied when the reader has already moved to another message — which matters more here than
   * for the cloud path, since a slow local model makes that window seconds wide.
   */
  async analyze(
    email: EmailMessage,
    options: SemanticAnalyzeOptions = {},
  ): Promise<SemanticAnalysis | null> {
    if (!isModelServerConfigured(this.#settings)) return null;
    if (isAborted(options.signal)) return null;

    logger.debug('requesting model server analysis', {
      model: this.#settings.modelName,
      shape: describePromptShape(email),
    });

    const response = await sendMessage({
      type: 'MODEL_SERVER_ANALYZE',
      payload: { system: SYSTEM_PROMPT, user: buildUserPrompt(email) },
    });
    if (isAborted(options.signal)) return null;

    if (response?.ok !== true) {
      logger.debug('model server analysis failed', response === null ? 'no response' : response.error);
      return null;
    }
    if (response.type !== 'SEMANTIC') return null;
    return response.analysis;
  }
}
