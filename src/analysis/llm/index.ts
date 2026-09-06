/**
 * Semantic analyzer selection.
 *
 * Resolution is by explicit user setting, never by capability sniffing: if the user chose `off`, no
 * analyzer is constructed at all, and if they chose `local`, no adapter that could open a socket is even
 * instantiated. There is no fallback in any direction — silently sending content to a server because
 * the on-device model was missing would violate the privacy contract, and falling back to a weaker model
 * would change the analysis without saying so.
 */
import type { SemanticAnalyzer, Settings } from '../../shared/types.js';
import { ChromePromptAnalyzer } from './chrome-prompt.js';
import { CloudAnalyzer } from './cloud.js';
import { ModelServerAnalyzer } from './model-server.js';

/**
 * The single on-device analyzer instance.
 *
 * Module-level so the (expensive) model session is reused across messages. Safe only because this
 * module is loaded exclusively in the content script — see docs/ARCHITECTURE.md §2. It must not be
 * imported by `src/background/`.
 */
let sharedLocalAnalyzer: ChromePromptAnalyzer | null = null;

export function localAnalyzer(): ChromePromptAnalyzer {
  sharedLocalAnalyzer ??= new ChromePromptAnalyzer();
  return sharedLocalAnalyzer;
}

export function disposeLocalAnalyzer(): void {
  sharedLocalAnalyzer?.dispose();
  sharedLocalAnalyzer = null;
}

/** `null` when AI analysis is off, which the engine reports as `off` rather than as a failure. */
export function resolveAnalyzer(
  settings: Settings,
  deterministicSignalIds: readonly string[] = [],
): SemanticAnalyzer | null {
  switch (settings.aiMode) {
    case 'local':
      return localAnalyzer();
    case 'cloud':
      return new CloudAnalyzer(settings, deterministicSignalIds);
    case 'server':
      return new ModelServerAnalyzer(settings);
    case 'off':
      return null;
  }
}
