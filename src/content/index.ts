/**
 * Content script entry point.
 *
 * Bundled as an IIFE because MV3 declared content scripts are classic scripts. Deliberately thin: it
 * picks an adapter, starts the controller, and arranges teardown. All behaviour lives in modules that
 * can be reasoned about — and in the case of the analysis layer, tested — independently.
 */
import { GmailDomAdapter } from '../gmail/dom-adapter.js';
import { disposeLocalAnalyzer } from '../analysis/llm/index.js';
import { logger } from '../shared/logger.js';
import { Controller } from './controller.js';

function main(): void {
  // The manifest restricts this script to https://mail.google.com/*, but a defensive check costs
  // nothing and documents the assumption.
  if (window.location.hostname !== 'mail.google.com') return;
  // Gmail renders chat and compose in iframes; we only analyse the top-level conversation view.
  if (window.top !== window.self) return;

  const controller = new Controller(new GmailDomAdapter());

  void controller.start().catch((error: unknown) => {
    logger.error('failed to start', error);
  });

  // `pagehide` rather than `unload`: it fires for back/forward-cache navigations too, and releasing
  // the on-device model session matters because it can hold significant memory.
  window.addEventListener(
    'pagehide',
    () => {
      controller.stop();
      disposeLocalAnalyzer();
    },
    { once: true },
  );
}

main();
