/**
 * A report a user can paste into a bug report when extraction has failed.
 *
 * This is the project's substitute for telemetry. Nothing here phones home — the extension makes no
 * network call of its own volition (docs/PRIVACY.md) — so the only way a broken selector becomes known
 * is that the person in front of it can say something useful about it. "PhishLens stopped working" is
 * not actionable; a list naming which selector groups matched is, because it points at the exact
 * candidate list in `selectors.ts` that needs a new entry.
 *
 * **Contains no message content, and cannot come to.** Only selector strings we wrote, the parts that
 * were missing, and the two version numbers. Deliberately excluded:
 *
 *  - the URL, which carries a thread id, i.e. an identifier for a specific message in someone's mailbox;
 *  - any extracted value, since every one of them is either the mail itself or an address;
 *  - counts derived from content (body length, number of links), which are weak but real leakage and
 *    would not change which selector needs fixing.
 *
 * The whole point is that a user can read it before sending it, so it is plain text, short, and has
 * nothing in it that needs interpreting.
 */
import type { MessagePart } from '../shared/types.js';
import type { MessageHandle } from './adapter.js';
import { SELECTORS } from './selectors.js';

/** Where a selector group found its first match, or that it found none. */
type Scope = 'message' | 'document' | 'none';

export interface SelectorProbe {
  group: string;
  scope: Scope;
  /** Index into the group's candidate list, so a stale first candidate is visible. `-1` for no match. */
  candidate: number;
}

/**
 * Probes every selector group in `selectors.ts`, inside the message first and then the page.
 *
 * Every group rather than only the ones that failed: which candidate matched is as informative as
 * whether one did. A group falling through to its last resort is how a selector list decays, and seeing
 * that in a report from a working install is what makes it fixable before it breaks.
 */
export function probeSelectors(handle: MessageHandle): SelectorProbe[] {
  return Object.entries(SELECTORS).map(([group, candidates]) => {
    for (const [scope, root] of [
      ['message', handle.root],
      ['document', document],
    ] as const) {
      const candidate = firstMatch(root, candidates);
      if (candidate >= 0) return { group, scope, candidate };
    }
    return { group, scope: 'none' as const, candidate: -1 };
  });
}

function firstMatch(root: ParentNode, candidates: readonly string[]): number {
  for (const [index, selector] of candidates.entries()) {
    try {
      if (root.querySelector(selector) !== null) return index;
    } catch {
      // An invalid candidate is not a match, exactly as in `queryFirst`.
    }
  }
  return -1;
}

export interface DiagnosticInput {
  adapter: string;
  version: string;
  /** The `Chrome/<version>` token only, not the whole user-agent string. */
  browser: string;
  missing: readonly MessagePart[];
  probes: readonly SelectorProbe[];
}

/**
 * Renders the report. Pure, so the guarantee in this file's header is testable without a DOM: given
 * only the fields above, there is no path by which message content could appear in the output.
 */
export function formatDiagnostic(input: DiagnosticInput): string {
  const lines = [
    `PhishLens ${input.version} — extraction diagnostic`,
    `adapter:  ${input.adapter}`,
    `browser:  ${input.browser}`,
    `missing:  ${input.missing.length > 0 ? input.missing.join(', ') : 'nothing'}`,
    'selectors:',
  ];

  const width = input.probes.reduce((max, probe) => Math.max(max, probe.group.length), 0);
  for (const probe of input.probes) {
    lines.push(`  ${probe.group.padEnd(width)}  ${describeProbe(probe)}`);
  }

  return lines.join('\n');
}

function describeProbe(probe: SelectorProbe): string {
  if (probe.scope === 'none') return 'NO MATCH';
  // Widened rather than asserted: probes also arrive from the harness, where a group name need not be
  // one of ours, and a report is not worth throwing over.
  const groups: Record<string, readonly string[]> = SELECTORS;
  const candidate = groups[probe.group]?.[probe.candidate] ?? '?';
  return `${probe.scope} #${String(probe.candidate)} ${candidate}`;
}

/** The browser version, without the rest of a user-agent string's fingerprinting surface. */
export function browserVersion(userAgent: string): string {
  return /Chrom(?:e|ium)\/[\d.]+/u.exec(userAgent)?.[0] ?? 'unknown';
}

/** The whole report for the message on screen. */
export function buildDiagnostic(
  handle: MessageHandle,
  missing: readonly MessagePart[],
  adapter: string,
): string {
  return formatDiagnostic({
    adapter,
    version: extensionVersion(),
    browser: browserVersion(navigator.userAgent),
    missing,
    probes: probeSelectors(handle),
  });
}

function extensionVersion(): string {
  try {
    return chrome.runtime.getManifest().version;
  } catch {
    // The harness renders this card without an extension around it.
    return 'unpackaged';
  }
}
