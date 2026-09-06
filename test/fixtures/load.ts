/**
 * Fixture loader.
 *
 * Fixture files describe a message the way a *human* would write it down — anchor text and href,
 * filenames — and this loader derives the fields the Gmail adapter derives (`normalizedDomain`,
 * `extension`) using the same shared helpers the adapter uses.
 *
 * That indirection is deliberate: if fixtures hard-coded `normalizedDomain`, a bug in the real
 * normalisation would be invisible to the fixture tests, because the fixtures would carry the correct
 * answer that production code failed to compute.
 */
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { collapseWhitespace, fileExtension } from '../../src/shared/text.js';
import type {
  EmailAttachment,
  EmailLink,
  EmailMessage,
  RawFields,
} from '../../src/shared/types.js';
import { normalizeDomain, parseUrl } from '../../src/shared/url.js';

const fixturesDir = path.dirname(fileURLToPath(import.meta.url));

interface RawLink {
  text: string;
  href: string;
}

interface RawAttachment {
  filename: string;
}

interface RawFixture {
  name: string;
  description: string;
  email: Omit<Partial<EmailMessage>, 'links' | 'attachments' | 'bodyText'> & {
    bodyText: string;
    links?: RawLink[];
    attachments?: RawAttachment[];
  };
}

export interface Fixture {
  name: string;
  description: string;
  email: EmailMessage;
}

export function toEmailLink(raw: RawLink): EmailLink {
  const parsed = parseUrl(raw.href);
  return {
    text: raw.text,
    href: raw.href,
    normalizedDomain: parsed === null ? '' : normalizeDomain(parsed.hostname),
  };
}

export function toEmailAttachment(raw: RawAttachment): EmailAttachment {
  return { filename: raw.filename, extension: fileExtension(raw.filename) };
}

export function loadFixture(name: string): Fixture {
  const file = name.endsWith('.json') ? name : `${name}.json`;
  const raw = JSON.parse(readFileSync(path.join(fixturesDir, file), 'utf8')) as RawFixture;

  return {
    name: raw.name,
    description: raw.description,
    email: {
      ...raw.email,
      ...normalizeHeaders(raw.email.senderEmail, raw.email.subject),
      links: (raw.email.links ?? []).map(toEmailLink),
      attachments: (raw.email.attachments ?? []).map(toEmailAttachment),
    },
  };
}

/**
 * Applies the same normalisation the Gmail adapter applies, and carries the originals in `raw`.
 *
 * A fixture is written the way the *message* reads — `DoNoT.rEpLy@…`, a subject with its padding — and
 * the adapter case-folds the address and collapses the subject's whitespace before analysis sees them.
 * Reproducing that split here means a fixture cannot accidentally hand the detectors a raw value that
 * production would never give them, in either direction.
 */
function normalizeHeaders(
  senderEmail: string | undefined,
  subject: string | undefined,
): Pick<EmailMessage, 'senderEmail' | 'subject' | 'raw'> {
  const normalizedSender = senderEmail?.trim().toLowerCase();
  const collapsedSubject = subject === undefined ? undefined : collapseWhitespace(subject);

  const raw: RawFields = {
    ...(senderEmail !== undefined && senderEmail !== normalizedSender
      ? { senderEmail }
      : {}),
    ...(subject !== undefined && subject !== collapsedSubject ? { subject } : {}),
  };

  return {
    ...(normalizedSender !== undefined ? { senderEmail: normalizedSender } : {}),
    ...(collapsedSubject !== undefined ? { subject: collapsedSubject } : {}),
    ...(Object.keys(raw).length > 0 ? { raw } : {}),
  };
}

export function allFixtureNames(): string[] {
  return readdirSync(fixturesDir)
    .filter((f) => f.endsWith('.json'))
    .map((f) => f.replace(/\.json$/u, ''))
    .sort();
}

export function loadAllFixtures(): Fixture[] {
  return allFixtureNames().map((name) => loadFixture(name));
}
