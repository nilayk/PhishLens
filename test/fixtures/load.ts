/**
 * Fixture loading from disk. The conversion itself lives in `convert.ts`, which has no filesystem
 * dependency so the browser harness can share it.
 */
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { toFixture, type Fixture, type RawFixture } from './convert.js';

export { toEmailAttachment, toEmailLink } from './convert.js';
export type { Fixture, RawAttachment, RawFixture, RawLink } from './convert.js';

const fixturesDir = path.dirname(fileURLToPath(import.meta.url));

export function loadFixture(name: string): Fixture {
  const file = name.endsWith('.json') ? name : `${name}.json`;
  return toFixture(JSON.parse(readFileSync(path.join(fixturesDir, file), 'utf8')) as RawFixture);
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
