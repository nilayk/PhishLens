#!/usr/bin/env node
/**
 * Serves the UI harness (see harness/main.ts).
 *
 * Fixtures are injected as a define rather than imported, so the harness lists whatever is in
 * test/fixtures/ without a second copy of that list to keep in step.
 *
 *   npm run harness          # serve on 5199, rebuild on change
 *   npm run harness -- 5300  # another port
 */
import * as esbuild from 'esbuild';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const harnessDir = path.join(root, 'harness');
const fixturesDir = path.join(root, 'test/fixtures');

const port = Number(process.argv[2] ?? 5199);

const fixtures = readdirSync(fixturesDir)
  .filter((f) => f.endsWith('.json'))
  .sort()
  .map((f) => JSON.parse(readFileSync(path.join(fixturesDir, f), 'utf8')));

const context = await esbuild.context({
  entryPoints: { main: path.join(harnessDir, 'main.ts') },
  outdir: path.join(harnessDir, '.build'),
  bundle: true,
  format: 'iife',
  target: ['chrome120'],
  platform: 'browser',
  sourcemap: 'inline',
  logLevel: 'info',
  define: {
    __PHISHLENS_DEV__: 'true',
    __PHISHLENS_VERSION__: JSON.stringify('harness'),
    __PHISHLENS_FIXTURES__: JSON.stringify(JSON.stringify(fixtures)),
  },
});

await context.watch();
const server = await context.serve({
  port,
  // Requests fall back to harness/, so index.html is served from source and .build/main.js resolves.
  servedir: harnessDir,
});

const url = `http://${server.hosts[0] ?? 'localhost'}:${String(server.port)}`;
console.log(`\nPhishLens UI harness on ${url}`);
console.log(`${fixtures.length} fixtures. Every control is a query parameter:`);
console.log(`  ${url}/?fixture=microsoft-phish&card=1&bare=1\n`);
