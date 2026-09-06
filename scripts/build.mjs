#!/usr/bin/env node
/**
 * PhishLens build.
 *
 * esbuild is used instead of Vite because the three entry points have three different output
 * contracts (content script must be IIFE, worker and options must be ESM), and because the primary
 * UI is injected into Gmail's DOM, so a dev server cannot preview it. See docs/ARCHITECTURE.md §1.1.
 */
import * as esbuild from 'esbuild';
import { readFile, writeFile, mkdir, rm, cp, access } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const outdir = path.join(root, 'dist');

const args = new Set(process.argv.slice(2));
const watch = args.has('--watch');
const dev = args.has('--dev');
const cleanOnly = args.has('--clean-only');

const pkg = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));

/** @type {esbuild.BuildOptions} */
const common = {
  bundle: true,
  target: ['chrome120'],
  platform: 'browser',
  sourcemap: dev ? 'inline' : false,
  minify: !dev,
  legalComments: 'none',
  logLevel: 'info',
  define: {
    __PHISHLENS_DEV__: dev ? 'true' : 'false',
    __PHISHLENS_VERSION__: JSON.stringify(pkg.version),
  },
};

/** @type {esbuild.BuildOptions[]} */
const targets = [
  {
    ...common,
    entryPoints: { content: path.join(root, 'src/content/index.ts') },
    outdir,
    // MV3 declared content scripts are classic scripts, not modules.
    format: 'iife',
  },
  {
    ...common,
    entryPoints: { background: path.join(root, 'src/background/index.ts') },
    outdir,
    format: 'esm',
  },
  {
    ...common,
    entryPoints: { options: path.join(root, 'src/options/index.ts') },
    outdir,
    format: 'esm',
  },
];

async function copyStatic() {
  const manifest = JSON.parse(await readFile(path.join(root, 'src/manifest.json'), 'utf8'));
  manifest.version = pkg.version;
  manifest.description = pkg.description;
  await writeFile(path.join(outdir, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  await cp(path.join(root, 'src/options/options.html'), path.join(outdir, 'options.html'));

  const icons = path.join(root, 'assets/icons');
  if (await exists(icons)) {
    await cp(icons, path.join(outdir, 'icons'), { recursive: true });
  }
}

async function exists(p) {
  try {
    await access(p);
    return true;
  } catch {
    return false;
  }
}

await rm(outdir, { recursive: true, force: true });
if (cleanOnly) {
  console.log('cleaned dist/');
  process.exit(0);
}
await mkdir(outdir, { recursive: true });
await mkdir(path.join(root, 'assets/icons'), { recursive: true });
await import('./gen-icons.mjs');

if (watch) {
  const contexts = await Promise.all(targets.map((t) => esbuild.context(t)));
  await Promise.all(contexts.map((c) => c.watch()));
  await copyStatic();
  console.log(`\nPhishLens dev build watching. Load dist/ as an unpacked extension.\n`);
} else {
  await Promise.all(targets.map((t) => esbuild.build(t)));
  await copyStatic();
  console.log(`\nPhishLens ${pkg.version} built to dist/ (${dev ? 'dev' : 'production'}).\n`);
}
