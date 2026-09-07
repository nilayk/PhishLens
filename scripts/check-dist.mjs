#!/usr/bin/env node
/**
 * Checks that dist/ is something Chrome will actually load.
 *
 * Every failure here is one that is invisible until a person unzips the download and Chrome refuses it,
 * or accepts it and silently does nothing. That is the worst place to find out, so the same check runs in
 * CI, in the release workflow before publishing, and locally via `npm run check:dist`.
 *
 * The file list is read out of the manifest rather than hardcoded. A hardcoded list only checks the files
 * someone remembered to add to it, which means the guard stops covering the manifest the moment the
 * manifest grows a new reference — exactly when it would start being useful.
 */
import { readFile, access, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dist = path.join(root, 'dist');

const problems = [];
const fail = (message) => problems.push(message);

async function exists(p) {
  try {
    await access(p);
    return true;
  } catch {
    return false;
  }
}

async function readJson(p) {
  return JSON.parse(await readFile(p, 'utf8'));
}

if (!(await exists(path.join(dist, 'manifest.json')))) {
  console.error('dist/manifest.json is missing. Run `npm run build` first.');
  process.exit(1);
}

const manifest = await readJson(path.join(dist, 'manifest.json'));
const pkg = await readJson(path.join(root, 'package.json'));

if (manifest.manifest_version !== 3) {
  fail(`expected manifest_version 3, found ${JSON.stringify(manifest.manifest_version)}`);
}

// The manifest version is generated from package.json, so a mismatch means the build was stale — and a
// release whose asset reports a different version than its tag is worse than no release at all.
if (manifest.version !== pkg.version) {
  fail(`manifest version ${manifest.version} does not match package.json ${pkg.version}`);
}

/** Every path the manifest points at, with the field that named it, for an error a reader can act on. */
function referencedPaths(m) {
  const found = [];
  const add = (file, field) => {
    if (typeof file === 'string' && file.length > 0) found.push({ file, field });
  };

  add(m.background?.service_worker, 'background.service_worker');
  add(m.options_ui?.page, 'options_ui.page');
  add(m.options_page, 'options_page');
  add(m.action?.default_popup, 'action.default_popup');
  add(m.devtools_page, 'devtools_page');
  add(m.sandbox?.pages, 'sandbox.pages');

  for (const [size, file] of Object.entries(m.icons ?? {})) add(file, `icons.${size}`);
  for (const [size, file] of Object.entries(m.action?.default_icon ?? {})) {
    add(file, `action.default_icon.${size}`);
  }

  for (const [i, script] of (m.content_scripts ?? []).entries()) {
    for (const file of script.js ?? []) add(file, `content_scripts[${i}].js`);
    for (const file of script.css ?? []) add(file, `content_scripts[${i}].css`);
  }

  for (const [i, entry] of (m.web_accessible_resources ?? []).entries()) {
    // Resources may be glob patterns, which cannot be checked by existence.
    for (const file of entry.resources ?? []) {
      if (!file.includes('*')) add(file, `web_accessible_resources[${i}].resources`);
    }
  }

  return found;
}

const referenced = referencedPaths(manifest);
for (const { file, field } of referenced) {
  if (!(await exists(path.join(dist, file)))) {
    fail(`${field} names ${file}, which is not in dist/`);
  }
}

/*
 * Pages are copied verbatim rather than bundled, so a renamed output leaves a dead <script> that fails
 * silently at runtime with the page rendering as bare HTML.
 *
 * Every HTML file in dist/ is checked, not only the ones the manifest names: the welcome page is opened
 * with `chrome.tabs.create` and so is referenced by nothing the manifest can be read for, which makes it
 * exactly the page whose script reference would rot unnoticed.
 */
for (const page of (await readdir(dist)).filter((f) => f.endsWith('.html'))) {
  const html = await readFile(path.join(dist, page), 'utf8');
  for (const [, src] of html.matchAll(/<script[^>]+src=["']([^"']+)["']/g)) {
    if (/^[a-z]+:|^\/\//i.test(src)) {
      fail(`${page} loads a remote script (${src}), which the CSP forbids`);
    } else if (!(await exists(path.join(dist, src.replace(/^\.?\//, ''))))) {
      fail(`${page} loads ${src}, which is not in dist/`);
    }
  }
  // An inline <script> would be blocked by the extension CSP, silently, at runtime.
  if (/<script(?![^>]*\ssrc=)[^>]*>[\s\S]*?\S[\s\S]*?<\/script>/i.test(html)) {
    fail(`${page} contains an inline <script>, which the CSP forbids`);
  }
}

// A sourcemap reference in a production bundle leaks the original sources and paths.
for (const { file } of referenced.filter((r) => r.file.endsWith('.js'))) {
  const p = path.join(dist, file);
  if (!(await exists(p))) continue;
  if ((await readFile(p, 'utf8')).includes('sourceMappingURL')) {
    fail(`${file} contains a sourcemap reference`);
  }
}

if (problems.length > 0) {
  for (const problem of problems) {
    // The ::error:: prefix is what surfaces the message on the job summary in GitHub Actions; it is
    // harmless noise anywhere else.
    console.error(process.env.GITHUB_ACTIONS ? `::error::${problem}` : `error: ${problem}`);
  }
  process.exit(1);
}

console.log(
  `dist/ looks loadable: manifest v${manifest.manifest_version}, version ${manifest.version}, ` +
    `${referenced.length} referenced files present.`,
);
