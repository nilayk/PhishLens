#!/usr/bin/env node
/**
 * Regenerates the images in docs/assets/ from the UI harness.
 *
 * Uses headless Chrome's own `--screenshot` rather than Puppeteer or Playwright: this repository ships
 * zero runtime dependencies and keeps its dev tree small on purpose, and a browser automation stack is
 * a large amount of supply chain to own for four PNGs. The cost is that each shot is a separate process
 * and the window size is the only cropping tool, which is why the harness has a `view=card` mode sized
 * to the card.
 *
 *   npm run harness      # in one terminal
 *   npm run screenshots  # in another
 *
 * Set CHROME_PATH if Chrome is somewhere unusual.
 */
import { spawn } from 'node:child_process';
import { access, mkdir, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const outDir = path.join(root, 'docs/assets');
const base = process.env['PHISHLENS_HARNESS_URL'] ?? 'http://127.0.0.1:5199';

/**
 * Each shot names its own window size.
 *
 * Chrome clamps small windows to a platform minimum but still captures at the size asked for, so window
 * size cannot be used to crop to something positioned relative to the viewport. `view=card` lays the
 * card out at the top-left of the page for that reason, which makes these sizes simply "big enough":
 * 380x620 of card plus a 16px surround. Any excess is transparent (`--default-background-color`).
 */
const SHOTS = [
  {
    name: 'in-message.png',
    query: { fixture: 'microsoft-phish', semantic: 'ready', view: 'full', card: '1', bare: '1' },
    width: 1180,
    height: 760,
    caption: 'badge in the header and the card open',
  },
  {
    name: 'card-light.png',
    query: { fixture: 'microsoft-phish', semantic: 'ready', view: 'card', bare: '1' },
    width: 424,
    height: 664,
    caption: 'the explanation card',
  },
  {
    name: 'card-dark.png',
    query: { fixture: 'microsoft-phish', semantic: 'ready', view: 'card', bare: '1' },
    width: 424,
    height: 664,
    dark: true,
    caption: 'the same card in dark mode',
  },
  {
    name: 'badges.png',
    query: { view: 'badges', semantic: 'ready', bare: '1' },
    width: 900,
    // One row taller than the bands, for the "not checked" state at the bottom.
    height: 266,
    caption: 'the badge at each risk level, and unable to read',
  },
];

const CHROME_CANDIDATES = [
  process.env['CHROME_PATH'],
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
  `${process.env['LOCALAPPDATA'] ?? ''}/Google/Chrome/Application/chrome.exe`,
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
].filter((p) => typeof p === 'string' && p !== '');

async function findChrome() {
  for (const candidate of CHROME_CANDIDATES) {
    try {
      await access(candidate);
      return candidate;
    } catch {
      // Try the next location.
    }
  }
  throw new Error(
    'Could not find Chrome. Set CHROME_PATH to the executable, e.g.\n' +
      '  CHROME_PATH="C:/Program Files/Google/Chrome/Application/chrome.exe" npm run screenshots',
  );
}

async function reachable(url) {
  try {
    const response = await fetch(url, { redirect: 'manual' });
    return response.status < 500;
  } catch {
    return false;
  }
}

function urlFor(shot) {
  const url = new URL(base);
  for (const [key, value] of Object.entries(shot.query)) url.searchParams.set(key, value);
  return url.toString();
}

async function capture(chrome, shot) {
  const profile = await mkdtemp(path.join(tmpdir(), 'phishlens-shot-'));
  const target = path.join(outDir, shot.name);

  const args = [
    '--headless=new',
    `--screenshot=${target}`,
    `--window-size=${String(shot.width)},${String(shot.height)}`,
    '--hide-scrollbars',
    '--force-device-scale-factor=2',
    // The page runs analysis and paints on load; virtual time lets that settle without a fixed sleep.
    '--virtual-time-budget=3000',
    '--default-background-color=00000000',
    `--user-data-dir=${profile}`,
    '--no-first-run',
    '--no-default-browser-check',
    ...(shot.dark === true
      ? ['--force-dark-mode', '--blink-settings=preferredColorScheme=0']
      : ['--blink-settings=preferredColorScheme=1']),
    urlFor(shot),
  ];

  try {
    await run(chrome, args);
    console.log(`  ${shot.name.padEnd(18)} ${String(shot.width)}x${String(shot.height)}  ${shot.caption}`);
  } finally {
    await rm(profile, { recursive: true, force: true });
  }
}

function run(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: 'ignore' });
    child.on('error', reject);
    child.on('exit', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`${path.basename(command)} exited with ${String(code)}`));
    });
  });
}

const chrome = await findChrome();

if (!(await reachable(base))) {
  console.error(`The harness is not answering on ${base}. Start it first:\n\n  npm run harness\n`);
  process.exit(1);
}

await mkdir(outDir, { recursive: true });
console.log(`\nCapturing from ${base} with ${path.basename(chrome)}:\n`);
for (const shot of SHOTS) await capture(chrome, shot);
console.log(`\nWrote ${String(SHOTS.length)} images to docs/assets/\n`);
