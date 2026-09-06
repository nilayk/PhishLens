# Development

## Requirements

Node.js **≥ 22.13.0** (declared in `package.json` `engines` and tested in CI) and Chrome **≥ 120**.

```bash
npm install
npm run build        # production build into dist/
```

Then load it: `chrome://extensions` → **Developer mode** → **Load unpacked** → select `dist/`.

## Commands

```bash
npm run dev          # esbuild watch; reload the extension in Chrome to pick up changes
npm run build        # production build to dist/
npm run build:dev    # unminified, inline sourcemaps, debug logging enabled
npm run clean        # remove dist/

npm run harness      # UI harness on http://127.0.0.1:5199 (see below)
npm run screenshots  # regenerate docs/assets/ from the harness

npm run typecheck    # tsc --noEmit
npm run lint         # eslint .
npm run lint:fix
npm test             # vitest run
npm run test:watch
npm run test:coverage

npm run verify       # lint && typecheck && test — the gate before committing
```

The icons in `dist/icons/` are generated at build time by `scripts/gen-icons.mjs` rather than committed as
binaries, so no opaque blob ships in a repository whose whole value is being auditable.

## Project layout

```text
src/
  content/      orchestration: observe → extract → analyse → render. All state lives here.
  background/   service worker: settings, future cloud egress. Deliberately stateless.
  gmail/        DOM adapter + SPA observer. The only place that knows Gmail's markup.
  analysis/
    rules/      deterministic detectors: identity, link, attachment, content, authentication
    scoring/    weights, ceilings, thresholds, and the pure aggregation function
    llm/        semantic layer: prompt, strict output parsing, on-device + cloud adapters
  ui/           badge, panel, highlighting. No framework; Shadow DOM; textContent only.
  shared/       types, URL/Unicode/brand primitives, settings, logging
harness/        development-only UI harness. Not shipped.
```

Data flows one way. `gmail/` produces an `EmailMessage`, `analysis/` turns it into an `AnalysisResult`,
`ui/` renders it. `analysis/` imports nothing from `gmail/` or `ui/` and touches no browser API, which is
why the whole detection engine runs under `vitest` in plain Node.

## Toolchain choices

| Choice | Why |
| --- | --- |
| TypeScript ES2022, `strict` | Plus `noUncheckedIndexedAccess` and `noPropertyAccessFromIndexSignature`, because most of this code indexes into structures derived from hostile input. |
| **esbuild**, not Vite | Three entry points with three different output contracts: the content script must be an IIFE, since MV3 declared content scripts are classic scripts, while the worker and options page are ESM. Vite's main advantage is a dev server, which is worth little when the primary UI only exists injected into Gmail's DOM. esbuild also keeps the dependency tree small, which matters for a security tool that asks to read your mail. Full build is ~50 ms. |
| Vitest | ESM-native, no transform config, and fast enough that the fixture suite is usable as an inner-loop tool. |
| ESLint + `typescript-eslint` (`strictTypeChecked`) | Flags `any`, unused vars and floating promises, plus `no-innerHTML` / `no-eval` house rules that make the XSS posture mechanical rather than aspirational. |
| Zero runtime dependencies | `"dependencies": {}`. Everything shipped into the browser is in `src/` and can be read end to end. |

## The UI harness

The badge and card only exist injected into a Gmail message, so there is nothing an ordinary dev server can
preview and every UI state otherwise has to be reached by finding an email that produces it. The harness
closes that gap:

```bash
npm run harness   # http://127.0.0.1:5199
```

It mounts the **real** `Badge` and `Panel` against the **real** engine output for any fixture in
`test/fixtures/`, inside a deliberately minimal header mock. Every control is also a query parameter, so
each state is a link:

```text
?fixture=microsoft-phish   any file in test/fixtures/
?semantic=ready            ready | pending | unavailable | no-output | error | cancelled | off
?view=full                 full (mock message) | card (card alone) | badges (one row per risk band)
?card=1                    open the explanation card
?bare=1                    hide the harness controls, for screenshots
```

Fixtures are injected into the bundle by `scripts/harness.mjs`, so adding a fixture file is enough to make
it appear in the picker.

### Regenerating the screenshots

```bash
npm run harness      # in one terminal
npm run screenshots  # in another
```

`scripts/screenshots.mjs` drives headless Chrome — no Puppeteer or Playwright, since a browser automation
stack is a large amount of supply chain to own for four PNGs — and overwrites `docs/assets/`. Set
`CHROME_PATH` if Chrome is somewhere unusual. Because the images are renders of the shipping components, a
UI change is one command away from being reflected in the README instead of silently outdating it.

## Testing

674 tests, all in plain Node — no Chrome, no Gmail, no network.

| File | Covers |
| --- | --- |
| `test/aggregate.test.ts` | The scoring functions in isolation: per-severity ceilings, category caps, `[0, 100]` clamping, and zero contribution from an empty category, which is the "no local model" path. |
| `test/detection.test.ts` | The full pipeline against 19 fixtures, invariants across all of them, and which message in a thread gets picked — including the forged-from-yourself cases that must *not* be skipped. |
| `test/semantic.test.ts` | The containment guarantees, the calibration limits, and the unavailable / throwing / hanging / cancelled analyzer paths — including which status each reports and which may be cached. |
| `test/chrome-prompt.test.ts` | The on-device adapter against fakes for every API shape Chrome has shipped and every malformed shape it might, plus concurrency: a session fake that rejects overlapping prompts the way the real one does. |
| `test/url.test.ts` | Obfuscated IP forms, forged suffix boundaries, redirect chains, hostnames `new URL()` accepts but that cannot exist. |
| `test/unicode.test.ts` | Punycode decoding, script mixing, bidi tricks, confusable folding, bounded edit distance. |
| `test/privacy.test.ts` | Settings validation, and what `buildCloudPayload` **drops** as well as what it keeps. |
| `test/observer.test.ts` | The SPA observer's emit and suppress decisions in both directions, since every negative decision it makes is silent by design. |

Fixture philosophy and the both-directions assertion are described in
[DETECTION.md](DETECTION.md#confidence-in-the-numbers).

## Continuous integration

`.github/workflows/ci.yml` runs `lint`, `typecheck` and `test` on Node 22.13.0 — the `engines` floor,
because an untested promise is a guess — as well as the current LTS. It then builds and uploads the
extension as an artifact, so every commit has an installable package attached. Before uploading, it runs
`npm run check:dist` (`scripts/check-dist.mjs`), which catches what a broken build would otherwise ship
silently: a file the manifest names but the build did not produce, a `<script>` in `options.html` pointing
at a renamed bundle, a manifest version out of step with `package.json`, or a sourcemap reference left in a
production bundle. The file list is read out of the manifest rather than hardcoded, so adding a reference to
the manifest extends the check automatically. Run it locally after `npm run build` if you are touching the
build.

Dependabot (`.github/dependabot.yml`) proposes weekly updates, grouped into one pull request per ecosystem
so the noise stays proportionate to a dev-only dependency tree.

## Releasing

```bash
npm version patch      # writes package.json and creates the tag
git push --follow-tags
```

`.github/workflows/release.yml` verifies, builds, runs `check:dist`, zips `dist/`, and publishes a GitHub
Release with install instructions. It refuses to publish when the tag disagrees with `package.json`, because
the manifest version is generated from that field and a release whose contents contradict its label is worse
than no release.

A `v*` tag cannot be deleted or moved once pushed (see below), so a mistagged release is corrected by
releasing the next patch version, never by repointing the tag. Someone may already have downloaded the asset,
and a tag that no longer describes what they have is a worse outcome than a skipped version number.

## Branch and tag protection

Configured as repository rulesets, which live on GitHub rather than in this repository — hence recorded here.
Both apply to every account including the owner, since a rule that the person most likely to be typing at
2am can bypass is documentation, not protection.

| Target                | Rule                            | Reason                                                                              |
| --------------------- | ------------------------------- | ----------------------------------------------------------------------------------- |
| `main`                | No force-push, no deletion      | History is the audit trail for a security tool; losing it silently is unrecoverable. |
| `refs/tags/v*`        | No deletion, no moving          | A release asset is public and permanent, so its tag has to be too.                   |

Status checks are deliberately **not** required. A commit cannot have passing checks before it is pushed, so
requiring them would block direct pushes to `main` and force every change through a pull request — friction
that buys little on a single-maintainer repository, given `npm run verify` runs before every commit anyway.

If that changes, do not require the matrix jobs by name: they are called `Verify (Node 22.13.0)` and
`Verify (Node 24)`, so the floor is baked into the string, and the ruleset would silently demand a check that
no longer runs the next time the floor moves. Add an aggregate job with a stable name and require that.

## Conventions

- `npm run verify` must pass before a commit. It is what CI runs.
- All scoring numbers live in `src/analysis/scoring/config.ts`. A magic number elsewhere is a bug.
- All Gmail selectors live in `src/gmail/selectors.ts`.
- New detection behaviour comes with a fixture and assertions in both directions — that it fires when it
  should, and that legitimate fixtures stay low.
- Commit messages describe why, not what. Do not add co-author trailers.

See [AGENTS.md](../AGENTS.md) for the same ground rules written for AI coding agents, including the
invariants that must not be broken.
