# AGENTS.md

Instructions for AI coding agents working in this repository. Humans want
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md), which covers the same ground without the emphasis on things
agents get wrong.

## What this is

A Chrome Manifest V3 extension that scores Gmail messages 0–100 for phishing risk and explains every point
of that score. Two properties matter more than any feature:

1. **It is explainable.** A finding a user cannot check is worse than no finding.
2. **It is trustworthy with mail.** Zero runtime dependencies, two permissions, no network calls in the
   default configuration.

Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) before changing anything structural. It is a design
record, not a tour: most of it explains why an obvious alternative was rejected, which is the part you
cannot infer from the code.

## Definition of done

```bash
npm run verify   # lint && typecheck && test — all three, every time
```

CI runs exactly this on Node 22.13.0 and 24. Do not finish a task with a failing or skipped check, and
do not weaken a lint rule, loosen a `tsconfig` option, or delete an assertion to make something pass. If a
rule seems wrong, say so instead of routing around it.

## Invariants

Each of these is enforced by a test, a lint rule, or the type system. Breaking one is a defect even if the
suite happens to stay green.

**No HTML from message content.** Everything reaching the DOM goes through `el({ text })` in
`src/ui/dom.ts`, which sets `textContent`. `innerHTML`, `outerHTML` and `insertAdjacentHTML` are ESLint
errors project-wide. Do not add a "safe" exception; every string in a message is attacker-controlled.

**Scoring numbers live in one file.** Weights, severity ceilings, thresholds, floors and tuning constants
belong in `src/analysis/scoring/config.ts`. A number inside a detector is a bug, because the point of the
file is that the model can be read off it in one place.

**`analysis/` is pure.** No `chrome.*`, no `document`, no `fetch`, no `Date.now()` outside an injected
parameter. This is what lets the entire detection engine run under Vitest in plain Node, and it is the
reason the suite is fast enough to be useful. Anything needing a browser belongs in `content/`, `gmail/`,
`ui/`, or `background/`.

**Gmail selectors live in one file.** `src/gmail/selectors.ts`, as prioritised candidate lists. A selector
inline in `dom-adapter.ts` is a bug — when Gmail changes its markup, one file should need editing.

**A message that could not be read is never scored.** `extract()` returns the message *and* the parts it
could not find; `isScorable()` in `src/gmail/adapter.ts` decides whether a score would be honest. With no
sender, nearly every check has nothing to test, so the engine returns no findings and the aggregation
turns that into **Low Risk** — a confident all-clear on mail nobody checked, which is the one failure
direction this project does not accept. Do not "fix" that by scoring it anyway, by removing the badge
(indistinguishable from a clean message when `showBadgeWhenLow` is off), or by softening the card's
wording: the sentence saying this is not a judgement of safety is load-bearing and is asserted by a test.

**The model cannot outvote the checks.** The `llm` category is capped at 15 points, contributes additively,
and scores zero when no deterministic signal corroborates it. It cannot remove a finding, lower a score
past a deterministic floor, or change a classification on its own. If a change would let it, the change is
wrong, not the cap. This holds for *every* source, including a large model a user runs themselves: the
feature buys better reasons, not more weight. See [docs/LOCAL-AI.md](docs/LOCAL-AI.md).

**All egress is in the service worker, to an address read from settings.** `src/background/index.ts` is the
only file that may call `fetch`. Never let an endpoint arrive in a message — that turns the worker into a
general-purpose fetcher. `http://` is valid only for loopback (`normalizeModelBaseUrl`); everything else
needs `https:`. New network reach goes in `optional_host_permissions` and is requested per-origin from the
options page on a click, so a default install keeps the two permissions the README advertises.

**Severity floors are deterministic-only.** Never let a semantic signal set a floor, and keep
`authentication.gmail_warning` excluded — Gmail renders that banner conditionally on the folder, so a floor
from it would make a message's score change when it is moved to Spam.

**Trust cannot silence identity.** A trusted sender dampens `content` and `authentication` findings only,
only when Gmail's summary proves the sender's domain, and never a `high` or `critical` finding. Widening any
of the three turns the trust list into the spoofing hole it is designed not to be — trusting `paypal.com`
must never quieten `paypa1.com`. Dampened findings stay visible and reversible; nothing is removed.

**A list row is sender-only, and never an all-clear.** `analysis/triage.ts` runs an explicit allowlist of
identity rules against a name and an address. Do not add a rule needing a body, links, or an authentication
result, do not add a "looks fine" verdict, and do not lower the `high` floor — an unmarked row means
unchecked, and a marker on ordinary mail is what gets the feature switched off. A test forces every new
identity rule to be classified either way.

**The service worker is stateless.** MV3 terminates it after ~30 seconds idle. No module-level cache, no
model session, no in-flight work in `src/background/`. Stateful things live in the content script, whose
context lasts as long as the tab.

**Nothing from an email is ever dereferenced.** No `fetch` of a URL found in a message, no attachment read,
no image or favicon load, no DNS. All analysis is textual. This is a privacy guarantee, not an optimisation.

**Normalise for comparison, keep the original for evidence.** Compare case-folded, whitespace-collapsed,
confusable-folded values; read `EmailMessage.raw` only in detectors that examine *formatting*, since a
subject padded with 700 spaces and an address spelled `DoNoT.rEpLy` are themselves evidence. Comparing a
raw value against a domain or brand reintroduces the bugs normalisation exists to prevent.

## Working on detection

Detection changes are the most likely to do harm, because a false positive on ordinary mail costs more
trust than a missed phish. So:

- **Add a fixture** in `test/fixtures/` for any new behaviour, and assert in **both** directions: that the
  signal fires on the malicious case, *and* that every legitimate fixture stays `low` with no `high` or
  `critical` deterministic signal. The second half is what makes severity floors safe.
- **Prefer brand-independent signals.** A curated table gives the best wording but only for what is in it.
  If a check can only work via `src/shared/brands.ts`, ask whether a structural version exists — "does the
  display name share any name with the sending domain" needs no table at all.
- **Write findings a user can verify.** "Sender domain resembles Microsoft but is not Microsoft-owned" is
  useful. "Suspicious sender" is not. Include the evidence and, where the UI can locate it, a locator.
- **Assume the input is hostile.** Bound every loop over message-derived data, anchor every regex, and
  treat any field as absent, enormous, or malformed.

Read [docs/DETECTION.md](docs/DETECTION.md) first; several categories already have dampening and
suppression rules whose purpose is to stop exactly the false positive a new check is likely to reintroduce.

## Seeing the UI

Do not guess at what a UI change looks like, and do not ask the user to check for you:

```bash
npm run harness      # http://127.0.0.1:5199 — real components, real engine, any fixture
npm run screenshots  # regenerates docs/assets/ from that page
```

Every state is a URL (`?fixture=…&semantic=…&view=…&card=1`), including each `SemanticStatus` and both
colour schemes. If you change the badge or card, regenerate the screenshots in the same commit so the README
does not drift.

## Comments and documentation

The codebase holds a high standard here, and matching it is part of the task.

- Explain **why**, never what. A comment restating the next line is noise; a comment recording the
  constraint that makes the line necessary is the most valuable thing in the file.
- Do not narrate your own changes. No "fixed a bug where…", no "changed to…", no dates, no ticket numbers.
  A comment is read by someone who never saw the diff.
- Prefer documenting the rejected alternative. "A plain `Set` would be enough if X" tells the next reader
  what they may not change.
- Keep the docs true. `README.md` is for end users and should stay non-technical; technical detail belongs
  in `docs/`. If behaviour changes, update the document that describes it in the same commit.
- **Never name a real organisation seen in someone's own mailbox.** Testing against live Gmail produces the
  best bug reports this project gets, and the detail that makes one concrete — which bank, which supplier,
  which brand the model misjudged — is private correspondence, published permanently the moment it reaches
  a commit message, a comment, or a fixture. Record the shape instead: "a genuine bank notification",
  "a supplier the brand table does not contain". Nothing of value is lost, because the shape is what the
  next reader needs. Invented organisations follow the `northwind-*` house names already in
  `test/fixtures/`, and the curated `src/shared/brands.ts` entries are the one exception — those are public
  brands chosen for being widely phished, not messages anyone received.

## Git

- **Never add co-author trailers.** No `Co-authored-by: Cursor`, no agent attribution of any kind. A local
  `commit-msg` hook strips them; do not rely on it, and do not remove it.
- Commit messages: a short imperative subject, then why the change was needed. Not a list of files.
- Do not commit `dist/`, `harness/.build/`, or anything in `.gitignore`.
- Do not push, tag, or open a pull request unless asked.

## Things that are deliberate, not oversights

Do not "fix" these without discussion:

- No framework, no runtime dependencies, no CSS files — the UI is hand-written with Shadow DOM.
- No `dist/` in the repository. CI builds and attaches it.
- The public suffix list and brand table are curated subsets, with the limitation documented rather than
  papered over.
- Cloud analysis is designed and left inert. Do not implement it as a side effect of another task.
- Icons are generated at build time rather than committed as binaries.
