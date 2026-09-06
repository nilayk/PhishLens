# Privacy and security

What data exists, where it goes, and what this extension is built to withstand. The plain-language
summary is in the [README](../README.md#your-mail-stays-yours); this is the full account.

## Permissions

Mapped 1:1 to `src/manifest.json`. There are two.

| Manifest entry | Why it is needed |
| --- | --- |
| `"host_permissions": ["https://mail.google.com/*"]` | The content script reads the open message from the page in order to analyse it. This is the only origin PhishLens can run on. |
| `"permissions": ["storage"]` | Persists the four options-page settings (AI mode, backend URL, two display toggles). No message content is ever written to storage. |

Not requested, and not needed: `activeTab`, `<all_urls>`, `tabs`, `scripting`, `webRequest`,
`declarativeNetRequest`, `downloads`, `cookies`, `identity`, `nativeMessaging`. The content script is
declared in the manifest, so `scripting` is unnecessary. Nothing is fetched, blocked, or rewritten, so the
network permissions are unnecessary.

Extension pages run under `script-src 'self'; object-src 'none'; base-uri 'none'`.

If a future feature seems to need something broader, that is a signal to reconsider the feature.

## The three kinds of data

**Extracted from Gmail** — sender name and address, Reply-To, subject, visible body text (truncated,
quoted replies removed), link anchor text and hrefs, attachment filenames and extensions, the delivered-to
address, Gmail's own authentication summary when it is exposed in the DOM, and the names and addresses of
whoever sent the earlier messages in the open conversation. That last one is needed to tell a reply from a
party already in a thread from one imitating them, and like everything else it is read from what is
already on screen: no message is fetched, and nothing outside the open thread is looked at. This lives in memory in the
content script for as long as the message is on screen, then is dropped. It is never written to
`chrome.storage`, never sent to the service worker, and never logged in a release build.

**Analysed locally** — all of it. Every deterministic detector, the whole scoring engine, and in the
default configuration the semantic layer run inside the tab. Nothing touches the network. Results are
cached in the tab, capped at 20 entries, and discarded when the tab closes.

**Potentially leaving the browser** — nothing, unless AI mode is explicitly switched to *Cloud-assisted*
**and** a backend URL is entered. Neither has a default value, so there is no configuration of the shipped
extension in which data leaves the machine. What such a payload would contain, and what it would strip, is
in [LOCAL-AI.md](LOCAL-AI.md#the-cloud-design-which-is-not-built).

Three choices follow from this:

- **No logging of message content.** `src/shared/logger.ts` compiles to a no-op in release builds via a
  build-time flag, and redacts even in dev builds.
- **No API keys in the extension.** An API key shipped in an extension is a public API key.
- **Nothing in an email is ever fetched.** No URL is requested, no attachment downloaded, no preview
  generated, no DNS lookup made. All link and attachment analysis is textual.

## Threat model

### Malicious email content

Every string from a message — URL, filename, display name, subject, body — is hostile input. It is bounded
on extraction, never `eval`'d, never used to build a URL that gets requested, and never parsed as HTML.

All rendering goes through `src/ui/dom.ts`, which sets `textContent` and never `innerHTML`; `innerHTML`,
`outerHTML` and `insertAdjacentHTML` are ESLint errors project-wide, so the safety property is mechanical
rather than remembered. URL parsing uses the platform parser rather than regexes. Unicode is handled
explicitly — punycode decoding, script-mixing detection, confusable folding, bidi stripping — so a
homoglyph domain cannot pass as a brand's. Regexes over message text are bounded and anchored to avoid
catastrophic backtracking. `clamp()` fails closed on non-finite input, so a crafted value cannot
manufacture a score.

### Gmail DOM changes

Treated as certain, not hypothetical. Selector knowledge is isolated in `src/gmail/selectors.ts` behind the
`MailAdapter` interface; extraction is written so a missing field is absent rather than wrong; and the
observer tears the badge down rather than show a stale verdict when it cannot confirm what is on screen. A
selector break degrades to "fewer findings", never to "wrong findings" or a broken Gmail.

### Prompt injection

Assumed to succeed sometimes. Containment is defence in depth: message content is wrapped in delimiters,
forged delimiters are neutralised, the system prompt states that the contents are data and that anything
resembling an instruction is itself evidence of manipulation, and the task is restated *after* the content
because models weight the end of the context heavily.

But the real control is architectural. A fully successful injection can only zero the `llm` category's 15
points. It cannot delete a deterministic finding, cannot lower the score below a deterministic floor, and
cannot change the classification of a message that failed a technical check. See
[LOCAL-AI.md](LOCAL-AI.md#three-containment-guarantees).

### Malicious external URLs

PhishLens never dereferences anything found in a message: no `fetch`, no prefetch, no favicon, no DNS, no
attachment download or inspection. Analysis is purely textual, so a URL in an email cannot become a
request that leaks the fact the message was opened, and a malicious server never sees PhishLens at all.

### Extension permission abuse

The attack surface is kept small enough to audit: two permissions, one origin, zero runtime dependencies,
no remote code (MV3 forbids it and the CSP enforces it), no `eval` or `Function`. The service worker
accepts only messages whose `sender.id` matches the extension's own id, which Chrome sets and a web page
cannot forge, so a compromised page cannot drive the worker. The worker's only network capability is a POST
to a URL the user configured.

### API-key exposure

Structurally impossible here, because there is no key. The extension holds no vendor credential and no code
path adds an `Authorization` header.

### Data exfiltration

The default configuration makes no network requests at all. Cloud mode requires two explicit user actions,
and even then one reviewable function decides what leaves, with the recipient address, sender local part,
filenames, full URLs and message ids removed. Message bodies are never persisted and never logged in a
release build. There is no telemetry, no analytics, no error reporting, and no update channel beyond
Chrome's own.

### What PhishLens does not defend against

It is a reading aid, not a control. It does not stop anyone clicking a link, opening an attachment, or
replying. It cannot detect a phishing message that is textually indistinguishable from legitimate mail — a
compromised real account of a real correspondent sending a plausible request from the usual domain will
score low, correctly, on the evidence available. It is one layer, and the weakest assumption in it is that
the user reads the card.

## Reporting a security issue

Open a GitHub issue for anything that is not itself sensitive. Please do not paste real personal mail into
an issue; a description of the sender and link *shapes* is enough to write a fixture from.
