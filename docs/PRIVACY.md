# Privacy and security

What data exists, where it goes, and what this extension is built to withstand. The plain-language
summary is in the [README](../README.md#your-mail-stays-yours); this is the full account.

## Permissions

Mapped 1:1 to `src/manifest.json`. Two are granted at install; one is offered and granted only if asked
for.

| Manifest entry | Why it is needed |
| --- | --- |
| `"host_permissions": ["https://mail.google.com/*"]` | The content script reads the open message from the page in order to analyse it. This is the only origin PhishLens can run on. |
| `"permissions": ["storage"]` | Persists the options-page settings (AI mode, backend URL, model server address and model name, two display toggles). No message content is ever written to storage. |
| `"optional_host_permissions": ["http://*/*", "https://*/*"]` | **Not granted at install.** If you configure your own model server, the options page requests access to that single origin on a click, and revokes it when the address changes. Chrome names the origin in the prompt. |

The optional entry has to be a broad pattern because Chrome only grants what a pattern in the manifest
covers, and a model server can be on any host and port. What matters is that it is *optional*: a default
install holds two permissions, the grant is per-origin, made on a deliberate click, and visible in
`chrome://extensions`. The alternative — putting `http://localhost/*` in `host_permissions` — would charge
every user a permission for a feature most will never turn on.

Not requested, and not needed: `activeTab`, `<all_urls>`, `tabs`, `scripting`, `webRequest`,
`declarativeNetRequest`, `downloads`, `cookies`, `identity`, `nativeMessaging`. The content script is
declared in the manifest, so `scripting` is unnecessary. Nothing in a message is ever fetched, blocked, or
rewritten, so the network permissions are unnecessary.

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

**Potentially leaving the browser** — nothing by default. Two modes can send message content, and both
require an explicit choice *and* an address, neither of which has a default value:

- *Your own model server* sends the sender's display name, the subject and a body excerpt to the address
  you configure — and nothing else. No link targets, no sending domain, no attachment types, no recipient
  address, no API key. Plain `http://` is only accepted for `localhost`, so in the intended setup this data
  reaches a process on your own machine and no network. Point it at an `https://` address elsewhere and it
  crosses a network to that address; the options page says so where you type it. See
  [LOCAL-AI.md](LOCAL-AI.md#your-own-model-server).
- *Cloud-assisted* is designed and inert, with no default backend. What such a payload would contain, and
  what it would strip, is in [LOCAL-AI.md](LOCAL-AI.md#the-cloud-design-which-is-not-built).

Nothing else ever leaves, in any configuration.

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

The attack surface is kept small enough to audit: two granted permissions, one origin, zero runtime
dependencies, no remote code (MV3 forbids it and the CSP enforces it), no `eval` or `Function`. The service
worker accepts only messages whose `sender.id` matches the extension's own id, which Chrome sets and a web
page cannot forge, so a compromised page cannot drive the worker.

The worker's only network capability is a request to a URL the user configured. Deliberately, **no message
can supply an endpoint**: the analyze and list-models handlers read the address from settings, where it has
already been through `normalizeModelBaseUrl`. Had the URL travelled in the message instead, anything able to
send the worker a message would have had a general-purpose fetcher, which is a much larger thing to have
built than a model client.

### API-key exposure

Structurally impossible here, because there is no key. The extension holds no vendor credential and no code
path adds an `Authorization` header.

### Data exfiltration

The default configuration makes no network requests at all. Both network modes require an explicit mode
choice, an address, and — for a model server — a permission grant Chrome prompts for by origin. Cloud mode
additionally passes everything through one reviewable redaction function, with the recipient address, sender
local part, filenames, full URLs and message ids removed. Message bodies are never persisted and never
logged in a release build. There is no telemetry, no analytics, no error reporting, and no update channel
beyond Chrome's own.

### What PhishLens does not defend against

It is a reading aid, not a control. It does not stop anyone clicking a link, opening an attachment, or
replying. It cannot detect a phishing message that is textually indistinguishable from legitimate mail — a
compromised real account of a real correspondent sending a plausible request from the usual domain will
score low, correctly, on the evidence available. It is one layer, and the weakest assumption in it is that
the user reads the card.

## Reporting a security issue

Open a GitHub issue for anything that is not itself sensitive. Please do not paste real personal mail into
an issue; a description of the sender and link *shapes* is enough to write a fixture from.
