# Visual File Transfer (VFT)

Two self-contained HTML pages that move a file over a video call or screen share as
rotating QR codes: `dist/vft-tx.html` shows them, `dist/vft-rx.html` captures and
reassembles them. SHA-256 is checked before the receiver offers Save; Gap Reports tell the
sender what to repeat. README.md has the architecture and the test table; this file is how
to work here. If `AGENTS.local.md` exists, read it too (this machine's context, never committed).

## Goals, in order

1. **A received file is exactly the sent file, or the page says it is not.** Wrong bytes
   shown as success is the failure this project exists to prevent (incoherence is reported
   loudly, Save is withheld).
2. **Zero egress.** Each page's CSP is `default-src 'none'`; the browser enforces it. Nothing
   a change adds may weaken the CSP or reference an external URL.
3. **Single files that open from disk.** No server, install, or network.
4. **Public and clean.** The repo and the Pages site are public: nothing personal,
   machine-specific, or internal ever reaches them.

## Layout

- `src/` sources and templates; `vendor/` third-party code, byte-for-byte as published (never
  edited; `test/static.test.mjs` asserts it); `build.mjs` the pure assembler.
- `dist/` the two pages. `docs/` the GitHub Pages site: `index.html` (the splash, built from
  `src/splash.template.html`, QR drawn at build time), `tx.html` and `rx.html` (copies of
  `dist/`), `licenses.txt`. Both are committed build outputs: change `src/`, run
  `node build.mjs`, commit the result. Never edit them by hand.
- `scripts/scan.mjs` the public-data and security scan; `scripts/scan-allow.json` its reviewed
  exceptions; `scripts/prepush.mjs` the gate; `scripts/hooks/` the git hooks.
- Live: https://tg-techie-agents.github.io/vft/ (`tx.html`, `rx.html`). Source:
  https://github.com/tg-techie-agents/vft

## Commands

- `npm install` once; `npm run setup` once per clone (points git at `scripts/hooks`).
- `node build.mjs` rebuilds. `npm test` runs the node suites (static, protocol, pipeline,
  real file, scanner). `npm run test:browser` is the two-Chrome product test (needs Google
  Chrome); run it after any change to `src/*.template.html` or `src/*.js`.
- `npm run scan` is the strict scan (tree and history). `npm run prepush` is the whole gate.

## Publishing is gated, mechanically

The `pre-commit` hook scans what is staged, `commit-msg` scans the message, `pre-push` runs
`scripts/prepush.mjs`. The scan looks inside binaries, inlined base64, UTF-16, and deflated PDF
streams, and checks commit authors and every historical blob. A scan that only a person
remembers to run is luck; do not bypass a hook (`--no-verify`) and do not widen
`scan-allow.json` without reading what the new entry points at.

Machine-specific names live in `.scan-denylist.local` (gitignored); the strict scan refuses to
run without it. After a clone, create it before pushing.

When a scan finds something, fix the cause, then add to `test/scan.test.mjs` the shape of
anything the scanner missed, so the next one is caught by the tool.

## Conventions

- Commits are authored as the repository's public noreply identity and carry no
  harness or session trailers (the scanner rejects them). Run `git status` before staging and
  stage paths explicitly, never `git add -A`.
- A new `innerHTML` (or `eval`, `document.write`) in `src/` is a scan finding. Prefer
  `textContent`; if markup is unavoidable, interpolate only validated numbers and add a
  `// scan-ok: <why it is safe>` line above it. Anything from the wire (file name, error
  detail) goes in as text.
- Claims on the splash page and README come from measurements in this repo's tests or the
  recorded call; say "measured once" when it was.
- Third-party code goes in `vendor/` untouched, with its licence in `THIRD-PARTY-NOTICES.txt`.
- No licence has been chosen for this project's own code. Do not add one; it is the owner's call.
