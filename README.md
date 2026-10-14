# Visual File Transfer — single-file clients

Live: <https://tg-techie-agents.github.io/vft/> — the splash page, with
[`tx.html`](https://tg-techie-agents.github.io/vft/tx.html) (send) and
[`rx.html`](https://tg-techie-agents.github.io/vft/rx.html) (receive).

Implements "Visual File Transfer Protocol, version 1" (see SPEC) as two
self-contained HTML pages. Open them from disk; they need no server, no
install, and no network. A `Content-Security-Policy` of `default-src 'none'`
in each page makes the browser itself enforce zero egress.

## Deliverables

- **`dist/vft-tx.html`** (~95 KiB) — TX Client. Load a file, it renders QR
  Slides in Rotations, one Symbol per Slide. Paste a Gap Report to narrow
  later Rotations. Inlines Project Nayuki's `qrcodegen` (MIT) for encoding.
- **`dist/vft-rx.html`** (~1.5 MiB) — RX Client. Captures a shared window via
  `getDisplayMedia`, reconstructs files keyed by File Tag, produces
  coalescible Gap Reports, verifies the SHA-256 digest before offering the
  file, and reports incoherence loudly. Inlines `zxing-wasm` (MIT, built on
  zxing-cpp, Apache-2.0; see `THIRD-PARTY-NOTICES.txt`) with its WASM binary
  embedded as base64.

Append `?selftest` to either page's URL to run its built-in self-test,
including live probes proving the CSP blocks fetch/XHR/WebSocket/beacon/img.

## Architecture

One source of truth per concern; the build only assembles.

| File | Owns |
|---|---|
| `src/protocol.js` | The protocol: MessagePack codec, SHA-256, message build/classify, RX state machine (§7), Gap Report grammar (§8), interval bookkeeping. No I/O, no DOM — loads unchanged in Node for the tests. |
| `src/shared.css` | Design tokens and shared components (status strip, chips, tiles, meters, controls). Pages extend, never redefine. |
| `src/shared-ui.js` | Shared page helpers: formatting, status chips, self-test reporting, the egress probe suite. |
| `src/zxing-boot.js` | The decoder's egress guarantee, at the API layer: supplies the WASM binary via `wasmBinary` and overrides `locateFile` so the library's CDN fallback cannot resolve. Used by the RX Client, both browser harnesses, and the Node tests. |
| `vendor/` | Third-party sources, byte-for-byte as published (qrcodegen 1.8.0, zxing-wasm 2.2.0 reader). The build never rewrites them; `test/static.test.mjs` asserts that. |
| `build.mjs` | Pure assembler: inlines sources at `@@MARKER@@` points, generates the RX self-test fixture (pre-rendered QR matrices of a miniature complete transfer), writes `dist/` and the harnesses. Fails loudly on a missing or duplicated marker. |

Zero egress rests on three independent layers, each separately tested: the
page CSP, the `locateFile` override, and — empirically — a Chrome net-log
showing no page-initiated requests at all.

## Tests

Run `node build.mjs` first. Everything below passes on the current build.

| Suite | Command | Covers |
|---|---|---|
| Static invariants | `node test/static.test.mjs` | No external `src`/`href`, no unfilled markers, CSP present and restrictive, shared layer inlined exactly once, vendor inlined verbatim, embedded WASM byte-identical to `vendor/` |
| Protocol | `node test/protocol.test.mjs` | msgpack edges, SHA-256 vs `node:crypto`, gap grammar + coalescing superset property, every §7 obligation (conflict, beyond-length, digest mismatch, idempotent/mismatched Setup, unknown `v`/`z`, empty file, concurrent transfers) |
| Pipeline | `node test/pipeline.test.mjs` | file→msgpack→QR→zxing→engine with bursty Slide loss, coalesced Gap Reports, narrowed Rotations, multi-Symbol Slides, video-degradation proxies |
| Real file | `node test/realfile.test.mjs` | A generated 68 KiB PDF-shaped binary and a 4 MiB US federal PDF (IRS Publication 1076) through the real encode/decode pipeline under bursty loss; byte identity, digest, and PDF structure all verified |
| Large files | `node test/large.test.mjs` | 100 MiB through the RX engine (47k shuffled Chunks, ~5k held fragments, Gap Report coalescing at scale) and 2 MiB through the real QR pipeline |
| Browser E2E | headless Chrome on `test/e2e.html`, grep `VFT-E2E: PASS` | The same loop in-browser through real canvases, plus conflict-through-the-channel and CSP probes |
| Page self-tests | headless Chrome on `dist/…?selftest` | TX: scripted DOM transmission, §9.1/§9.2, gap narrow/ignore/stop. RX: fixture decode → verified completion, card UI, Save withheld after incoherence (§7.4.14), egress probes |
| Live capture | `node test/cdp-capture.mjs` | A real `getDisplayMedia` stream through the actual scan loop to a digest-verified transfer |
| Scanner | `node test/scan.test.mjs` | The public-data and security scanner finds each planted leak class (plain text, binaries, inlined base64, deflated PDF streams, git history) and stays silent on clean input |
| **Product** | `node test/product.test.mjs` | **The shipped pages driving each other in two real Chrome windows**: TX loads the PDF through its own file input, RX captures the TX window, the operator relays a Gap Report, TX narrows, RX saves — and the saved file is compared byte-for-byte with the source |

`test/product.test.mjs` is the one that matters most among the automated
suites: it touches nothing but the pages' own UI, and its verdict is the file
on disk. It joins the RX Client late on purpose, so the Gap Report path is
exercised rather than skipped.

**Verified over a real video call (2026-08-04).** The shipped pages carried
a 69,466-byte PDF across a live Google Meet call: the TX tab was presented into the meeting, a second participant's
tab rendered the received video, the RX Client captured that tab, two Gap
Reports were relayed operator-style, and the file the RX Client saved was
byte-identical to the source. Zero channel-level
conflicts or incoherence. Field notes: Meet toasts/overlays that cover a
finder pattern stop decoding entirely (move or dismiss them), and Slice sizes
of 250–450 bytes decoded reliably at ~1920×1000 tab-share resolution while
800 bytes did not; throughput observed was ~350–450 B/s. `test/webrtc.html`
(built but not part of the default suite) is a no-network RTCPeerConnection
loopback harness that approximates this codec path automatically.

## Notes

- Slice size is the main tuning knob (SPEC A.5); the TX default of 800 bytes
  at ECC M is conservative for screen-share video. The TX clamps the maximum
  per ECC level so every Chunk fits a version-40 QR Code.
- Rotation order is reshuffled every Rotation (A.3), and Setup Slides repeat
  periodically (A.4) so a late-joining RX Client binds without coordination.
- The RX treats a decodable v=1 Setup Message with an unknown `z` as
  incoherence under the §1 principle (the channel cannot produce it), the same
  way §3.5 treats an unknown version.
- The TX Client sends one Symbol per Slide; the RX Client still decodes
  multi-Symbol Slides, since §6.5 permits them and another TX may send them.
- RX transfer cards put "Copy Gap Report" first; Discard is gated behind
  Pause (a paused transfer stops applying incoming messages — the engine
  counts them as `pausedDropped` — so state can't change under the operator).
- The TX Rotation indicator is a circular sweep, not a bar: a Rotation
  cycles, it doesn't complete.
- New transfers surface as **FILE DETECTED** and buffer (bounded) until the
  operator presses Start receiving; nothing accumulates unconfirmed.
- The RX Tuning panel (rolling 20 s) shows Slice size in use, new codes/s,
  scans-per-Slide (adjacent re-scans only — retransmissions excluded), and
  unreadable rate, with a one-line suggestion, so the two operators can
  coordinate Slice size and Slide interval over chat.
- Both pages work served or opened from disk; when served over HTTP they show
  a "Download this page" button offering the single-file tool itself.

## Publishing

`docs/` is the GitHub Pages site (served from the `main` branch): the splash
page plus `tx.html` and `rx.html`, which are byte-copies of `dist/`. `node
build.mjs` regenerates `dist/` and `docs/`; both are committed.

Nothing is pushed unless `npm run prepush` passes (installed as the git
`pre-push` hook by `npm run setup`): a strict public-data and secrets scan of the
tree and the whole history (`scripts/scan.mjs`), a rebuild that must match what is
committed, the static invariants, the scanner's own test, and `npm audit`.
