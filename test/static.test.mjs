// Static invariants of the shipped deliverables. These assert the properties
// the build must never lose: no external references, no unfilled markers,
// CSP present and restrictive, everything genuinely inlined, and the shared
// layer actually shared (not re-declared per page).
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, '..');

let pass = 0, fail = 0;
function check(name, ok, extra = '') {
  if (ok) { pass++; console.log(`ok    ${name}`); }
  else { fail++; console.log(`FAIL  ${name} ${extra}`); }
}

const PAGES = ['dist/vft-tx.html', 'dist/vft-rx.html'];

for (const rel of PAGES) {
  const src = fs.readFileSync(path.join(root, rel), 'utf8');
  const tag = rel.split('/').pop();

  check(`${tag}: no unfilled build markers`, !/@@[A-Z0-9_]+@@/.test(src));

  // No HTML element may load anything over the network. (Matches attributes
  // inside tags only — URLs in script text are covered by the next check.)
  const externalAttrs = src.match(/<[^>]*\s(?:src|href)\s*=\s*["'](?!data:|blob:|#)[a-z]+:[^"']*/gi) || [];
  check(`${tag}: no external src/href attribute`, externalAttrs.length === 0, externalAttrs.join(' '));

  // Every absolute URL in the page must be one of three known-inert kinds.
  // Anything else is a new egress path and must fail this test.
  const ALLOWED = [
    // deliberate egress-probe targets, which must fail (proving CSP works)
    /^https?:\/\/example\.com\//,
    // license and attribution text in comments
    /^https?:\/\/(www\.nayuki\.io|www\.apache\.org|opensource\.org)\//,
    // zxing's CDN fallback template, left byte-identical in the vendored source
    // and made unreachable by the locateFile override asserted below
    /^https:\/\/fastly\.jsdelivr\.net\/npm\/zxing-wasm@/,
  ];
  const urls = src.match(/https?:\/\/[^\s"'`)<]+/g) || [];
  const unexpected = urls.filter(u => !ALLOWED.some(re => re.test(u)));
  check(`${tag}: no unexpected absolute URLs`, unexpected.length === 0, [...new Set(unexpected)].join(' '));

  // If the vendored CDN fallback string is present, the boot module's
  // locateFile override must also be present — that is what makes it inert.
  // (Independently: CSP blocks it, and the net-log check proves zero traffic.)
  check(`${tag}: CDN fallback neutralized by locateFile override`,
    !src.includes('jsdelivr') || src.includes('about:invalid#vft-embedded-only/'));

  // CSP: default-src 'none' with no network sources anywhere in the policy.
  const csp = /<meta http-equiv="Content-Security-Policy" content="([^"]+)"/.exec(src);
  check(`${tag}: CSP present`, !!csp);
  if (csp) {
    const policy = csp[1];
    check(`${tag}: CSP default-src 'none'`, /default-src\s+'none'/.test(policy), policy);
    check(`${tag}: CSP names no network scheme or host`,
      !/(https?:|wss?:|\*|\.com|\.net|\.org)/.test(policy), policy);
    check(`${tag}: CSP has no connect-src escape hatch`, !/connect-src/.test(policy), policy);
  }

  // Nothing may reference a sibling file: the page must stand alone.
  check(`${tag}: no relative script/style includes`,
    !/<script[^>]+src=/i.test(src) && !/<link[^>]+rel=["']?stylesheet/i.test(src));
}

// The shared layer must be inlined once per page, from the single source.
const sharedCss = fs.readFileSync(path.join(root, 'src/shared.css'), 'utf8');
const sharedUi = fs.readFileSync(path.join(root, 'src/shared-ui.js'), 'utf8');
const cssProbe = '--track-accent: #22304a;';
const uiProbe = 'async function egressProbes()';
check('shared.css contains the probe line', sharedCss.includes(cssProbe));
check('shared-ui.js contains the probe line', sharedUi.includes(uiProbe));
for (const rel of PAGES) {
  const src = fs.readFileSync(path.join(root, rel), 'utf8');
  const tag = rel.split('/').pop();
  check(`${tag}: shared CSS inlined exactly once`, src.split(cssProbe).length === 2);
  check(`${tag}: shared UI inlined exactly once`, src.split(uiProbe).length === 2);
}

// Vendored sources must be byte-identical to what the build consumes: the
// build is an assembler, not a rewriter.
const vendorFiles = ['vendor/qrcodegen.js', 'vendor/zxing-reader-iife.js'];
for (const rel of vendorFiles) {
  const vendorSrc = fs.readFileSync(path.join(root, rel), 'utf8');
  const target = rel.includes('zxing') ? 'dist/vft-rx.html' : 'dist/vft-tx.html';
  const page = fs.readFileSync(path.join(root, target), 'utf8');
  // qrcodegen has its ESM export line stripped (the only permitted transform).
  const expected = vendorSrc.replace(/export default qrcodegen;?/, '');
  check(`${rel} inlined verbatim into ${target.split('/').pop()}`, page.includes(expected.trim()));
}

// The embedded WASM must match the vendored binary exactly.
{
  const rx = fs.readFileSync(path.join(root, 'dist/vft-rx.html'), 'utf8');
  const m = /var VFT_WASM_B64 = "([A-Za-z0-9+/=]+)"/.exec(rx);
  check('rx: wasm embedded as base64', !!m);
  if (m) {
    const embedded = Buffer.from(m[1], 'base64');
    const onDisk = fs.readFileSync(path.join(root, 'vendor/zxing_reader.wasm'));
    check('rx: embedded wasm is byte-identical to vendor', embedded.equals(onDisk));
    check('rx: embedded wasm has the wasm magic number',
      embedded.subarray(0, 4).equals(Buffer.from([0x00, 0x61, 0x73, 0x6d])));
  }
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
