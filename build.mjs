// Assembles the single-file HTML deliverables and test harnesses.
// This is a pure assembler: it inlines sources at markers and generates the
// RX self-test fixture. It never rewrites vendored code — the zxing egress
// guarantee lives in src/zxing-boot.js (API-layer overrides) and each page's
// CSP, and is asserted by test/static.test.mjs and the browser egress probes.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadQrcodegen } from './test/lib.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const read = p => fs.readFileSync(path.join(here, p), 'utf8');

const protocol = read('src/protocol.js');
const sharedCss = read('src/shared.css');
const sharedUi = read('src/shared-ui.js');
const zxingBoot = read('src/zxing-boot.js');
const qrgen = read('vendor/qrcodegen.js').replace(/export default qrcodegen;?/, '');
const zxing = read('vendor/zxing-reader-iife.js');
const wasmB64 = fs.readFileSync(path.join(here, 'vendor/zxing_reader.wasm')).toString('base64');

// ---- self-test fixture for the RX Client: a complete miniature transfer,
// pre-rendered to QR module matrices at build time (RX ships no encoder).
const qrcodegen = loadQrcodegen();
const VFT = (() => {
  const module = { exports: {} };
  new Function('module', protocol)(module);
  return module.exports;
})();

const fixtureText = 'VFT RX Client self-test: this tiny transfer is embedded in the page. ' +
  'If it assembles and verifies, the decode and receive paths work. éø✓';
const fixtureBytes = new TextEncoder().encode(fixtureText);
const fixtureH = VFT.sha256(fixtureBytes);
const fixtureTag = fixtureH.subarray(0, 8);
const split = Math.floor(fixtureBytes.length / 2);
const fixtureMsgs = [
  VFT.buildSetupMessage(fixtureTag, 'selftest.txt', fixtureBytes.length, fixtureH),
  VFT.buildDataMessage(fixtureTag, 0, fixtureBytes.subarray(0, split)),
  VFT.buildDataMessage(fixtureTag, split, fixtureBytes.subarray(split)),
];
const fixtureSymbols = fixtureMsgs.map(m => {
  const qr = qrcodegen.QrCode.encodeSegments(
    [qrcodegen.QrSegment.makeBytes(Array.from(m))], qrcodegen.QrCode.Ecc.MEDIUM);
  const rows = [];
  for (let y = 0; y < qr.size; y++) {
    let row = '';
    for (let x = 0; x < qr.size; x++) row += qr.getModule(x, y) ? '1' : '0';
    rows.push(row);
  }
  return { size: qr.size, rows };
});
const fixture = 'var VFT_FIXTURE = ' + JSON.stringify({
  tagHex: VFT.toHex(fixtureTag),
  text: fixtureText,
  symbols: fixtureSymbols,
}) + ';';

// ---- assembly (split/join, not replace: sources contain $ sequences)
function fill(template, marks) {
  let out = template;
  for (const [mark, content] of Object.entries(marks)) {
    const parts = out.split(mark);
    if (parts.length !== 2) throw new Error(`marker ${mark} found ${parts.length - 1} times`);
    out = parts[0] + content + parts[1];
  }
  if (/@@[A-Z0-9_]+@@/.test(out)) throw new Error('unfilled marker remains');
  return out;
}

const marks = {
  '/* @@SHARED_CSS@@ */': sharedCss,
  '/* @@SHARED_UI@@ */': sharedUi,
  '/* @@ZXING_BOOT@@ */': zxingBoot,
  '/* @@PROTOCOL@@ */': protocol,
  '/* @@QRCODEGEN@@ */': qrgen,
  '/* @@ZXING@@ */': zxing,
  '@@WASM_B64@@': wasmB64,
  '/* @@FIXTURE@@ */': fixture,
};
// Each template names only the markers it contains.
function pick(...names) {
  return Object.fromEntries(names.map(n => [n, marks[n]]));
}

fs.mkdirSync(path.join(here, 'dist'), { recursive: true });

fs.writeFileSync(path.join(here, 'dist/vft-tx.html'), fill(read('src/tx.template.html'),
  pick('/* @@SHARED_CSS@@ */', '/* @@SHARED_UI@@ */', '/* @@QRCODEGEN@@ */', '/* @@PROTOCOL@@ */')));

fs.writeFileSync(path.join(here, 'dist/vft-rx.html'), fill(read('src/rx.template.html'),
  pick('/* @@SHARED_CSS@@ */', '/* @@SHARED_UI@@ */', '/* @@ZXING_BOOT@@ */',
       '/* @@ZXING@@ */', '@@WASM_B64@@', '/* @@PROTOCOL@@ */', '/* @@FIXTURE@@ */')));

fs.writeFileSync(path.join(here, 'test/e2e.html'), fill(read('src/e2e.template.html'),
  pick('/* @@ZXING_BOOT@@ */', '/* @@QRCODEGEN@@ */', '/* @@ZXING@@ */',
       '@@WASM_B64@@', '/* @@PROTOCOL@@ */')));

fs.writeFileSync(path.join(here, 'test/capture.html'), fill(read('test/capture.template.html'),
  pick('/* @@ZXING_BOOT@@ */', '/* @@QRCODEGEN@@ */', '/* @@ZXING@@ */',
       '@@WASM_B64@@', '/* @@PROTOCOL@@ */')));

fs.writeFileSync(path.join(here, 'test/webrtc.html'), fill(read('test/webrtc.template.html'),
  pick('/* @@ZXING_BOOT@@ */', '/* @@QRCODEGEN@@ */', '/* @@ZXING@@ */',
       '@@WASM_B64@@', '/* @@PROTOCOL@@ */')));

// ---- the Pages site (docs/): the splash page plus the two clients, unchanged.
// The splash QR is drawn here, at build time, from the same vendored encoder.
const SITE_URL = 'https://tg-techie-agents.github.io/vft/';
const siteQr = qrcodegen.QrCode.encodeText(SITE_URL, qrcodegen.QrCode.Ecc.MEDIUM);
let qrPath = '';
for (let y = 0; y < siteQr.size; y++) {
  for (let x = 0; x < siteQr.size; x++) if (siteQr.getModule(x, y)) qrPath += `M${x + 4} ${y + 4}h1v1h-1z`;
}
const qrSvg = `<svg viewBox="0 0 ${siteQr.size + 8} ${siteQr.size + 8}" shape-rendering="crispEdges" role="img" aria-label="QR code for ${SITE_URL}"><path fill="#fff" d="M0 0h${siteQr.size + 8}v${siteQr.size + 8}H0z"/><path fill="#1d1c1a" d="${qrPath}"/></svg>`;
fs.mkdirSync(path.join(here, 'docs'), { recursive: true });
fs.writeFileSync(path.join(here, 'docs/index.html'), fill(read('src/splash.template.html').split('@@SITE_URL@@').join(SITE_URL), {
  '@@QR_SVG@@': qrSvg,
  '@@SITE_LABEL@@': SITE_URL.replace(/^https:\/\//, ''),
}));
fs.copyFileSync(path.join(here, 'dist/vft-tx.html'), path.join(here, 'docs/tx.html'));
fs.copyFileSync(path.join(here, 'dist/vft-rx.html'), path.join(here, 'docs/rx.html'));
fs.copyFileSync(path.join(here, 'THIRD-PARTY-NOTICES.txt'), path.join(here, 'docs/licenses.txt'));
fs.writeFileSync(path.join(here, 'docs/.nojekyll'), '');

for (const f of ['dist/vft-tx.html', 'dist/vft-rx.html', 'docs/index.html', 'test/e2e.html', 'test/capture.html']) {
  const kb = (fs.statSync(path.join(here, f)).size / 1024).toFixed(0);
  console.log(`${f}  ${kb} KiB`);
}
