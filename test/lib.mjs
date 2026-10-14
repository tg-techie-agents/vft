// Shared test harness: loads the browser-side sources into Node so the tests
// exercise the same code the pages ship, and boots zxing through the same
// boot module the RX Client uses.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, '..');
const readSrc = rel => fs.readFileSync(path.join(root, rel), 'utf8');

// Evaluate a browser script that assigns a global and exports via module.exports.
function evalModule(rel) {
  const module = { exports: {} };
  new Function('module', readSrc(rel))(module);
  return module.exports;
}

export function loadProtocol() {
  return evalModule('src/protocol.js');
}

export function loadZxingBoot() {
  return evalModule('src/zxing-boot.js');
}

export function loadQrcodegen() {
  const src = readSrc('vendor/qrcodegen.js').replace(/export default qrcodegen;?/, '');
  return new Function(src + '\n;return qrcodegen;')();
}

// Boots zxing-wasm from the vendored binary via the shared boot module, and
// returns a decode function with the RX Client's exact options.
export async function loadDecoder() {
  const zx = await import('zxing-wasm/reader');
  const VFTZX = loadZxingBoot();
  const wasm = fs.readFileSync(path.join(root, 'vendor/zxing_reader.wasm'));
  await VFTZX.boot(zx, wasm.buffer.slice(wasm.byteOffset, wasm.byteOffset + wasm.byteLength));
  return imageData => VFTZX.decodeSymbols(zx, imageData);
}

// Rasterize a qrcodegen QrCode to an RGBA image with a quiet zone.
export function rasterize(qr, scale = 4, quiet = 4) {
  const n = (qr.size + quiet * 2) * scale;
  const data = new Uint8ClampedArray(n * n * 4).fill(255);
  for (let y = 0; y < qr.size; y++) {
    for (let x = 0; x < qr.size; x++) {
      if (!qr.getModule(x, y)) continue;
      for (let dy = 0; dy < scale; dy++) {
        const row = ((y + quiet) * scale + dy) * n;
        for (let dx = 0; dx < scale; dx++) {
          const i = (row + (x + quiet) * scale + dx) * 4;
          data[i] = data[i + 1] = data[i + 2] = 0;
        }
      }
    }
  }
  return { data, width: n, height: n };
}

// Render a Slide carrying one or more Symbols in a grid, as the TX canvas does.
export function renderSlide(qrcodegen, messages, scale = 3, quiet = 4) {
  const qrs = messages.map(m => qrcodegen.QrCode.encodeSegments(
    [qrcodegen.QrSegment.makeBytes(Array.from(m))], qrcodegen.QrCode.Ecc.MEDIUM));
  const cols = Math.ceil(Math.sqrt(qrs.length));
  const rows = Math.ceil(qrs.length / cols);
  const cell = Math.max(...qrs.map(q => q.size)) + quiet * 2;
  const w = cols * cell * scale, h = rows * cell * scale;
  const data = new Uint8ClampedArray(w * h * 4).fill(255);
  qrs.forEach((qr, i) => {
    const cx = (i % cols) * cell + quiet, cy = Math.floor(i / cols) * cell + quiet;
    for (let y = 0; y < qr.size; y++) for (let x = 0; x < qr.size; x++) {
      if (!qr.getModule(x, y)) continue;
      for (let dy = 0; dy < scale; dy++) for (let dx = 0; dx < scale; dx++) {
        const px = ((cy + y) * scale + dy) * w + (cx + x) * scale + dx;
        data[px * 4] = data[px * 4 + 1] = data[px * 4 + 2] = 0;
      }
    }
  });
  return { data, width: w, height: h };
}

// Minimal test reporter shared by the Node suites.
export function makeChecker() {
  const state = { pass: 0, fail: 0 };
  const check = (name, ok, extra = '') => {
    if (ok) { state.pass++; console.log(`ok    ${name}`); }
    else { state.fail++; console.log(`FAIL  ${name} ${extra}`); }
  };
  check.done = () => {
    console.log(`\n${state.pass} passed, ${state.fail} failed`);
    process.exit(state.fail ? 1 : 0);
  };
  check.info = msg => console.log(`info  ${msg}`);
  return check;
}

// A deterministic 69,466-byte binary shaped like a PDF (header, seeded
// pseudo-random body, trailer), generated so no third-party document ships
// in the repository. Returns its path under test/fixtures/.
export function sampleFixture() {
  const out = path.join(here, 'fixtures', 'sample.pdf');
  const SIZE = 69466;
  const head = Buffer.from('%PDF-1.4\n');
  const tail = Buffer.from('\n%%EOF\n');
  const body = Buffer.alloc(SIZE - head.length - tail.length);
  let a = 0x9e3779b9;
  for (let i = 0; i < body.length; i++) {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    body[i] = ((t ^ (t >>> 14)) >>> 0) & 0xff;
  }
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, Buffer.concat([head, body, tail]));
  return out;
}
