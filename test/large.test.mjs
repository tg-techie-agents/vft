// Large-file tests.
//  A: 100 MB through the RX engine — shuffled arrival, heavy interval
//     fragmentation, loss + gap reports at scale, digest verify, timing.
//  B: 2 MB through the full QR pipeline (encode -> rasterize -> zxing decode).
import crypto from 'node:crypto';
import { loadProtocol, loadQrcodegen, loadDecoder, rasterize } from './lib.mjs';

const VFT = loadProtocol();
const qrcodegen = loadQrcodegen();
const decode = await loadDecoder();

let pass = 0, fail = 0;
function check(name, ok, extra = '') {
  if (ok) { pass++; console.log(`ok    ${name}`); }
  else { fail++; console.log(`FAIL  ${name} ${extra}`); }
}
const mark = (label, t0) => console.log(`info  ${label}: ${(performance.now() - t0).toFixed(0)}ms`);

// ---------- A: 100 MB protocol-level transfer ----------
await (async () => {
  const L = 100 * 1024 * 1024, SLICE = 2000;
  let t0 = performance.now();
  const file = crypto.randomBytes(L);
  const h = new Uint8Array(crypto.createHash('sha256').update(file).digest());
  const tag = h.subarray(0, 8);
  mark('generate + hash 100 MiB', t0);

  const eng = new VFT.RxEngine();
  const incs = [];
  eng.onIncoherence = (t, inc) => incs.push(inc.type);
  eng.ingest(VFT.buildSetupMessage(tag, 'big.bin', L, h));

  // Round 1: shuffled chunks with 10% random loss — maximum fragmentation.
  t0 = performance.now();
  const chunks = VFT.shuffle(VFT.planChunks([[0, L]], SLICE), VFT.rng(7));
  const lossRng = VFT.rng(99);
  let sent = 0;
  for (const [s, e] of chunks) {
    if (lossRng() < 0.10) continue;
    eng.ingest(VFT.buildDataMessage(tag, s, file.subarray(s, e)));
    sent++;
  }
  const tr = eng.transfers.get(VFT.toHex(tag));
  mark(`round 1: ${sent} chunks ingested (held ${tr.held.length} fragments)`, t0);
  check('round 1 held most of the file', tr.heldBytes() > 0.85 * L);

  // Gap report at scale: thousands of missing ranges, coalesced to 20.
  t0 = performance.now();
  const missing = tr.missingRanges();
  const report = tr.gapReport(20);
  mark(`gap report over ${missing.length} missing ranges`, t0);
  check('gap report parses and stays short', !VFT.parseGapReport(report).error && report.length < 400,
    `len=${report.length}`);
  const parsed = VFT.parseGapReport(report);

  // Round 2: resend only the coalesced ranges — must complete.
  t0 = performance.now();
  for (const [s, e] of VFT.planChunks(parsed.ranges, SLICE))
    eng.ingest(VFT.buildDataMessage(tag, s, file.subarray(s, e)));
  mark('round 2: narrowed resend', t0);
  check('full coverage', tr.hasFullCoverage());

  t0 = performance.now();
  await tr.checkCompletion();
  mark('digest verify 100 MiB', t0);
  check('100 MiB transfer complete + digest verified', tr.complete);
  check('bytes identical (spot: sampled offsets)', [0, 1, L >> 1, L - 1, 12345678]
    .every(i => tr.buf[i] === file[i]));
  check('no incoherence at scale', incs.length === 0, JSON.stringify(incs));
  console.log(`info  counters: ${JSON.stringify(tr.counters)}`);
})();

// ---------- B: 2 MB through the full QR pipeline ----------
await (async () => {
  const L = 2 * 1024 * 1024, SLICE = 2200;   // ECC M capacity is 2331
  const t0 = performance.now();
  const file = crypto.randomBytes(L);
  const h = new Uint8Array(crypto.createHash('sha256').update(file).digest());
  const tag = h.subarray(0, 8);
  const eng = new VFT.RxEngine();
  const incs = [];
  eng.onIncoherence = (t, inc) => incs.push(inc.type);
  eng.ingest(VFT.buildSetupMessage(tag, '2mb.bin', L, h));

  const chunks = VFT.shuffle(VFT.planChunks([[0, L]], SLICE), VFT.rng(3));
  let symbols = 0;
  for (const [s, e] of chunks) {
    const msg = VFT.buildDataMessage(tag, s, file.subarray(s, e));
    const qr = qrcodegen.QrCode.encodeSegments(
      [qrcodegen.QrSegment.makeBytes(Array.from(msg))], qrcodegen.QrCode.Ecc.MEDIUM);
    for (const payload of await decode(rasterize(qr, 2))) {
      eng.ingest(payload);
      symbols++;
    }
  }
  const tr = eng.transfers.get(VFT.toHex(tag));
  mark(`2 MiB through QR pipeline (${chunks.length} slides, ${symbols} decoded)`, t0);
  check('every slide decoded', symbols === chunks.length, `${symbols}/${chunks.length}`);
  check('full coverage', tr.hasFullCoverage());
  await tr.checkCompletion();
  check('2 MiB transfer complete + digest verified', tr.complete);
  check('assembled identical', VFT.bytesEqual(tr.buf, new Uint8Array(file.buffer, file.byteOffset, L)));
  check('no incoherence', incs.length === 0);
})();

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
