// Real-file transfers: actual binary documents carried end to end through the
// real QR encode -> decode pipeline, under bursty Slide loss, with Gap Reports
// narrowing later Rotations. Byte-for-byte identity and the SHA-256 digest are
// what pass or fail this test — a PDF is unforgiving, since a single wrong byte
// breaks the file.
//
// Usage: node test/realfile.test.mjs [fixture.pdf ...]   (defaults to all)
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadProtocol, loadQrcodegen, loadDecoder, rasterize, makeChecker, sampleFixture } from './lib.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const VFT = loadProtocol();
const qrcodegen = loadQrcodegen();
const decode = await loadDecoder();
const check = makeChecker();

const FIXTURE_DIR = path.join(here, 'fixtures');
const DEFAULTS = [sampleFixture(), 'irs-1076-2023.pdf'];
const fixtures = (process.argv.slice(2).length ? process.argv.slice(2) : DEFAULTS)
  .map(f => (path.isAbsolute(f) ? f : path.join(FIXTURE_DIR, f)));

// TX Client defaults: one Symbol per Slide, ECC M, 800-byte Slices.
const SLICE = 800, SETUP_EVERY = 10;

for (const fixture of fixtures) {
  const raw = fs.readFileSync(fixture);
  const file = new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength);
  const name = path.basename(fixture);
  const h = new Uint8Array(crypto.createHash('sha256').update(raw).digest());
  const tag = h.subarray(0, 8);

  console.log(`\n--- ${name}: ${file.length} bytes, tag ${VFT.toHex(tag)} ---`);
  check(`${name}: fixture is a PDF`, raw.subarray(0, 5).toString('latin1') === '%PDF-');

  const setupMsg = VFT.buildSetupMessage(tag, name, file.length, h);
  check(`${name}: setup message classifies`, VFT.classify(setupMsg).kind === 'setup');

  const eng = new VFT.RxEngine();
  const incs = [];
  eng.onIncoherence = (t, inc) => incs.push(inc);

  const t0 = performance.now();
  let ranges = [[0, file.length]];
  let rotations = 0, shown = 0, lost = 0;
  const lossRng = VFT.rng(20260804);

  while (rotations < 8) {
    rotations++;
    // One Rotation: shuffled per A.3, periodic Setup Slides per A.4.
    const chunks = VFT.shuffle(VFT.planChunks(ranges, SLICE), VFT.rng(rotations * 101));
    const slides = [[setupMsg]];
    let dataSlides = 0;
    for (const [s, e] of chunks) {
      slides.push([VFT.buildDataMessage(tag, s, file.subarray(s, e))]);
      if (++dataSlides % SETUP_EVERY === 0) slides.push([setupMsg]);
    }

    // Bursty channel: on the first two Rotations, ~12% of Slides begin a burst
    // of 1-4 consecutive lost Slides (the loss pattern A.3 describes).
    let burst = 0;
    for (const msgs of slides) {
      if (burst > 0) { burst--; lost++; continue; }
      if (rotations <= 2 && lossRng() < 0.12) { burst = 1 + Math.floor(lossRng() * 4); lost++; continue; }
      shown++;
      const qr = qrcodegen.QrCode.encodeSegments(
        [qrcodegen.QrSegment.makeBytes(Array.from(msgs[0]))], qrcodegen.QrCode.Ecc.MEDIUM);
      for (const payload of await decode(rasterize(qr, 3))) eng.ingest(payload);
    }

    const t = eng.transfers.get(VFT.toHex(tag));
    check.info(`${name} rotation ${rotations}: ${(100 * t.heldBytes() / file.length).toFixed(1)}% held, ` +
      `${t.missingRanges().length} missing ranges`);
    if (t.hasFullCoverage()) break;

    // The RX Operator copies a coalesced Gap Report into chat; the TX Operator
    // pastes it in and the next Rotation is narrowed to it (§8.2).
    const report = t.gapReport(8);
    const parsed = VFT.parseGapReport(report);
    check(`${name} rotation ${rotations}: Gap Report valid and chat-pasteable (${report.length} chars)`,
      !parsed.error && report.length < 300, report);
    ranges = parsed.ranges;
  }

  const t = eng.transfers.get(VFT.toHex(tag));
  const elapsed = performance.now() - t0;
  check.info(`${name}: ${shown} Slides decoded, ${lost} lost, ${rotations} Rotations, ${(elapsed / 1000).toFixed(1)}s`);
  check.info(`${name}: counters ${JSON.stringify(t.counters)}`);

  check(`${name}: full coverage reached`, t.hasFullCoverage());
  await t.checkCompletion();
  check(`${name}: digest verified — transfer complete (§7.3.10)`, t.complete);
  check(`${name}: no incoherence during the transfer (§7.4)`, incs.length === 0, JSON.stringify(incs.slice(0, 3)));
  check(`${name}: reconstructed bytes identical to the source`, VFT.bytesEqual(t.buf, file));
  check(`${name}: reconstructed SHA-256 matches`,
    crypto.createHash('sha256').update(t.buf).digest('hex') ===
    crypto.createHash('sha256').update(raw).digest('hex'));
  check(`${name}: reconstruction is a valid PDF (header + EOF marker)`,
    Buffer.from(t.buf.subarray(0, 5)).toString('latin1') === '%PDF-' &&
    Buffer.from(t.buf.subarray(-2048)).toString('latin1').includes('%%EOF'));
  check(`${name}: Gap Report says nothing missing`, t.gapReport() === `VFT1 ${VFT.toHex(tag)} -`);
  check(`${name}: advisory filename carried intact`, t.setup.n === name);

  // Round-trip through disk, so the result is a file, not just a buffer.
  const outPath = path.join(FIXTURE_DIR, name + '.received');
  fs.writeFileSync(outPath, t.buf);
  check(`${name}: reconstruction identical on disk`, fs.readFileSync(outPath).equals(raw));
  fs.unlinkSync(outPath);
}

check.done();
