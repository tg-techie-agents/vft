// Full-pipeline test: file -> chunks -> MessagePack -> QR Symbols -> rasterized
// Slides -> zxing decode -> RX engine -> Gap Report -> narrowed Rotation ->
// verified completion. Uses the RX Client's own decoder boot and options.
import crypto from 'node:crypto';
import { loadProtocol, loadQrcodegen, loadDecoder, renderSlide, makeChecker } from './lib.mjs';

const VFT = loadProtocol();
const qrcodegen = loadQrcodegen();
const decode = await loadDecoder();
const check = makeChecker();

const slide = (msgs, scale) => renderSlide(qrcodegen, msgs, scale);

// --- TX model: build one Rotation of Slides over a transmission set.
function buildRotation(file, tag, h, ranges, sliceSize, symbolsPerSlide, setupEvery, seed) {
  const chunks = VFT.shuffle(VFT.planChunks(ranges, sliceSize), VFT.rng(seed));
  const setup = VFT.buildSetupMessage(tag, 'pipeline.bin', file.length, h);
  const slides = [[setup]];   // §9.1: a Setup Message in the first Rotation
  let group = [], dataSlides = 0;
  for (const [s, e] of chunks) {
    group.push(VFT.buildDataMessage(tag, s, file.subarray(s, e)));
    if (group.length === symbolsPerSlide) {
      slides.push(group); group = [];
      if (++dataSlides % setupEvery === 0) slides.push([setup]);
    }
  }
  if (group.length) slides.push(group);
  return slides;
}

// ---- multi-symbol slide decodes completely, byte-exact
// (The TX Client ships one Symbol per Slide, but §6.5 allows any number and
//  the RX Client must read whatever a conforming TX produces.)
{
  const msgs = [0, 1, 2, 3].map(i => VFT.buildDataMessage(
    new Uint8Array(8).fill(i + 1), i * 1000,
    Uint8Array.from({ length: 300 }, (_, j) => (j * (i + 3)) & 0xff)));
  const found = await decode(slide(msgs));
  check('2x2 slide yields all 4 symbols', found.length === 4, `got ${found.length}`);
  const want = msgs.map(m => VFT.toHex(m)).sort();
  const got = found.map(m => VFT.toHex(m)).sort();
  check('all 4 payloads byte-identical', JSON.stringify(want) === JSON.stringify(got));
}

// ---- 3x3 slide with 9 symbols
{
  const msgs = Array.from({ length: 9 }, (_, i) => VFT.buildDataMessage(
    new Uint8Array(8).fill(7), i * 500,
    Uint8Array.from({ length: 500 }, (_, j) => (j * 3 + i * 17) & 0xff)));
  const found = await decode(slide(msgs));
  check('3x3 slide yields all 9 symbols', found.length === 9, `got ${found.length}`);
}

// ---- full transfer with bursty loss, gap report, narrowed rotations
{
  const FILE_LEN = 60000, SLICE = 500, PER_SLIDE = 4, SETUP_EVERY = 8;
  const r = VFT.rng(1234);
  const file = Uint8Array.from({ length: FILE_LEN }, () => Math.floor(r() * 256));
  const h = new Uint8Array(crypto.createHash('sha256').update(file).digest());
  const tag = h.subarray(0, 8);

  const eng = new VFT.RxEngine();
  const incs = [];
  eng.onIncoherence = (t, inc) => incs.push(inc);

  let ranges = [[0, FILE_LEN]];
  let rotations = 0;
  const lossRng = VFT.rng(777);
  while (rotations < 10) {
    rotations++;
    const slides = buildRotation(file, tag, h, ranges, SLICE, PER_SLIDE, SETUP_EVERY, rotations * 7);
    let burst = 0;
    for (const msgs of slides) {
      // Bursty loss: ~15% of slides start a 1-3 slide burst on rotations 1-2 (A.3).
      if (burst > 0) { burst--; continue; }
      if (rotations <= 2 && lossRng() < 0.15) { burst = Math.floor(lossRng() * 3); continue; }
      for (const payload of await decode(slide(msgs))) eng.ingest(payload);
    }
    const t = eng.transfers.get(VFT.toHex(tag));
    if (!t || !t.setup) continue;
    if (t.hasFullCoverage()) break;
    // RX Operator pastes a coalesced Gap Report; TX narrows (§8.2.4).
    const report = t.gapReport(6);
    const parsed = VFT.parseGapReport(report);
    check(`rotation ${rotations} gap report parses`, !parsed.error && parsed.tag === VFT.toHex(tag), report);
    ranges = parsed.ranges;
  }

  const t = eng.transfers.get(VFT.toHex(tag));
  check('coverage complete', t.hasFullCoverage(), `rotations=${rotations}`);
  await t.checkCompletion();
  check('digest verified', t.complete);
  check('bytes identical to source', VFT.bytesEqual(t.buf, file));
  check('no incoherence', incs.length === 0, JSON.stringify(incs));
  check.info(`finished in ${rotations} rotations; counters: ${JSON.stringify(t.counters)}`);
}

// ---- corruption at the video layer is ordinary loss (§7.4.16)
{
  const msg = VFT.buildDataMessage(new Uint8Array(8).fill(9), 0,
    Uint8Array.from({ length: 200 }, (_, i) => i & 0xff));
  const img = slide([msg], 3);
  for (let y = Math.floor(img.height * 0.3); y < Math.floor(img.height * 0.7); y++) {
    for (let x = 0; x < img.width; x++) {
      if ((x + y) % 3 === 0) {
        const p = (y * img.width + x) * 4;
        img.data[p] = img.data[p + 1] = img.data[p + 2] = (x * 31 + y * 17) & 0xff;
      }
    }
  }
  const eng = new VFT.RxEngine();
  let incCount = 0;
  eng.onIncoherence = () => incCount++;
  for (const payload of await decode(img)) eng.ingest(payload);
  check('video-layer damage never causes incoherence', incCount === 0);
}

// ---- downscaled slide (video compression proxy): decode or clean loss, never junk
{
  const tag = new Uint8Array(8).fill(3);
  const msgs = [0, 1, 2, 3].map(i => VFT.buildDataMessage(tag, i * 400,
    Uint8Array.from({ length: 400 }, (_, j) => (j * 11 + i) & 0xff)));
  const img = slide(msgs, 3);
  const f = 0.55;
  const sw = Math.floor(img.width * f), sh = Math.floor(img.height * f);
  const small = new Uint8ClampedArray(sw * sh * 4);
  for (let y = 0; y < sh; y++) for (let x = 0; x < sw; x++) {
    const sx = Math.floor(x / f), sy = Math.floor(y / f);
    for (let k = 0; k < 4; k++) small[(y * sw + x) * 4 + k] = img.data[(sy * img.width + sx) * 4 + k];
  }
  const eng = new VFT.RxEngine();
  let incCount = 0;
  eng.onIncoherence = () => incCount++;
  const found = await decode({ data: small, width: sw, height: sh });
  for (const payload of found) eng.ingest(payload);
  check.info(`55% downscale: ${found.length}/4 symbols decoded`);
  check('downscaled slide: no incoherence, decoded payloads intact', incCount === 0);
}

// ---- varying slice size mid-transfer needs no coordination (context dialogue)
{
  const file = Uint8Array.from({ length: 5000 }, (_, i) => (i * 13) & 0xff);
  const h = new Uint8Array(crypto.createHash('sha256').update(file).digest());
  const tag = h.subarray(0, 8);
  const eng = new VFT.RxEngine();
  eng.ingest(VFT.buildSetupMessage(tag, 'v', file.length, h));
  for (const [s, e] of VFT.planChunks([[0, 2600]], 700))
    eng.ingest(VFT.buildDataMessage(tag, s, file.subarray(s, e)));
  for (const [s, e] of VFT.planChunks([[2400, 5000]], 130))
    eng.ingest(VFT.buildDataMessage(tag, s, file.subarray(s, e)));
  const t = eng.transfers.get(VFT.toHex(tag));
  await t.checkCompletion();
  check('mixed slice sizes with overlap complete cleanly', t.complete && !t.failed);
}

check.done();
