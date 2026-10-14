import crypto from 'node:crypto';
import { loadProtocol } from './lib.mjs';

const VFT = loadProtocol();

let pass = 0, fail = 0;
function check(name, ok, extra = '') {
  if (ok) { pass++; console.log(`ok    ${name}`); }
  else { fail++; console.log(`FAIL  ${name} ${extra}`); }
}
function randBytes(n, seed = 1) {
  const r = VFT.rng(seed);
  return Uint8Array.from({ length: n }, () => Math.floor(r() * 256));
}

// ---- sha256 vs node:crypto across many lengths (incl. block boundaries)
{
  let allOk = true;
  for (const n of [0, 1, 3, 31, 32, 55, 56, 57, 63, 64, 65, 100, 1000, 65536, 200000]) {
    const b = randBytes(n, n + 7);
    const want = new Uint8Array(crypto.createHash('sha256').update(b).digest());
    if (!VFT.bytesEqual(VFT.sha256(b), want)) { allOk = false; break; }
  }
  check('sha256 matches node:crypto for 15 lengths', allOk);
}

// ---- msgpack round trip of protocol messages
{
  const tag = randBytes(8, 2), h = randBytes(32, 3);
  const setup = VFT.buildSetupMessage(tag, 'Exämple 😀.bin', 1234567, h);
  const { value: sm } = VFT.msgpackDecode(setup);
  check('setup round trip', sm.v === 1 && sm.t === 's' && VFT.bytesEqual(sm.f, tag)
    && sm.n === 'Exämple 😀.bin' && sm.l === 1234567 && VFT.bytesEqual(sm.h, h) && sm.z === 'none');

  const slice = randBytes(400, 4);
  const data = VFT.buildDataMessage(tag, 987654321, slice);
  const { value: dm } = VFT.msgpackDecode(data);
  check('data round trip', dm.v === 1 && dm.t === 'd' && dm.o === 987654321
    && VFT.bytesEqual(dm.d, slice) && VFT.bytesEqual(dm.c, VFT.sha256(slice).subarray(0, 4)));
}

// ---- msgpack uint widths
{
  for (const n of [0, 127, 128, 255, 256, 65535, 65536, 4294967295, 4294967296, 2 ** 53 - 1]) {
    const enc = VFT.msgpackEncode([['x', { u: n }]]);
    const { value } = VFT.msgpackDecode(enc);
    if (value.x !== n) { check(`uint ${n}`, false, `got ${value.x}`); }
  }
  check('uint widths 0..2^53-1 round trip', true);
}

// ---- unknown keys of every shape are ignored (§3.3)
{
  // Hand-build a map: v:1, t:"d", junk keys with nested values, then real fields.
  const parts = [
    [0x8c],                          // map of 12
    [0xa1, 0x76, 0x01],              // v: 1
    [0xa1, 0x74, 0xa1, 0x64],        // t: "d"
    [0xa1, 0x61, 0xc0],              // a: nil
    [0xa1, 0x62, 0xc3],              // b: true
    [0xa1, 0x65, 0xcb, 64, 9, 33, 249, 240, 27, 134, 110], // e: float64 pi
    [0xa1, 0x67, 0x92, 0x01, 0xa1, 0x78], // g: [1, "x"]
    [0xa1, 0x6a, 0x81, 0xa1, 0x6b, 0x02], // j: {k: 2}
    [0xa1, 0x6d, 0xd6, 0x01, 1, 2, 3, 4], // m: fixext4
  ];
  const tag = randBytes(8, 5);
  const slice = new Uint8Array([9, 8, 7]);
  parts.push([0xa1, 0x66, 0xc4, 8, ...tag]);                       // f
  parts.push([0xa1, 0x6f, 0xcd, 0x30, 0x39]);                      // o: 12345
  parts.push([0xa1, 0x64, 0xc4, 3, ...slice]);                     // d
  parts.push([0xa1, 0x63, 0xc4, 4, ...VFT.sha256(slice).subarray(0, 4)]); // c
  const msg = Uint8Array.from(parts.flat());
  const c = VFT.classify(msg);
  check('unknown keys ignored, message still received', c.kind === 'data' && c.o === 12345
    && VFT.bytesEqual(c.d, slice), JSON.stringify(c));
}

// ---- classification: the channel-expected losses (§7.4.16)
{
  check('garbage is loss', VFT.classify(randBytes(50, 6)).kind === 'loss');
  check('non-map is loss', VFT.classify(new Uint8Array([0x93, 1, 2, 3])).kind === 'loss');

  const tag = randBytes(8, 7);
  const slice = randBytes(100, 8);
  const good = VFT.buildDataMessage(tag, 0, slice);
  const corrupted = good.slice();
  corrupted[corrupted.length - 1] ^= 0xff;   // flip a slice byte
  check('corrupted slice digest is loss', VFT.classify(corrupted).kind === 'loss');

  const h = randBytes(32, 9);
  const wrongTag = VFT.buildSetupMessage(randBytes(8, 10), 'x', 5, h);
  check('setup with f != h[0..8] is loss (§4.1)', VFT.classify(wrongTag).kind === 'loss');

  const goodSetup = VFT.buildSetupMessage(h.subarray(0, 8), 'x', 5, h);
  check('setup with matching tag received', VFT.classify(goodSetup).kind === 'setup');
}

// ---- unknown version is incoherence, not loss (§3.5)
{
  const msg = VFT.msgpackEncode([['v', { u: 2 }], ['t', { s: 'd' }], ['f', { b: randBytes(8, 11) }]]);
  check('v=2 classified bad-version', VFT.classify(msg).kind === 'bad-version');
}

// ---- unknown compression on a valid v=1 setup is incoherence (§1, §4.3)
{
  const h = randBytes(32, 12);
  const msg = VFT.msgpackEncode([
    ['v', { u: 1 }], ['t', { s: 's' }], ['f', { b: h.slice(0, 8) }],
    ['n', { s: 'x' }], ['l', { u: 10 }], ['h', { b: h }], ['z', { s: 'zstd' }],
  ]);
  check('unknown z classified bad-compression', VFT.classify(msg).kind === 'bad-compression');
  const eng = new VFT.RxEngine();
  const incs = [];
  eng.onIncoherence = (t, inc) => incs.push(inc.type);
  eng.ingest(msg);
  check('unknown z reported to operator', incs.includes('bad-compression'));
}

// ---- intervals
{
  let iv = [];
  iv = VFT.intervalsAdd(iv, 10, 20);
  iv = VFT.intervalsAdd(iv, 30, 40);
  iv = VFT.intervalsAdd(iv, 20, 30);   // adjacency merges
  check('intervals merge adjacent', iv.length === 1 && iv[0][0] === 10 && iv[0][1] === 40);
  const missing = VFT.intervalsMissing(iv, 50);
  check('missing complement', JSON.stringify(missing) === '[[0,10],[40,50]]');
  const co = VFT.coalesceRanges([[0, 5], [10, 15], [100, 110]], 2);
  check('coalesce merges the smallest gap first', JSON.stringify(co) === '[[0,15],[100,110]]');
  const co1 = VFT.coalesceRanges([[0, 5], [10, 15], [100, 110]], 1);
  check('coalesce to one range', JSON.stringify(co1) === '[[0,110]]');
}

// ---- gap report grammar (§8.1)
{
  const spec = 'VFT1 a3f2c1d40b8e7a12 0-7d0,1f400-1f7e8,3d0900-3e8000';
  const p = VFT.parseGapReport(spec);
  check('parses the spec example', !p.error && p.tag === 'a3f2c1d40b8e7a12'
    && JSON.stringify(p.ranges) === JSON.stringify([[0, 0x7d0], [0x1f400, 0x1f7e8], [0x3d0900, 0x3e8000]]));
  check('format echoes the spec example',
    VFT.formatGapReport('a3f2c1d40b8e7a12', [[0, 0x7d0], [0x1f400, 0x1f7e8], [0x3d0900, 0x3e8000]]) === spec);
  const empty = VFT.parseGapReport('VFT1 aaaaaaaaaaaaaaaa -');
  check('dash body parses as nothing missing', !empty.error && empty.ranges.length === 0);
  check('rejects bad tag', !!VFT.parseGapReport('VFT1 xyz -').error);
  check('rejects empty range', !!VFT.parseGapReport('VFT1 aaaaaaaaaaaaaaaa 5-5').error);
  check('rejects reversed range', !!VFT.parseGapReport('VFT1 aaaaaaaaaaaaaaaa 10-2').error);
  check('rejects uppercase hex', !!VFT.parseGapReport('VFT1 AAAAAAAAAAAAAAAA 0-5').error);
}

// ---- RX state machine end to end (no QR layer)
await (async () => {
  const file = randBytes(10000, 20);
  const h = new Uint8Array(crypto.createHash('sha256').update(file).digest());
  const tag = h.subarray(0, 8);
  const eng = new VFT.RxEngine();
  const incs = [];
  eng.onIncoherence = (t, inc) => incs.push(inc.type);

  // Data before setup is retained and bound on arrival of setup (§7.1.3).
  eng.ingest(VFT.buildDataMessage(tag, 0, file.subarray(0, 500)));
  const t0 = eng.transfers.get(VFT.toHex(tag));
  check('pre-setup data pending', t0.counters.dataPending === 1 && t0.heldBytes() === 0);
  eng.ingest(VFT.buildSetupMessage(tag, 'test.bin', file.length, h));
  check('pending bound after setup', t0.heldBytes() === 500);

  // Feed the rest in shuffled slices of varying sizes (§5.3).
  const chunks = VFT.planChunks([[0, file.length]], 700);
  for (const [s, e] of VFT.shuffle(chunks, VFT.rng(42)))
    eng.ingest(VFT.buildDataMessage(tag, s, file.subarray(s, e)));
  // Overlapping identical re-send is a duplicate, not a conflict (§7.2.7).
  eng.ingest(VFT.buildDataMessage(tag, 100, file.subarray(100, 900)));
  check('identical overlap is duplicate', t0.counters.conflicts === 0 && t0.counters.dataDuplicate >= 1);

  check('full coverage reached', t0.hasFullCoverage());
  check('not complete before digest check', !t0.complete);
  await t0.checkCompletion();
  check('complete after digest verify', t0.complete && !t0.failed);
  check('assembled bytes identical', VFT.bytesEqual(t0.buf, file));
  check('gap report says nothing missing', t0.gapReport() === `VFT1 ${VFT.toHex(tag)} -`);
  check('no incoherence on the clean path', incs.length === 0);
})();

// ---- conflict detection (§7.2.8)
{
  const file = randBytes(2000, 21);
  const h = new Uint8Array(crypto.createHash('sha256').update(file).digest());
  const tag = h.subarray(0, 8);
  const eng = new VFT.RxEngine();
  const incs = [];
  eng.onIncoherence = (t, inc) => incs.push(inc.type);
  eng.ingest(VFT.buildSetupMessage(tag, 'x', file.length, h));
  eng.ingest(VFT.buildDataMessage(tag, 0, file.subarray(0, 1000)));
  const evil = file.slice(500, 1500);
  evil[0] ^= 0x55;   // disagrees with held byte 500; carries a valid slice digest
  eng.ingest(VFT.buildDataMessage(tag, 500, evil));
  const t = eng.transfers.get(VFT.toHex(tag));
  check('conflict reported', incs.includes('conflict') && t.counters.conflicts === 1);
  check('conflict keeps first bytes', t.buf[500] === file[500]);
  check('transfer marked failed', t.failed);
}

// ---- beyond-length discard (§7.2.9)
{
  const file = randBytes(1000, 22);
  const h = new Uint8Array(crypto.createHash('sha256').update(file).digest());
  const tag = h.subarray(0, 8);
  const eng = new VFT.RxEngine();
  const incs = [];
  eng.onIncoherence = (t, inc) => incs.push(inc.type);
  eng.ingest(VFT.buildSetupMessage(tag, 'x', file.length, h));
  eng.ingest(VFT.buildDataMessage(tag, 900, randBytes(200, 23)));
  const t = eng.transfers.get(VFT.toHex(tag));
  check('beyond-length reported, state unchanged', incs.includes('beyond-length')
    && t.heldBytes() === 0 && t.failed);
}

// ---- digest mismatch on full coverage (§7.4.13c)
await (async () => {
  const file = randBytes(1000, 24);
  const wrongH = randBytes(32, 25);
  const tag = wrongH.subarray(0, 8);   // setup is self-consistent, file bytes won't match
  const eng = new VFT.RxEngine();
  const incs = [];
  eng.onIncoherence = (t, inc) => incs.push(inc.type);
  eng.ingest(VFT.buildSetupMessage(tag, 'x', file.length, wrongH));
  eng.ingest(VFT.buildDataMessage(tag, 0, file));
  const t = eng.transfers.get(VFT.toHex(tag));
  check('coverage full', t.hasFullCoverage());
  await t.checkCompletion();
  check('digest mismatch reported, not complete', !t.complete && incs.includes('digest-mismatch'));
})();

// ---- setup mismatch (same tag, different length)
{
  const h = randBytes(32, 26);
  const tag = h.subarray(0, 8);
  const eng = new VFT.RxEngine();
  const incs = [];
  eng.onIncoherence = (t, inc) => incs.push(inc.type);
  eng.ingest(VFT.buildSetupMessage(tag, 'x', 1000, h));
  eng.ingest(VFT.buildSetupMessage(tag, 'x', 1000, h));   // idempotent repeat (§4.2)
  const t = eng.transfers.get(VFT.toHex(tag));
  check('repeated setup idempotent', t.counters.setupRepeat === 1 && incs.length === 0);
  eng.ingest(VFT.buildSetupMessage(tag, 'x', 2000, h));
  check('disagreeing setup reported', incs.includes('setup-mismatch'));
}

// ---- unknown version reaches the operator (§3.5, §7.4.13d)
{
  const eng = new VFT.RxEngine();
  const incs = [];
  eng.onIncoherence = (t, inc) => incs.push(inc.type);
  eng.ingest(VFT.msgpackEncode([['v', { u: 3 }], ['t', { s: 's' }], ['f', { b: randBytes(8, 27) }]]));
  check('bad version reported', incs.includes('bad-version') && eng.counters.badVersion === 1);
}

// ---- empty file (l = 0)
await (async () => {
  const h = new Uint8Array(crypto.createHash('sha256').update(new Uint8Array(0)).digest());
  const eng = new VFT.RxEngine();
  eng.ingest(VFT.buildSetupMessage(h.subarray(0, 8), 'empty', 0, h));
  const t = eng.transfers.get(VFT.toHex(h.subarray(0, 8)));
  await t.checkCompletion();
  check('empty file completes on setup alone', t.complete);
})();

// ---- concurrent transfers stay separate (§7.1.1)
{
  const f1 = randBytes(500, 30), f2 = randBytes(500, 31);
  const h1 = new Uint8Array(crypto.createHash('sha256').update(f1).digest());
  const h2 = new Uint8Array(crypto.createHash('sha256').update(f2).digest());
  const eng = new VFT.RxEngine();
  eng.ingest(VFT.buildSetupMessage(h1.subarray(0, 8), 'a', 500, h1));
  eng.ingest(VFT.buildSetupMessage(h2.subarray(0, 8), 'b', 500, h2));
  eng.ingest(VFT.buildDataMessage(h1.subarray(0, 8), 0, f1.subarray(0, 250)));
  eng.ingest(VFT.buildDataMessage(h2.subarray(0, 8), 250, f2.subarray(250)));
  const t1 = eng.transfers.get(VFT.toHex(h1.subarray(0, 8)));
  const t2 = eng.transfers.get(VFT.toHex(h2.subarray(0, 8)));
  check('two transfers, independent state', eng.transfers.size === 2
    && t1.heldBytes() === 250 && t2.heldBytes() === 250
    && JSON.stringify(t1.held) === '[[0,250]]' && JSON.stringify(t2.held) === '[[250,500]]');
}

// ---- accept gate: detected transfers buffer until the operator confirms
{
  const file = randBytes(1200, 44);
  const h = new Uint8Array(crypto.createHash('sha256').update(file).digest());
  const tag = h.subarray(0, 8);
  const eng = new VFT.RxEngine();
  eng.acceptRequired = true;
  eng.ingest(VFT.buildSetupMessage(tag, 'gated', file.length, h));
  eng.ingest(VFT.buildDataMessage(tag, 0, file.subarray(0, 600)));
  eng.ingest(VFT.buildDataMessage(tag, 600, file.subarray(600)));
  const t = eng.transfers.get(VFT.toHex(tag));
  check('unaccepted transfer holds nothing, buffers everything',
    !t.accepted && t.setup !== null && t.heldBytes() === 0 && t.pendingBytes === 1200);
  t.accept();
  check('accept applies the buffer', t.hasFullCoverage());
  await t.checkCompletion();
  check('gated transfer completes after accept', t.complete);
}

// ---- paused transfers accept nothing until resumed
{
  const file = randBytes(1000, 33);
  const h = new Uint8Array(crypto.createHash('sha256').update(file).digest());
  const tag = h.subarray(0, 8);
  const eng = new VFT.RxEngine();
  eng.ingest(VFT.buildSetupMessage(tag, 'p', file.length, h));
  eng.ingest(VFT.buildDataMessage(tag, 0, file.subarray(0, 500)));
  const t = eng.transfers.get(VFT.toHex(tag));
  eng.paused.add(VFT.toHex(tag));
  const r = eng.ingest(VFT.buildDataMessage(tag, 500, file.subarray(500)));
  check('paused transfer drops the message', r.kind === 'paused-drop'
    && t.heldBytes() === 500 && eng.counters.pausedDropped === 1);
  eng.paused.delete(VFT.toHex(tag));
  eng.ingest(VFT.buildDataMessage(tag, 500, file.subarray(500)));
  check('resumed transfer accepts again', t.hasFullCoverage());
}

// ---- gap report superset property under coalescing (§8.2.1), randomized
{
  const r = VFT.rng(99);
  let ok = true;
  for (let trial = 0; trial < 200 && ok; trial++) {
    const l = 1 + Math.floor(r() * 100000);
    let held = [];
    const n = Math.floor(r() * 20);
    for (let i = 0; i < n; i++) {
      const s = Math.floor(r() * l);
      held = VFT.intervalsAdd(held, s, Math.min(l, s + 1 + Math.floor(r() * 5000)));
    }
    const missing = VFT.intervalsMissing(held, l);
    const maxR = 1 + Math.floor(r() * 5);
    const co = VFT.coalesceRanges(missing, maxR);
    if (co.length > maxR) { ok = false; break; }
    // every missing byte range must be inside some coalesced range
    for (const [ms, me] of missing) {
      if (!co.some(([cs, ce]) => cs <= ms && me <= ce)) { ok = false; break; }
    }
  }
  check('coalesced report is always a superset (200 random trials)', ok);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
