/*
 * VFT protocol core, shared by the TX Client, the RX Client, and the tests.
 * Implements the normative parts of "Visual File Transfer Protocol, version 1":
 * serialization (§3), Setup/Data Messages (§4, §5), receiver obligations (§7),
 * and the Gap Report grammar (§8). No I/O and no DOM in this file.
 */
'use strict';

var VFT = (function () {

  // ---------------------------------------------------------------- SHA-256
  // Pure-JS SHA-256, synchronous. Used for Slice digests and as the fallback
  // for whole-file digests where WebCrypto is unavailable.
  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);

  function sha256(bytes) {
    const len = bytes.length;
    const bitLenHi = Math.floor(len / 0x20000000);
    const bitLenLo = (len << 3) >>> 0;
    const padded = new Uint8Array((((len + 8) >> 6) + 1) << 6);
    padded.set(bytes);
    padded[len] = 0x80;
    const dv = new DataView(padded.buffer);
    dv.setUint32(padded.length - 8, bitLenHi);
    dv.setUint32(padded.length - 4, bitLenLo);

    const h = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]);
    const w = new Uint32Array(64);
    for (let off = 0; off < padded.length; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
      for (let i = 16; i < 64; i++) {
        const s0 = ((w[i-15] >>> 7) | (w[i-15] << 25)) ^ ((w[i-15] >>> 18) | (w[i-15] << 14)) ^ (w[i-15] >>> 3);
        const s1 = ((w[i-2] >>> 17) | (w[i-2] << 15)) ^ ((w[i-2] >>> 19) | (w[i-2] << 13)) ^ (w[i-2] >>> 10);
        w[i] = (w[i-16] + s0 + w[i-7] + s1) >>> 0;
      }
      let a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
      for (let i = 0; i < 64; i++) {
        const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        const ch = (e & f) ^ (~e & g);
        const t1 = (hh + S1 + ch + K[i] + w[i]) >>> 0;
        const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) >>> 0;
        hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
      h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0; h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
    }
    const out = new Uint8Array(32);
    const odv = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) odv.setUint32(i * 4, h[i]);
    return out;
  }

  // Whole-file digest: WebCrypto when present (fast on large files), else pure JS.
  async function sha256Async(bytes) {
    if (typeof crypto !== 'undefined' && crypto.subtle) {
      try {
        return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
      } catch (e) { /* fall through to pure JS */ }
    }
    return sha256(bytes);
  }

  // ------------------------------------------------------------------- hex
  function toHex(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
    return s;
  }

  function bytesEqual(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
  }

  // ------------------------------------------------------------- MessagePack
  // Encoder for exactly what the protocol emits: maps with short-string keys,
  // uint, str, bin. Decoder handles the full format well enough to skip
  // unknown keys of any type (§3.3).
  function msgpackEncode(entries) {
    // entries: array of [key, value] where value is
    // {u: number} uint, {s: string} str, {b: Uint8Array} bin
    const parts = [];
    let size = 0;
    function push(arr) { parts.push(arr); size += arr.length; }
    if (entries.length > 15) throw new Error('fixmap only');
    push([0x80 | entries.length]);
    const te = new TextEncoder();
    for (const [key, val] of entries) {
      const kb = te.encode(key);
      if (kb.length > 31) throw new Error('fixstr key only');
      push([0xa0 | kb.length]); push(kb);
      if ('u' in val) {
        const n = val.u;
        if (!Number.isSafeInteger(n) || n < 0) throw new Error('bad uint');
        if (n < 128) push([n]);
        else if (n < 0x100) push([0xcc, n]);
        else if (n < 0x10000) push([0xcd, n >> 8, n & 0xff]);
        else if (n < 0x100000000) push([0xce, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
        else {
          const hi = Math.floor(n / 0x100000000), lo = n % 0x100000000;
          push([0xcf, (hi >>> 24) & 0xff, (hi >>> 16) & 0xff, (hi >>> 8) & 0xff, hi & 0xff,
                (lo >>> 24) & 0xff, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff]);
        }
      } else if ('s' in val) {
        const sb = te.encode(val.s);
        if (sb.length < 32) push([0xa0 | sb.length]);
        else if (sb.length < 0x100) push([0xd9, sb.length]);
        else if (sb.length < 0x10000) push([0xda, sb.length >> 8, sb.length & 0xff]);
        else throw new Error('str too long');
        push(sb);
      } else if ('b' in val) {
        const bb = val.b;
        if (bb.length < 0x100) push([0xc4, bb.length]);
        else if (bb.length < 0x10000) push([0xc5, bb.length >> 8, bb.length & 0xff]);
        else push([0xc6, (bb.length >>> 24) & 0xff, (bb.length >>> 16) & 0xff, (bb.length >>> 8) & 0xff, bb.length & 0xff]);
        push(bb);
      } else throw new Error('bad value');
    }
    const out = new Uint8Array(size);
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  }

  // Decodes one MessagePack value. Returns {value, bytesUsed} or throws.
  // uints > 2^53 throw (nothing valid in this protocol needs them).
  function msgpackDecode(bytes) {
    const td = new TextDecoder('utf-8', { fatal: true });
    let pos = 0;
    function need(n) { if (pos + n > bytes.length) throw new Error('truncated'); }
    function u8() { need(1); return bytes[pos++]; }
    function uN(n) {
      need(n);
      let v = 0;
      for (let i = 0; i < n; i++) v = v * 256 + bytes[pos++];
      if (!Number.isSafeInteger(v)) throw new Error('uint too large');
      return v;
    }
    function raw(n) { need(n); const r = bytes.subarray(pos, pos + n); pos += n; return r; }
    function value() {
      const b = u8();
      if (b < 0x80) return b;                       // positive fixint
      if (b >= 0xe0) return b - 0x100;              // negative fixint
      if (b >= 0xa0 && b <= 0xbf) return td.decode(raw(b & 0x1f));  // fixstr
      if (b >= 0x80 && b <= 0x8f) return mapN(b & 0x0f);
      if (b >= 0x90 && b <= 0x9f) return arrN(b & 0x0f);
      switch (b) {
        case 0xc0: return null;
        case 0xc2: return false;
        case 0xc3: return true;
        case 0xc4: return new Uint8Array(raw(uN(1)));
        case 0xc5: return new Uint8Array(raw(uN(2)));
        case 0xc6: return new Uint8Array(raw(uN(4)));
        case 0xc7: { const n = uN(1); pos += 1; return new Uint8Array(raw(n)); } // ext8
        case 0xc8: { const n = uN(2); pos += 1; return new Uint8Array(raw(n)); }
        case 0xc9: { const n = uN(4); pos += 1; return new Uint8Array(raw(n)); }
        case 0xca: { need(4); const v = new DataView(bytes.buffer, bytes.byteOffset + pos, 4).getFloat32(0); pos += 4; return v; }
        case 0xcb: { need(8); const v = new DataView(bytes.buffer, bytes.byteOffset + pos, 8).getFloat64(0); pos += 8; return v; }
        case 0xcc: return uN(1);
        case 0xcd: return uN(2);
        case 0xce: return uN(4);
        case 0xcf: return uN(8);
        case 0xd0: { const v = uN(1); return v > 0x7f ? v - 0x100 : v; }
        case 0xd1: { const v = uN(2); return v > 0x7fff ? v - 0x10000 : v; }
        case 0xd2: { const v = uN(4); return v > 0x7fffffff ? v - 0x100000000 : v; }
        case 0xd3: { const v = uN(8); return v; } // approximate for huge negatives; irrelevant here
        case 0xd4: pos += 2; return null;  // fixext1
        case 0xd5: pos += 3; return null;
        case 0xd6: pos += 5; return null;
        case 0xd7: pos += 9; return null;
        case 0xd8: pos += 17; return null;
        case 0xd9: return td.decode(raw(uN(1)));
        case 0xda: return td.decode(raw(uN(2)));
        case 0xdb: return td.decode(raw(uN(4)));
        case 0xdc: return arrN(uN(2));
        case 0xdd: return arrN(uN(4));
        case 0xde: return mapN(uN(2));
        case 0xdf: return mapN(uN(4));
        default: throw new Error('bad byte 0x' + b.toString(16));
      }
    }
    function arrN(n) { const a = []; for (let i = 0; i < n; i++) a.push(value()); return a; }
    function mapN(n) {
      const m = {};
      for (let i = 0; i < n; i++) {
        const k = value();
        const v = value();
        if (typeof k === 'string' && !(k in m)) m[k] = v;
      }
      return m;
    }
    const v = value();
    return { value: v, bytesUsed: pos };
  }

  // -------------------------------------------------------- message building
  function buildSetupMessage(fileTag, name, length, digest) {
    return msgpackEncode([
      ['v', { u: 1 }], ['t', { s: 's' }], ['f', { b: fileTag }],
      ['n', { s: name }], ['l', { u: length }], ['h', { b: digest }], ['z', { s: 'none' }],
    ]);
  }

  function buildDataMessage(fileTag, offset, slice) {
    return msgpackEncode([
      ['v', { u: 1 }], ['t', { s: 'd' }], ['f', { b: fileTag }],
      ['o', { u: offset }], ['d', { b: slice }], ['c', { b: sha256(slice).subarray(0, 4) }],
    ]);
  }

  // ------------------------------------------------------ message classifying
  // Sorts one decoded Symbol payload into exactly one of (§7.2, §7.4):
  //   {kind:'setup', f, n, l, h}       received Setup Message
  //   {kind:'data', f, o, d}           received Data Message (7.2.4 holds)
  //   {kind:'loss', reason}            channel-expected, count and ignore (7.4.16)
  //   {kind:'bad-version', v}          incoherent (3.5, 7.4.13d)
  function classify(bytes) {
    let m;
    try {
      const r = msgpackDecode(bytes);
      m = r.value;
    } catch (e) {
      return { kind: 'loss', reason: 'undecodable' };
    }
    if (m === null || typeof m !== 'object' || Array.isArray(m)) return { kind: 'loss', reason: 'not-a-map' };
    const isBin = (x, n) => x instanceof Uint8Array && (n === undefined || x.length === n);
    const isUint = (x) => typeof x === 'number' && Number.isSafeInteger(x) && x >= 0;
    if (!isUint(m.v)) return { kind: 'loss', reason: 'missing-v' };
    if (m.v !== 1) return { kind: 'bad-version', v: m.v };
    if (typeof m.t !== 'string' || !isBin(m.f, 8)) return { kind: 'loss', reason: 'missing-fields' };
    if (m.t === 's') {
      if (typeof m.n !== 'string' || !isUint(m.l) || !isBin(m.h, 32) || typeof m.z !== 'string')
        return { kind: 'loss', reason: 'missing-fields' };
      // §4.1: f must be the first 8 bytes of h; discard silently otherwise (7.4.16).
      if (!bytesEqual(m.f, m.h.subarray(0, 8))) return { kind: 'loss', reason: 'setup-tag-mismatch' };
      // §4.3: version 1 defines no other value. A message that decodes, passes
      // 4.1, and still carries an unknown z is wrong upstream of the channel —
      // incoherence under the §1 principle, like an unknown version.
      if (m.z !== 'none') return { kind: 'bad-compression', z: m.z };
      return { kind: 'setup', f: m.f, n: m.n, l: m.l, h: m.h };
    }
    if (m.t === 'd') {
      if (!isUint(m.o) || !isBin(m.d) || !isBin(m.c, 4)) return { kind: 'loss', reason: 'missing-fields' };
      if (!bytesEqual(sha256(m.d).subarray(0, 4), m.c)) return { kind: 'loss', reason: 'slice-digest' };
      return { kind: 'data', f: m.f, o: m.o, d: m.d };
    }
    return { kind: 'loss', reason: 'unknown-type' };
  }

  // ---------------------------------------------------------------- intervals
  // Sorted, disjoint, non-adjacent list of [start, end) pairs.
  function intervalsAdd(list, start, end) {
    if (start >= end) return list;
    const out = [];
    let i = 0;
    while (i < list.length && list[i][1] < start) out.push(list[i++]);
    while (i < list.length && list[i][0] <= end) {
      start = Math.min(start, list[i][0]);
      end = Math.max(end, list[i][1]);
      i++;
    }
    out.push([start, end]);
    while (i < list.length) out.push(list[i++]);
    return out;
  }

  function intervalsTotal(list) {
    let t = 0;
    for (const [s, e] of list) t += e - s;
    return t;
  }

  // Complement of `list` within [0, l).
  function intervalsMissing(list, l) {
    const out = [];
    let cursor = 0;
    for (const [s, e] of list) {
      if (s > cursor) out.push([cursor, Math.min(s, l)]);
      cursor = Math.max(cursor, e);
      if (cursor >= l) break;
    }
    if (cursor < l) out.push([cursor, l]);
    return out;
  }

  // Merge missing ranges across held bytes until at most maxRanges remain.
  // Merging only ever widens coverage, so 8.2.1 (superset) always holds.
  function coalesceRanges(ranges, maxRanges) {
    if (maxRanges < 1) maxRanges = 1;
    const r = ranges.map(x => x.slice());
    while (r.length > maxRanges) {
      let best = 1, bestGap = Infinity;
      for (let i = 1; i < r.length; i++) {
        const gap = r[i][0] - r[i - 1][1];
        if (gap < bestGap) { bestGap = gap; best = i; }
      }
      r[best - 1][1] = r[best][1];
      r.splice(best, 1);
    }
    return r;
  }

  // ---------------------------------------------------------------- Gap Report
  function formatGapReport(tagHex, missingRanges) {
    const body = missingRanges.length === 0
      ? '-'
      : missingRanges.map(([s, e]) => s.toString(16) + '-' + e.toString(16)).join(',');
    return 'VFT1 ' + tagHex + ' ' + body;
  }

  // Returns {tag, ranges} (ranges [] when body is "-") or {error}.
  function parseGapReport(text) {
    const m = /^\s*VFT1\s+([0-9a-f]{16})\s+(\S+)\s*$/.exec(text);
    if (!m) return { error: 'not a VFT1 gap report' };
    const tag = m[1];
    if (m[2] === '-') return { tag, ranges: [] };
    const ranges = [];
    for (const part of m[2].split(',')) {
      const rm = /^([0-9a-f]+)-([0-9a-f]+)$/.exec(part);
      if (!rm) return { error: 'bad range: ' + part };
      const s = parseInt(rm[1], 16), e = parseInt(rm[2], 16);
      if (!Number.isSafeInteger(s) || !Number.isSafeInteger(e) || s >= e)
        return { error: 'bad range: ' + part };
      ranges.push([s, e]);
    }
    // Normalize: sorted and disjoint.
    let norm = [];
    for (const [s, e] of ranges.sort((a, b) => a[0] - b[0])) norm = intervalsAdd(norm, s, e);
    return { tag, ranges: norm };
  }

  // ---------------------------------------------------------------- RxTransfer
  // One transfer, keyed by File Tag. Implements §7.
  const PENDING_CAP_BYTES = 64 * 1024 * 1024;

  class RxTransfer {
    constructor(tagBytes, accepted = true) {
      this.tag = new Uint8Array(tagBytes);
      this.tagHex = toHex(tagBytes);
      this.accepted = accepted; // operator gate: no bytes accumulate until true
      this.setup = null;        // {n, l, h}
      this.buf = null;          // Uint8Array(l) once setup is known
      this.held = [];           // sorted disjoint [start, end)
      this.pending = [];        // Data Messages before Setup (§7.1.3)
      this.pendingBytes = 0;
      this.incoherences = [];   // {type, detail} — any entry disables success (§7.4.14)
      this.conflictPolicy = 'keep-first';
      this.counters = {
        dataStored: 0, dataDuplicate: 0, dataPending: 0,
        setupApplied: 0, setupRepeat: 0, beyondLength: 0, conflicts: 0,
        pendingDropped: 0,
      };
      this.complete = false;    // full coverage AND digest verified (§7.3.10)
      this.digestChecked = false;
      this.onIncoherence = null;  // callback({type, detail})
    }

    _report(type, detail) {
      this.incoherences.push({ type, detail });
      if (this.onIncoherence) this.onIncoherence({ type, detail });
    }

    get failed() { return this.incoherences.length > 0; }

    applySetup(msg) {
      if (this.setup) {
        // §4.2: idempotent when it matches. Same tag but different l or h means
        // an upstream implementation problem, not channel loss (§1).
        if (this.setup.l !== msg.l || !bytesEqual(this.setup.h, msg.h)) {
          this._report('setup-mismatch',
            `Setup Message for ${this.tagHex} disagrees with the one already applied (l=${msg.l} vs ${this.setup.l})`);
        } else {
          this.counters.setupRepeat++;
        }
        return;
      }
      this.setup = { n: msg.n, l: msg.l, h: msg.h.slice() };
      this.buf = new Uint8Array(msg.l);
      this.counters.setupApplied++;
      if (this.accepted) this._flushPending();
    }

    // The operator confirms this transfer; buffered Slices apply immediately.
    accept() {
      if (this.accepted) return;
      this.accepted = true;
      if (this.setup) this._flushPending();
    }

    _flushPending() {
      const pend = this.pending;
      this.pending = [];
      this.pendingBytes = 0;
      for (const p of pend) this.applyData(p);
    }

    // Returns 'stored' | 'duplicate' | 'conflict' | 'beyond-length' | 'pending'
    applyData(msg) {
      // Buffer while identity is unknown (§7.1.3) or the operator has not yet
      // confirmed the transfer — the accept gate must not lose the Rotation
      // that is on screen while they decide.
      if (!this.setup || !this.accepted) {
        if (this.pendingBytes + msg.d.length > PENDING_CAP_BYTES) {
          this.counters.pendingDropped++;
          return 'pending';
        }
        this.pending.push({ o: msg.o, d: msg.d.slice() });
        this.pendingBytes += msg.d.length;
        this.counters.dataPending++;
        return 'pending';
      }
      const { o, d } = msg;
      const l = this.setup.l;
      // §7.2.9: passed its own integrity check but lies outside the file.
      if (o + d.length > l) {
        this.counters.beyondLength++;
        this._report('beyond-length',
          `Data Message [${o}, ${o + d.length}) exceeds file length ${l}`);
        return 'beyond-length';
      }
      // §7.2.7: compare every overlapping byte already held.
      let conflictAt = -1;
      for (const [hs, he] of this.held) {
        const s = Math.max(hs, o), e = Math.min(he, o + d.length);
        for (let i = s; i < e; i++) {
          if (this.buf[i] !== d[i - o]) { conflictAt = i; break; }
        }
        if (conflictAt >= 0) break;
      }
      if (conflictAt >= 0) {
        this.counters.conflicts++;
        this._report('conflict',
          `Conflict at byte ${conflictAt}: Data Message [${o}, ${o + d.length}) disagrees with held bytes`);
        // Policy after reporting (§7.2.8 leaves it open): keep what we had.
        return 'conflict';
      }
      const before = intervalsTotal(this.held);
      this.buf.set(d, o);
      this.held = intervalsAdd(this.held, o, o + d.length);
      if (intervalsTotal(this.held) === before) {
        this.counters.dataDuplicate++;
        return 'duplicate';
      }
      this.counters.dataStored++;
      return 'stored';
    }

    missingRanges() {
      if (!this.setup) return null;
      return intervalsMissing(this.held, this.setup.l);
    }

    heldBytes() { return intervalsTotal(this.held); }

    hasFullCoverage() {
      if (!this.setup) return false;
      const l = this.setup.l;
      if (l === 0) return true;
      return this.held.length === 1 && this.held[0][0] === 0 && this.held[0][1] === l;
    }

    // §7.3: full coverage alone is not completion; the digest must match.
    // Call whenever coverage may have become full. Async for WebCrypto.
    // Concurrent callers share one verification; all observe its result.
    checkCompletion() {
      if (!this.hasFullCoverage()) return Promise.resolve(this.complete);
      if (!this._completionPromise) {
        this.digestChecked = true;
        this._completionPromise = (async () => {
          const digest = await sha256Async(this.buf);
          if (bytesEqual(digest, this.setup.h)) {
            this.complete = true;
          } else {
            this._report('digest-mismatch',
              'Full coverage but the assembled digest does not equal the Setup Message digest');
          }
          return this.complete;
        })();
      }
      return this._completionPromise;
    }

    gapReport(maxRanges) {
      const missing = this.missingRanges();
      if (missing === null) return null;
      const ranges = maxRanges ? coalesceRanges(missing, maxRanges) : missing;
      return formatGapReport(this.tagHex, ranges);
    }
  }

  // ------------------------------------------------------------------ RxEngine
  // Routes classified messages to transfers by File Tag (§7.1).
  class RxEngine {
    constructor() {
      this.transfers = new Map();   // tagHex -> RxTransfer
      this.paused = new Set();      // tagHex of transfers not accepting messages
      this.acceptRequired = false;  // new transfers wait for operator confirmation
      this.counters = { symbols: 0, loss: 0, badVersion: 0, pausedDropped: 0 };
      this.lossReasons = {};
      this.onIncoherence = null;
      this.onChange = null;
    }

    transferFor(tagBytes) {
      const hex = toHex(tagBytes);
      let t = this.transfers.get(hex);
      if (!t) {
        t = new RxTransfer(tagBytes, !this.acceptRequired);
        t.onIncoherence = (inc) => { if (this.onIncoherence) this.onIncoherence(t, inc); };
        this.transfers.set(hex, t);
      }
      return t;
    }

    // Feed one decoded Symbol payload. Returns the classification.
    ingest(bytes) {
      this.counters.symbols++;
      const c = classify(bytes);
      if (c.kind === 'loss') {
        this.counters.loss++;
        this.lossReasons[c.reason] = (this.lossReasons[c.reason] || 0) + 1;
        return c;
      }
      if (c.kind === 'bad-version') {
        // §3.5: decodable, unknown v — must reach the operator.
        this.counters.badVersion++;
        if (this.onIncoherence) this.onIncoherence(null, {
          type: 'bad-version', detail: `Message with unrecognized protocol version ${c.v}`,
        });
        return c;
      }
      if (c.kind === 'bad-compression') {
        this.counters.badVersion++;
        if (this.onIncoherence) this.onIncoherence(null, {
          type: 'bad-compression', detail: `Setup Message with unrecognized compression ${JSON.stringify(c.z)}`,
        });
        return c;
      }
      // A paused transfer accepts nothing; its messages are ordinary traffic,
      // counted and otherwise ignored, so state cannot change under the
      // operator while they decide what to do with it.
      if (this.paused.has(toHex(c.f))) {
        this.counters.pausedDropped++;
        return { kind: 'paused-drop', f: c.f };
      }
      const t = this.transferFor(c.f);
      if (c.kind === 'setup') t.applySetup(c);
      else t.applyData(c);
      if (this.onChange) this.onChange(t);
      return c;
    }
  }

  // ---------------------------------------------------------------- TX chunking
  // Cut a transmission set (list of [start,end) ranges) into slice descriptors.
  function planChunks(ranges, sliceSize) {
    const chunks = [];
    for (const [s, e] of ranges) {
      for (let o = s; o < e; o += sliceSize) chunks.push([o, Math.min(o + sliceSize, e)]);
    }
    return chunks;
  }

  // Deterministic PRNG (mulberry32) for shuffling rotations reproducibly in tests.
  function rng(seed) {
    let a = seed >>> 0;
    return function () {
      a |= 0; a = (a + 0x6d2b79f5) | 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  function shuffle(arr, random) {
    const a = arr.slice();
    for (let i = a.length - 1; i > 0; i--) {
      const j = Math.floor(random() * (i + 1));
      [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
  }

  return {
    sha256, sha256Async, toHex, bytesEqual,
    msgpackEncode, msgpackDecode,
    buildSetupMessage, buildDataMessage, classify,
    intervalsAdd, intervalsTotal, intervalsMissing, coalesceRanges,
    formatGapReport, parseGapReport,
    RxTransfer, RxEngine,
    planChunks, rng, shuffle,
    PENDING_CAP_BYTES,
  };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = VFT;
