// Public-data and security scan. Nothing is published unless this exits 0.
//
//   node scripts/scan.mjs [--tree] [--staged] [--history] [--message FILE]
//                         [--dir PATH] [--strict]
//
// Sources scanned (default: --tree, plus --history once commits exist):
//   --tree      every file git would track here (tracked + untracked, not ignored)
//   --staged    the staged blobs, as they will be committed
//   --history   every commit reachable from HEAD: author/committer, message,
//               and every distinct blob ever committed
//   --message   one commit-message file (the commit-msg hook)
//   --dir       any directory, tracked or not (a fresh clone, the built site)
//
// What it looks inside, because a leak hides where a grep does not look:
//   binary files        printable ASCII and UTF-16 strings
//   PDFs                the same, after inflating every FlateDecode stream
//   long base64 blobs   decoded, then scanned as binary (the inlined WASM)
//
// Rules are generic and committed. This machine's own names (account, host,
// people, agents) come from two places that are never committed: values read
// from the running system (user, host, home directory), and the lines of
// .scan-denylist.local. --strict (the push hook) fails if that file is
// missing, because a scan that cannot know the local names passes by luck.
//
// Exit: 0 clean, 1 findings, 2 the scan could not run.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
// VFT_SCAN_ROOT lets the scanner's own test point it at a throwaway repository.
const root = process.env.VFT_SCAN_ROOT || path.join(here, '..');
const ALLOW = JSON.parse(fs.readFileSync(path.join(here, 'scan-allow.json'), 'utf8'));
const allowRes = key => ALLOW[key].map(s => new RegExp(s, 'i'));
const ALLOW_URL = allowRes('urls');
const ALLOW_EMAIL = allowRes('emails');
const ALLOW_PATH = allowRes('paths');
const ALLOW_BARE = ALLOW.bare.map(s => new RegExp(s, 'gi'));
const ALLOW_IDENTITY = new Set(ALLOW.identities);
const EXEMPT = ALLOW.exempt;

// ---- rules ---------------------------------------------------------------
const RULES = [
  ['home-path', /(?:\/Users\/|\/home\/|[A-Za-z]:\\Users\\|\/private\/(?:tmp|var)\/|\/var\/folders\/)[^\s/\\"'`]+/g],
  ['tilde-path', /~\/(?:Documents|Downloads|Library|Desktop|\.claude|\.config|\.ssh|Agent\w*)\b[\w./-]*/g],
  ['private-host', /(?<![\w.-])[\w-]+(?:\.[\w-]+)*\.(?:local|lan|ts\.net|internal|home\.arpa|corp|intranet)\b(?!\.\w)/gi, m => !/^\.?scan-denylist\./.test(m)],
  // Private/CGNAT/link-local ranges are flagged everywhere; any other address only in text,
  // since version strings inside binaries look exactly like addresses.
  ['ip-address', /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
    (m, label) => !/^(?:127\.0\.0\.1|0\.0\.0\.0|255\.255\.255\.\d+)$/.test(m) &&
      (!label.includes('#') || /^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|169\.254\.)/.test(m))],
  ['session-url', /claude\.ai\/code\/session\S*|Claude-Session\b/g],
  ['secret-token', /\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_\w{20,}|sk-ant-[\w-]{20,}|sk-[A-Za-z0-9]{32,}|xox[abprs]-[\w-]{10,}|AIza[\w-]{35}|ya29\.[\w-]{20,})\b/g],
  ['private-key', /-----BEGIN [A-Z ]*PRIVATE KEY-----/g],
  ['jwt', /\beyJ[\w-]{10,}\.eyJ[\w-]{10,}\.[\w-]{5,}/g],
  ['credential-assignment', /\b(?:api[_-]?key|secret|token|passw(?:or)?d|auth)\b["']?\s*[:=]\s*["'][^"'\s]{8,}["']/gi],
  ['dangerous-sink', /\b(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval)\b\s*(?:[=(+]|$)|\bnew Function\b/g, null, ['src/']],
];
const EMAIL = /[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}\b/g;
const URL_RE = /\bhttps?:\/\/[^\s"'`)<>\\]+/g;

// ---- local terms ---------------------------------------------------------
function localTerms() {
  const terms = new Set();
  for (const t of [os.userInfo().username, os.hostname().split('.')[0], path.basename(os.homedir())]) {
    if (t && t.length >= 4) terms.add(t.toLowerCase());
  }
  const file = path.join(root, '.scan-denylist.local');
  let fromFile = 0;
  if (fs.existsSync(file)) {
    for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
      const t = line.replace(/#.*/, '').trim().toLowerCase();
      if (t) { terms.add(t); fromFile++; }
    }
  }
  return { terms: [...terms], fromFile };
}

// ---- string extraction ---------------------------------------------------
const isBinary = buf => buf.subarray(0, 8192).includes(0);

function printableRuns(buf, min) {
  const out = [];
  let start = -1;
  for (let i = 0; i <= buf.length; i++) {
    const c = i < buf.length ? buf[i] : 0;
    const ok = c === 9 || (c >= 32 && c < 127);
    if (ok) { if (start < 0) start = i; }
    else {
      if (start >= 0 && i - start >= min) out.push(buf.toString('latin1', start, i));
      start = -1;
    }
  }
  return out;
}

function utf16Runs(buf, min) {
  const out = [];
  for (const enc of [0, 1]) {
    const b = buf.subarray(enc);
    const s = b.toString('utf16le');
    for (const m of s.matchAll(new RegExp(`[\\x20-\\x7e]{${min},}`, 'g'))) out.push(m[0]);
  }
  return out;
}

// Yield [label, text] views of one file's content.
function* views(rel, buf, at = '') {
  const label = (suffix = '') => rel + at + suffix;
  const binary = isBinary(buf);
  if (!binary) {
    const text = buf.toString('utf8');
    yield [label(), text];
    for (const m of text.matchAll(/[A-Za-z0-9+/]{400,}={0,2}/g)) {
      const dec = Buffer.from(m[0], 'base64');
      const line = text.slice(0, m.index).split('\n').length;
      yield* binaryViews(label(`#base64@line${line}`), dec);
    }
    return;
  }
  yield* binaryViews(label(), buf);
}

function* binaryViews(rel, buf) {
  yield [rel + '#strings', printableRuns(buf, 6).join('\n')];
  yield [rel + '#utf16', utf16Runs(buf, 8).join('\n')];
  if (buf.subarray(0, 5).toString('latin1') === '%PDF-') {
    const s = buf.toString('latin1');
    let n = 0;
    for (const m of s.matchAll(/stream\r?\n/g)) {
      const from = m.index + m[0].length;
      const to = s.indexOf('endstream', from);
      if (to < 0) continue;
      let inflated;
      try { inflated = zlib.inflateSync(buf.subarray(from, to)); } catch { try { inflated = zlib.inflateSync(buf.subarray(from, to - 1)); } catch { continue; } }
      n++;
      yield [`${rel}#pdf-stream${n}`, printableRuns(inflated, 6).join('\n')];
      yield [`${rel}#pdf-stream${n}-utf16`, utf16Runs(inflated, 8).join('\n')];
    }
  }
}

// ---- scanning ------------------------------------------------------------
const redact = s => (s.length <= 12 ? s : s.slice(0, 6) + '…' + s.slice(-3));
const findings = [];
const add = (where, line, rule, hit) => findings.push({ where, line, rule, hit: redact(hit) });

function scanText(label, text, relForPathRules, local) {
  if (ALLOW_PATH.some(re => re.test(relForPathRules))) return;
  const lines = text.split('\n');
  lines.forEach((raw, i) => {
    const n = i + 1;
    if (raw.length > 4000) raw = raw.slice(0, 4000); // minified lines: a leak is still in the head
    // URLs: every one must be on the allowlist; then blank the allowed ones so
    // they cannot mask or trigger the other rules.
    let line = raw;
    for (const m of raw.matchAll(URL_RE)) {
      if ((EXEMPT[relForPathRules] || []).includes('unlisted-url')) break;
      const u = m[0].replace(/[.,;]+$/, '');
      if (ALLOW_URL.some(re => re.test(u))) line = line.replace(m[0], ' ');
      else add(label, n, 'unlisted-url', u);
    }
    // The project's own public address, written without a scheme in prose.
    for (const re of ALLOW_BARE) line = line.replace(re, ' ');
    for (const m of line.matchAll(EMAIL)) {
      if (!ALLOW_EMAIL.some(re => re.test(m[0]))) add(label, n, 'email', m[0]);
    }
    for (const [rule, re, accept, onlyIn] of RULES) {
      if (onlyIn && !onlyIn.some(p => relForPathRules.startsWith(p))) continue;
      if (rule === 'dangerous-sink' && (/scan-ok/.test(raw) || /scan-ok/.test(lines[i - 1] || ''))) continue;
      if ((EXEMPT[relForPathRules] || []).includes(rule)) continue;
      for (const m of line.matchAll(re)) {
        if (accept && !accept(m[0], label)) continue;
        add(label, n, rule, m[0]);
      }
    }
    const low = line.toLowerCase();
    for (const t of local.terms) {
      if (low.includes(t) && !(EXEMPT[relForPathRules] || []).includes('local-term')) add(label, n, 'local-term', t);
    }
  });
}

function scanFile(rel, buf, local, at = '') {
  for (const [label, text] of views(rel, buf, at)) {
    if (text) scanText(label, text, rel, local);
  }
}

// ---- sources -------------------------------------------------------------
const git = (...args) => execFileSync('git', args, { cwd: root, encoding: 'buffer', maxBuffer: 1 << 30 });
const gitText = (...args) => git(...args).toString('utf8');

function scanTree(local) {
  const files = gitText('ls-files', '-co', '--exclude-standard', '-z').split('\0').filter(Boolean);
  for (const rel of files) {
    const abs = path.join(root, rel);
    if (fs.existsSync(abs) && fs.statSync(abs).isFile()) scanFile(rel, fs.readFileSync(abs), local);
  }
  return files.length;
}

function scanStaged(local) {
  const files = gitText('diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z').split('\0').filter(Boolean);
  for (const rel of files) scanFile(rel, git('show', ':' + rel), local);
  return files.length;
}

function checkIdentity(who, label) {
  if (!ALLOW_IDENTITY.has(who)) add(label, 0, 'identity', who);
}

function scanHistory(local) {
  const commits = gitText('rev-list', 'HEAD').split('\n').filter(Boolean);
  const seen = new Set();
  for (const c of commits) {
    const meta = gitText('show', '-s', '--format=%an <%ae>%n%cn <%ce>%n%B', c);
    const [author, committer, ...msg] = meta.split('\n');
    checkIdentity(author, `commit ${c.slice(0, 8)} author`);
    checkIdentity(committer, `commit ${c.slice(0, 8)} committer`);
    scanText(`commit ${c.slice(0, 8)} message`, msg.join('\n'), '', local);
    for (const line of gitText('ls-tree', '-r', '-z', c).split('\0').filter(Boolean)) {
      const [info, rel] = [line.slice(0, line.indexOf('\t')), line.slice(line.indexOf('\t') + 1)];
      const oid = info.split(' ')[2];
      if (seen.has(oid)) continue;
      seen.add(oid);
      scanFile(rel, git('cat-file', 'blob', oid), local, ` @${c.slice(0, 8)}`);
    }
  }
  return commits.length;
}

function scanDir(dir, local) {
  let n = 0;
  const walk = d => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      if (e.name === '.git') continue;
      const abs = path.join(d, e.name);
      if (e.isDirectory()) walk(abs);
      else if (e.isFile()) { scanFile(path.relative(dir, abs), fs.readFileSync(abs), local); n++; }
    }
  };
  walk(dir);
  return n;
}

// ---- main ----------------------------------------------------------------
const args = process.argv.slice(2);
const flag = f => args.includes(f);
const val = f => (args.includes(f) ? args[args.indexOf(f) + 1] : null);

try {
  const local = localTerms();
  if (flag('--strict') && local.fromFile === 0) {
    console.error('scan: --strict needs .scan-denylist.local (this machine\'s names, one per line); none found.');
    console.error('scan: without it the scan cannot know which names are private. Not scanning.');
    process.exit(2);
  }
  const summary = [];
  const hasCommits = (() => { try { execFileSync('git', ['rev-parse', '--verify', 'HEAD'], { cwd: root, stdio: 'ignore' }); return true; } catch { return false; } })();
  const explicit = ['--tree', '--staged', '--history', '--message', '--dir'].some(flag);
  if (flag('--tree') || !explicit) summary.push(`tree: ${scanTree(local)} files`);
  if (flag('--staged')) summary.push(`staged: ${scanStaged(local)} files`);
  if (flag('--history') || (!explicit && hasCommits)) {
    if (!hasCommits) throw new Error('--history: no commits');
    summary.push(`history: ${scanHistory(local)} commits`);
  }
  if (flag('--message')) {
    scanText('commit message', fs.readFileSync(val('--message'), 'utf8').replace(/^#.*$/gm, ''), '', local);
    summary.push('message');
  }
  if (flag('--dir')) summary.push(`dir ${val('--dir')}: ${scanDir(path.resolve(val('--dir')), local)} files`);

  const uniq = [...new Map(findings.map(f => [`${f.where}|${f.line}|${f.rule}|${f.hit}`, f])).values()];
  console.log(`scan: ${summary.join('; ')}; ${local.terms.length} local terms (${local.fromFile} from file)`);
  if (uniq.length) {
    for (const f of uniq.slice(0, 200)) console.log(`  ${f.rule.padEnd(20)} ${f.where}${f.line ? ':' + f.line : ''}  ${f.hit}`);
    if (uniq.length > 200) console.log(`  … ${uniq.length - 200} more`);
    console.log(`scan: FAILED, ${uniq.length} finding(s)`);
    process.exit(1);
  }
  console.log('scan: clean');
} catch (e) {
  console.error('scan: could not run:', e.message);
  process.exit(2);
}
