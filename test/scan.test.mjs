// The scanner's own test. A scan that reports "clean" proves nothing until it
// has been shown to find each kind of leak where leaks hide, so this plants one
// of each and demands the matching finding, then demands silence on clean input.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { makeChecker } from './lib.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const SCAN = path.join(here, '..', 'scripts', 'scan.mjs');
const check = makeChecker();
const user = os.userInfo().username;
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vft-scan-'));

const run = (args, env = {}) => {
  const r = spawnSync('node', [SCAN, ...args], { encoding: 'utf8', env: { ...process.env, ...env } });
  return { code: r.status, out: r.stdout + r.stderr };
};
const planted = (name, content, expectRule, expectIn = name) => {
  const dir = fs.mkdtempSync(path.join(tmp, 'case-'));
  fs.writeFileSync(path.join(dir, name), content);
  const r = run(['--dir', dir]);
  const hit = r.out.split('\n').some(l => l.includes(expectRule) && l.includes(expectIn));
  check(`finds ${expectRule} in ${name}`, r.code === 1 && hit, r.out.trim().split('\n').slice(-3).join(' | '));
};

// Plain text, one per rule.
planted('a.txt', 'see /Users' + '/someone/notes', 'home-path');
planted('b.txt', 'mail ' + 'person' + '@' + 'example.org', 'email');
planted('c.txt', 'token ' + 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8', 'secret-token');
planted('d.txt', '-----BEGIN ' + 'RSA PRIVATE KEY-----', 'private-key');
planted('e.txt', 'host 192.168.' + '1.20', 'ip-address');
planted('f.txt', 'at box.tail1234.' + 'ts.net', 'private-host');
planted('g.txt', 'Claude-' + 'Session: https:/' + '/claude.ai/code/' + 'session_x', 'session-url');
planted('h.txt', 'fetch("https:/' + '/unlisted.example.org/x")', 'unlisted-url');
planted('i.txt', `owned by ${user}`, 'local-term');
planted('j.txt', 'pass' + 'word = "hunter2hunter2"', 'credential-assignment');
{
  const dir = fs.mkdtempSync(path.join(tmp, 'case-'));
  fs.mkdirSync(path.join(dir, 'src'));
  fs.writeFileSync(path.join(dir, 'src', 'k.js'), 'el.innerHTML = x;\n');
  const r = run(['--dir', dir]);
  // --dir paths are relative to that dir, so src/ rules apply.
  check('finds dangerous-sink in src/k.js', r.code === 1 && /dangerous-sink/.test(r.out), r.out);
}

// Where leaks hide: inside binaries, inlined base64, UTF-16, deflated PDF streams.
planted('bin.dat', Buffer.concat([Buffer.from([0, 1, 2, 3]), Buffer.from('/Users/' + 'someone/x\n'), Buffer.from([0])]), 'home-path', 'bin.dat#strings');
planted('wide.dat', Buffer.concat([Buffer.from([0, 0]), Buffer.from('author ' + user + ' here', 'utf16le')]), 'local-term', 'wide.dat#utf16');
planted('blob.html', '<script>var B="' + Buffer.concat([Buffer.alloc(300, 7), Buffer.from('person' + '@' + 'example.org')]).toString('base64') + '";</script>', 'email', 'blob.html#base64');
{
  const body = zlib.deflateSync(Buffer.from('/Author (person' + '@' + 'example.org)'));
  const pdf = Buffer.concat([Buffer.from('%PDF-1.4\n1 0 obj\n<< /Filter /FlateDecode >>\nstream\n'), body, Buffer.from('\nendstream\nendobj\n%%EOF\n')]);
  planted('doc.pdf', pdf, 'email', 'doc.pdf#pdf-stream');
}

// Silence on clean input, and on an allowlisted URL.
{
  const dir = fs.mkdtempSync(path.join(tmp, 'clean-'));
  fs.writeFileSync(path.join(dir, 'ok.txt'), 'Plain notes. See https://github.com/tg-techie-agents/vft for the project.\n');
  const r = run(['--dir', dir]);
  check('clean input exits 0', r.code === 0, r.out);
}

// --strict refuses to run without the local denylist (it cannot know the names).
{
  const root = fs.mkdtempSync(path.join(tmp, 'repo-'));
  const r = run(['--strict', '--tree'], { VFT_SCAN_ROOT: root });
  check('--strict without .scan-denylist.local exits 2', r.code === 2, r.out);
}

// History: a leak removed from the tree, a foreign author, a session trailer.
{
  const root = fs.mkdtempSync(path.join(tmp, 'repo-'));
  const g = (...a) => execFileSync('git', a, { cwd: root, stdio: 'pipe' });
  g('init', '-q', '-b', 'main');
  g('config', 'user.name', 'Someone Else'); g('config', 'user.email', 'someone' + '@elsewhere.test');
  fs.writeFileSync(path.join(root, 'secret.txt'), 'token ' + 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8\n');
  g('add', 'secret.txt'); g('commit', '-q', '-m', 'add\n\nClaude-' + 'Session: https:/' + '/claude.ai/code/' + 'session_x');
  g('rm', '-q', 'secret.txt'); g('commit', '-q', '-m', 'remove it');
  const r = run(['--history'], { VFT_SCAN_ROOT: root });
  const has = rule => r.out.includes(rule);
  check('history: finds deleted-then-committed secret', r.code === 1 && has('secret-token') && r.out.includes('secret.txt'), r.out);
  check('history: finds foreign identity', has('identity'), r.out);
  check('history: finds session trailer in a message', has('session-url'), r.out);
}

// The real repository, as it stands.
{
  const r = run(['--tree']);
  check('this repository scans clean (tree)', r.code === 0, r.out);
}

fs.rmSync(tmp, { recursive: true, force: true });
check.done?.();
