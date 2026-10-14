// The gate before anything is pushed. Any failing step stops the push.
//   1. strict scan of the working tree and the whole history (public data, secrets)
//   2. rebuild, and fail if the committed dist/ and docs/ are not what the sources build
//   3. the static invariants (CSP, no external references) and the scanner's own test
//   4. npm audit
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const run = (label, cmd, args, opts = {}) => {
  console.log(`\n== ${label}`);
  const r = spawnSync(cmd, args, { cwd: root, stdio: opts.capture ? ['ignore', 'pipe', 'inherit'] : 'inherit', encoding: 'utf8' });
  if (r.status !== 0) { console.error(`prepush: "${label}" failed (exit ${r.status}); not pushing.`); process.exit(1); }
  return r.stdout;
};

run('scan (strict): tree and history', 'node', ['scripts/scan.mjs', '--strict', '--tree', '--history']);
run('build', 'node', ['build.mjs']);
const drift = run('built output matches what is committed', 'git', ['status', '--porcelain', '--', 'dist', 'docs'], { capture: true });
if (drift.trim()) { console.error(`prepush: dist/ or docs/ differ from a fresh build:\n${drift}Commit them first.`); process.exit(1); }
run('static invariants', 'node', ['test/static.test.mjs']);
run('scanner self-test', 'node', ['test/scan.test.mjs']);
run('npm audit', 'npm', ['audit', '--audit-level=low']);
console.log('\nprepush: all gates passed');
