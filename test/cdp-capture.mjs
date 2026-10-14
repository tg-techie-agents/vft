// Runs test/capture.html in HEADED Chrome (tab capture never resolves in
// headless) with --auto-accept-this-tab-capture, and reads the verdict over
// the DevTools protocol. Uses a throwaway profile; touches nothing global.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const PORT = 9377;
const profile = fs.mkdtempSync('/tmp/vft-cap-profile-');
const url = 'file://' + path.join(here, 'capture.html');

const chrome = spawn(CHROME, [
  `--user-data-dir=${profile}`,
  `--remote-debugging-port=${PORT}`,
  '--no-first-run', '--no-default-browser-check',
  '--auto-accept-this-tab-capture',
  '--window-size=900,900', '--window-position=50,50',
  url,
], { stdio: 'ignore' });

const sleep = ms => new Promise(r => setTimeout(r, ms));

async function targets() {
  const res = await fetch(`http://127.0.0.1:${PORT}/json/list`);
  return res.json();
}

let verdict = 'NO-VERDICT';
try {
  // Wait for the page target.
  let page = null;
  for (let i = 0; i < 50 && !page; i++) {
    await sleep(300);
    try { page = (await targets()).find(t => t.type === 'page' && t.url.includes('capture.html')); }
    catch { /* CDP not up yet */ }
  }
  if (!page) throw new Error('page target never appeared');

  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
  let msgId = 0;
  const pending = new Map();
  ws.onmessage = e => {
    const m = JSON.parse(e.data);
    if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
  };
  const call = (method, params) => new Promise(res => {
    const id = ++msgId;
    pending.set(id, res);
    ws.send(JSON.stringify({ id, method, params }));
  });

  // Poll the page's title until the harness posts its verdict.
  const deadline = Date.now() + 60000;
  while (Date.now() < deadline) {
    const r = await call('Runtime.evaluate', { expression: 'document.title', returnByValue: true });
    const title = r.result && r.result.result && r.result.result.value;
    if (title && title.startsWith('VFT-CAPTURE-')) { verdict = title; break; }
    await sleep(500);
  }
  const out = await call('Runtime.evaluate', {
    expression: 'document.getElementById("out").textContent', returnByValue: true,
  });
  console.log(out.result && out.result.result && out.result.result.value || '(no detail)');
  ws.close();
} finally {
  chrome.kill('SIGTERM');
  await sleep(500);
  chrome.kill('SIGKILL');
  fs.rmSync(profile, { recursive: true, force: true });
}
console.log('verdict:', verdict);
process.exit(verdict === 'VFT-CAPTURE-PASS' ? 0 : 1);
