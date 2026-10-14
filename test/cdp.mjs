// Minimal Chrome DevTools Protocol client for the browser tests.
// No dependencies: Node's built-in WebSocket plus /json HTTP endpoints.
import { spawn } from 'node:child_process';
import fs from 'node:fs';

export const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

export const sleep = ms => new Promise(r => setTimeout(r, ms));

export async function launchChrome({ port, args = [], urls = [] }) {
  const profile = fs.mkdtempSync('/tmp/vft-profile-');
  const proc = spawn(CHROME, [
    `--user-data-dir=${profile}`,
    `--remote-debugging-port=${port}`,
    '--no-first-run', '--no-default-browser-check',
    '--disable-background-networking', '--disable-component-update',
    '--disable-sync', '--disable-default-apps',
    ...args,
    ...urls,
  ], { stdio: 'ignore' });

  // Wait for the DevTools endpoint to answer.
  for (let i = 0; i < 60; i++) {
    await sleep(250);
    try {
      const res = await fetch(`http://127.0.0.1:${port}/json/version`);
      if (res.ok) break;
    } catch { /* not up yet */ }
  }

  return {
    proc,
    profile,
    port,
    async targets() {
      const res = await fetch(`http://127.0.0.1:${port}/json/list`);
      return res.json();
    },
    async close() {
      proc.kill('SIGTERM');
      await sleep(600);
      proc.kill('SIGKILL');
      fs.rmSync(profile, { recursive: true, force: true });
    },
  };
}

// Waits for a page target whose URL contains `match`, then attaches.
export async function attach(chrome, match, timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  let target = null;
  while (Date.now() < deadline && !target) {
    try {
      target = (await chrome.targets()).find(t => t.type === 'page' && t.url.includes(match));
    } catch { /* retry */ }
    if (!target) await sleep(250);
  }
  if (!target) throw new Error(`no page target matching ${match}`);

  const ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((res, rej) => {
    ws.onopen = res;
    ws.onerror = () => rej(new Error('CDP websocket failed'));
  });

  let nextId = 0;
  const pending = new Map();
  const events = [];
  ws.onmessage = e => {
    const m = JSON.parse(e.data);
    if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
    else if (m.method) events.push(m);
  };

  const session = {
    target,
    events,
    send(method, params = {}) {
      return new Promise(res => {
        const id = ++nextId;
        pending.set(id, res);
        ws.send(JSON.stringify({ id, method, params }));
      });
    },
    // Evaluate an expression in the page and return its value.
    async eval(expression) {
      const r = await session.send('Runtime.evaluate', {
        expression, returnByValue: true, awaitPromise: true,
      });
      if (r.error) throw new Error(r.error.message);
      const res = r.result;
      if (res && res.exceptionDetails) {
        throw new Error('page exception: ' + (res.exceptionDetails.exception?.description
          || res.exceptionDetails.text));
      }
      return res && res.result ? res.result.value : undefined;
    },
    // Poll `expression` until it is truthy; returns its value or throws.
    async waitFor(expression, { timeoutMs = 60000, intervalMs = 500, label = expression } = {}) {
      const deadline = Date.now() + timeoutMs;
      while (Date.now() < deadline) {
        const v = await session.eval(expression);
        if (v) return v;
        await sleep(intervalMs);
      }
      throw new Error(`timed out waiting for: ${label}`);
    },
    close() { ws.close(); },
  };
  return session;
}

// Sets a real File on an <input type="file">, exercising the page's own
// file-loading path rather than reaching past it.
export async function setFileInput(session, selector, filePath) {
  await session.send('DOM.enable');
  const doc = await session.send('DOM.getDocument', { depth: -1 });
  const node = await session.send('DOM.querySelector', {
    nodeId: doc.result.root.nodeId, selector,
  });
  if (!node.result || !node.result.nodeId) throw new Error(`no node for ${selector}`);
  await session.send('DOM.setFileInputFiles', {
    files: [filePath], nodeId: node.result.nodeId,
  });
}
