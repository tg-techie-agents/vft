// Runs test/webrtc.html in headed Chrome. WebRTC needs real wall-clock time, so
// headless --virtual-time-budget cannot drive it. The verdict is read from the
// target's title over the HTTP endpoint, which survives page busyness better
// than a long-lived CDP evaluate.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { launchChrome, attach, sleep } from './cdp.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const url = 'file://' + path.join(here, 'webrtc.html');

const chrome = await launchChrome({
  port: 9433,
  args: ['--window-size=900,900', '--window-position=60,60',
         '--use-fake-ui-for-media-stream', '--use-fake-device-for-media-stream'],
  urls: [url],
});

let verdict = 'NO-VERDICT', detail = '';
try {
  const deadline = Date.now() + 8 * 60 * 1000;
  while (Date.now() < deadline) {
    await sleep(2000);
    let t = null;
    try {
      t = (await chrome.targets()).find(x => x.type === 'page' && x.url.includes('webrtc.html'));
    } catch { continue; }
    if (!t) continue;
    if (t.title && t.title.startsWith('VFT-WEBRTC-')) { verdict = t.title; break; }
  }
  // Pull the detail text once, briefly, now that the run has settled.
  try {
    const s = await attach(chrome, 'webrtc.html', 10000);
    detail = await Promise.race([
      s.eval("document.getElementById('out').textContent"),
      sleep(10000).then(() => '(detail unavailable)'),
    ]);
    s.close();
  } catch (e) { detail = '(detail unavailable: ' + e.message + ')'; }
} finally {
  await chrome.close();
}

console.log(detail || '(no detail)');
console.log('verdict:', verdict);
process.exit(verdict === 'VFT-WEBRTC-PASS' ? 0 : 1);
