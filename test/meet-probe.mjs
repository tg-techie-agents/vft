// Exploratory: launch the Agents Chrome profile, open a new Google Meet, and
// report what the pre-join UI actually looks like so the real test can drive it.
import { spawn } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { attach, sleep, CHROME } from './cdp.mjs';

const PORT = 9500;
const USER_DATA = path.join(os.homedir(), 'Library/Application Support/Google/Chrome');

const proc = spawn(CHROME, [
  `--user-data-dir=${USER_DATA}`,
  '--profile-directory=Profile 1',
  `--remote-debugging-port=${PORT}`,
  '--no-first-run', '--no-default-browser-check',
  '--use-fake-ui-for-media-stream',
  '--use-fake-device-for-media-stream',
  '--auto-select-desktop-capture-source=VFT TX Client',
  '--window-size=1280,900', '--window-position=40,40',
  'https://meet.google.com/new',
], { stdio: 'ignore', detached: true });

const chrome = {
  port: PORT,
  async targets() {
    const res = await fetch(`http://127.0.0.1:${PORT}/json/list`);
    return res.json();
  },
};

try {
  await sleep(6000);
  const s = await attach(chrome, 'meet.google.com', 60000);
  await s.send('Runtime.enable');
  await sleep(9000);

  const state = await s.eval(`(() => {
    const buttons = [...document.querySelectorAll('button,[role=button]')]
      .map(b => ({
        text: (b.innerText || '').trim().slice(0, 40),
        aria: b.getAttribute('aria-label'),
        vis: !!(b.offsetWidth || b.offsetHeight),
      }))
      .filter(b => b.vis && (b.text || b.aria))
      .slice(0, 30);
    return JSON.stringify({
      url: location.href,
      title: document.title,
      bodyStart: document.body.innerText.slice(0, 400),
      buttons,
    }, null, 1);
  })()`);
  console.log(state);
} catch (e) {
  console.log('probe error:', e.message);
} finally {
  console.log('\n(leaving Chrome running on port ' + PORT + ')');
  proc.unref();
}
