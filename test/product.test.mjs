// Two-window product test: the shipped pages, unmodified, transferring a real
// file across a real screen capture.
//
//   dist/vft-tx.html  loads the PDF through its own file input and renders Slides
//   dist/vft-rx.html  captures the TX window via getDisplayMedia and rebuilds it
//   the operator relay  (this script) carries the Gap Report between them
//
// Nothing here reaches past the pages' UI: the file goes in through the file
// input, the Gap Report is copied out of the RX textarea and pasted into the TX
// textarea, and the result is the file the RX Client saves to disk.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { launchChrome, attach, setFileInput, sleep } from './cdp.mjs';
import { makeChecker, sampleFixture } from './lib.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, '..');
const check = makeChecker();

const PDF = sampleFixture();
const source = fs.readFileSync(PDF);
const sourceHex = crypto.createHash('sha256').update(source).digest('hex');
check.info(`source: ${path.basename(PDF)}, ${source.length} bytes, sha256 ${sourceHex.slice(0, 16)}…`);

const downloadDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vft-downloads-'));
const txUrl = 'file://' + path.join(root, 'dist/vft-tx.html');
const rxUrl = 'file://' + path.join(root, 'dist/vft-rx.html');

// The TX window must be findable by title for the RX window's capture picker.
const chrome = await launchChrome({
  port: 9412,
  args: [
    '--window-size=1000,1000', '--window-position=0,0',
    // RX's getDisplayMedia auto-selects the window whose title matches. The
    // picker matches the window (tab) title, which is document.title.
    '--auto-select-desktop-capture-source=VFT TX Client',
  ],
  urls: [txUrl],
});

let tx = null, rx = null;
try {
  tx = await attach(chrome, 'vft-tx.html');
  await tx.send('Page.enable');
  await tx.send('Runtime.enable');
  check('TX page loaded', (await tx.eval('document.title')) === 'VFT TX Client');

  // Open the RX page in a second window so it can capture the TX window.
  await tx.send('Target.createTarget', { url: rxUrl, newWindow: true, width: 900, height: 900 });
  rx = await attach(chrome, 'vft-rx.html');
  await rx.send('Page.enable');
  await rx.send('Runtime.enable');
  await rx.send('Browser.setDownloadBehavior', {
    behavior: 'allow', downloadPath: downloadDir,
  });
  check('RX page loaded', (await rx.eval('document.title')) === 'VFT RX Client');

  // The RX Client must boot its decoder from the embedded WASM, with no network.
  await rx.waitFor("document.getElementById('decstate').textContent === 'ready'",
    { timeoutMs: 30000, label: 'RX decoder ready' });
  check('RX decoder ready (embedded wasm, no network)', true);

  // ---- TX: load the PDF through the page's own file input.
  await setFileInput(tx, '#filein', PDF);
  await tx.waitFor("document.getElementById('ftag').textContent.length === 16",
    { timeoutMs: 30000, label: 'TX file hashed' });
  const txTag = await tx.eval("document.getElementById('ftag').textContent");
  check('TX File Tag equals the first 8 bytes of the file digest',
    txTag === sourceHex.slice(0, 16), `${txTag} vs ${sourceHex.slice(0, 16)}`);
  check.info(`TX loaded: ${await tx.eval("document.getElementById('fsize').textContent")}`);

  // Pace the Slides so the RX scan loop gets at least two looks at each one.
  // The RX joins late, so enable periodic Setup repeats (A.4) as an operator would.
  await tx.eval(`
    document.getElementById('slicesize').value = 800;
    document.getElementById('interval').value = 420;
    document.getElementById('setuprepeat').checked = true;
    document.getElementById('setupevery').value = 10;
    true`);
  await rx.eval(`document.getElementById('scaninterval').value = 150; true`);

  // ---- TX starts first and the RX Operator joins late, which is the normal
  // case on a call and the one that forces the Gap Report path: the RX Client
  // misses the opening Slides and must recover them in a later Rotation. It
  // also exercises A.4 — a late joiner binds via a periodic Setup Slide.
  await tx.eval("document.getElementById('startbtn').click(); true");
  check('TX transmitting before RX joins',
    await tx.eval("document.getElementById('statetext').textContent.includes('Transmitting')"));
  await sleep(14000);
  const missedSlides = await tx.eval("document.getElementById('t_slide').textContent");
  check.info(`RX joins late; TX is already at Slide ${missedSlides}`);

  // ---- RX: start capturing the TX window (auto-selected by title).
  // A failed capture raises alert(), which would block the page; surface the
  // message as a test failure instead of hanging.
  await rx.eval(`
    window.__vftCaptureError = null;
    window.alert = (m) => { window.__vftCaptureError = m; };
    document.getElementById('capbtn').click();
    true`);
  try {
    await rx.waitFor("document.getElementById('capchip').textContent.includes('Capturing')"
      + " || window.__vftCaptureError",
      { timeoutMs: 30000, label: 'RX capture to start or fail' });
  } catch (e) { /* fall through to the explicit check below */ }
  const capErr = await rx.eval('window.__vftCaptureError');
  check('RX capture started', !capErr && await rx.eval(
    "document.getElementById('capchip').textContent.includes('Capturing')"), capErr || '');
  check.info('RX capture: ' + await rx.eval("document.getElementById('captext').textContent"));

  // ---- The operator relay: watch RX, and when progress stalls, copy its Gap
  // Report into the TX Client, exactly as a human would over chat.
  const started = Date.now();
  const BUDGET_MS = 9 * 60 * 1000;
  let relays = 0, done = false, narrowedFrom = null;

  const rxProgress = `(() => {
    const cards = document.querySelectorAll('.card');
    for (const c of cards) {
      if (c.querySelector('.tag').textContent !== ${JSON.stringify(txTag)}) continue;
      return {
        badge: c.querySelector('.badge').textContent,
        meta: c.querySelector('.meta').textContent,
        gap: c.querySelector('.gaptext').textContent,
        saveShown: c.querySelector('.save').style.display !== 'none',
        acceptShown: c.querySelector('.accept').style.display !== 'none',
        incoherent: c.querySelector('.incoh').style.display === 'block',
      };
    }
    return null;
  })()`;

  let accepted = false;
  while (Date.now() - started < BUDGET_MS && !done) {
    await sleep(2000);
    const p = await rx.eval(rxProgress);
    if (!p) continue;
    // The operator confirms the detected file before anything accumulates.
    if (p.acceptShown) {
      check('transfer surfaces as FILE DETECTED first', /DETECTED/.test(p.badge), p.badge);
      await rx.eval(`(() => {
        for (const c of document.querySelectorAll('.card'))
          if (c.querySelector('.tag').textContent === ${JSON.stringify(txTag)})
            c.querySelector('.accept').click();
        return true;
      })()`);
      accepted = true;
      check.info('accepted the detected transfer');
      continue;
    }
    const pct = parseFloat((/([\d.]+)%/.exec(p.meta) || [0, 0])[1]);
    if (p.badge.includes('COMPLETE')) { done = true; break; }
    if (p.incoherent) { check('no incoherence during the transfer', false, p.meta); break; }

    // The documented workflow: once a Rotation has passed, the RX Operator
    // sends the Gap Report over chat and the TX Operator applies it, so the
    // next Rotation carries only what is still missing.
    const rotation = +(await tx.eval("document.getElementById('t_rot').textContent")) || 0;
    if (!relays && rotation >= 2 && pct > 0 && pct < 100 && p.gap.startsWith('VFT1')) {
      const setBefore = await tx.eval("document.getElementById('t_set').textContent");
      relays++;
      check.info(`relay ${relays} at ${pct.toFixed(1)}%: ${p.gap}`);
      const applied = await tx.eval(`(() => {
        document.getElementById('gapin').value = ${JSON.stringify(p.gap)};
        document.getElementById('gapapply').click();
        return document.getElementById('gapmsg').textContent;
      })()`);
      check(`Gap Report accepted by the TX Client`, /Narrowed to/.test(applied), applied);
      const setAfter = await tx.eval("document.getElementById('t_set').textContent");
      narrowedFrom = [setBefore, setAfter];
      check('TX narrowed its transmission set (§8.2.4)',
        setBefore !== setAfter, `${setBefore} -> ${setAfter}`);
      check.info(`transmission set ${setBefore} -> ${setAfter}`);
    }
  }

  const final = await rx.eval(rxProgress);
  check.info(`final RX state: ${final ? final.meta : '(no card)'}`);
  check.info(`elapsed ${((Date.now() - started) / 1000).toFixed(0)}s, ${relays} Gap Report relay(s)`);
  check('accept gate was exercised', accepted);
  check('Gap Report relay was exercised', relays >= 1, `${relays} relays`);
  check('RX reports COMPLETE · DIGEST VERIFIED', !!final && final.badge.includes('COMPLETE'), final && final.badge);
  check('RX offers the file for saving', !!final && final.saveShown);
  check('no incoherence reported', !!final && !final.incoherent);
  check('RX Gap Report says nothing missing', !!final && final.gap === `VFT1 ${txTag} -`, final && final.gap);

  // ---- Save through the page's own button and compare the bytes on disk.
  if (final && final.saveShown) {
    await rx.eval(`(() => {
      for (const c of document.querySelectorAll('.card')) {
        if (c.querySelector('.tag').textContent === ${JSON.stringify(txTag)}) {
          c.querySelector('.save').click();
          return true;
        }
      }
      return false;
    })()`);
    let saved = null;
    for (let i = 0; i < 40 && !saved; i++) {
      await sleep(250);
      const files = fs.readdirSync(downloadDir).filter(f => !f.endsWith('.crdownload'));
      if (files.length) saved = path.join(downloadDir, files[0]);
    }
    check('RX wrote a file to disk', !!saved, saved || 'nothing appeared');
    if (saved) {
      const got = fs.readFileSync(saved);
      check.info(`saved as "${path.basename(saved)}", ${got.length} bytes`);
      check('saved file is byte-identical to the source PDF', got.equals(source));
      check('saved file digest matches',
        crypto.createHash('sha256').update(got).digest('hex') === sourceHex);
      check('saved file is a valid PDF',
        got.subarray(0, 5).toString('latin1') === '%PDF-' &&
        got.subarray(-1024).toString('latin1').includes('%%EOF'));
      check('saved filename contains no path separators (§7.3.12)',
        !path.basename(saved).includes('/') && !path.basename(saved).includes('\\'));
    }
  }

  // ---- TX side: telling it nothing is missing must stop transmission.
  const stopMsg = await tx.eval(`(() => {
    document.getElementById('gapin').value = 'VFT1 ${txTag} -';
    document.getElementById('gapapply').click();
    return document.getElementById('statetext').textContent;
  })()`);
  check('TX stops when RX reports nothing missing', /Complete/.test(stopMsg), stopMsg);

  // ---- Neither page may have touched the network.
  for (const [name, session] of [['TX', tx], ['RX', rx]]) {
    const blocked = await session.eval(`(async () => {
      try { await fetch('https://example.com/vft'); return false; } catch (e) { return true; }
    })()`);
    check(`${name} page: network egress blocked by CSP`, blocked === true);
  }
} finally {
  if (tx) tx.close();
  if (rx) rx.close();
  await chrome.close();
  fs.rmSync(downloadDir, { recursive: true, force: true });
}

check.done();
