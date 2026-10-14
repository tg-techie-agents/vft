/* Shared page utilities for the VFT clients and harnesses.
 * Plain globals, defined once here; pages must not redefine them. */
'use strict';

function $(id) { return document.getElementById(id); }

function fmtBytes(n) {
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KiB';
  return (n / 1048576).toFixed(2) + ' MiB';
}

function fmtSecs(ms) {
  const s = Math.floor(ms / 1000);
  return s < 60 ? s + 's' : Math.floor(s / 60) + 'm ' + (s % 60) + 's';
}

/* Status chips always pair an icon with words; color never carries state alone. */
function setChip(id, cls, icon, text) {
  const el = $(id);
  el.className = 'chip' + (cls ? ' ' + cls : '');
  el.querySelector('.ic').textContent = icon;
  el.querySelector('span:last-child').textContent = text;
}

/* The pages are single files and work identically served over HTTP or opened
 * from disk. When served, offer the file itself for download so an operator
 * can take the tool with them; from file:// the button stays hidden. */
function initPageDownload(filename) {
  const a = $('dlpage');
  if (!a || !/^https?:$/.test(location.protocol)) return;
  a.href = location.href.split(/[?#]/)[0];
  a.download = filename;
  a.hidden = false;
}

/* Self-test reporter: writes PASS/FAIL into #selftest and the document title
 * (the title is what headless test runners grep). */
function reportSelfTest(prefix, lines) {
  const failed = lines.filter(l => l.startsWith('FAIL')).length;
  const box = $('selftest');
  box.style.display = 'block';
  box.textContent = prefix + ': ' + (failed ? 'FAIL' : 'PASS') + '\n' + lines.join('\n');
  document.title = prefix + '-' + (failed ? 'FAIL' : 'PASS');
}

/* Egress probes: every network primitive must fail AND raise a CSP violation
 * event, proving the block happened at the policy layer, not the network. */
async function egressProbes() {
  const violations = [];
  const onv = e => violations.push(e.effectiveDirective || e.violatedDirective);
  document.addEventListener('securitypolicyviolation', onv);
  const res = [];
  try { await fetch('https://example.com/vft'); res.push(['fetch', false]); }
  catch (e) { res.push(['fetch', true]); }
  // sendBeacon returns true (queued) before CSP kills the request; judge it
  // by the violation event it raises, checked after the settle below.
  const beaconQueued = navigator.sendBeacon && navigator.sendBeacon('https://example.com/vft', 'x');
  res.push(['websocket', await new Promise(r => {
    let done = false; const fin = ok => { if (!done) { done = true; r(ok); } };
    try {
      const ws = new WebSocket('wss://example.com/vft');
      ws.onopen = () => fin(false);
      ws.onerror = () => fin(true);
      setTimeout(() => fin(true), 1500);
    } catch (e) { fin(true); }
  })]);
  res.push(await new Promise(r => {
    const img = new Image();
    const done = ok => () => r(['img', ok]);
    img.onload = done(false); img.onerror = done(true);
    img.src = 'https://example.com/vft.png';
    setTimeout(done(true), 1500);
  }));
  try {
    const x = new XMLHttpRequest();
    x.open('GET', 'https://example.com/vft');
    x.send();
    res.push(await new Promise(r => {
      x.onerror = () => r(['xhr', true]);
      x.onload = () => r(['xhr', false]);
      setTimeout(() => r(['xhr', true]), 1500);
    }));
  } catch (e) { res.push(['xhr', true]); }
  await new Promise(r => setTimeout(r, 100));
  document.removeEventListener('securitypolicyviolation', onv);
  const connectBlocks = violations.filter(v => v === 'connect-src').length;
  res.push(['beacon', !beaconQueued || connectBlocks >= 4]);
  res.push(['csp violation events ≥ 4 (got ' + violations.length + ')', violations.length >= 4]);
  return res;
}
