/* Decoder boot for zxing-wasm, shared by the RX Client, the browser harnesses,
 * and the Node tests. This is the single place that configures the module.
 *
 * Egress guarantee lives HERE, at the API layer: the WASM binary is supplied
 * directly via `wasmBinary`, and `locateFile` is overridden so the library's
 * built-in CDN fallback can never resolve to a fetchable URL. The vendored
 * source stays pristine; the pages' CSP is the second, independent layer.
 */
'use strict';

var VFTZX = (function () {

  function wasmFromBase64(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
  }

  // zx: the zxing-wasm module namespace (the ZXingWASM global in a browser,
  // or `import('zxing-wasm/reader')` in Node). wasmBinary: ArrayBuffer.
  function boot(zx, wasmBinary) {
    return zx.prepareZXingModule({
      overrides: {
        wasmBinary,
        locateFile: (path) => 'about:invalid#vft-embedded-only/' + path,
      },
      fireImmediately: true,
    });
  }

  // One decode configuration for every scan path.
  async function decodeSymbols(zx, imageData) {
    const results = await zx.readBarcodes(imageData, {
      formats: ['QRCode'], maxNumberOfSymbols: 64, tryHarder: true,
    });
    return results.filter(r => !r.error && r.bytes && r.bytes.length)
      .map(r => new Uint8Array(r.bytes));
  }

  return { wasmFromBase64, boot, decodeSymbols };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = VFTZX;
