// The Node.js entry of ua-cryptography: the browser module with its WebAssembly read from the package at import, so
// Node.js callers need no init(); calling it anyway returns at once, which keeps one code path for both.
import { readFileSync } from 'node:fs';
import { initSync } from './ua_cryptography.js';

initSync({ module: readFileSync(new URL('./ua_cryptography_bg.wasm', import.meta.url)) });

export * from './ua_cryptography.js';
export { default } from './ua_cryptography.js';
