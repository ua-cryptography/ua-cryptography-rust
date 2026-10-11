// A JavaScript caller of the npm package ua-cryptography, run in a project where it is installed:
//
//   build_scripts/npm-smoke-test.sh <ua-cryptography-VERSION.tgz>
import assert from 'node:assert/strict';
import init, * as ua from 'ua-cryptography';

// The Node.js entry has loaded the WebAssembly already; init() is the browser's step and returns at once here.
await init();
const text = new TextEncoder().encode('message');

assert.equal(ua.dstu7564CalculateHash(text, 256).length, 32);
const state = ua.dstu7564BeginHash(256);
state.update(text.subarray(0, 3)); state.update(text.subarray(3));
assert.deepEqual(state.end(), ua.dstu7564CalculateHash(text, 256));

const key = ua.dstu4145GenerateKeyPair(ua.CurveBasis.OptimalNormal, 233);
const signature = ua.dstu4145SignMessage(ua.CurveBasis.OptimalNormal, 233, key.privateKey, text);
assert.equal(ua.dstu4145VerifyMessage(ua.CurveBasis.OptimalNormal, 233, key.publicKey, text, undefined, signature), true);

const sealed = ua.dstu7624GcmEncrypt(256, new Uint8Array(32), new Uint8Array(16), new Uint8Array(0), text, 128);
sealed[0] ^= 1;
assert.throws(() => ua.dstu7624GcmDecrypt(256, new Uint8Array(32), new Uint8Array(16), new Uint8Array(0), sealed, 128),
  (error) => error.name === 'AuthenticationFailed');

const store = ua.createKeyStore('CN=Node,C=UA', undefined, 257, 30, ua.SignatureHash.Dstu7564, 'password');
const files = [{ name: 'a.txt', content: text }, { name: 'b.txt', content: text }];
const asice = ua.sign(store.keyStore, 'password', undefined, files, ua.SignatureFormat.AsicE, ua.SignatureLevel.B,
  ua.SignatureHash.Dstu7564, false, []);
const report = ua.verify(asice, [], [store.certificate], []);
assert.equal(report.is_valid, true);
assert.deepEqual(report.signed_files, ['a.txt', 'b.txt']);
assert.throws(() => ua.sign(store.keyStore, 'password', undefined, files.slice(0, 1), ua.SignatureFormat.Cades,
  ua.SignatureLevel.T, ua.SignatureHash.Dstu7564, false, []), (error) => error.name === 'InvalidArgument');
assert.throws(() => ua.getCertificate(store.keyStore, 'wrong'), (error) => error.name === 'WrongPassword');

// The async pair: level B asks nothing, an unreachable time-stamping service is a ServiceFailure.
const cades = await ua.signOnline(store.keyStore, 'password', undefined, files.slice(0, 1), ua.SignatureFormat.Cades,
  ua.SignatureLevel.B, ua.SignatureHash.Dstu7564, false, false, undefined, undefined, []);
assert.equal((await ua.verifyOnline(cades, [], [store.certificate], [])).is_valid, true);
await assert.rejects(ua.signOnline(store.keyStore, 'password', undefined, files.slice(0, 1), ua.SignatureFormat.Cades,
  ua.SignatureLevel.T, ua.SignatureHash.Dstu7564, false, false, 'http://127.0.0.1:1/tsp', undefined, []),
  (error) => error.name === 'ServiceFailure');
console.log(`ua_cryptography ${ua.getVersion()} (wasm): the smoke test passed.`);
