// signOnline and verifyOnline of the npm package ua-cryptography against the test PKI server
// (crates/ua-cryptography-sign/tests/pki_server.rs), run in a project where the package is installed:
//
//   build_scripts/npm-online-test.sh <ua-cryptography-VERSION.tgz>
//
// UA_SIGN_TEST_PKI_DIRECTORY names the server's directory; the test stops the server at the end to see an
// unreachable responder leave a warning.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import * as ua from 'ua-cryptography';

const directory = process.env.UA_SIGN_TEST_PKI_DIRECTORY;
const password = process.env.UA_SIGN_TEST_PKI_PASSWORD ?? 'test password';
const read = (name) => new Uint8Array(readFileSync(join(directory, name)));
const base = readFileSync(join(directory, 'ready'), 'utf8').trim();
const root = read('root.cer');
const ca = read('ca.cer');
const customer = read('customer.jks');
const files = [{ name: 'document.txt', content: new TextEncoder().encode('Документ для підпису') }];
const checks = (report) => report.signatures.flatMap((signature) => signature.checks);
const revocation = (report, subject) =>
  checks(report).find((check) => check.name.startsWith('signer: revocation') && check.name.includes(subject));
const describe = (report) => JSON.stringify(report, null, 2);

const signOnline = (format, level, ocspUrl, certificates = []) => ua.signOnline(customer, password, undefined, files,
  format, level, ua.SignatureHash.Dstu7564, false, false, `${base}/tsp`, ocspUrl, certificates);

// T in every format; verifyOnline downloads the CA by caIssuers and asks the customer's responder.
for (const format of [ua.SignatureFormat.Cades, ua.SignatureFormat.Xades, ua.SignatureFormat.AsicS,
  ua.SignatureFormat.AsicE]) {
  const signature = await signOnline(format, ua.SignatureLevel.T);
  const data = format === ua.SignatureFormat.Xades ? files : [];
  const report = await ua.verifyOnline(signature, data, [root], []);
  assert.equal(report.is_valid, true, describe(report));
  assert.ok(report.signatures.some((s) => /-T$/.test(s.level)), describe(report));
  const status = revocation(report, 'Test Customer');
  assert.equal(status?.status, 'passed', describe(report));
  assert.match(status.details, /online response/);

  // Offline, the CA is not at hand and nobody is asked.
  const offline = ua.verify(signature, data, [root], []);
  assert.equal(revocation(offline, 'Test Customer'), undefined, describe(offline));
}

// LT carries the chain and the responses: it verifies offline. The CA is downloaded, the root is given.
const longTerm = await signOnline(ua.SignatureFormat.Cades, ua.SignatureLevel.LT, `${base}/ocsp`, [root]);
const longTermReport = ua.verify(longTerm, [], [root], []);
assert.equal(longTermReport.is_valid, true, describe(longTermReport));
assert.equal(longTermReport.signatures[0].level, 'CAdES-X Long');
assert.match(revocation(longTermReport, 'Test Customer').details, /embedded response/);

// The server stopped: the responder is unreachable, the status stays a warning, the signature holds.
const signature = await signOnline(ua.SignatureFormat.Cades, ua.SignatureLevel.T);
writeFileSync(join(directory, 'stop'), '');
while (await fetch(base).then(() => true, () => false)) await sleep(100);
const unreachable = await ua.verifyOnline(signature, [], [root], [ca]);
assert.equal(unreachable.is_valid, true, describe(unreachable));
const failed = revocation(unreachable, 'Test Customer');
assert.equal(failed?.status, 'warning', describe(unreachable));
assert.match(failed.details, /the OCSP request failed/);

console.log(`ua_cryptography ${ua.getVersion()} (wasm): signOnline and verifyOnline passed against ${base}.`);
