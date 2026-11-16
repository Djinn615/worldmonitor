/**
 * Floors for advisories still selected by the lockfiles on 2026-11-16:
 * DOMPurify GHSA-cg2g-xh64-v4q7 / GHSA-mrv2-3pqr-j5jr (<=3.4.16),
 * undici GHSA-2m5v-pch6-74hx (<7.30.1), Zod GHSA-mrhx-c7xc-m3w5 (<4.6.6),
 * markdown-it GHSA-gfr2-rv44-r23c (<14.3.3), Vite GHSA-rq7h-c2jc-7f22 (<=6.4.3),
 * Happy DOM GHSA-834v-8h66-3h79 (<=21.0.3), fast-xml-parser <=5.11.2,
 * serialize-javascript <7.1.3, fast-uri <3.1.9, ip-address <=10.7.3,
 * Vitest GHSA path traversal <4.1.11.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const floors = [
  ['../package-lock.json', 'dompurify', '3.4.18'],
  ['../package-lock.json', 'undici', '7.30.2'],
  ['../package-lock.json', 'zod', '4.6.7'],
  ['../package-lock.json', 'markdown-it', '14.3.3'],
  ['../package-lock.json', 'vite', '6.4.6'],
  ['../package-lock.json', 'happy-dom', '21.0.4'],
  ['../package-lock.json', 'fast-xml-parser', '5.12.1'],
  ['../package-lock.json', 'serialize-javascript', '7.1.4'],
  ['../package-lock.json', 'fast-uri', '3.1.9'],
  ['../package-lock.json', 'ip-address', '10.7.6'],
  ['../package-lock.json', 'vitest', '4.1.12'],
  ['../package-lock.json', '@vitest/mocker', '4.1.12'],
  ['../scripts/package-lock.json', 'undici', '7.30.2'],
  ['../scripts/package-lock.json', 'fast-xml-parser', '5.12.1'],
  ['../scripts/package-lock.json', 'ip-address', '10.7.6'],
  ['../blog-site/package-lock.json', 'zod', '4.6.7'],
  ['../blog-site/package-lock.json', 'fast-xml-parser', '5.12.1'],
  ['../consumer-prices-core/package-lock.json', 'fast-uri', '3.1.9'],
  ['../workers/railway-reconcile-control/package-lock.json', 'undici', '7.30.2'],
  ['../workers/api-cors-preflight/package-lock.json', 'undici', '7.30.2'],
];

function versionsOf(lockPath, name) {
  const lock = JSON.parse(readFileSync(new URL(lockPath, import.meta.url), 'utf8'));
  return Object.entries(lock.packages)
    .filter(([key]) => key === `node_modules/${name}` || key.endsWith(`/node_modules/${name}`))
    .map(([, entry]) => entry.version);
}

function atLeast(version, floor) {
  const left = version.split('.').map(Number);
  const right = floor.split('.').map(Number);
  for (let i = 0; i < 3; i += 1) {
    const a = left[i] ?? 0;
    const b = right[i] ?? 0;
    if (a > b) return true;
    if (a < b) return false;
  }
  return true;
}

test('Umami lock selects fast-uri 3.1.9', () => {
  const lock = readFileSync(new URL('../docker/umami/runtime/pnpm-lock.yaml', import.meta.url), 'utf8');
  assert.match(lock, /fast-uri@3\.1\.9/);
  assert.doesNotMatch(lock, /fast-uri@3\.1\.8/);
});

for (const [lockPath, name, floor] of floors) {
  test(`${lockPath.slice(3)} selects only ${name} >= ${floor}`, () => {
    const versions = versionsOf(lockPath, name);
    assert.ok(versions.length > 0, `${name} missing from ${lockPath}`);
    for (const version of versions) {
      assert.equal(atLeast(version, floor), true, `${name}@${version} is below ${floor}`);
    }
  });
}

test('undici Agent keeps tls.checkServerIdentity and connect.lookup', async () => {
  const { Agent } = await import('undici');
  const checkServerIdentity = () => undefined;
  const lookup = () => {};
  const agent = new Agent({ connect: { lookup }, tls: { checkServerIdentity } });
  try {
    const options = agent[Object.getOwnPropertySymbols(agent).find((symbol) => String(symbol) === 'Symbol(options)')];
    assert.equal(options.tls.checkServerIdentity, checkServerIdentity);
    assert.equal(options.connect.lookup, lookup);
  } finally {
    await agent.close();
  }
});

test('zod max() rejects an oversized array before validating every element', async () => {
  const { z } = await import('zod');
  const input = Array.from({ length: 2000 }, () => 'x');
  const result = z.array(z.number()).max(8).safeParse(input);
  assert.equal(result.success, false);
  assert.equal(result.error.issues.length, 1);
});
