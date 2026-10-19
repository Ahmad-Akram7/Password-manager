import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { KDF_ITERATIONS, fromB64, deriveKey, encryptPayload, decryptPayload } from './crypto-core.js';
const crypto = webcrypto;
const subtle = webcrypto.subtle;
const fixture = { version:1, entries:[{id:'test-id',title:'Example',username:'user@example.com',password:'correct horse battery staple',url:'https://example.com',notes:'private note',category:'Login',favorite:true,createdAt:1,updatedAt:1}] };
test('uses the configured PBKDF2 work factor', () => assert.equal(KDF_ITERATIONS, 600000));
test('encrypts and decrypts a full vault payload', async () => {
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey('a-long-unique-test-passphrase', salt, subtle);
  const encrypted = await encryptPayload(fixture, key, subtle);
  assert.notEqual(encrypted.ciphertext, JSON.stringify(fixture));
  const opened = await decryptPayload(encrypted, key, subtle);
  assert.equal(opened.length, 1); assert.equal(opened[0].password, fixture.entries[0].password); assert.equal(opened[0].notes, 'private note');
});
test('fresh nonce is used for each encryption', async () => {
  const key = await deriveKey('a-long-unique-test-passphrase', new Uint8Array(16).fill(7), subtle);
  const first = await encryptPayload(fixture, key, subtle); const second = await encryptPayload(fixture, key, subtle);
  assert.notEqual(first.iv, second.iv); assert.notEqual(first.ciphertext, second.ciphertext);
});
test('wrong key and tampered ciphertext are rejected', async () => {
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey('correct long passphrase', salt, subtle); const wrong = await deriveKey('different long passphrase', salt, subtle);
  const encrypted = await encryptPayload(fixture, key, subtle);
  await assert.rejects(() => decryptPayload(encrypted, wrong, subtle));
  const bytes = Buffer.from(encrypted.ciphertext, 'base64'); bytes[bytes.length-1] ^= 1;
  await assert.rejects(() => decryptPayload({...encrypted,ciphertext:bytes.toString('base64')}, key, subtle));
});
test('rejects invalid decrypted vault schema', async () => {
  const key = await deriveKey('a-long-unique-test-passphrase', new Uint8Array(16), subtle);
  const encrypted = await encryptPayload({version:2,entries:[]}, key, subtle);
  await assert.rejects(() => decryptPayload(encrypted,key,subtle), /format/);
});

test('rejects duplicate entry IDs in an otherwise valid vault', async () => {
  const key = await deriveKey('a-long-unique-test-passphrase', new Uint8Array(16).fill(4), subtle);
  const duplicate = { ...fixture, entries:[fixture.entries[0], { ...fixture.entries[0], title:'Second item' }] };
  const encrypted = await encryptPayload(duplicate, key, subtle);
  await assert.rejects(() => decryptPayload(encrypted, key, subtle), /duplicate item IDs/);
});
test('base64 conversion handles large data and rejects oversized input', () => {
  const bytes = new Uint8Array(100_000);
  for (let offset = 0; offset < bytes.length; offset += 65_536) webcrypto.getRandomValues(bytes.subarray(offset, Math.min(offset + 65_536, bytes.length)));
  const encoded = Buffer.from(bytes).toString('base64');
  assert.equal(fromB64(encoded).length, bytes.length);
  assert.throws(() => fromB64('A'.repeat(20_000_001)), /Invalid backup data/);
});
