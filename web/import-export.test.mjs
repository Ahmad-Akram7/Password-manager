import test from 'node:test';
import assert from 'node:assert/strict';
import { entriesToCSV, parseCSV, normalizeBrowserCSV, mergeImportedEntries } from './import-export.js';

let id = 0;
const makeId = () => `imported-${++id}`;

test('parses quoted CSV values, commas, quotes, and newlines', () => {
  const rows = parseCSV('name,url,username,password,notes\r\n"Example, Inc",https://example.com,user,"pass,with ""quotes""","line one\nline two"\r\n');
  assert.equal(rows.length, 1);
  assert.equal(rows[0].name, 'Example, Inc');
  assert.equal(rows[0].password, 'pass,with "quotes"');
  assert.equal(rows[0].notes, 'line one\nline two');
});

test('imports Chrome and Brave CSV columns', () => {
  const result = normalizeBrowserCSV('name,url,username,password\nGitHub,https://github.com,ahmad@example.com,secret', makeId);
  assert.equal(result.entries.length, 1);
  assert.equal(result.entries[0].title, 'GitHub');
  assert.equal(result.entries[0].username, 'ahmad@example.com');
  assert.equal(result.entries[0].password, 'secret');
  assert.equal(result.entries[0].url, 'https://github.com');
});

test('imports Firefox CSV columns and derives a title from URL', () => {
  const result = normalizeBrowserCSV('url,username,password,httpRealm,formActionOrigin,guid,timeCreated\nhttps://accounts.example.org/login,user,secret,,,abc,123', makeId);
  assert.equal(result.entries[0].title, 'accounts.example.org');
  assert.equal(result.entries[0].url, 'https://accounts.example.org/login');
  assert.equal(result.entries[0].password, 'secret');
});

test('does not trim or alter passwords with leading/trailing spaces', () => {
  const result = normalizeBrowserCSV('name,url,username,password\nExample,https://example.com,user,"  spaced secret  "', makeId);
  assert.equal(result.entries[0].password, '  spaced secret  ');
});

test('skips rows without a usable name or password and reports skipped rows', () => {
  const result = normalizeBrowserCSV('name,url,username,password\nNo password,https://a.example,user,\nGood,https://b.example,user,secret', makeId);
  assert.equal(result.entries.length, 1);
  assert.equal(result.skipped, 1);
});

test('CSV export round-trips commas, quotes, and multiline notes', () => {
  const source = [{title:'A, "B"',url:'https://example.com',username:'user',password:' pass ',notes:'first\nsecond',category:'Login',favorite:true}];
  const parsed = normalizeBrowserCSV(entriesToCSV(source), makeId).entries[0];
  assert.equal(parsed.title, source[0].title);
  assert.equal(parsed.password, source[0].password);
  assert.equal(parsed.notes, source[0].notes);
});

test('rejects malformed quoted CSV and empty files', () => {
  assert.throws(() => parseCSV('name,password\n"unfinished,secret'), /unterminated/);
  assert.throws(() => parseCSV('  \n'), /empty/);
});

test('merges new accounts and skips duplicate site/account identities', () => {
  const existing = [{title:'GitHub',url:'https://github.com',username:'user',password:'old'}];
  const incoming = [
    {title:'GitHub clone',url:'https://github.com',username:'user',password:'new'},
    {title:'GitHub work',url:'https://github.com',username:'work',password:'work-secret'}
  ];
  const result = mergeImportedEntries(existing, incoming);
  assert.equal(result.added, 1);
  assert.equal(result.duplicates, 1);
  assert.equal(result.entries.length, 2);
  assert.equal(result.entries[0].username, 'work');
});
