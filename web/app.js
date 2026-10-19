import { KDF_ITERATIONS, toB64, fromB64, deriveKey, encryptPayload, decryptPayload, validateEntry, validateBackupEnvelope } from './crypto-core.js';
import { entriesToCSV, normalizeBrowserCSV, mergeImportedEntries } from './import-export.js';

/* PassSafe stores only an authenticated ciphertext in IndexedDB. No network calls. */
const DB_NAME = 'passsafe-local-vault';
const DB_VERSION = 1;
const STORE = 'vault';
const AUTO_LOCK_MS = 5 * 60 * 1000;
const VERIFY_TEXT = 'PassSafe vault verification v1';
const $ = (id) => document.getElementById(id);
const ui = {
  gate: $('gate'), vault: $('vault'), gateTitle: $('gate-title'), gateCopy: $('gate-copy'), gateFoot: $('gate-foot'),
  form: $('unlock-form'), master: $('master'), confirmRow: $('confirm-row'), confirm: $('master-confirm'),
  unlockBtn: $('unlock-btn'), gateError: $('gate-error'), entries: $('entries'), empty: $('empty'), search: $('search'),
  category: $('category-filter'), listTitle: $('list-title'), headerCount: $('header-count'), allCount: $('all-count'),
  favCount: $('fav-count'), listFooter: $('list-footer'), entryDialog: $('entry-dialog'), entryForm: $('entry-form'),
  generatorDialog: $('generator-dialog'), confirmDialog: $('confirm-dialog'), toast: $('toast')
};
let db;
let vaultRecord = null;
let hasStoredVault = false;
let vaultKey = null;
let entries = [];
let activeFilter = 'all';
let pendingDeleteId = null;
let toastTimeout;
let lockTimeout;
let writeQueue = Promise.resolve();
let vaultSession = 0;

function openDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE, { keyPath: 'id' });
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error('This browser could not open local storage.'));
  });
}
function readRecord() {
  return new Promise((resolve, reject) => {
    const request = db.transaction(STORE, 'readonly').objectStore(STORE).get('primary');
    request.onsuccess = () => resolve(request.result || null);
    request.onerror = () => reject(new Error('Could not read the local vault.'));
  });
}
function writeRecord(record) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).put(record);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(new Error('Could not save the encrypted vault.'));
    tx.onabort = () => reject(new Error('Saving the vault was interrupted.'));
  });
}
function newId() { return crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Array.from(crypto.getRandomValues(new Uint8Array(16)), byte => byte.toString(16).padStart(2, '0')).join('')}`; }
function showError(message) { ui.gateError.textContent = message; }
function toast(message, error = false) {
  clearTimeout(toastTimeout); ui.toast.textContent = message; ui.toast.classList.toggle('error', error); ui.toast.classList.add('show');
  toastTimeout = setTimeout(() => ui.toast.classList.remove('show'), 2600);
}
function setGateMode(existing) {
  ui.confirmRow.classList.toggle('hidden', existing);
  ui.gateTitle.innerHTML = existing ? 'Your passwords.<br><span>Only yours.</span>' : 'Create your private<br><span>vault.</span>';
  ui.gateCopy.textContent = existing ? 'Enter your master password to decrypt your vault on this device.' : 'Create a strong master password. Your encrypted vault stays in this browser only.';
  ui.unlockBtn.innerHTML = existing ? 'Unlock vault <span>↗</span>' : 'Create encrypted vault <span>↗</span>';
  ui.gateFoot.textContent = 'Your master password is never stored. If you forget it, your vault cannot be recovered.';
  ui.master.autocomplete = existing ? 'current-password' : 'new-password';
}
function escapeHTML(value) { return String(value).replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch])); }
function initials(title) { return title.trim().split(/\s+/).slice(0,2).map(part => part[0] || '').join('').toUpperCase() || '?'; }
function currentEntries() {
  const query = ui.search.value.trim().toLowerCase();
  const category = ui.category.value;
  return entries.filter(item => (activeFilter !== 'favorites' || item.favorite) && (category === 'all' || item.category === category) &&
    [item.title,item.username,item.url,item.notes,item.category].some(value => value.toLowerCase().includes(query)));
}
function render() {
  const filtered = currentEntries();
  ui.entries.replaceChildren();
  ui.allCount.textContent = String(entries.length); ui.favCount.textContent = String(entries.filter(item => item.favorite).length);
  ui.headerCount.textContent = String(filtered.length); ui.listTitle.childNodes[0].textContent = activeFilter === 'favorites' ? 'Favorites ' : 'All items ';
  ui.empty.classList.toggle('hidden', filtered.length !== 0);
  ui.entries.classList.toggle('hidden', filtered.length === 0);
  ui.listFooter.textContent = entries.length ? `${filtered.length} of ${entries.length} encrypted ${entries.length === 1 ? 'item' : 'items'} · stored on this device` : '';
  for (const item of filtered) {
    const card = document.createElement('article'); card.className = 'entry';
    card.innerHTML = `<div class="entry-top"><div class="entry-logo">${escapeHTML(initials(item.title))}</div><div class="entry-name"><strong title="${escapeHTML(item.title)}">${escapeHTML(item.title)}</strong><small>${escapeHTML(item.username || item.url || 'No username added')}</small></div><button class="favorite ${item.favorite ? 'on' : ''}" data-action="favorite" data-id="${escapeHTML(item.id)}" aria-label="${item.favorite ? 'Remove favorite' : 'Add favorite'}">${item.favorite ? '★' : '☆'}</button></div><div class="entry-meta"><span class="category-pill">${escapeHTML(item.category)}</span><span class="entry-user">${item.url ? escapeHTML(item.url.replace(/^https?:\/\//,'').replace(/\/$/,'')) : 'Password saved'}</span></div><div class="entry-actions"><button data-action="copy-user" data-id="${escapeHTML(item.id)}">Copy username</button><button data-action="copy-pass" data-id="${escapeHTML(item.id)}">Copy password</button><button class="edit-entry" data-action="edit" data-id="${escapeHTML(item.id)}">Edit</button><button class="delete-entry" data-action="delete" data-id="${escapeHTML(item.id)}" aria-label="Delete ${escapeHTML(item.title)}">×</button></div>`;
    ui.entries.append(card);
  }
}
async function persist(nextEntries = entries) {
  const key = vaultKey;
  const baseRecord = vaultRecord;
  if (!key || !baseRecord) throw new Error('Vault is locked. Unlock it before saving.');
  const encrypted = await encryptPayload({ version:1, entries:nextEntries }, key);
  const record = { id:'primary', version:1, kdf:'PBKDF2-SHA256', iterations:KDF_ITERATIONS, salt:baseRecord.salt, ...encrypted, updatedAt:Date.now() };
  await writeRecord(record);
  if (vaultKey === key && vaultRecord === baseRecord) vaultRecord = record;
}
function commitEntries(update) {
  const session = vaultSession;
  const task = writeQueue.then(async () => {
    if (session !== vaultSession || !vaultKey || !vaultRecord) throw new Error('Vault is locked. Unlock it before saving.');
    const nextEntries = typeof update === 'function' ? update(entries) : update;
    await persist(nextEntries);
    if (session !== vaultSession || !vaultKey) throw new Error('Vault locked before the save completed.');
    entries = nextEntries;
    render();
    return nextEntries;
  });
  writeQueue = task.catch(() => {});
  return task;
}
async function unlockOrCreate(event) {
  event.preventDefault(); showError(''); const password = ui.master.value;
  const session = ++vaultSession;
  if (password.length < 12) { showError('Use at least 12 characters. A longer passphrase is safer.'); return; }
  ui.unlockBtn.disabled = true; ui.unlockBtn.textContent = 'Working securely…';
  try {
    const existing = await readRecord();
    hasStoredVault = Boolean(existing);
    if (existing) {
      const key = await deriveKey(password, fromB64(existing.salt));
      const opened = await decryptPayload(existing, key);
      if (session !== vaultSession) return;
      vaultRecord = existing; vaultKey = key; entries = opened;
    } else {
      if (password !== ui.confirm.value) throw new Error('Master passwords do not match.');
      const salt = crypto.getRandomValues(new Uint8Array(16));
      vaultKey = await deriveKey(password, salt); vaultRecord = { id:'primary', version:1, kdf:'PBKDF2-SHA256', iterations:KDF_ITERATIONS, salt:toB64(salt) };
      entries = []; await persist();
    }
    if (session !== vaultSession) return;
    ui.master.value = ''; ui.confirm.value = ''; ui.gate.classList.add('hidden'); ui.vault.classList.remove('hidden');
    render(); resetAutoLock(); $('search').focus();
  } catch (error) {
    showError(error instanceof DOMException && error.name === 'OperationError' ? 'Incorrect master password or damaged vault.' : (error.message || 'Could not unlock the vault.'));
  } finally { ui.unlockBtn.disabled = false; setGateMode(hasStoredVault); }
}
function lockVault() {
  vaultSession++;
  vaultKey = null; entries = []; vaultRecord = null; clearTimeout(lockTimeout);
  ui.vault.classList.add('hidden'); ui.gate.classList.remove('hidden'); ui.master.value=''; ui.confirm.value=''; ui.search.value='';
  if (ui.entryDialog.open) ui.entryDialog.close();
  if (ui.generatorDialog.open) ui.generatorDialog.close();
  if (ui.confirmDialog.open) ui.confirmDialog.close();
  $('generated-value').textContent = '';
  ui.entryForm.reset();
  ui.entries.replaceChildren(); showError('');
  readRecord().then(record => { hasStoredVault=Boolean(record); setGateMode(hasStoredVault); }).catch(() => setGateMode(false));
}
function resetAutoLock() {
  clearTimeout(lockTimeout);
  lockTimeout = setTimeout(() => { if (vaultKey) { lockVault(); toast('Vault locked after 5 minutes of inactivity.'); } }, AUTO_LOCK_MS);
}
function openEntry(item = null) {
  ui.entryForm.reset(); $('entry-id').value = item?.id || ''; $('entry-dialog-title').textContent = item ? 'Edit password' : 'Add password';
  $('entry-title').value = item?.title || ''; $('entry-username').value = item?.username || ''; $('entry-password').value = item?.password || '';
  $('entry-url').value = item?.url || ''; $('entry-notes').value = item?.notes || ''; $('entry-category').value = item?.category || 'Login'; $('entry-favorite').checked = item?.favorite || false;
  updateStrength(); ui.entryDialog.showModal(); $('entry-title').focus();
}
async function saveEntry(event) {
  event.preventDefault();
  const id = $('entry-id').value; const old = entries.find(item => item.id === id);
  const item = validateEntry({ id: id || newId(), title:$('entry-title').value.trim(), username:$('entry-username').value, password:$('entry-password').value, url:$('entry-url').value.trim(), notes:$('entry-notes').value, category:$('entry-category').value, favorite:$('entry-favorite').checked, createdAt:old?.createdAt || Date.now(), updatedAt:Date.now() });
  if (!item.title || !item.password) { toast('Service name and password are required.', true); return; }
  try {
    const values = { ...item };
    await commitEntries(current => {
      const currentItem = current.find(value => value.id === id);
      values.createdAt = currentItem?.createdAt || values.createdAt;
      return currentItem ? current.map(value => value.id === id ? values : value) : [values, ...current];
    });
    ui.entryDialog.close(); toast(id ? 'Password updated and encrypted.' : 'Password added and encrypted.'); resetAutoLock();
  } catch (error) { toast(error.message || 'Could not save item.', true); }
}
function passwordScore(password) {
  if (!password) return 0;
  let score = 0; if (password.length >= 12) score++; if (password.length >= 18) score++; if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++; if (/\d/.test(password)) score++; if (/[^A-Za-z0-9]/.test(password)) score++;
  if (/^(.)\1+$/.test(password) || /password|qwerty|123456/i.test(password)) score = Math.min(score, 1);
  return score;
}
function updateStrength() {
  const score = passwordScore($('entry-password').value); const bar = $('strength').firstElementChild;
  bar.className = `score-${score}`;
  $('strength').setAttribute('aria-label', `Password strength ${score}/5`);
}
function randomIndex(max) {
  const range = 0x100000000;
  const limit = Math.floor(range / max) * max;
  const value = new Uint32Array(1);
  do { crypto.getRandomValues(value); } while (value[0] >= limit);
  return value[0] % max;
}
function generatePassword(length = 24) {
  const groups = [];
  if ($('gen-upper').checked) groups.push('ABCDEFGHJKLMNPQRSTUVWXYZ');
  if ($('gen-lower').checked) groups.push('abcdefghijkmnopqrstuvwxyz');
  if ($('gen-number').checked) groups.push('23456789');
  if ($('gen-symbol').checked) groups.push('!#$%&()*+,-./:;=?@[]^_{|}~');
  if (!groups.length) throw new Error('Select at least one character set.');
  const chars = groups.join(''); const out = groups.map(group => group[randomIndex(group.length)]);
  while (out.length < length) out.push(chars[randomIndex(chars.length)]);
  for (let i=out.length-1;i>0;i--) { const j = randomIndex(i+1); [out[i],out[j]]=[out[j],out[i]]; }
  return out.join('').slice(0,length);
}
async function copyText(value) {
  if (!value) { toast('Nothing to copy.', true); return; }
  try { await navigator.clipboard.writeText(value); toast('Copied. Clipboard may retain it until cleared.'); resetAutoLock(); }
  catch { toast('Clipboard access is unavailable in this browser.', true); }
}
function triggerDownload(contents, type, filename) {
  const url = URL.createObjectURL(new Blob([contents], { type }));
  const anchor = document.createElement('a');
  anchor.href = url; anchor.download = filename; anchor.rel = 'noopener';
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function downloadBackup() {
  if (!vaultKey || !vaultRecord) throw new Error('Unlock the vault before exporting.');
  const backup = { app:'PassSafe', formatVersion:1, createdAt:new Date().toISOString(), kdf:vaultRecord.kdf, iterations:vaultRecord.iterations, salt:vaultRecord.salt, iv:vaultRecord.iv, ciphertext:vaultRecord.ciphertext };
  triggerDownload(JSON.stringify(backup,null,2), 'application/json', `passsafe-encrypted-backup-${new Date().toISOString().slice(0,10)}.passsafe`);
  toast('Encrypted backup exported. Keep it somewhere private.');
}
function downloadPlainCSV() {
  if (!vaultKey) throw new Error('Unlock the vault before exporting.');
  if (!window.confirm('Plaintext CSV contains readable passwords. Anyone who obtains this file can read them. Export only to a trusted location, then securely delete it when finished. Continue?')) return false;
  triggerDownload(entriesToCSV(entries), 'text/csv;charset=utf-8', `passsafe-passwords-${new Date().toISOString().slice(0,10)}.csv`);
  toast('Plaintext CSV exported. It is not encrypted.');
  return true;
}
async function restoreEncryptedBackup(file, text) {
  let backup;
  try { backup = JSON.parse(text); } catch { throw new Error('This file is not a valid PassSafe encrypted backup or CSV.'); }
  const envelope = validateBackupEnvelope(backup);
  const password = window.prompt('Enter the master password used when this backup was exported. It is processed locally and is not sent anywhere.');
  if (password === null) return;
  const key = await deriveKey(password, fromB64(envelope.salt));
  let imported;
  try { imported = await decryptPayload(envelope, key); }
  catch { throw new Error('Incorrect master password or damaged encrypted backup.'); }
  if (!window.confirm(`Restore ${imported.length} items? This replaces the current local vault and makes the backup's master password the password for this vault.`)) return;
  const record = { id:'primary', version:1, ...envelope, updatedAt:Date.now() };
  const session = vaultSession;
  const task = writeQueue.then(async () => {
    if (session !== vaultSession || !vaultKey) throw new Error('Vault is locked. Unlock it before restoring a backup.');
    await writeRecord(record);
    if (session !== vaultSession || !vaultKey) throw new Error('Vault locked before the restore completed.');
    vaultRecord = record; vaultKey = key; entries = imported; render();
    toast('Encrypted backup restored.'); resetAutoLock();
  });
  writeQueue = task.catch(() => {});
  await task;
}
async function importCSV(text) {
  const parsed = normalizeBrowserCSV(text, newId);
  const merged = mergeImportedEntries(entries, parsed.entries.map(validateEntry));
  if (!merged.added) {
    toast(`No new passwords imported; ${merged.duplicates} duplicate(s) were skipped.`);
    return;
  }
  const summary = `Import ${merged.added} password(s)? ${merged.duplicates} duplicate(s) and ${parsed.skipped} unusable row(s) will be skipped. Existing vault entries will be kept.`;
  if (!window.confirm(summary)) return;
  await commitEntries(merged.entries);
  toast(`Imported ${merged.added}; skipped ${merged.duplicates} duplicate(s) and ${parsed.skipped} unusable row(s).`);
  resetAutoLock();
}
async function importFile(file) {
  if (!file || file.size > 20_000_000) throw new Error('File is too large or unavailable (maximum 20 MB).');
  if (!vaultKey) throw new Error('Unlock the vault before importing passwords.');
  const text = await file.text();
  const looksLikeJSON = file.name.toLowerCase().endsWith('.json') || file.name.toLowerCase().endsWith('.passsafe') || text.trimStart().startsWith('{');
  if (looksLikeJSON) await restoreEncryptedBackup(file, text);
  else await importCSV(text);
}
function handleEntryAction(event) {
  const button = event.target.closest('button[data-action]'); if (!button) return;
  const item = entries.find(value => value.id === button.dataset.id); if (!item) return;
  switch (button.dataset.action) {
    case 'favorite': commitEntries(current => current.map(value => value.id === item.id ? { ...value, favorite:!value.favorite } : value)).then(() => toast('Favorite updated.')).catch(error => toast(error.message, true)); break;
    case 'copy-user': copyText(item.username); break;
    case 'copy-pass': copyText(item.password); break;
    case 'edit': openEntry(item); break;
    case 'delete': pendingDeleteId=item.id; $('confirm-title').textContent='Delete this password?'; $('confirm-copy').textContent=`“${item.title}” will be removed from your encrypted vault. This cannot be undone.`; $('confirm-action').textContent='Delete password'; ui.confirmDialog.showModal(); break;
  }
}
function wire() {
  ui.form.addEventListener('submit', unlockOrCreate);
  $('toggle-master').addEventListener('click', () => { ui.master.type = ui.master.type === 'password' ? 'text' : 'password'; });
  ['add-btn','mobile-add','empty-add'].forEach(id => $(id).addEventListener('click', () => openEntry()));
  ui.entryForm.addEventListener('submit', saveEntry); $('entry-password').addEventListener('input',updateStrength);
  $('entry-show').addEventListener('click', () => { $('entry-password').type=$('entry-password').type==='password'?'text':'password'; });
  $('entry-generate').addEventListener('click', () => { $('entry-password').value=generatePassword(24); $('entry-password').type='text'; updateStrength(); });
  document.querySelectorAll('[data-close]').forEach(button => button.addEventListener('click',()=>$(button.dataset.close).close()));
  document.querySelectorAll('.nav-item[data-filter]').forEach(button => button.addEventListener('click',()=>{activeFilter=button.dataset.filter;document.querySelectorAll('.nav-item[data-filter]').forEach(el=>el.classList.toggle('active',el===button));render();}));
  ui.search.addEventListener('input',render); ui.category.addEventListener('change',render); ui.entries.addEventListener('click',handleEntryAction);
  $('generator-open').addEventListener('click',()=>{ $('generated-value').textContent=generatePassword(Number($('gen-length').value)); ui.generatorDialog.showModal(); });
  $('gen-length').addEventListener('input',()=>{$('gen-length-label').textContent=$('gen-length').value;});
  $('regenerate').addEventListener('click',()=>{try{$('generated-value').textContent=generatePassword(Number($('gen-length').value));}catch(e){toast(e.message,true);}});
  $('copy-generated').addEventListener('click',()=>copyText($('generated-value').textContent));
  $('use-generated').addEventListener('click',()=>{const value=$('generated-value').textContent;ui.generatorDialog.close();openEntry();$('entry-password').value=value; $('entry-password').type='text';updateStrength();});
  $('export-btn').addEventListener('click',()=> $('transfer-dialog').showModal()); $('export-encrypted').addEventListener('click',()=>{try{downloadBackup();$('transfer-dialog').close();}catch(error){toast(error.message,true);}}); $('export-csv').addEventListener('click',()=>{try{if(downloadPlainCSV())$('transfer-dialog').close();}catch(error){toast(error.message,true);}}); $('import-file').addEventListener('change',async event=>{try{await importFile(event.target.files[0]);}catch(error){toast(error.message||'Could not import file.',true);}finally{event.target.value='';}});
  $('lock-btn').addEventListener('click',()=>{lockVault();toast('Vault locked.');});
  $('confirm-action').addEventListener('click',async()=>{if(!pendingDeleteId)return;try{await commitEntries(current => current.filter(item => item.id !== pendingDeleteId));ui.confirmDialog.close();toast('Item deleted from vault.');}catch(error){toast(error.message,true);}finally{pendingDeleteId=null;}});
  ['pointerdown','keydown','touchstart'].forEach(name=>document.addEventListener(name,()=>{if(vaultKey)resetAutoLock();},{passive:true}));
  ui.entryDialog.addEventListener('close', () => { $('entry-password').value = ''; $('entry-notes').value = ''; $('entry-username').value = ''; updateStrength(); });
  ui.generatorDialog.addEventListener('close', () => { $('generated-value').textContent = ''; });
  document.addEventListener('visibilitychange', () => { if (document.hidden && vaultKey) { lockVault(); toast('Vault locked because the tab was hidden.'); } });
  window.addEventListener('beforeunload',()=>{vaultKey=null;entries=[];});
}
async function init() {
  wire();
  try {
    if (!window.crypto?.subtle || !window.indexedDB) throw new Error('Use a modern browser with Web Crypto and IndexedDB support.');
    if (location.protocol !== 'https:' && location.hostname !== 'localhost' && location.hostname !== '127.0.0.1' && location.protocol !== 'file:') throw new Error('Open PassSafe over HTTPS to enable browser cryptography.');
    db = await openDatabase(); const record = await readRecord(); hasStoredVault = Boolean(record); setGateMode(hasStoredVault);
  } catch (error) { showError(error.message || 'PassSafe could not initialize.'); ui.unlockBtn.disabled=true; }
}
init();
