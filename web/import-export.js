const MAX_CSV_BYTES = 20_000_000;
const MAX_ROWS = 100_000;

function cell(value) {
  const text = String(value ?? '');
  return /[",\r\n]/.test(text) ? '"' + text.replace(/"/g, '""') + '"' : text;
}

export function entriesToCSV(entries) {
  const columns = ['name', 'url', 'username', 'password', 'notes', 'category', 'favorite'];
  return '\uFEFF' + [columns.join(','), ...entries.map(entry => [
    entry.title, entry.url, entry.username, entry.password, entry.notes, entry.category, entry.favorite ? 'true' : 'false'
  ].map(cell).join(','))].join('\r\n') + '\r\n';
}

export function parseCSV(text) {
  if (typeof text !== 'string' || new TextEncoder().encode(text).length > MAX_CSV_BYTES) throw new Error('CSV file is too large.');
  const rows = [];
  let row = [], field = '', quoted = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"' && text[i + 1] === '"') { field += '"'; i++; }
      else if (ch === '"') quoted = false;
      else field += ch;
    } else if (ch === '"' && field.length === 0) quoted = true;
    else if (ch === ',') { row.push(field); field = ''; }
    else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && text[i + 1] === '\n') i++;
      row.push(field); field = '';
      if (row.some(value => value.length)) rows.push(row);
      row = [];
      if (rows.length > MAX_ROWS + 1) throw new Error('CSV contains too many rows.');
    } else field += ch;
  }
  if (quoted) throw new Error('CSV contains an unterminated quoted field.');
  if (field.length || row.length) { row.push(field); if (row.some(value => value.length)) rows.push(row); }
  if (!rows.length) throw new Error('CSV file is empty.');
  const headers = rows.shift().map((value, index) => (index === 0 ? value.replace(/^\uFEFF/, '') : value).trim().toLowerCase());
  if (!headers.some(Boolean)) throw new Error('CSV header row is missing.');
  return rows.map(values => Object.fromEntries(headers.map((header, i) => [header, String(values[i] ?? '').trim()])));
}

function first(row, names) {
  for (const name of names) {
    const value = row[name];
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return '';
}

export function normalizeBrowserCSV(text, idFactory = () => crypto.randomUUID()) {
  const rows = parseCSV(text);
  const imported = [];
  let skipped = 0;
  for (const row of rows) {
    const url = first(row, ['url', 'website', 'website url', 'hostname', 'origin', 'formactionorigin']);
    const username = first(row, ['username', 'user name', 'user', 'login', 'email', 'email address']);
    const password = first(row, ['password', 'pass']);
    let title = first(row, ['name', 'title', 'site', 'website name', 'hostname']);
    if (!title && url) {
      try { title = new URL(url.includes('://') ? url : 'https://' + url).hostname || url; }
      catch { title = url; }
    }
    if (!title || !password) { skipped++; continue; }
    const category = first(row, ['category']) || 'Login';
    imported.push({
      id: idFactory(), title: title.slice(0, 120), username: username.slice(0, 254),
      password: password.slice(0, 4096), url: url.slice(0, 2048),
      notes: first(row, ['notes', 'note', 'comments']).slice(0, 5000),
      category: ['Login', 'Banking', 'Work', 'Personal', 'Other'].includes(category) ? category : 'Login',
      favorite: ['true', 'yes', '1'].includes(first(row, ['favorite', 'favourite']).toLowerCase()),
      createdAt: Date.now(), updatedAt: Date.now()
    });
  }
  if (!imported.length) throw new Error('No usable passwords found. Choose a PassSafe backup or a CSV exported by Chrome, Firefox, or Brave.');
  return { entries: imported, skipped };
}

export function mergeImportedEntries(existing, incoming) {
  const identity = item => [item.url || item.title, item.username].map(value => String(value || '').trim().toLowerCase()).join('\u0000');
  const seen = new Set(existing.map(identity));
  const added = [];
  let duplicates = 0;
  for (const item of incoming) {
    const key = identity(item);
    if (seen.has(key)) { duplicates++; continue; }
    seen.add(key); added.push(item);
  }
  return { entries: [...added, ...existing], added: added.length, duplicates };
}
