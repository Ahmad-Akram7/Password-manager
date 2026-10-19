export const KDF_ITERATIONS = 600000;
const ADDITIONAL_DATA = new TextEncoder().encode('PassSafe:v1');
const MAX_PAYLOAD_BYTES = 14_000_000;
const toB64 = bytes => {
  const data = new Uint8Array(bytes);
  let binary = '';
  for (let offset = 0; offset < data.length; offset += 0x8000) {
    binary += String.fromCharCode(...data.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
};
export function fromB64(value) {
  if (typeof value !== 'string' || value.length > 20_000_000) throw new Error('Invalid backup data.');
  const raw = atob(value);
  if (raw.length > MAX_PAYLOAD_BYTES) throw new Error('Vault data is too large.');
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}
export async function deriveKey(password, salt, subtle = crypto.subtle) {
  const material = await subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey({ name:'PBKDF2', salt, iterations:KDF_ITERATIONS, hash:'SHA-256' }, material,
    { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt']);
}
export async function encryptPayload(payload, key, subtle = crypto.subtle) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = new TextEncoder().encode(JSON.stringify(payload));
  if (plain.length > MAX_PAYLOAD_BYTES) throw new Error('Vault is too large to save or export.');
  const cipher = await subtle.encrypt({ name:'AES-GCM', iv, additionalData:ADDITIONAL_DATA }, key, plain);
  return { iv:toB64(iv), ciphertext:toB64(cipher) };
}
export async function decryptPayload(record, key, subtle = crypto.subtle) {
  const plain = await subtle.decrypt({ name:'AES-GCM', iv:fromB64(record.iv), additionalData:ADDITIONAL_DATA }, key, fromB64(record.ciphertext));
  const payload = JSON.parse(new TextDecoder().decode(plain));
  if (!payload || payload.version !== 1 || !Array.isArray(payload.entries)) throw new Error('This vault format is not supported.');
  if (payload.entries.length > 100000) throw new Error('Vault contains too many items.');
  const validated = payload.entries.map(validateEntry);
  if (new Set(validated.map(entry => entry.id)).size !== validated.length) throw new Error('Vault contains duplicate item IDs.');
  return validated;
}
export function validateEntry(entry) {
  if (!entry || typeof entry !== 'object' || typeof entry.id !== 'string' || typeof entry.title !== 'string' || typeof entry.password !== 'string') throw new Error('Vault contains an invalid item.');
  const fields = ['title','username','password','url','notes','category'];
  const limits = { title:120, username:254, password:4096, url:2048, notes:5000, category:30 };
  const clean = { id:entry.id, favorite:entry.favorite === true, createdAt:Number(entry.createdAt)||Date.now(), updatedAt:Number(entry.updatedAt)||Date.now() };
  for (const field of fields) {
    if (typeof entry[field] !== 'string' || entry[field].length > limits[field]) throw new Error('Vault contains an invalid field.');
    clean[field] = entry[field];
  }
  if (!['Login','Banking','Work','Personal','Other'].includes(clean.category)) clean.category='Other';
  return clean;
}
