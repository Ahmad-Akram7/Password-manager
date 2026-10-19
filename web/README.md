# PassSafe web vault

PassSafe is a static password manager that keeps its vault in the browser profile where you use it. There is no login account, backend API, analytics, or automatic cloud sync. The host serves the app files; it does not receive the vault through the app's normal operation.

## Run locally

From this directory:

```bash
npm test
python -m http.server 8000
```

Open `http://localhost:8000`. A current browser with Web Crypto and IndexedDB is required. Use a long, unique master passphrase. PassSafe cannot recover a forgotten one.

## What it does

- Encrypts vault entries with AES-256-GCM before storing them in IndexedDB.
- Derives the encryption key with PBKDF2-HMAC-SHA-256 at 600,000 iterations and a random salt.
- Stores logins, usernames, website URLs, categories, favorites, and notes.
- Supports search, editing, deletion, and a cryptographically random password generator.
- Exports and restores encrypted JSON backups.
- Locks after five minutes without activity.

## Deploy

For Cloudflare Pages, connect the repository, set the build command to `exit 0`, and set the output directory to `web`. Deploy over HTTPS. The `_headers` file configures the security headers used by Cloudflare Pages.

## Limitations

There is no automatic sync between browsers or devices. Use encrypted backup export/import to move a vault. Browser extensions, malware, or a compromised device or hosting origin can expose entries while the vault is unlocked. See [SECURITY.md](SECURITY.md) before storing real credentials.
