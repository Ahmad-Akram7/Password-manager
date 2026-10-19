# PassSafe security notes

PassSafe is a static app. It does not send vault data to an application server, and it has no analytics or third-party runtime scripts. The browser stores a single encrypted record in IndexedDB.

## How encryption works

- PassSafe derives a non-extractable AES-256-GCM key from the master password using PBKDF2-HMAC-SHA-256 with 600,000 iterations and a random 128-bit salt.
- Each save uses a new random 96-bit nonce. AES-GCM authenticates the encrypted data and the fixed context string `PassSafe:v1`.
- Entry data is encrypted together, including usernames, website URLs, passwords, notes, and favorites.
- The master password is not stored. The derived key remains in page memory while the vault is open and is discarded when the app locks or the page unloads.
- Backup files contain encrypted data and the metadata needed to derive the key. Restore decrypts and validates the backup before asking to replace the current vault.
- Password generation uses the browser's cryptographic random source and rejection sampling to avoid modulo bias.

## What this protects against

It helps protect a saved vault if someone obtains the browser's IndexedDB record or an exported backup without knowing the master password. A weak master password can still be guessed offline. Choose a long, unique passphrase and keep backups in a separate, secure location.

## What it does not protect against

- A compromised device, malicious browser extension, keylogger, or compromised hosting origin can read entries while the vault is unlocked.
- The browser may keep sensitive data in memory until it is reclaimed. JavaScript cannot guarantee secure erasure of memory.
- Clipboard contents can remain available to other applications after copying.
- Data is local to one browser profile. There is no sync or account recovery.
- PBKDF2 is used because it is built into the Web Crypto API. Argon2id can offer better resistance to password guessing, but requires an additional implementation and supply-chain review.

## Deployment and maintenance

Serve the app over HTTPS. The `web/_headers` file configures Content Security Policy and other browser security headers on Cloudflare Pages. The HTML meta policy is a fallback; `frame-ancestors` must be delivered as an HTTP response header to be enforced.

The GitHub Actions workflow runs automated crypto tests and checks JavaScript syntax. These checks do not replace a browser test matrix or an independent security review. Do not add remote scripts, analytics, or APIs that can access vault data without reviewing the security impact first.

PassSafe has not been independently audited. Test backup restoration and review the deployed origin before trusting it with important credentials.
