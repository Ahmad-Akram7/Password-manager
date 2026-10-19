# PassSafe password manager

PassSafe has a Python terminal app and a static web vault. The web version is in `web/` and runs in your browser. It stores one encrypted vault in that browser profile; there is no account, server-side password storage, or automatic sync.

## Web vault

The web app uses the browser's Web Crypto API to derive an AES-256-GCM key from your master password. It encrypts the vault before writing it to IndexedDB. Search, categories, favorites, notes, and password generation work locally. You can export an encrypted backup and restore it on another device.

### Run it locally

Use a current version of Node.js, then run:

```bash
cd web
npm test
python -m http.server 8000
```

Open `http://localhost:8000`. Web Crypto is available on localhost and HTTPS origins. Create a long, unique master passphrase and keep an encrypted backup somewhere safe.

### Deploy to Cloudflare Pages

1. Connect this GitHub repository to Cloudflare Pages.
2. Set the production branch to the branch you want to release.
3. Set the build command to `exit 0` and the output directory to `web`.
4. Deploy, then check the site on desktop and mobile before adding real credentials.

The `web/_headers` file sets browser security headers for Cloudflare Pages. The GitHub Actions workflow runs the crypto tests and JavaScript syntax check when web files change.

## Python terminal app

The original Textual terminal app remains available. Install its dependencies with `pip install -r requirements.txt`, then run `python tui_password_manager.py`. It uses a separate SQLite database and does not share data with the web vault.

## Before using it for important accounts

Read [web/SECURITY.md](web/SECURITY.md). This project has not had an independent security audit. Losing the master password means losing access to the vault, so keep backups and test restoring one. Never commit `passwords.db`, exported backups, or other files containing credentials.
