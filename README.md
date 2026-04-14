# TOTP Generator

> Local 2FA code generator compatible with Google Authenticator (RFC 6238). Zero dependencies, no build step.

**Live demo:** https://sen.ltd/portfolio/totp-generator/

## Features

- TOTP implementation from scratch (RFC 6238 / RFC 4226)
- HMAC-SHA1 via Web Crypto API — fully client-side, no network calls
- Multiple accounts with labels and issuers
- Progress ring showing time until next code refresh (30-second interval)
- One-click copy
- Import via `otpauth://` URL (paste from Google Authenticator QR export, Bitwarden, etc.)
- Export / Import all accounts as JSON (optional AES-GCM password encryption)
- Japanese / English UI
- Dark theme

## Security Notice

Secrets are stored in `localStorage`. This is more convenient but less secure than a dedicated authenticator app (e.g., Google Authenticator, Authy, 1Password). Use this tool for development/testing or low-risk accounts.

## Usage

```sh
# Serve locally
npm run serve
# → open http://localhost:8080
```

No build step required. Open `index.html` directly in a browser or serve via any static HTTP server.

## Importing an account

1. Click **+ Add Account**
2. Either:
   - Paste an `otpauth://totp/...` URL and click **Import from URL**, or
   - Enter the label, issuer, and base32 secret manually
3. Click **Add**

## Running tests

```sh
node --test tests/*.test.js
```

Tests cover:
- RFC 4226 HOTP test vectors (counter 0–9)
- RFC 6238 TOTP test vectors (Appendix B, including T=59 and T=20000000000)
- base32 encode/decode (RFC 4648)
- `parseOtpauthUrl`
- `getTimeRemaining`
- Edge cases

## Tech

- Vanilla JS (ES modules)
- Web Crypto API (`crypto.subtle`) for HMAC-SHA1 and AES-GCM
- Zero npm dependencies

## License

MIT © 2026 SEN LLC (SEN 合同会社)

<!-- sen-publish:links -->
## Links

- 🌐 Demo: https://sen.ltd/portfolio/totp-generator/
- 📝 dev.to: https://dev.to/sendotltd/implementing-totp-from-scratch-rfc-6238-test-vectors-and-web-crypto-10fl
<!-- /sen-publish:links -->
