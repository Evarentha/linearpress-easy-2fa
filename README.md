# Easy 2FA

[![LinearPress](https://img.shields.io/badge/LinearPress-plugin-7C3AED.svg)](https://www.npmjs.com/package/@evarentha/linearpress) [![npm](https://img.shields.io/npm/v/@evarentha/linearpress-easy-2fa.svg)](https://www.npmjs.com/package/@evarentha/linearpress-easy-2fa) [![Node.js](https://img.shields.io/badge/node-%3E%3D22-green.svg)](https://nodejs.org) [![TypeScript](https://img.shields.io/badge/TypeScript-strict-blue.svg)](https://www.typescriptlang.org) [![License: GPL-3.0-or-later](https://img.shields.io/badge/License-GPL--3.0--or--later-blue.svg)](LICENSE)

**English** | [简体中文](README.zh-CN.md)

A second factor for LinearPress logins using TOTP, working with every mainstream authenticator app, backed by 10 single-use recovery codes, with optional WebAuthn passkeys and zero external dependencies. Strict mode pushes every account through binding at its next login; enable it when you are ready for that.

## Install

```bash
git clone https://github.com/Evarentha/linearpress-easy-2fa.git src/plugins/easy-2fa
```

The directory name must equal the plugin id. Restart afterwards, or sync from the `base` checkout (`sh scripts/sync-plugins.sh easy-2fa`), or upload the ZIP / npm name from the admin Plugins page. Users need any RFC 6238 authenticator app. WebAuthn requires a secure context: HTTPS in production, localhost for local development.

## How login changes

The plugin overrides `POST /login`. After a successful password check it parks a pending session (no login yet) and redirects to the challenge page, or to the binding page for an account that has no second factor yet. When no challenge is required the request passes through untouched, which is why the login rate limiting of advanced-user-management keeps working alongside. A global enforcement middleware acts as the safety net: any session that logged in without completing the challenge gets redirected back, and completing the challenge regenerates the session id.

Ten failed challenge attempts within 5 minutes lock that subject out of further attempts.

## Recovery codes

Binding (or rebinding) generates 10 single-use codes, each 4 common English words joined by hyphens, like `morning-apple-bed-egg`. No word repeats within a batch; the ten codes are drawn from a shuffled 83-word list, which is where the roughly 240 bits of entropy across the batch come from, and only SHA-256 hashes are stored, with input normalized before checking. Codes are shown exactly once. When all 10 are spent, an admin force-disables 2FA for that user so they can bind again.

## Passkeys

WebAuthn is optional and off by default. A passkey satisfies the login challenge without consuming a recovery code. Credentials may be ES256 or RS256. Verification covers challenge, origin, RP-ID hash, user presence, user verification, the sign-count clone check, and the signature. At registration, packed attestation signatures are verified: with an x5c chain the leaf certificate must parse, must not be a CA, its key type must match the declared algorithm, and the signature must verify against the leaf public key; with self-attestation the declared algorithm must match the credential key and the signature must verify with it. Chaining the attestation certificate to a trusted root stays out of scope, since registration requests attestation "none".

Base32, TOTP, the byte-mode QR encoder that emits the binding page's SVG, and the CBOR decoder are all implemented inside the plugin. Nothing else gets pulled in at install time.

## Admin

Settings live at `/admin/easy-2fa`: mode (off / optional / strict), the issuer name shown inside authenticator apps, the TOTP window (0 to 5 periods, up to ±150 seconds, for device clock drift), and the WebAuthn toggle. Users manage their own second factor at `/profile/security`: enable, disable, regenerate recovery codes, add or remove passkeys. Login challenges and first-time binding run under `/login/2fa/*`.

`easy-2fa:manage` opens the admin pages: a per-user overview (who has 2FA on, how many recovery codes remain, how many passkeys are bound) and force-disable per user, which deletes the secret, voids the recovery codes, and removes the passkeys.

Three tables, in dialect-neutral SQL so they follow whichever database driver the site runs: `easy2fa_users` (secret, enabled state, the anti-replay step anchor), `easy2fa_recovery_codes` (hashes with single-use flags), `easy2fa_passkeys` (COSE public keys and signature counters). Uninstalling returns the site to plain password login.

## FAQ

**Forgot the authenticator and spent all ten recovery codes.** An admin opens `/admin/easy-2fa` and force-disables 2FA for that user; this deletes the secret, voids the recovery codes, and removes the passkeys, so the user can bind again at the next login.

**Passkeys keep failing.** WebAuthn requires a secure context: HTTPS in production, localhost for local development. Also check that the site is served from the exact origin used at registration; origin and RP-ID are both verified on every assertion.

**Does it conflict with advanced-user-management?** No. When no challenge is required, the login request passes through untouched, so AUM's rate limiting keeps working; when one is required, the pending session is parked before AUM sees a login.

## License

GPL-3.0-or-later, Copyright (C) 2026 Evarentha. See LICENSE.
