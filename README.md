# Two-Step Verification

[![LinearPress](https://img.shields.io/badge/LinearPress-plugin-7C3AED.svg)](https://www.npmjs.com/package/@evarentha/linearpress) [![npm](https://img.shields.io/npm/v/@evarentha/linearpress-easy-2fa.svg)](https://www.npmjs.com/package/@evarentha/linearpress-easy-2fa) [![License: GPL-3.0-or-later](https://img.shields.io/badge/License-GPL--3.0--or--later-blue.svg)](LICENSE)

**English** | [简体中文](README.zh-CN.md)

TOTP two-factor sign-in for LinearPress.

## Features

- After the password, users enter a code from an authenticator app (TOTP).
- Modes: off, optional, or strict (everyone must set it up at their next sign-in).
- One-time recovery codes; optional passkeys.
- Applies to every sign-in method, including single sign-on.
- Users manage it at /account/two-factor (linked from the account page).

## Where to find it

- `/admin/two-factor`: mode, users with two-factor on, turning it off for a user (permission easy-2fa:manage)

## Install

Bundled with LinearPress 4. Enable or disable it on the admin Plugins page; the change applies immediately, no restart. In another checkout, run `npm run sync -- easy-2fa` from LinearPress, or put this repository at `src/plugins/easy-2fa` (the directory name must equal the plugin id).

Requires LinearPress ^4.0.0. Works on SQLite and MySQL.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).

Source: https://github.com/Evarentha/linearpress-easy-2fa
