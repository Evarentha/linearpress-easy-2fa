<!--
  Author: MoyuZJ
  Team: LinearTeam
  Contact: linearteam@foxmail.com
  Made by MoyuZJ in China with ♥
-->

# 两步验证 · Easy 2FA

**TOTP (RFC 6238)** two-factor authentication for LinearPress. Keys and `otpauth://` URIs follow the standard and work with Google Authenticator, Microsoft Authenticator, 1Password, Aegis, Authy and more. **Zero external dependencies** — QR encoder, Base32, CBOR decoder and WebAuthn signature checks are all built in.

基于 **TOTP（RFC 6238）** 的两步验证插件，密钥与 `otpauth://` URI 完全遵循标准，兼容主流验证器；**全插件零外部依赖**（QR 编码、Base32、CBOR、WebAuthn 验签均为内置实现）。

> Independent plugin repository for LinearPress **easy-2fa**. A plugin is a Cordis plugin function — install on demand, disable/uninstall cleanly.
> 本仓库是 LinearPress 插件 **easy-2fa** 的独立仓库。

## Why Plugins? / 插件化的优势

- **Auth-flow takeover without touching core** —— inserts a second factor after authentication; the core `auth` service and login views are untouched; disabling returns to password-only login.
  **登录流程接管不碰核心**——认证后插入两因素挑战；卸载即回到纯密码登录。
- **Compliant & self-contained** —— no third-party runtime deps; install and use.
  **合规内置**——无依赖实现 TOTP/QR/WebAuthn。
- **Publishable independently** —— any LinearPress site gets 2FA via ZIP/npm.
  **可独立分发**。

## Verification Modes / 验证模式（plugin setting / 插件设置）

| Mode / 模式 | Behavior / 行为 |
| --- | --- |
| **Off / 关闭** | no 2FA; direct password login. |
| **On / 开启** | users may opt in from「账户安全」; enabled users must pass 2FA to log in. |
| **Strict / 严格开启** | everyone must use 2FA; unconfigured users are guided to bind after password verification. |

## Recovery Codes / 还原码

- 10 codes per enrollment, each `word-word-word-word`（no word repeats within a batch）.
- Shown only once on the challenge page; each code is **single-use**; when all are spent the admin must force-disable and re-bind.

## Admin Operations / 管理员操作

Users with `easy-2fa:manage` can view enable status / remaining codes / passkeys and **force-disable** a user's 2FA（removes key, invalidates codes, removes passkeys）.

## WebAuthn Passkeys / 通行密钥（optional, off by default / 可选，默认关闭）

Off by default（passkeys bypass codes and recovery）。Once enabled，users can add platform passkeys（Touch ID / Windows Hello / security keys）and pass challenges without consuming recovery codes.

> WebAuthn requires a secure context：HTTPS in production；localhost works in dev.

## Install / 安装

```bash
# Option 1 — workspace sync（工作区同步）
cd base && sh scripts/sync-plugins.sh easy-2fa

# Option 2 — clone into runtime dir（目录名必须等于插件 id）
git clone https://github.com/Averithen/linearpress-easy-2fa src/plugins/easy-2fa
```

## Local Development / 本地开发：怎么拉 / 怎么改 / 怎么跑

```bash
git clone https://github.com/Averithen/linearpress-easy-2fa LinearPress/Plugins/easy-2fa
cd LinearPress/base
npm install && npm run db:init
sh scripts/sync-plugins.sh easy-2fa
npm run dev
```

## Directory / 目录结构

```text
easy-2fa/
├── plugin.json            Manifest
├── index.ts               entry：login takeover, strict middleware, routes
├── src/
│   ├── config.ts          modes / WebAuthn toggle / issuer
│   ├── store.ts           data access
│   ├── totp.ts            Base32 + RFC 6238 + otpauth URI
│   ├── recovery.ts        word list / generation / consumption
│   ├── qr.ts              dependency-free QR encoder（SVG）
│   ├── cbor.ts            minimal CBOR decoder
│   └── webauthn.ts        COSE key parse + assertion verification
├── views/                 admin pages + challenge/bind/security pages
├── public/                front-end CSS & JS（WebAuthn）
└── types/session.d.ts
```

## Contribute & Release / 贡献与发布

- conventional commits；`cd base && npm run typecheck` before commit
- Version：`git tag v1.0.0 && git push --tags`
- License：MIT（LICENSE）