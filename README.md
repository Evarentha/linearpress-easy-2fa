<!--
  Author: MoyuZJ
  Team: LinearTeam
  Contact: linearteam@foxmail.com
  Made by MoyuZJ in China with ♥
-->

# Easy 2FA（两步验证）

基于 TOTP（RFC 6238）的两步验证插件，密钥与 `otpauth://` URI 完全遵循标准，
兼容 Google Authenticator、Microsoft Authenticator、1Password、Aegis、Authy 等主流验证器。
全插件**无外部依赖**：QR 码编码器、Base32、CBOR 解码与 WebAuthn 验签均为内置实现。

## 验证模式（插件设置）

| 模式 | 行为 |
| --- | --- |
| **关闭** | 不启用两步验证，所有用户直接登录。 |
| **开启** | 用户可在「个人资料 → 账户安全」选择性启用；启用的用户登录需通过两步验证。 |
| **严格开启** | 所有用户必须使用两步验证。未启用的用户在密码校验成功后会被引导至绑定页，扫码确认后才能完成登录。 |

## 还原码

- 启用/重新绑定时生成 **10 个还原码**，每个由 4 个简单英文单词以 `-` 连接
  （如 `morning-apple-bed-egg`）；**同一批还原码中任何单词都不会重复出现**。
- 还原码仅在登录挑战页展示一次，请自行妥善保存。
- 无法取得验证码时可在挑战页使用还原码登录；**每个码仅限使用一次**，验证成功立即作废。
- 10 个码用尽后无法再自助登录，需联系管理员关闭该用户的两步验证后重新绑定。

## 管理员操作

拥有 `easy-2fa:manage` 权限的用户可在后台「两步验证」页：

- 查看全部用户的启用状态 / 剩余还原码 / 已绑定通行密钥数；
- 对单个用户**强制关闭两步验证**：删除其密钥、作废全部剩余还原码并移除通行密钥。
  关闭后该用户可直接登录；若站点处于严格模式，下次登录会被要求重新绑定。

## WebAuthn 通行密钥（可选，默认关闭）

该功能会降低安全性（通行密钥可代替验证码与还原码），因此默认关闭，需管理员在设置中启用。
启用后，已绑定两步验证的用户可在「账户安全」页添加平台通行密钥（Touch ID / Windows Hello /
USB 安全钥匙等）。忘记验证码时可直接用通行密钥通过挑战，**不消耗还原码**。

> WebAuthn 要求安全上下文：生产环境需 HTTPS 访问站点，本机开发可用 localhost。

## 使用方式

1. 在 `Plugins/` 工作区开发，`npm run sync` 同步到 `src/plugins/easy-2fa`。
2. 后台「插件」页启用本插件。
3. 打开「两步验证」设置页选择模式并保存（即时生效，无需重启）。

## 目录结构

```text
easy-2fa/
├── plugin.json            Manifest
├── index.ts               入口：登录接管 + 强制中间件 + 路由注册
├── src/
│   ├── config.ts          配置模型（模式 / WebAuthn 开关 / 签发方名称）
│   ├── store.ts           数据访问层（跨方言 SQL）
│   ├── totp.ts            Base32 + RFC 6238 TOTP 校验 + otpauth URI
│   ├── recovery.ts        还原码词表 / 生成（单词跨码唯一）/ 消费
│   ├── qr.ts              无依赖 QR 编码器（byte 模式，输出 SVG）
│   ├── cbor.ts            最小 CBOR 解码器（WebAuthn 用）
│   └── webauthn.ts        COSE 公钥解析 + attestation/assertion 校验
├── views/
│   ├── admin/easy-2fa.ejs           后台管理页
│   ├── admin/easy-2fa-settings.ejs  设置页
│   └── web/*.ejs                    挑战页 / 绑定页 / 账户安全页
├── public/                前端 CSS 与 JS（WebAuthn 浏览器端）
└── types/session.d.ts     会话字段声明
```
