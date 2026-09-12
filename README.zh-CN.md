# 两步验证（easy-2fa）

[![LinearPress](https://img.shields.io/badge/LinearPress-plugin-7C3AED.svg)](https://www.npmjs.com/package/@evarentha/linearpress) [![npm](https://img.shields.io/npm/v/@evarentha/linearpress-easy-2fa.svg)](https://www.npmjs.com/package/@evarentha/linearpress-easy-2fa) [![Node.js](https://img.shields.io/badge/node-%3E%3D22-green.svg)](https://nodejs.org) [![TypeScript](https://img.shields.io/badge/TypeScript-strict-blue.svg)](https://www.typescriptlang.org) [![License: GPL-3.0-or-later](https://img.shields.io/badge/License-GPL--3.0--or--later-blue.svg)](LICENSE)

[English](README.md) | **简体中文**

为 LinearPress 登录提供基于 TOTP 的第二因子，兼容各主流验证器应用，配备 10 个一次性还原码，可选 WebAuthn 通行密钥，零外部依赖。严格模式下，所有账号在下次登录时都将被要求完成绑定，启用前请确认此影响。

## 安装

```bash
git clone https://github.com/Evarentha/linearpress-easy-2fa.git src/plugins/easy-2fa
```

目录名必须与插件 id 一致，安装后需重启 LinearPress。也可以在 `base` 检出中执行 `sh scripts/sync-plugins.sh easy-2fa`，或在后台插件页上传 ZIP、填写 npm 包名。用户端需安装任意符合 RFC 6238 的验证器应用。WebAuthn 要求安全上下文：生产环境使用 HTTPS，本地开发 localhost 即可。

## 登录流程的变化

本插件接管 `POST /login`。密码校验通过后先挂起会话（尚未登录），跳转至挑战页；尚无第二因子的账号则跳转至绑定页。无须挑战时请求原样放行，因此 advanced-user-management 的登录限流照常工作。另有一道全局强制中间件兜底：任何未完成挑战即登录的会话都将被重定向回挑战页，完成挑战时将重建会话 id。

五分钟内挑战失败 10 次，该账号将被锁定一段时间。

## 还原码

绑定（或重新绑定）时生成 10 个一次性还原码，每个由 4 个常见英文单词以连字符连接，例如 `morning-apple-bed-egg`。同一批次内单词不重复；十个还原码取自经洗牌的 83 词表，整批约 240 位熵即来源于此。数据库仅存储 SHA-256 哈希，校验前先行归一化输入。还原码仅在生成时展示一次。10 个全部用尽后，须由管理员对该用户强制关闭两步验证方可重新绑定。

## 通行密钥

WebAuthn 为可选功能，默认关闭。通行密钥可替代验证码完成登录挑战，且不消耗还原码。凭证支持 ES256 与 RS256。校验覆盖挑战值、来源、RP-ID 哈希、用户在场、用户已验证、签名计数器防克隆检查及签名本身。注册时同步验证 packed 证明签名：携带 x5c 证书链时，叶子证书必须可解析、不得为 CA、公钥类型必须与声明的算法一致、签名必须可由叶子证书公钥验证；自证明时，声明的算法必须与凭证公钥一致，签名必须可由凭证公钥验证。证明证书到信任根的链路校验不在范围内，因为注册请求的证明策略为 `none`。

Base32、TOTP、绑定页输出 SVG 的字节模式二维码编码器、CBOR 解码器全部在插件内实现，安装时不引入任何外部依赖。

## 后台

设置位于 `/admin/easy-2fa`：模式（关闭 / 可选 / 严格）、验证器中显示的签发方名称、TOTP 窗口（0 至 5 个周期，最多 ±150 秒，容忍设备时钟漂移）、WebAuthn 开关。用户在 `/profile/security` 自助管理：开启、关闭、重新生成还原码、增删通行密钥。登录挑战与首次绑定在 `/login/2fa/*` 下进行。

`easy-2fa:manage` 权限开放管理页：逐用户总览（两步验证状态、剩余还原码数量、已绑定通行密钥数量）及逐用户强制关闭（删除密钥、作废还原码、移除通行密钥）。

三张表以跨方言 SQL 编写，跟随站点当前使用的数据库驱动：`easy2fa_users`（密钥、启用状态、防重放步进锚点）、`easy2fa_recovery_codes`（哈希与一次性标记）、`easy2fa_passkeys`（COSE 公钥与签名计数器）。卸载本插件即恢复纯密码登录。

## 常见问题

**验证器丢了，十个还原码也全部用尽，怎么办？** 管理员在 `/admin/easy-2fa` 对该用户执行强制关闭：系统将删除密钥、作废还原码并移除通行密钥，该用户下次登录时即可重新绑定。

**通行密钥总是失败，怎么办？** WebAuthn 要求安全上下文：生产环境使用 HTTPS，本地开发 localhost 即可。另请确认站点以注册时完全一致的源对外提供服务；来源与 RP-ID 在每次断言校验中均被验证。

**与 advanced-user-management 冲突吗？** 不冲突。无须挑战时登录请求原样放行，AUM 的限流照常工作；需要挑战时会话先被挂起，AUM 不会看到一次已完成登录。

## 许可证

本项目以 GPL-3.0-or-later 许可发布，Copyright (C) 2026 Evarentha，完整文本见 [LICENSE](LICENSE)。
