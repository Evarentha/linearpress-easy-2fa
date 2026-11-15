# 两步验证

[![LinearPress](https://img.shields.io/badge/LinearPress-plugin-7C3AED.svg)](https://www.npmjs.com/package/@evarentha/linearpress) [![npm](https://img.shields.io/npm/v/@evarentha/linearpress-easy-2fa.svg)](https://www.npmjs.com/package/@evarentha/linearpress-easy-2fa) [![License: GPL-3.0-or-later](https://img.shields.io/badge/License-GPL--3.0--or--later-blue.svg)](LICENSE)

[English](README.md) | **简体中文**

为 LinearPress 登录加上 TOTP 两步验证。

## 功能

- 输入密码后，再输入验证器应用里的动态码（TOTP）。
- 模式：关闭、可选、强制（所有人在下次登录时必须设置）。
- 一次性还原码；可选通行密钥。
- 对所有登录方式生效，包括单点登录。
- 用户在 /account/two-factor 管理（“账户与安全”页面有入口）。

## 入口

- `/admin/two-factor`：模式、已开启的用户、为某个用户关闭（权限 easy-2fa:manage）

## 安装

LinearPress 4 已内置。在后台“插件”页启用或停用，立即生效，无需重启。其他安装方式：在 LinearPress 目录执行 `npm run sync -- easy-2fa`，或把本仓库放到 `src/plugins/easy-2fa`（目录名必须等于插件 id）。

需要 LinearPress ^4.0.0，支持 SQLite 和 MySQL。

## 许可

GPL-3.0-or-later，见 [LICENSE](LICENSE)。

源码：https://github.com/Evarentha/linearpress-easy-2fa
