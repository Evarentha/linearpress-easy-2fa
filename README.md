<!--
  Author: MoyuZJ
  Team: LinearTeam
  Contact: linearteam@foxmail.com
  Made by MoyuZJ in China with ♥
-->

# 两步验证（easy-2fa）

基于 **TOTP（RFC 6238）** 的两步验证插件，密钥与 `otpauth://` URI 完全遵循标准，
兼容 Google Authenticator、Microsoft Authenticator、1Password、Aegis、Authy 等主流验证器；
**全插件零外部依赖**（QR 编码器、Base32、CBOR 解码、WebAuthn 验签均为内置实现）。

> 本仓库是 LinearPress 插件 **easy-2fa** 的独立开发仓库。插件即 Cordis 插件函数，即插即用、可停用可卸载。

## 插件化的优势

- **登录流程接管不碰核心**：在认证成功后插入两因素挑战，核心 `auth` 服务与登录视图的渲染由插件接管，卸载即回到纯密码登录。
- **合规内置**：无依赖实现 TOTP/QR/WebAuthn，安装即用，不引第三方运行时依赖。
- **可独立分发**：任何 LinearPress 站点 ZIP/npm 安装即可获得两步验证能力。

## 验证模式（插件设置）

| 模式 | 行为 |
| --- | --- |
| **关闭** | 不启用两步验证，所有用户直接登录。 |
| **开启** | 用户可在「个人资料 → 账户安全」选择性启用；启用的用户登录需通过两步验证。 |
| **严格开启** | 所有用户必须使用两步验证；未启用的用户密码校验成功后会被引导至绑定页，扫码确认后才能完成登录。 |

## 还原码

- 启用/重新绑定时生成 **10 个还原码**，每个由 4 个简单英文单词以 `-` 连接（如 `morning-apple-bed-egg`），**同一批中任何单词都不重复**。
- 还原码仅在挑战页展示一次；每个码**仅限使用一次**，验证成功立即作废；10 个用尽后需管理员关闭该用户的两步验证后重新绑定。

## 管理员操作

拥有 `easy-2fa:manage` 权限的用户可在后台「两步验证」页：查看全部用户启用状态/剩余还原码/已绑定通行密钥数；对单个用户**强制关闭两步验证**（删除密钥、作废还原码、移除通行密钥）。

## WebAuthn 通行密钥（可选，默认关闭）

默认关闭（通行密钥可代替验证码与还原码，会降低安全性）。启用后用户可在「账户安全」页添加平台通行密钥（Touch ID / Windows Hello / USB 安全钥匙等），挑战时可直接通过，**不消耗还原码**。

> WebAuthn 要求安全上下文：生产需 HTTPS，本机开发可用 localhost。

## 安装

```bash
# 方式一：工作区同步
cd base && sh scripts/sync-plugins.sh easy-2fa

# 方式二：克隆到运行目录（目录名必须等于插件 id）
git clone <本仓库地址> src/plugins/easy-2fa
```

启用后进入后台「两步验证」设置页选择模式并保存（即时生效，无需重启）。

## 本地开发：怎么拉 / 怎么改 / 怎么跑

```bash
git clone <本仓库地址> LinearPress/Plugins/easy-2fa
cd LinearPress/base
npm install && npm run db:init
sh scripts/sync-plugins.sh easy-2fa
npm run dev
```

## 目录结构

```text
easy-2fa/
├── plugin.json            # Manifest
├── index.ts               # 入口：登录接管 + 强制中间件 + 路由注册
├── src/
│   ├── config.ts          # 配置模型（模式 / WebAuthn 开关 / 签发方名称）
│   ├── store.ts           # 数据访问层（跨方言 SQL）
│   ├── totp.ts            # Base32 + RFC 6238 TOTP 校验 + otpauth URI
│   ├── recovery.ts        # 还原码词表 / 生成 / 消费
│   ├── qr.ts              # 无依赖 QR 编码器（byte 模式，输出 SVG）
│   ├── cbor.ts            # 最小 CBOR 解码器（WebAuthn 用）
│   └── webauthn.ts        # COSE 公钥解析 + attestation/assertion 校验
├── views/                 # 后台管理/设置页 + 挑战页/绑定页/账户安全页
├── public/                # 前端 CSS 与 JS（WebAuthn 浏览器端）
└── types/session.d.ts     # 会话字段声明
```

## 贡献与发布

- conventional commits；提交前 `cd base && npm run typecheck`
- 版本：`git tag v1.0.0 && git push --tags`
- License：MIT（见仓库 LICENSE）