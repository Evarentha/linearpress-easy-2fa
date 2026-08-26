/*
 * Author: MoyuZJ
 * Team: LinearTeam
 * Contact: linearteam@foxmail.com
 * Made by MoyuZJ in China with ♥
 */

/**
 * 两步验证插件入口（Cordis 原生插件，export default 即 activate 阶段）。
 *
 * 功能：
 *  1. TOTP 两步验证（RFC 6238）：兼容 Google/Microsoft Authenticator、1Password 等验证器，
 *     绑定页提供 otpauth:// 二维码（内置无依赖 QR 编码器）与密钥文本。
 *  2. 三种模式：off 关闭 / optional 开启（用户自选）/ strict 严格开启（全员强制，未绑定者
 *     密码校验通过后必须先完成绑定才能登录）。
 *  3. 还原码：绑定成功生成 10 个四词还原码（全批单词不重复），单次使用即作废。
 *  4. 管理端：拥有 easy-2fa:manage 权限的用户可对单个用户强制关闭两步验证
 *     （密钥、还原码、通行密钥一并删除）；严格模式下该用户下次登录需重新绑定。
 *  5. WebAuthn 通行密钥辅助登录（默认关闭）：忘记验证码时可用通行密钥代替，不消耗还原码。
 *
 * 与 advanced-user-management 共存策略：
 *  - 覆盖 POST /login：密码校验成功且需要挑战时拦截进二次验证；否则 next() 交还
 *    后加载的处理器（限流/邮件验证等照常执行）；
 *  - 全局强制中间件兜底：若其他插件的登录处理器先完成了会话写入，而该用户需要两步
 *    验证但本会话尚未通过挑战，则后续所有请求都被重定向到挑战/绑定页。
 */

import { Context } from 'cordis';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import type { Easy2faConfig } from './src/config.js';
import { loadConfig, normalizeConfig, parseSettingsForm, saveConfig } from './src/config.js';
import type { Db } from './src/store.js';
import {
  ensureSchema, getTwoFactor, upsertPendingSecret, confirmBinding, updateLastStep, removeTwoFactor,
  replaceRecoveryCodes, consumeRecoveryCode, countUnusedRecoveryCodes,
  addPasskey, listPasskeys, getPasskey, updatePasskeySignCount, deletePasskey,
  type PasskeyRow
} from './src/store.js';
import { buildOtpauthUri, generateSecret, verifyTotp } from './src/totp.js';
import { generateRecoveryCodes, hashRecoveryCode, RECOVERY_CODE_COUNT } from './src/recovery.js';
import { renderQrSvg } from './src/qr.js';
import {
  buildCreationOptions, buildRequestOptions, generateChallenge,
  verifyAssertion, verifyRegistration
} from './src/webauthn.js';
import { requireAuth, checkPermission } from '../../services/permission.service.js';

const PLUGIN_ID = 'easy-2fa';
const CHALLENGE_URL = '/login/2fa';
const SETUP_URL = `${CHALLENGE_URL}/setup`;
const ADMIN_ROOT = '/admin/easy-2fa';
const SETTINGS_URL = `${ADMIN_ROOT}/settings`;
const SECURITY_URL = '/profile/security';
const MANAGE_PERMISSION = 'easy-2fa:manage';

/** 挑战尝试限制：同一主体 5 分钟窗口内最多 10 次失败（进程内滑动窗口）。 */
const ATTEMPT_WINDOW_MS = 5 * 60 * 1000;
const ATTEMPT_MAX_FAILURES = 10;

const text = (value: unknown): string => String(value ?? '').trim();
const param = (value: unknown): string => Array.isArray(value) ? String(value[0] ?? '') : String(value ?? '');
const asId = (value: unknown): number => Number(value) || 0;
const messageOf = (error: unknown): string => error instanceof Error ? error.message : '操作失败';
/** 页面处理器包装：失败时渲染 error 视图（与 Base wrap 语义一致）。 */
const wrap = (fn: (req: Request, res: Response) => Promise<unknown> | unknown): RequestHandler => (req, res, next) => {
  void Promise.resolve(fn(req, res)).catch((error) => {
    console.error(`[${PLUGIN_ID}] handler error:`, error);
    if (!res.headersSent) res.status(500).render('error', { title: '服务器错误', message: messageOf(error) });
    else next(error);
  });
};
/** JSON API 处理器包装：失败时返回 { ok:false }。 */
const wrapJson = (fn: (req: Request, res: Response) => Promise<unknown> | unknown): RequestHandler => (req, res) => {
  void Promise.resolve(fn(req, res)).catch((error) => {
    console.error(`[${PLUGIN_ID}] handler error:`, error);
    if (!res.headersSent) res.status(400).json({ ok: false, message: messageOf(error) });
  });
};

interface SessionLike {
  userId?: number;
  easy2faPendingUserId?: number;
  easy2faPassed?: boolean;
  easy2faSetupSecret?: string;
  easy2faWebauthnRegisterChallenge?: string;
  easy2faWebauthnLoginChallenge?: string;
}

export default async function easy2fa(context: Context): Promise<void> {
  const { web, admin } = context.linearpress;
  const hooks = context.hooks;
  const plugins = context.plugins;
  const auth = context.auth;
  const users = context.users;
  const db = context.databaseService as unknown as Db;

  await ensureSchema(db);
  let config: Easy2faConfig = loadConfig(plugins);
  await context.permissions.register(MANAGE_PERMISSION, '管理两步验证（对单个用户强制关闭）');

  /* ------------------------------------------------------------ 内部工具 */

  const rowFor = async (userId: number) => getTwoFactor(db, userId);
  /** 该用户是否被要求两步验证：已启用，或站点处于严格模式。 */
  const userNeedsChallenge = async (userId: number): Promise<boolean> => {
    if (config.mode === 'off') return false;
    const row = await rowFor(userId);
    return config.mode === 'strict' || Boolean(row?.enabled === 1);
  };

  // 挑战失败滑动窗口（进程内；重启即清零，作为轻量防爆破层）。
  const challengeFailures = new Map<string, number[]>();
  function isLockedOut(scope: string, now: number): boolean {
    return (challengeFailures.get(scope) ?? []).filter((t) => now - t < ATTEMPT_WINDOW_MS).length >= ATTEMPT_MAX_FAILURES;
  }
  function recordFailure(scope: string, now: number): void {
    const hits = (challengeFailures.get(scope) ?? []).filter((t) => now - t < ATTEMPT_WINDOW_MS);
    hits.push(now);
    challengeFailures.set(scope, hits);
    if (challengeFailures.size > 5000) for (const [k, v] of challengeFailures) if (!v.some((t) => now - t < ATTEMPT_WINDOW_MS)) challengeFailures.delete(k);
  }
  function clearFailures(scope: string): void { challengeFailures.delete(scope); }

  /** 当前挑战/绑定的目标用户：优先 pending（密码已过、会话未发），其次已登录用户。 */
  function subjectOf(session: SessionLike): number {
    return session.easy2faPendingUserId ?? session.userId ?? 0;
  }

  /** 挑战完成：重建会话并写入正式登录态（防 Session Fixation）。 */
  function completeLogin(req: Request, userId: number): Promise<void> {
    return new Promise((resolve) => {
      req.session.regenerate(() => {
        req.session.userId = userId;
        req.session.easy2faPassed = true;
        resolve();
      });
    });
  }

  async function passkeyReadyFor(userId: number): Promise<boolean> {
    if (!config.webauthnEnable) return false;
    const keys = await listPasskeys(db, userId);
    return keys.length > 0;
  }

  /** 为待绑定流程准备密钥（复用会话中已有的，避免反复刷新换码）。 */
  async function prepareSetupSecret(req: Request, userId: number): Promise<string> {
    let secret = req.session.easy2faSetupSecret ?? '';
    if (!secret) {
      secret = generateSecret();
      req.session.easy2faSetupSecret = secret;
      await upsertPendingSecret(db, userId, secret, Date.now());
    }
    return secret;
  }

  /* ------------------------------------------------------------ POST /login 接管 */

  const loginHandler: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (config.mode === 'off') return next();
      const username = text(req.body.username);
      const password = text(req.body.password);
      if (!username || !password) return next();
      const user = await Promise.resolve(auth.authenticate(username, password)).catch(() => undefined);
      if (!user) return next(); // 密码错误交还基础/限流处理器渲染统一错误

      if (!(await userNeedsChallenge(user.id))) return next();

      // 需要两步验证：不发正式会话，进入挑战/绑定流程。
      req.session.easy2faPendingUserId = user.id;
      req.session.easy2faSetupSecret = undefined;
      const row = await rowFor(user.id);
      if (row?.enabled === 1) return res.redirect(CHALLENGE_URL);

      if (config.mode !== 'strict') return next(); // optional 且未启用：正常放行
      await prepareSetupSecret(req, user.id);
      return res.redirect(SETUP_URL);
    } catch (error) {
      console.error(`[${PLUGIN_ID}] login handler error:`, error);
      next(error);
    }
  };

  /* ------------------------------------------------------------ 强制中间件（兜底） */

  const ALLOWED_PREFIXES = ['/login', '/logout', '/plugins/easy-2fa'];
  const enforcementMiddleware: RequestHandler = async (req, res, next: NextFunction) => {
    try {
      if (ALLOWED_PREFIXES.some((prefix) => req.path.startsWith(prefix))) return next();

      const session = req.session as SessionLike;

      // 情形 B：密码已过、等待二次验证的会话——除白名单外全部拦下。
      if (session.easy2faPendingUserId && !session.userId) {
        const uid = session.easy2faPendingUserId;
        if (!(await userNeedsChallenge(uid))) {
          session.easy2faPendingUserId = undefined; // 管理员已关闭或模式切回 off
          return next();
        }
        const row = await rowFor(uid);
        if (row?.enabled === 1) return res.redirect(CHALLENGE_URL);
        if (config.mode === 'strict') {
          await prepareSetupSecret(req, uid);
          return res.redirect(SETUP_URL);
        }
        session.easy2faPendingUserId = undefined;
        return next();
      }

      // 情形 A：其他登录处理器直接发了会话，但该用户需要两步验证而本会话未通过挑战。
      if (session.userId && session.easy2faPassed !== true && (await userNeedsChallenge(session.userId))) {
        session.easy2faPendingUserId = session.userId;
        const row = await rowFor(session.userId);
        if (row?.enabled === 1) return res.redirect(CHALLENGE_URL);
        if (config.mode === 'strict') {
          await prepareSetupSecret(req, session.userId);
          return res.redirect(SETUP_URL);
        }
      }
      return next();
    } catch (error) {
      console.error(`[${PLUGIN_ID}] middleware error:`, error);
      next(error);
    }
  };
  web.middleware(enforcementMiddleware);

  /* ------------------------------------------------------------ 挑战页与校验 */

  const renderChallenge = async (res: Response, req: Request, error: string, status = 200): Promise<void> => {
    const session = req.session as SessionLike;
    const uid = subjectOf(session);
    const user = uid ? await Promise.resolve(users.findById(uid)) : undefined;
    if (!user) return void res.redirect('/login');
    const remaining = await countUnusedRecoveryCodes(db, user.id);
    res.status(status).render('web/e2fa-challenge', {
      title: '两步验证',
      username: user.username,
      remainingRecovery: remaining,
      passkeyReady: await passkeyReadyFor(user.id),
      error
    });
  };

  web.register('get', CHALLENGE_URL, wrap(async (req, res) => {
    const session = req.session as SessionLike;
    if (!subjectOf(session)) return res.redirect('/login');
    await renderChallenge(res, req, '');
  }));

  /** 挑战通用后验：成功则完成登录，失败则记录并回显。 */
  async function handleChallenge(req: Request, res: Response, verify: () => Promise<{ ok: boolean; message: string; consumedRecovery?: boolean }>): Promise<unknown> {
    const session = req.session as SessionLike;
    const uid = subjectOf(session);
    if (!uid) return res.redirect('/login');
    const scope = `challenge:${uid}`;
    const now = Date.now();
    if (isLockedOut(scope, now)) return renderChallenge(res, req, '尝试次数过多，请 5 分钟后再试。', 429);

    const result = await verify();
    if (result.ok) {
      clearFailures(scope);
      delete session.easy2faPendingUserId;
      await completeLogin(req, uid);
      return res.redirect('/admin');
    }
    recordFailure(scope, now);
    const left = ATTEMPT_MAX_FAILURES - (challengeFailures.get(scope)?.length ?? 0);
    const hint = left > 0 && left < ATTEMPT_MAX_FAILURES ? `（还可尝试 ${left} 次）` : '';
    return renderChallenge(res, req, `${result.message}${hint}`, 401);
  }

  web.register('post', `${CHALLENGE_URL}/totp`, wrap(async (req, res) => {
    const session = req.session as SessionLike;
    const uid = subjectOf(session);
    await handleChallenge(req, res, async () => {
      const row = uid ? await rowFor(uid) : undefined;
      if (!row?.enabled) return { ok: false, message: '该账号尚未绑定两步验证。' };
      const result = verifyTotp(row.secret, text(req.body.code), Date.now(), config.totpWindow, row.last_totp_step);
      if (!result.ok) return { ok: false, message: '验证码错误或已过期，请重试。' };
      await updateLastStep(db, uid, result.step);
      return { ok: true, message: '' };
    });
  }));

  web.register('post', `${CHALLENGE_URL}/recovery`, wrap(async (req, res) => {
    const session = req.session as SessionLike;
    const uid = subjectOf(session);
    await handleChallenge(req, res, async () => {
      const code = text(req.body.code);
      if (!code) return { ok: false, message: '请输入还原码。' };
      const consumed = await consumeRecoveryCode(db, uid, hashRecoveryCode(code), Date.now());
      if (!consumed) return { ok: false, message: '还原码无效或已被使用。' };
      return { ok: true, message: '', consumedRecovery: true };
    });
  }));

  /* ------------------------------------------------------------ WebAuthn 挑战 */

  web.register('get', `${CHALLENGE_URL}/passkey/options`, wrapJson(async (req, res) => {
    const session = req.session as SessionLike;
    const uid = subjectOf(session);
    if (!uid || !(await passkeyReadyFor(uid))) return res.status(400).json({ ok: false, message: '当前不可用通行密钥登录。' });
    const keys = await listPasskeys(db, uid);
    const challenge = generateChallenge();
    session.easy2faWebauthnLoginChallenge = challenge;
    res.json(buildRequestOptions({
      rpId: req.hostname,
      challenge,
      allowCredentials: keys.map((key: PasskeyRow) => ({ id: key.id, type: 'public-key' as const }))
    }));
  }));

  web.register('post', `${CHALLENGE_URL}/passkey`, wrapJson(async (req, res) => {
    const session = req.session as SessionLike;
    const uid = subjectOf(session);
    const challenge = session.easy2faWebauthnLoginChallenge;
    session.easy2faWebauthnLoginChallenge = undefined;
    if (!uid || !challenge) return res.status(400).json({ ok: false, message: '挑战不存在，请重新发起验证。' });

    // 前端提交形态：{ id, rawId, response: { clientDataJSON, authenticatorData, signature, userHandle } }
    const body = (req.body ?? {}) as { id?: string; response?: Record<string, string> };
    const credential = body.id ? await getPasskey(db, body.id) : undefined;
    if (!credential || credential.user_id !== uid) return res.status(400).json({ ok: false, message: '通行密钥未注册。' });

    const origin = `${req.protocol}://${req.get('host')}`;
    try {
      const { newSignCount } = verifyAssertion({
        clientDataJSON: body.response?.clientDataJSON ?? '',
        authenticatorData: body.response?.authenticatorData ?? '',
        signature: body.response?.signature ?? ''
      }, credential.public_key_cose, credential.sign_count, false, challenge, origin, req.hostname);

      await updatePasskeySignCount(db, credential.id, newSignCount, Date.now());
      clearFailures(`challenge:${uid}`);
      delete session.easy2faPendingUserId;
      await completeLogin(req, uid);
      res.json({ ok: true, redirect: '/admin' });
    } catch (error) {
      recordFailure(`challenge:${uid}`, Date.now());
      res.status(401).json({ ok: false, message: messageOf(error) });
    }
  }));

  /* ------------------------------------------------------------ 绑定流程 */

  /** 渲染绑定页（严格模式强制 / 用户主动启用共用）。 */
  const renderSetup = async (req: Request, res: Response, strict: boolean): Promise<void> => {
    const session = req.session as SessionLike;
    const uid = subjectOf(session);
    const user = uid ? await Promise.resolve(users.findById(uid)) : undefined;
    if (!user) return void res.redirect('/login');
    const row = await rowFor(user.id);
    if (row?.enabled === 1) return void res.redirect(session.userId ? SECURITY_URL : CHALLENGE_URL);
    const secret = await prepareSetupSecret(req, user.id);
    const uri = buildOtpauthUri(secret, config.issuer, user.username);
    res.render('web/e2fa-setup', {
      title: '绑定两步验证',
      enforceStrict: strict,
      username: user.username,
      issuer: config.issuer,
      secret,
      qrSvg: renderQrSvg(uri),
      setupAction: strict ? `${SETUP_URL}/confirm` : `${SECURITY_URL}/setup/confirm`,
      error: param(req.query.notice)
    });
  };

  web.register('get', SETUP_URL, wrap(async (req, res) => {
    const session = req.session as SessionLike;
    if (!subjectOf(session)) return res.redirect('/login');
    await renderSetup(req, res, !session.userId);
  }));

  /** 绑定确认共用逻辑：校验验证码 → 启用 + 生成还原码 → 完成登录或留在后台。 */
  async function confirmSetup(req: Request, res: Response, expectedActionUrl: string): Promise<unknown> {
    const session = req.session as SessionLike;
    const uid = subjectOf(session);
    if (!uid) return res.redirect('/login');
    const secret = text(req.body.secret);
    if (!secret || secret !== session.easy2faSetupSecret) {
      return res.redirect(`${expectedActionUrl}?notice=${encodeURIComponent('绑定会话已失效，请刷新页面重试。')}`);
    }
    const result = verifyTotp(secret, text(req.body.code), Date.now(), config.totpWindow, -1);
    if (!result.ok) return renderSetup(req, res, !session.userId).then(() => undefined);

    const now = Date.now();
    await upsertPendingSecret(db, uid, secret, now);
    await confirmBinding(db, uid, now);
    const codes = generateRecoveryCodes();
    await replaceRecoveryCodes(db, uid, codes.hashes, codes.ids);
    session.easy2faSetupSecret = undefined;

    const wasPending = Boolean(session.easy2faPendingUserId);
    delete session.easy2faPendingUserId;
    session.easy2faPassed = true; // 刚刚证明持有验证器，本会话视为已通过
    if (wasPending) await completeLogin(req, uid);
    return res.render('web/e2fa-recovery-codes', { title: '你的还原码', codes: codes.codes });
  }

  web.register('post', `${SETUP_URL}/confirm`, wrap(async (req, res) => confirmSetup(req, res, SETUP_URL)));

  /* ------------------------------------------------------------ 用户自助（账户安全页） */

  const requireSecurityAccess: RequestHandler = (req, res, next) => {
    if (!req.session?.userId) return res.redirect('/login');
    next();
  };

  const securityPage: RequestHandler = wrap(async (req, res) => {
    const uid = req.session.userId!;
    const user = await Promise.resolve(users.findById(uid));
    if (!user) return res.status(404).render('error', { title: '用户不存在', message: '当前登录用户不存在。' });
    const row = await rowFor(uid);
    const notices: Record<string, string> = {
      enabled: '两步验证已启用。',
      disabled: '已关闭两步验证。',
      regenerated: '已生成新的还原码，旧码全部作废。',
      'passkey-added': '通行密钥添加成功。',
      'passkey-deleted': '通行密钥已删除。'
    };
    res.render('web/e2fa-security', {
      title: '账户安全 · 两步验证',
      user,
      enabled: row?.enabled === 1,
      strictMode: config.mode === 'strict',
      webauthnEnabled: config.webauthnEnable,
      remainingRecovery: await countUnusedRecoveryCodes(db, uid),
      passkeys: row?.enabled === 1 ? await listPasskeys(db, uid) : [],
      notice: notices[param(req.query.notice)] ?? '',
      error: param(req.query.message)
    });
  });

  web.register('get', SECURITY_URL, requireSecurityAccess, securityPage);
  web.register('get', `${SECURITY_URL}/setup`, requireSecurityAccess, wrap(async (req, res) => {
    const uid = req.session.userId!;
    const row = await rowFor(uid);
    if (row?.enabled === 1) return res.redirect(`${SECURITY_URL}?notice=enabled`);
    await prepareSetupSecret(req, uid);
    await renderSetup(req, res, false);
  }));
  web.register('post', `${SECURITY_URL}/setup/confirm`, requireSecurityAccess, wrap(async (req, res) => confirmSetup(req, res, `${SECURITY_URL}/setup`)));

  /** 自助操作的验证码确认（关闭 / 重生成还原码前必须提供有效 TOTP）。 */
  async function requireValidTotp(req: Request, res: Response, uid: number): Promise<boolean> {
    const row = await rowFor(uid);
    if (!row?.enabled) return true;
    const result = verifyTotp(row.secret, text(req.body.code), Date.now(), config.totpWindow, row.last_totp_step);
    if (!result.ok) {
      res.redirect(`${SECURITY_URL}?message=${encodeURIComponent('验证码错误，请输入当前验证器上的 6 位验证码。')}`);
      return false;
    }
    await updateLastStep(db, uid, result.step);
    return true;
  }

  web.register('post', `${SECURITY_URL}/disable`, requireSecurityAccess, wrap(async (req, res) => {
    const uid = req.session.userId!;
    if (!(await requireValidTotp(req, res, uid))) return;
    await removeTwoFactor(db, uid);
    req.session.easy2faPassed = undefined;
    res.redirect(`${SECURITY_URL}?notice=disabled`);
  }));

  web.register('post', `${SECURITY_URL}/regenerate-recovery`, requireSecurityAccess, wrap(async (req, res) => {
    const uid = req.session.userId!;
    if (!(await requireValidTotp(req, res, uid))) return;
    const codes = generateRecoveryCodes();
    await replaceRecoveryCodes(db, uid, codes.hashes, codes.ids);
    res.render('web/e2fa-recovery-codes', { title: '你的还原码', codes: codes.codes });
  }));

  /* ---- 通行密钥管理 ---- */
  web.register('get', `${SECURITY_URL}/passkeys/options`, requireSecurityAccess, wrapJson(async (req, res) => {
    const uid = req.session.userId!;
    const row = await rowFor(uid);
    if (row?.enabled !== 1) return res.status(400).json({ ok: false, message: '请先启用两步验证。' });
    const user = await Promise.resolve(users.findById(uid));
    const existing = await listPasskeys(db, uid);
    const challenge = generateChallenge();
    (req.session as SessionLike).easy2faWebauthnRegisterChallenge = challenge;
    res.json(buildCreationOptions({
      rpName: config.issuer,
      rpId: req.hostname,
      origin: `${req.protocol}://${req.get('host')}`,
      userName: user?.username ?? `user-${uid}`,
      userIdHandle: Buffer.from(`easy2fa:${uid}`).toString('base64url'),
      challenge,
      excludeCredentials: existing.map((key) => ({ id: key.id, type: 'public-key' as const }))
    }));
  }));

  web.register('post', `${SECURITY_URL}/passkeys/register`, requireSecurityAccess, wrapJson(async (req, res) => {
    const uid = req.session.userId!;
    const row = await rowFor(uid);
    if (row?.enabled !== 1) return res.json({ ok: false, message: '请先启用两步验证。' });
    const challenge = (req.session as SessionLike).easy2faWebauthnRegisterChallenge;
    (req.session as SessionLike).easy2faWebauthnRegisterChallenge = undefined;
    if (!challenge) return res.json({ ok: false, message: '注册会话已过期，请重试。' });

    const body = (req.body ?? {}) as Record<string, never>;
    const response = (body as { response?: Record<string, string> }).response ?? {};
    const verified = verifyRegistration(
      { clientDataJSON: response.clientDataJSON ?? '', attestationObject: response.attestationObject ?? '' },
      challenge,
      `${req.protocol}://${req.get('host')}`,
      req.hostname
    );
    const name = text(String((body as { name?: string }).name ?? '')).slice(0, 40);
    await addPasskey(db, { id: verified.credentialId, user_id: uid, public_key_cose: verified.publicKeyCose, sign_count: verified.signCount, name, created_at: Date.now(), last_used_at: null });
    res.json({ ok: true, message: '通行密钥已添加。' });
  }));

  web.register('post', `${SECURITY_URL}/passkeys/delete`, requireSecurityAccess, wrap(async (req, res) => {
    await deletePasskey(db, req.session.userId!, text(req.body.id));
    res.redirect(`${SECURITY_URL}?notice=passkey-deleted`);
  }));

  /* ------------------------------------------------------------ 管理端 */

  const requireManage = (): RequestHandler => async (req, res, next) => {
    if (!req.session?.userId) return res.redirect('/login');
    const allowed = await Promise.resolve(context.permissions.has(req.session.userId, MANAGE_PERMISSION)).catch(() => false);
    if (!allowed) return res.status(403).render('error', { title: '权限不足', message: '你没有管理两步验证的权限。' });
    next();
  };
  const requireManageGuard = requireManage();

  const modeLabels: Record<Easy2faConfig['mode'], string> = { off: '关闭', optional: '开启（用户自选）', strict: '严格开启（全员强制）' };

  const adminPage: RequestHandler = wrap(async (_req, res) => {
    const allUsers = await Promise.resolve(users.list());
    const rows = [];
    for (const user of allUsers) {
      const row = await rowFor(user.id);
      rows.push({
        user_id: user.id,
        username: user.username,
        is_super_admin: user.is_super_admin,
        enabled: row?.enabled === 1,
        pending: row !== undefined && row.enabled !== 1,
        confirmed_at: row?.confirmed_at ?? null,
        remainingRecovery: row ? await countUnusedRecoveryCodes(db, user.id) : 0,
        passkeyCount: row ? (await listPasskeys(db, user.id)).length : 0
      });
    }
    res.render('admin/easy-2fa', {
      title: '两步验证 · 用户管理',
      rows,
      modeLabel: modeLabels[config.mode],
      settingsUrl: SETTINGS_URL,
      notice: param(_req.query.notice)
    });
  });

  const disableUserHandler: RequestHandler = wrap(async (req, res) => {
    const uid = asId(req.params.id);
    const row = await rowFor(uid);
    if (!uid || !row) return res.redirect(`${ADMIN_ROOT}?notice=missing`);
    await removeTwoFactor(db, uid);
    res.redirect(`${ADMIN_ROOT}?notice=disabled`);
  });

  const settingsView: RequestHandler = wrap((_req, res) => {
    res.render('admin/easy-2fa-settings', { title: '两步验证 · 设置', config, notice: param(_req.query.notice) });
  });
  const settingsSave: RequestHandler = wrap(async (req, res) => {
    try {
      const next = parseSettingsForm((req.body ?? {}) as Record<string, unknown>);
      saveConfig(plugins, next);
      config = next;
      res.redirect(`${SETTINGS_URL}?notice=saved`);
    } catch (error) {
      res.status(400).render('admin/easy-2fa-settings', { title: '两步验证 · 设置', config, notice: `保存失败：${messageOf(error)}` });
    }
  });
  const settingsReset: RequestHandler = wrap(async (_req, res) => {
    const defaults = normalizeConfig(undefined);
    saveConfig(plugins, defaults);
    config = defaults;
    res.redirect(`${SETTINGS_URL}?notice=reset`);
  });

  web.register('get', ADMIN_ROOT, requireAuth, checkPermission(MANAGE_PERMISSION), adminPage);
  web.register('post', `${ADMIN_ROOT}/user/:id/disable`, requireAuth, checkPermission(MANAGE_PERMISSION), disableUserHandler);
  web.register('get', SETTINGS_URL, requireAuth, checkPermission(MANAGE_PERMISSION), settingsView);
  web.register('post', SETTINGS_URL, requireAuth, checkPermission(MANAGE_PERMISSION), settingsSave);
  web.register('post', `${SETTINGS_URL}/reset`, requireAuth, checkPermission(MANAGE_PERMISSION), settingsReset);

  // 后台扩展：侧栏菜单 + 插件列表设置入口
  hooks.on('admin:menu', (menu: Array<{ title: string; link: string }>) => [...menu, { title: '两步验证', link: ADMIN_ROOT }]);
  admin.registerCustomSetting({ label: '两步验证设置', link: SETTINGS_URL });

  /* ------------------------------------------------------------ 登录路由接管 */

  web.register('post', '/login', loginHandler);

  /* ------------------------------------------------------------ 定时清理（Effect 自动释放） */

  context.effect(() => {
    const timer = setInterval(() => {
      const now = Date.now();
      for (const [scope, hits] of challengeFailures) {
        const alive = hits.filter((t) => now - t < ATTEMPT_WINDOW_MS);
        if (alive.length) challengeFailures.set(scope, alive);
        else challengeFailures.delete(scope);
      }
    }, 60 * 60 * 1000);
    timer.unref?.();
    return () => clearInterval(timer);
  });

  context.logger.info(`easy-2fa activated (mode=${config.mode}, webauthn=${config.webauthnEnable}, totpWindow=±${config.totpWindow})`);
}
