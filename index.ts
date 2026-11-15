/*
 * Two-Factor Sign-In Plugin Entry Point
 *
 * TOTP two-step verification as a core sign-in challenge, with recovery codes and optional passkeys.
 *
 * Authors:
 * MoyuZJ <moyuzj@evarentha.com> @LinearTeam - Made in China with ♥
 * worryzu <worryzu@evarentha.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * <p>Registered as a challenge in the core auth flow, so it runs after every
 * other check for every sign-in method (password, SSO, ...) and no session
 * exists until it is passed. 3.x replaced POST /login and patrolled every
 * request with a middleware instead, which other login handlers could
 * bypass.</p>
 * <p>Modes: off, optional (users opt in on their security page) and strict
 * (everyone must set it up during their next sign-in).</p>
 *
 * @since 1.0.0
 */

import type { Context } from 'cordis';
import type { Request, Response } from 'express';
import { checkPermission, requireAuth, route, text, parseId, messageOf } from 'linearpress/plugin-api';
import { normalizeConfig, parseSettingsForm, type Easy2faConfig } from './src/config.js';
import { renderQrSvg } from './src/qr.js';
import { generateRecoveryCodes, hashRecoveryCode, RECOVERY_CODE_COUNT } from './src/recovery.js';
import {
  addPasskey, confirmBinding, consumeRecoveryCode, countUnusedRecoveryCodes, deletePasskey, ensureSchema, getPasskey, getTwoFactor,
  listPasskeys, removeTwoFactor, replaceRecoveryCodes, statusByUser, updateLastStep, updatePasskeySignCount, upsertPendingSecret
} from './src/store.js';
import { buildOtpauthUri, generateSecret, verifyTotp } from './src/totp.js';
import { buildCreationOptions, buildRequestOptions, generateChallenge, verifyAssertion, verifyRegistration } from './src/webauthn.js';

const PLUGIN_ID = 'easy-2fa';
const CHALLENGE = '/login/2fa';
const ACCOUNT = '/account/two-factor';
const ADMIN = '/admin/two-factor';
const AUTH_LAYOUT = 'layouts/auth';
const WINDOW = 5 * 60_000;
const MAX_FAILURES = 8;

declare module 'express-session' {
  interface SessionData {
    e2faSetup?: { userId: number; secret: string };
    e2faCodes?: { userId: number; codes: string[]; then: 'continue' | 'account' };
    e2faPassed?: number;
    e2faWebauthn?: string;
  }
}

export default async function easy2fa(ctx: Context): Promise<void> {
  const { web, ui, admin, auth } = ctx.linearpress;
  const db = () => ctx.databaseService;
  await ensureSchema(db());
  let config: Easy2faConfig = normalizeConfig(await ctx.plugins.getConfig(PLUGIN_ID));
  const enabledFor = async (userId: number) => (await getTwoFactor(db(), userId))?.enabled === 1;
  const origin = (req: Request) => `${req.protocol}://${req.get('host')}`;

  /* ---------- attempt limits (per pending user, in memory) ---------- */
  const failures = new Map<number, number[]>();
  const recent = (userId: number) => (failures.get(userId) ?? []).filter((time) => Date.now() - time < WINDOW);
  const fail = (userId: number) => { const list = recent(userId); list.push(Date.now()); failures.set(userId, list); return MAX_FAILURES - list.length; };

  /* ---------- the challenge ---------- */
  auth.challenge({
    id: PLUGIN_ID,
    label: '两步验证',
    order: 10,
    needed: async (user) => config.mode === 'strict' || (config.mode === 'optional' && await enabledFor(user.id)),
    url: CHALLENGE
  });

  const pendingUser = async (req: Request) => {
    const pending = auth.pending(req);
    return pending && pending.remaining[0] === PLUGIN_ID ? ctx.users.findById(pending.userId) : undefined;
  };
  /** A fresh secret per setup attempt, kept in the session until confirmed. */
  const setupSecret = (req: Request, userId: number) => {
    if (req.session.e2faSetup?.userId !== userId) req.session.e2faSetup = { userId, secret: generateSecret() };
    return req.session.e2faSetup.secret;
  };
  const renderChallenge = async (req: Request, res: Response, extra: Record<string, unknown> = {}, status = 200) => {
    const user = await pendingUser(req);
    if (!user) return void res.redirect('/login');
    const row = await getTwoFactor(db(), user.id);
    if (row?.enabled !== 1) {
      const secret = setupSecret(req, user.id);
      return void res.status(status).render(`${PLUGIN_ID}/challenge-setup`, { layout: AUTH_LAYOUT, pageTitle: '设置两步验证', user, secret, qr: renderQrSvg(buildOtpauthUri(secret, config.issuer, user.username)), issuer: config.issuer, action: `${CHALLENGE}/setup`, ...extra });
    }
    const passkeys = config.webauthnEnable ? (await listPasskeys(db(), user.id)).length : 0;
    res.status(status).render(`${PLUGIN_ID}/challenge`, { layout: AUTH_LAYOUT, pageTitle: '两步验证', user, passkeys, recovery: await countUnusedRecoveryCodes(db(), user.id), method: 'totp', ...extra });
  };

  web.register('get', CHALLENGE, route(async (req, res) => renderChallenge(req, res)));
  web.register('post', `${CHALLENGE}/cancel`, (req, res) => { auth.cancel(req); req.session.e2faSetup = undefined; res.redirect(303, '/login'); });
  web.register('post', CHALLENGE, route(async (req, res) => {
    const user = await pendingUser(req);
    if (!user) return void res.redirect(303, '/login');
    const method = req.body.method === 'recovery' ? 'recovery' : 'totp';
    if (recent(user.id).length >= MAX_FAILURES) return void renderChallenge(req, res, { method, error: '尝试次数过多，请 5 分钟后再试，或者取消后重新登录。' }, 429);
    const row = await getTwoFactor(db(), user.id);
    let ok = false;
    if (row?.enabled === 1 && method === 'totp') {
      const result = verifyTotp(row.secret, text(req.body.code).replace(/\s+/g, ''), Date.now(), config.totpWindow, Number(row.last_totp_step));
      if (result.ok) { await updateLastStep(db(), user.id, result.step); ok = true; }
    } else if (row?.enabled === 1 && method === 'recovery') {
      ok = Boolean(text(req.body.code)) && await consumeRecoveryCode(db(), user.id, hashRecoveryCode(text(req.body.code)), Date.now());
    }
    if (!ok) {
      const left = fail(user.id);
      const message = method === 'recovery' ? '还原码不正确，或者已经用过。' : '验证码不正确。请确认手机时间准确，并输入验证器上当前显示的 6 位数字。';
      return void renderChallenge(req, res, { method, error: left <= 3 ? `${message}还可以再试 ${left} 次。` : message }, 401);
    }
    failures.delete(user.id);
    if (method === 'recovery') req.flash('warning', `你用了一个还原码，还剩 ${await countUnusedRecoveryCodes(db(), user.id)} 个。可以在“两步验证”页面重新生成。`, '已用还原码登录');
    await auth.passChallenge(req, res, PLUGIN_ID);
  }));

  /* strict mode: set up during sign-in */
  web.register('post', `${CHALLENGE}/setup`, route(async (req, res) => {
    const user = await pendingUser(req);
    if (!user) return void res.redirect(303, '/login');
    const secret = req.session.e2faSetup?.userId === user.id ? req.session.e2faSetup.secret : '';
    const result = secret ? verifyTotp(secret, text(req.body.code).replace(/\s+/g, ''), Date.now(), config.totpWindow, -1) : { ok: false, step: 0 };
    if (!result.ok) return void renderChallenge(req, res, { error: '验证码不正确。请用验证器扫描二维码后，输入它显示的 6 位数字。' }, 401);
    await enable(user.id, secret, result.step);
    req.session.e2faSetup = undefined;
    const codes = generateRecoveryCodes();
    await replaceRecoveryCodes(db(), user.id, codes.hashes, codes.ids);
    req.session.e2faCodes = { userId: user.id, codes: codes.codes, then: 'continue' };
    res.redirect(303, `${CHALLENGE}/codes`);
  }));
  web.register('get', `${CHALLENGE}/codes`, (req, res) => {
    const pending = req.session.e2faCodes;
    if (!pending) return void res.redirect(req.session.userId ? ACCOUNT : '/login');
    // Shown once. During sign-in they stay until "continue" (needed to finish signing in).
    if (pending.then === 'account') req.session.e2faCodes = undefined;
    res.render(`${PLUGIN_ID}/codes`, { layout: pending.then === 'continue' ? AUTH_LAYOUT : undefined, pageTitle: '保存还原码', codes: pending.codes, then: pending.then, action: pending.then === 'continue' ? `${CHALLENGE}/continue` : `${ACCOUNT}` });
  });
  web.register('post', `${CHALLENGE}/continue`, route(async (req, res) => {
    const codes = req.session.e2faCodes;
    const passed = req.session.e2faPassed;
    req.session.e2faCodes = undefined; req.session.e2faPassed = undefined;
    const pending = auth.pending(req);
    if (!pending || (codes?.userId !== pending.userId && passed !== pending.userId)) return void res.redirect(303, '/login');
    await auth.passChallenge(req, res, PLUGIN_ID);
  }));

  async function enable(userId: number, secret: string, step: number) {
    if (await enabledFor(userId)) throw new Error('两步验证已经开启');
    await upsertPendingSecret(db(), userId, secret, Date.now());
    await confirmBinding(db(), userId, Date.now());
    await updateLastStep(db(), userId, step);
  }

  /* passkey as the second step */
  web.register('get', `${CHALLENGE}/passkey/options`, route(async (req, res) => {
    const user = await pendingUser(req);
    const keys = user && config.webauthnEnable ? await listPasskeys(db(), user.id) : [];
    if (!user || !keys.length) return void res.status(400).json({ ok: false, message: '这个账号没有可用的通行密钥' });
    const challenge = generateChallenge();
    req.session.e2faWebauthn = challenge;
    res.json(buildRequestOptions({ rpId: req.hostname, challenge, allowCredentials: keys.map((key) => ({ id: key.id, type: 'public-key' as const })) }));
  }));
  web.register('post', `${CHALLENGE}/passkey`, route(async (req, res) => {
    const user = await pendingUser(req);
    const challenge = req.session.e2faWebauthn;
    req.session.e2faWebauthn = undefined;
    if (!user || !challenge) return void res.status(400).json({ ok: false, message: '验证已过期，请重新开始' });
    const body = (req.body ?? {}) as { id?: string; response?: Record<string, string> };
    const key = body.id ? await getPasskey(db(), body.id) : undefined;
    if (!key || Number(key.user_id) !== user.id) return void res.status(400).json({ ok: false, message: '这把通行密钥不属于这个账号' });
    try {
      const { newSignCount } = verifyAssertion({ clientDataJSON: body.response?.clientDataJSON ?? '', authenticatorData: body.response?.authenticatorData ?? '', signature: body.response?.signature ?? '' }, key.public_key_cose, Number(key.sign_count), false, challenge, origin(req), req.hostname);
      await updatePasskeySignCount(db(), key.id, newSignCount, Date.now());
      failures.delete(user.id);
      req.session.e2faPassed = user.id;
      res.json({ ok: true, redirect: `${CHALLENGE}/passkey/continue` });
    } catch (error) { fail(user.id); res.status(401).json({ ok: false, message: messageOf(error) }); }
  }));
  web.register('get', `${CHALLENGE}/passkey/continue`, route(async (req, res) => {
    const pending = auth.pending(req);
    const passed = req.session.e2faPassed;
    req.session.e2faPassed = undefined;
    if (!pending || passed !== pending.userId) return void res.redirect('/login');
    await auth.passChallenge(req, res, PLUGIN_ID);
  }));

  /* ---------- the user's own page ---------- */
  ui.menu('user.menu', { title: '两步验证', href: ACCOUNT, order: 81, when: () => config.mode !== 'off' });
  const renderAccount = async (req: Request, res: Response, extra: Record<string, unknown> = {}, status = 200) => {
    const user = (await ctx.users.findById(req.session.userId!))!;
    const enabled = await enabledFor(user.id);
    const setup = !enabled && config.mode !== 'off' ? setupSecret(req, user.id) : '';
    res.status(status).render(`${PLUGIN_ID}/account`, {
      pageTitle: '两步验证', user, enabled, mode: config.mode, webauthn: config.webauthnEnable,
      recovery: enabled ? await countUnusedRecoveryCodes(db(), user.id) : 0, total: RECOVERY_CODE_COUNT,
      passkeys: enabled ? await listPasskeys(db(), user.id) : [],
      setup: setup ? { secret: setup, qr: renderQrSvg(buildOtpauthUri(setup, config.issuer, user.username)), issuer: config.issuer } : null,
      ...extra
    });
  };
  web.register('get', ACCOUNT, requireAuth, route(async (req, res) => renderAccount(req, res)));
  const confirmCode = async (req: Request, userId: number) => {
    const row = await getTwoFactor(db(), userId);
    if (!row?.enabled) return false;
    const result = verifyTotp(row.secret, text(req.body.code).replace(/\s+/g, ''), Date.now(), config.totpWindow, Number(row.last_totp_step));
    if (result.ok) await updateLastStep(db(), userId, result.step);
    return result.ok;
  };
  web.register('post', `${ACCOUNT}/enable`, requireAuth, route(async (req, res) => {
    const userId = req.session.userId!;
    const secret = req.session.e2faSetup?.userId === userId ? req.session.e2faSetup.secret : '';
    const result = secret ? verifyTotp(secret, text(req.body.code).replace(/\s+/g, ''), Date.now(), config.totpWindow, -1) : { ok: false, step: 0 };
    if (!result.ok) return void renderAccount(req, res, { error: '验证码不正确。请扫描二维码后输入验证器显示的 6 位数字。' }, 400);
    await enable(userId, secret, result.step);
    req.session.e2faSetup = undefined;
    const codes = generateRecoveryCodes();
    await replaceRecoveryCodes(db(), userId, codes.hashes, codes.ids);
    req.session.e2faCodes = { userId, codes: codes.codes, then: 'account' };
    req.flash('success', '两步验证已开启。下次登录时需要输入验证码。');
    res.redirect(303, `${CHALLENGE}/codes`);
  }));
  web.register('post', `${ACCOUNT}/disable`, requireAuth, route(async (req, res) => {
    if (config.mode === 'strict') return void renderAccount(req, res, { error: '站点要求所有账号使用两步验证，不能关闭。' }, 400);
    if (!await confirmCode(req, req.session.userId!)) return void renderAccount(req, res, { error: '验证码不正确，没有关闭。' }, 400);
    await removeTwoFactor(db(), req.session.userId!);
    req.flash('success', '已关闭两步验证。');
    res.redirect(303, ACCOUNT);
  }));
  web.register('post', `${ACCOUNT}/recovery`, requireAuth, route(async (req, res) => {
    if (!await confirmCode(req, req.session.userId!)) return void renderAccount(req, res, { error: '验证码不正确，还原码没有更换。' }, 400);
    const codes = generateRecoveryCodes();
    await replaceRecoveryCodes(db(), req.session.userId!, codes.hashes, codes.ids);
    req.session.e2faCodes = { userId: req.session.userId!, codes: codes.codes, then: 'account' };
    req.flash('success', '已生成新的还原码，旧的全部失效。');
    res.redirect(303, `${CHALLENGE}/codes`);
  }));
  web.register('get', `${ACCOUNT}/passkeys/options`, requireAuth, route(async (req, res) => {
    const userId = req.session.userId!;
    if (!config.webauthnEnable || !await enabledFor(userId)) return void res.status(400).json({ ok: false, message: '请先开启两步验证' });
    const user = (await ctx.users.findById(userId))!;
    const challenge = generateChallenge();
    req.session.e2faWebauthn = challenge;
    res.json(buildCreationOptions({ rpName: config.issuer, rpId: req.hostname, origin: origin(req), userName: user.username, userIdHandle: Buffer.from(`easy2fa:${userId}`).toString('base64url'), challenge, excludeCredentials: (await listPasskeys(db(), userId)).map((key) => ({ id: key.id, type: 'public-key' as const })) }));
  }));
  web.register('post', `${ACCOUNT}/passkeys`, requireAuth, route(async (req, res) => {
    const userId = req.session.userId!;
    const challenge = req.session.e2faWebauthn;
    req.session.e2faWebauthn = undefined;
    if (!challenge || !config.webauthnEnable) return void res.status(400).json({ ok: false, message: '注册已过期，请重试' });
    try {
      const response = ((req.body ?? {}) as { response?: Record<string, string> }).response ?? {};
      const verified = verifyRegistration({ clientDataJSON: response.clientDataJSON ?? '', attestationObject: response.attestationObject ?? '' }, challenge, origin(req), req.hostname);
      await addPasskey(db(), { id: verified.credentialId, user_id: userId, public_key_cose: verified.publicKeyCose, sign_count: verified.signCount, name: text(req.body.name).slice(0, 40) || '通行密钥', created_at: Date.now(), last_used_at: null });
      res.json({ ok: true, message: '通行密钥已添加' });
    } catch (error) { res.status(400).json({ ok: false, message: messageOf(error) }); }
  }));
  web.register('post', `${ACCOUNT}/passkeys/:id/delete`, requireAuth, route(async (req, res) => {
    await deletePasskey(db(), req.session.userId!, String(req.params.id));
    req.flash('success', '已删除通行密钥。');
    res.redirect(303, ACCOUNT);
  }));
  web.register('get', '/profile/security', (_req, res) => res.redirect(301, ACCOUNT));

  /* ---------- admin ---------- */
  admin.registerMenu({ title: '两步验证', link: ADMIN, group: 'users', order: 35, permission: 'easy-2fa:manage' });
  admin.registerSettings({ label: '两步验证', link: `${ADMIN}#settings`, description: '验证器（TOTP）、还原码和通行密钥' });
  web.register('get', '/admin/easy-2fa', (_req, res) => res.redirect(301, ADMIN));
  const manage = [requireAuth, checkPermission('easy-2fa:manage')];
  web.register('get', ADMIN, ...manage, route(async (_req, res) => {
    const status = await statusByUser(db());
    const users = await ctx.users.list({ limit: 500 });
    res.render(`${PLUGIN_ID}/admin`, { pageTitle: '两步验证', config, rows: users.map((user) => ({ user, ...(status.get(user.id) ?? { enabled: false, confirmedAt: null, recovery: 0, passkeys: 0 }) })) });
  }));
  web.register('post', `${ADMIN}/settings`, ...manage, route(async (req, res) => {
    const next = parseSettingsForm(req.body ?? {});
    const turnedStrict = next.mode === 'strict' && config.mode !== 'strict';
    config = next;
    await ctx.plugins.setConfig(PLUGIN_ID, config);
    req.flash(turnedStrict ? 'warning' : 'success', turnedStrict ? '已改为强制模式：还没设置两步验证的用户（包括你）会在下次登录时被要求设置。' : '设置已保存。');
    res.redirect(303, ADMIN);
  }));
  web.register('post', `${ADMIN}/users/:id/disable`, ...manage, route(async (req, res) => {
    const user = await ctx.users.findById(parseId(req.params.id) ?? 0);
    if (user) await removeTwoFactor(db(), user.id);
    req.flash('success', user ? `已关闭 ${user.username} 的两步验证${config.mode === 'strict' ? '，TA 下次登录时需要重新设置' : ''}。` : '用户不存在。');
    res.redirect(303, ADMIN);
  }));

  ctx.effect(() => {
    const timer = setInterval(() => { for (const [id] of failures) if (!recent(id).length) failures.delete(id); }, 3600_000);
    timer.unref?.();
    return () => clearInterval(timer);
  });
  ctx.logger.info(`activated (mode=${config.mode}, passkeys=${config.webauthnEnable})`);
}
