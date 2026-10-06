/*
 * Easy 2FA Configuration Model
 *
 * Configuration model for the Easy 2FA plugin.
 *
 * Authors:
 * MoyuZJ <moyuzj@moyuzj.cn> @LinearTeam - Made in China with ♥
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Configuration model for the two-step verification plugin.
 *
 * <p>The whole configuration is persisted as JSON in the plugin registry
 * (ctx.plugins.getConfig/setConfig) with defaults + shallow merging, keeping behavior
 * predictable when fields are missing (consistent with easy-captcha and
 * advanced-user-management). This module does not depend on Base internals, only on the
 * plugins service exposed by the Cordis Context.</p>
 *
 * @since 1.0.0
 */

/** 插件注册表配置服务的最小接口（由 ctx.plugins 满足）。 */
export interface PluginConfigService {
  getConfig<T = unknown>(id: string): T | null;
  setConfig(id: string, config: unknown): void;
}

/** 两步验证模式：off 关闭 | optional 开启（用户自选）| strict 严格开启（全员强制）。 */
export type TwoFactorMode = 'off' | 'optional' | 'strict';

export interface Easy2faConfig {
  /** 验证模式，默认 off（不启用）。 */
  mode: TwoFactorMode;
  /** 是否允许 WebAuthn 通行密钥作为辅助登录（降低安全性，默认关闭）。 */
  webauthnEnable: boolean;
  /** 签发方名称：显示在验证器 App 与 otpauth URI 的 issuer 中。 */
  issuer: string;
  /** TOTP 校验窗口（允许前后 N 个周期，默认 1 = ±30s），兼顾设备时钟偏差。 */
  totpWindow: number;
}

const DEFAULT_CONFIG: Easy2faConfig = {
  mode: 'off',
  webauthnEnable: false,
  issuer: 'LinearPress',
  totpWindow: 1
};

export function getDefaultConfig(): Easy2faConfig { return structuredClone(DEFAULT_CONFIG); }

function asBoolean(value: unknown, fallback: boolean): boolean { return typeof value === 'boolean' ? value : fallback; }
function asString(value: unknown, fallback: string): string { return typeof value === 'string' ? value : fallback; }
function asInt(value: unknown, fallback: number, min: number, max: number): number {
  const n = Math.floor(Number(value));
  return Number.isFinite(n) && n >= min && n <= max ? n : fallback;
}

/** 合并用户配置到默认值；未知字段忽略，非法数值回退默认。 */
export function normalizeConfig(raw: unknown): Easy2faConfig {
  const input = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
  const defaults = getDefaultConfig();
  const mode = input.mode === 'optional' || input.mode === 'strict' ? input.mode : 'off';
  return {
    mode,
    webauthnEnable: asBoolean(input.webauthnEnable, defaults.webauthnEnable),
    issuer: asString(input.issuer, defaults.issuer).trim() || defaults.issuer,
    totpWindow: asInt(input.totpWindow, defaults.totpWindow, 0, 5)
  };
}

export function loadConfig(plugins: PluginConfigService): Easy2faConfig {
  return normalizeConfig(plugins.getConfig<unknown>('easy-2fa'));
}

export function saveConfig(plugins: PluginConfigService, config: Easy2faConfig): void {
  plugins.setConfig('easy-2fa', config);
}

/** 从设置页表单构建配置（checkbox 为 on/undefined，数字为空回退默认）。 */
export function parseSettingsForm(body: Record<string, unknown>): Easy2faConfig {
  const checkbox = (value: unknown): boolean => value === 'on' || value === '1' || value === true;
  const text = (value: unknown): string => String(value ?? '').trim();
  return normalizeConfig({
    mode: text(body.mode) === 'optional' || text(body.mode) === 'strict' ? text(body.mode) : 'off',
    webauthnEnable: checkbox(body.webauthn_enable),
    issuer: text(body.issuer),
    totpWindow: body.totp_window
  });
}
