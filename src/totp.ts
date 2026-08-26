/*
 * Author: MoyuZJ
 * Team: LinearTeam
 * Contact: linearteam@foxmail.com
 * Made by MoyuZJ in China with ♥
 */

/**
 * TOTP（RFC 6238）与 Base32（RFC 4648）实现，仅依赖 node:crypto。
 *
 * 参数与主流验证器对齐：HMAC-SHA1、6 位数字、30 秒周期；校验窗口 ±window 个
 * 周期以容忍设备时钟偏差。密钥为随机 20 字节（160 位），Base32 无填充编码，
 * 生成的 otpauth:// URI 可被 Google/Microsoft Authenticator、1Password、Aegis 等直接扫描。
 */

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** 生成新的 TOTP 密钥：20 字节随机数，返回无填充 Base32 字符串（32 字符）。 */
export function generateSecret(): string {
  return encodeBase32(randomBytes(20));
}

/** Base32 编码（RFC 4648，无填充）。 */
export function encodeBase32(bytes: Uint8Array): string {
  let output = '';
  let bits = 0;
  let value = 0;
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

/** Base32 解码（RFC 4648）：忽略空白、大小写不敏感、容忍填充符。非法字符抛错。 */
export function decodeBase32(input: string): Buffer {
  const clean = input.toUpperCase().replace(/[\s=-]/g, '');
  if (!clean.length) throw new Error('密钥为空');
  const bytes: number[] = [];
  let bits = 0;
  let value = 0;
  for (const char of clean) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index < 0) throw new Error('密钥包含非法字符');
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

/** 计算 HOTP（RFC 4226）并格式化为 6 位数字。 */
function hotp(secret: Buffer, counter: number): string {
  const buffer = Buffer.alloc(8);
  buffer.writeUInt32BE(Math.floor(counter / 2 ** 32), 0);
  buffer.writeUInt32BE(counter % 2 ** 32, 4);
  const digest = createHmac('sha1', secret).update(buffer).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const code = ((digest[offset] & 0x7f) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3];
  return String(code % 1_000_000).padStart(6, '0');
}

export interface TotpVerifyResult {
  /** 是否校验通过。 */
  ok: boolean;
  /** 通过时命中的时间片（用于 last_totp_step 防重放），失败为 -1。 */
  step: number;
}

/**
 * 校验 6 位验证码：在 [nowStep-window, nowStep+window] 内寻找匹配的时间片。
 * 命中后由调用方把 last_totp_step 更新为该值，后续拒绝相同或更早的时间片（防重放）。
 */
export function verifyTotp(base32Secret: string, code: string, nowMs: number, window: number, lastStep: number): TotpVerifyResult {
  const normalized = code.replace(/\s+/g, '');
  if (!/^\d{6}$/.test(normalized)) return { ok: false, step: -1 };
  let secret: Buffer;
  try {
    secret = decodeBase32(base32Secret);
  } catch {
    return { ok: false, step: -1 };
  }
  const nowStep = Math.floor(nowMs / 1000 / 30);
  for (let offset = -window; offset <= window; offset++) {
    const step = nowStep + offset;
    if (step <= lastStep) continue; // 只接受比上次使用更新的事件（含跨设备同码重放）
    const expected = hotp(secret, step);
    const a = Buffer.from(expected);
    const b = Buffer.from(normalized);
    if (a.length === b.length && timingSafeEqual(a, b)) return { ok: true, step };
  }
  return { ok: false, step: -1 };
}

/** 当前验证码（用于服务端自测/演示场景，正常流程不会用到）。 */
export function currentTotp(base32Secret: string, nowMs: number = Date.now()): string {
  return hotp(decodeBase32(base32Secret), Math.floor(nowMs / 1000 / 30));
}

/**
 * 构造 otpauth:// URI（Key URI Format，Google Authenticator 兼容）：
 * otpauth://totp/<issuer>:<account>?secret=...&issuer=<issuer>&algorithm=SHA1&digits=6&period=30
 */
export function buildOtpauthUri(base32Secret: string, issuer: string, account: string): string {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const params = new URLSearchParams({
    secret: base32Secret,
    issuer,
    algorithm: 'SHA1',
    digits: '6',
    period: '30'
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}
