/*
 * Easy 2FA Data Access Layer
 *
 * Standard-SQL data access for secrets, recovery codes and passkeys.
 *
 * Authors:
 * MoyuZJ <moyuzj@evarentha.com> @LinearTeam - Made in China with ♥
 * worryzu <worryzu@evarentha.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Data access layer: uses only standard SQL (compatible with both SQLite and MySQL), invoked
 * through databaseService and following the main business database (still correct when the
 * MySQL driver is active). This module does not depend on Base internals.
 *
 * @since 1.0.0
 */

import type { DatabaseService } from 'linearpress/plugin-api';

type Db = DatabaseService;

export interface TwoFactorRow { user_id: number; secret: string; enabled: number; last_totp_step: number; created_at: number; confirmed_at: number | null; }
export interface RecoveryRow { id: string; user_id: number; code_hash: string; used: number; used_at: number | null; }
export interface PasskeyRow { id: string; user_id: number; public_key_cose: string; sign_count: number; name: string; created_at: number; last_used_at: number | null; }

/** 建表（含索引）。全部为跨方言标准 SQL，主键用 UUID 文本避免方言差异；公钥以 Base64URL 文本存储。 */
export async function ensureSchema(db: Db): Promise<void> {
  const mysql = db.dialect === 'mysql';
  const str = (n: number) => mysql ? `VARCHAR(${n})` : 'TEXT';
  const int = mysql ? 'INT' : 'INTEGER';
  await db.exec([
    `CREATE TABLE IF NOT EXISTS easy2fa_users (user_id ${int} PRIMARY KEY, secret ${str(64)} NOT NULL, enabled INT NOT NULL DEFAULT 0, last_totp_step BIGINT NOT NULL DEFAULT 0, created_at BIGINT NOT NULL, confirmed_at BIGINT NULL)`,
    `CREATE TABLE IF NOT EXISTS easy2fa_recovery_codes (id ${str(64)} PRIMARY KEY, user_id ${int} NOT NULL, code_hash ${str(128)} NOT NULL, used INT NOT NULL DEFAULT 0, used_at BIGINT NULL)`,
    `CREATE TABLE IF NOT EXISTS easy2fa_passkeys (id ${str(255)} PRIMARY KEY, user_id ${int} NOT NULL, public_key_cose ${mysql ? 'TEXT' : 'TEXT'} NOT NULL, sign_count BIGINT NOT NULL DEFAULT 0, name ${str(80)} NOT NULL DEFAULT '', created_at BIGINT NOT NULL, last_used_at BIGINT NULL)`
  ].join(';\n'));
  if (!mysql) await db.exec('CREATE INDEX IF NOT EXISTS idx_easy2fa_recovery_user ON easy2fa_recovery_codes(user_id, used); CREATE INDEX IF NOT EXISTS idx_easy2fa_passkeys_user ON easy2fa_passkeys(user_id)');
}

/** Status of every user in one query (admin list). */
export async function statusByUser(db: Db): Promise<Map<number, { enabled: boolean; confirmedAt: number | null; recovery: number; passkeys: number }>> {
  const rows = await db.all<{ user_id: number; enabled: number; confirmed_at: number | null; recovery: number; passkeys: number }>(
    `SELECT u.user_id, u.enabled, u.confirmed_at,
      (SELECT COUNT(*) FROM easy2fa_recovery_codes r WHERE r.user_id = u.user_id AND r.used = 0) AS recovery,
      (SELECT COUNT(*) FROM easy2fa_passkeys p WHERE p.user_id = u.user_id) AS passkeys
     FROM easy2fa_users u`);
  return new Map(rows.map((row) => [Number(row.user_id), { enabled: Number(row.enabled) === 1, confirmedAt: row.confirmed_at ? Number(row.confirmed_at) : null, recovery: Number(row.recovery), passkeys: Number(row.passkeys) }]));
}
/* ------------------------------------------------------------ 用户密钥 */

export async function getTwoFactor(db: Db, userId: number): Promise<TwoFactorRow | undefined> {
  return db.get<TwoFactorRow>('SELECT * FROM easy2fa_users WHERE user_id=?', userId);
}

/** 创建未确认的绑定记录（严格模式进入绑定页时调用）；已存在则保留。 */
export async function upsertPendingSecret(db: Db, userId: number, secret: string, now: number): Promise<void> {
  const existing = await getTwoFactor(db, userId);
  if (existing) {
    // 已启用的绑定不允许覆盖密钥：需先关闭两步验证再重新绑定，防止中途放弃绑定导致软锁。
    if (existing.enabled) throw new Error('两步验证已启用，请先关闭后再重新绑定。');
    return void (await db.run('UPDATE easy2fa_users SET secret=? WHERE user_id=?', secret, userId));
  }
  await db.run('INSERT INTO easy2fa_users (user_id, secret, enabled, last_totp_step, created_at) VALUES (?, ?, 0, 0, ?)', userId, secret, now);
}

/** 确认绑定：写入正式启用的密钥并清空旧状态（还原码与通行密钥一并作废，由调用方决定是否重建还原码）。 */
export async function confirmBinding(db: Db, userId: number, now: number): Promise<void> {
  await db.run('UPDATE easy2fa_users SET enabled=1, confirmed_at=?, last_totp_step=0 WHERE user_id=?', now, userId);
}

export async function updateLastStep(db: Db, userId: number, step: number): Promise<void> {
  await db.run('UPDATE easy2fa_users SET last_totp_step=? WHERE user_id=?', step, userId);
}

/** 完全移除某用户的两步验证（管理员关闭 / 用户自行关闭共用）：连带删除还原码与通行密钥。 */
export async function removeTwoFactor(db: Db, userId: number): Promise<void> {
  await db.run('DELETE FROM easy2fa_users WHERE user_id=?', userId);
  await db.run('DELETE FROM easy2fa_recovery_codes WHERE user_id=?', userId);
  await db.run('DELETE FROM easy2fa_passkeys WHERE user_id=?', userId);
}

/* ------------------------------------------------------------ 还原码 */

export async function replaceRecoveryCodes(db: Db, userId: number, hashes: string[], ids: string[]): Promise<void> {
  await db.transaction(async () => {
    await db.run('DELETE FROM easy2fa_recovery_codes WHERE user_id=?', userId);
    for (let i = 0; i < hashes.length; i++) {
      await db.run('INSERT INTO easy2fa_recovery_codes (id, user_id, code_hash, used) VALUES (?, ?, ?, 0)', ids[i], userId, hashes[i]);
    }
  });
}

export async function listRecoveryCodes(db: Db, userId: number): Promise<RecoveryRow[]> {
  return db.all<RecoveryRow>('SELECT * FROM easy2fa_recovery_codes WHERE user_id=? ORDER BY used_at IS NOT NULL, used_at DESC, id', userId);
}

/** 按哈希查找未使用的还原码；命中即标记作废并返回 true（原子单次消费）。 */
export async function consumeRecoveryCode(db: Db, userId: number, codeHash: string, now: number): Promise<boolean> {
  const row = await db.get<RecoveryRow>('SELECT * FROM easy2fa_recovery_codes WHERE user_id=? AND code_hash=? AND used=0', userId, codeHash);
  if (!row) return false;
  // The conditional UPDATE's affected-row count identifies the winner; timestamps are not unique ownership tokens.
  const result = await db.run('UPDATE easy2fa_recovery_codes SET used=1, used_at=? WHERE id=? AND used=0', now, row.id) as { changes?: number | bigint };
  if (!result || result.changes === undefined) throw new Error('数据库驱动未返回恢复码消费结果');
  return Number(result.changes) === 1;
}

export async function countUnusedRecoveryCodes(db: Db, userId: number): Promise<number> {
  const row = await db.get<{ n: number }>('SELECT COUNT(*) AS n FROM easy2fa_recovery_codes WHERE user_id=? AND used=0', userId);
  return Number(row?.n ?? 0);
}

/* ------------------------------------------------------------ 通行密钥 */

export async function addPasskey(db: Db, row: PasskeyRow): Promise<void> {
  await db.run(
    'INSERT INTO easy2fa_passkeys (id, user_id, public_key_cose, sign_count, name, created_at) VALUES (?, ?, ?, ?, ?, ?)',
    row.id, row.user_id, row.public_key_cose, row.sign_count, row.name, row.created_at
  );
}

export async function listPasskeys(db: Db, userId: number): Promise<PasskeyRow[]> {
  return db.all<PasskeyRow>('SELECT * FROM easy2fa_passkeys WHERE user_id=? ORDER BY created_at DESC', userId);
}

export async function getPasskey(db: Db, credentialId: string): Promise<PasskeyRow | undefined> {
  return db.get<PasskeyRow>('SELECT * FROM easy2fa_passkeys WHERE id=?', credentialId);
}

export async function updatePasskeySignCount(db: Db, credentialId: string, signCount: number, now: number): Promise<void> {
  await db.run('UPDATE easy2fa_passkeys SET sign_count=?, last_used_at=? WHERE id=?', signCount, now, credentialId);
}

export async function deletePasskey(db: Db, userId: number, credentialId: string): Promise<void> {
  await db.run('DELETE FROM easy2fa_passkeys WHERE id=? AND user_id=?', credentialId, userId);
}
