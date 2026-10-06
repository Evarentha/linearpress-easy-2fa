/*
 * Recovery Code Generation and Consumption
 *
 * Generation and single-use consumption of four-word recovery codes.
 *
 * Authors:
 * MoyuZJ <moyuzj@moyuzj.cn> @LinearTeam - Made in China with ♥
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Recovery code generation and consumption.
 *
 * <ul>
 * <li>Each recovery code joins 4 simple English words with `-` (e.g. morning-apple-bed-egg),
 * making it easy to read aloud and copy by hand; a batch of 10 codes occupies 40 word slots
 * and no word appears more than once in the whole batch.</li>
 * <li>The word list holds 83 common, basic words; it is shuffled and the first 40 are taken,
 * for roughly log2(83*82*...*44) ≈ 240 bits of entropy.</li>
 * <li>Storage keeps only SHA-256 hashes (treated with the same care as passwords); a
 * successful verification invalidates the code immediately (single use).</li>
 * </ul>
 *
 * @since 1.0.0
 */

import { createHash, randomUUID, randomInt } from 'node:crypto';

/** 简单词汇表：全部为常用、无高级词汇、易拼写的小写英文单词。 */
const WORDS = [
  'apple', 'arrow', 'autumn', 'banana', 'basket', 'battery', 'bed', 'bird',
  'book', 'bread', 'bridge', 'butter', 'candle', 'castle', 'cheese', 'cherry',
  'cloud', 'coffee', 'copper', 'cotton', 'dance', 'desk', 'dinner', 'door',
  'dream', 'egg', 'farm', 'field', 'fire', 'fish', 'flower', 'forest',
  'garden', 'glass', 'grape', 'grass', 'green', 'harbor', 'horse', 'house',
  'island', 'kitchen', 'lake', 'lamp', 'leaf', 'leave', 'lemon', 'lunch',
  'market', 'melon', 'money', 'moon', 'morning', 'mountain', 'night', 'ocean',
  'orange', 'paper', 'pencil', 'pepper', 'pillow', 'plant', 'rain', 'river',
  'road', 'salt', 'sand', 'ship', 'silver', 'snow', 'sugar', 'summer',
  'table', 'tea', 'tiger', 'tomato', 'train', 'tree', 'water', 'window',
  'winter', 'wolf', 'wood'
];

export const RECOVERY_CODE_COUNT = 10;
export const WORDS_PER_CODE = 4;

/** Fisher-Yates 洗牌（crypto 随机源）。 */
function shuffle<T>(items: T[]): T[] {
  const copy = [...items];
  for (let i = copy.length - 1; i > 0; i--) {
    const j = randomInt(0, i + 1);
    [copy[i], copy[j]] = [copy[j], copy[i]];
  }
  return copy;
}

export interface GeneratedRecoveryCodes {
  /** 明文还原码（仅在生成瞬间返回一次，之后数据库只有哈希）。 */
  codes: string[];
  /** 与 codes 一一对应的哈希（入库）。 */
  hashes: string[];
  /** 与 codes 一一对应的一次性记录 ID（入库主键）。 */
  ids: string[];
}

/** 生成一批还原码：10 组 × 4 词，全批单词不重复。 */
export function generateRecoveryCodes(): GeneratedRecoveryCodes {
  const needed = RECOVERY_CODE_COUNT * WORDS_PER_CODE;
  if (WORDS.length < needed) throw new Error('词表不足');
  const picked = shuffle(WORDS).slice(0, needed);
  const codes: string[] = [];
  const hashes: string[] = [];
  const ids: string[] = [];
  for (let i = 0; i < RECOVERY_CODE_COUNT; i++) {
    const words = picked.slice(i * WORDS_PER_CODE, (i + 1) * WORDS_PER_CODE);
    const code = words.join('-');
    codes.push(code);
    hashes.push(hashRecoveryCode(code));
    ids.push(randomUUID());
  }
  return { codes, hashes, ids };
}

/** 归一化并哈希：忽略大小写与多余空白，分隔符统一为单个 `-`。 */
export function hashRecoveryCode(code: string): string {
  const normalized = code.toLowerCase().trim().split(/[\s-]+/).filter(Boolean).join('-');
  return createHash('sha256').update(normalized, 'utf8').digest('hex');
}
