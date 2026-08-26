/*
 * Author: MoyuZJ
 * Team: LinearTeam
 * Contact: linearteam@foxmail.com
 * Made by MoyuZJ in China with ♥
 */

/**
 * 还原码生成与消费。
 *
 * - 每个还原码由 4 个简单英文单词以 `-` 连接（如 morning-apple-bed-egg），
 *   便于口述与手抄；同一批 10 个码共占用 40 个词位，任何单词在全批中只出现一次。
 * - 词表共 64 个常见低级词汇，洗牌后取前 40 个；熵约 log2(64*63*...*25) ≈ 190 位。
 * - 存储只保留 SHA-256 哈希（与密码同等级对待），验证成功立即作废（单次使用）。
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
