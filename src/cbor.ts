/*
 * Minimal CBOR Decoder
 *
 * Minimal RFC 8949 subset decoder for WebAuthn attestation objects.
 *
 * Authors:
 * MoyuZJ <moyuzj@moyuzj.cn> @LinearTeam - Made in China with ♥
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Minimal CBOR decoder (RFC 8949 subset), covering only the types required by WebAuthn
 * attestationObject: unsigned/negative integers, byte strings, text strings, arrays, maps,
 * tag skipping and common simple values. Unsupported types throw an error.
 *
 * @since 1.0.0
 */

export class CborDecoder {
  private offset = 0;

  constructor(private readonly buffer: Buffer) {}

  /** 从指定偏移开始解码（用于 authData 中内嵌 COSE 密钥的场景）。 */
  static decodeAt(buffer: Buffer, offset: number): { value: unknown; bytesConsumed: number } {
    const decoder = new CborDecoder(buffer);
    decoder.offset = offset;
    const value = decoder.decodeItem();
    return { value, bytesConsumed: decoder.offset - offset };
  }

  decodeItem(): unknown {
    const initial = this.readByte();
    const majorType = initial >> 5;
    const shortCount = initial & 0x1f;
    const count = this.readCount(shortCount);

    switch (majorType) {
      case 0: return count; // 无符号整数
      case 1: return -1 - count; // 负整数
      case 2: return this.readBytes(count); // 字节串
      case 3: return this.readBytes(count).toString('utf8'); // 文本串
      case 4: { // 数组
        const items: unknown[] = [];
        for (let i = 0; i < count; i++) items.push(this.decodeItem());
        return items;
      }
      case 5: { // 映射（键保持原始类型；WebAuthn COSE 键的键为整数）
        const map = new Map<unknown, unknown>();
        for (let i = 0; i < count; i++) {
          const key = this.decodeItem();
          map.set(key, this.decodeItem());
        }
        return map;
      }
      case 6: return this.decodeItem(); // 标签：跳过标签号，返回内部值
      case 7: // 简单值 / 浮点
        if (shortCount === 20) return false;
        if (shortCount === 21) return true;
        if (shortCount === 22 || shortCount === 23) return null;
        if (shortCount === 24) return this.readByte(); // 扩展简单值（透传数值）
        if (shortCount === 25 || shortCount === 26 || shortCount === 27) return null; // 浮点（WebAuthn 不使用，忽略）
        throw new Error(`不支持的 CBOR 简单值：${shortCount}`);
      default:
        throw new Error(`不支持的 CBOR 主类型：${majorType}`);
    }
  }

  private readByte(): number {
    if (this.offset >= this.buffer.length) throw new Error('CBOR 数据提前结束');
    return this.buffer[this.offset++];
  }

  private readBytes(length: number): Buffer {
    if (this.offset + length > this.buffer.length) throw new Error('CBOR 数据提前结束');
    const slice = this.buffer.subarray(this.offset, this.offset + length);
    this.offset += length;
    return Buffer.from(slice);
  }

  /** 解析附加信息为长度/数值（含不定长 0x1f 拒绝）。 */
  private readCount(shortCount: number): number {
    if (shortCount < 24) return shortCount;
    if (shortCount === 24) return this.readByte();
    if (shortCount === 25) return this.readBytes(2).readUInt16BE(0);
    if (shortCount === 26) return this.readBytes(4).readUInt32BE(0);
    if (shortCount === 27) return Number(this.readBytes(8).readBigUInt64BE(0));
    throw new Error('不支持 CBOR 不定长编码');
  }
}

/** 顶层解码入口。 */
export function cborDecode(buffer: Buffer): unknown {
  return CborDecoder.decodeAt(buffer, 0).value;
}
