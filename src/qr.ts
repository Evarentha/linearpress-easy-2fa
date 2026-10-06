/*
 * Zero-Dependency QR Code Encoder
 *
 * Zero-dependency QR encoder rendering otpauth URIs as inline SVG.
 *
 * Authors:
 * MoyuZJ <moyuzj@moyuzj.cn> @LinearTeam - Made in China with ♥
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Zero-dependency QR code encoder (ISO/IEC 18004): byte mode, ECC level M, adaptive versions
 * 1-40, best mask chosen by full mask evaluation; outputs an inline SVG (crispEdges, with a
 * 4-module quiet zone).
 *
 * <p>Used to render the otpauth:// URI as a QR code that authenticators can scan; the
 * implementation follows the standard algorithm (data stream → block-wise Reed-Solomon error
 * correction → interleaving → function patterns → mask penalty scoring) and shares the
 * "zero dependency" strategy with easy-captcha's hand-written PNG encoder.</p>
 *
 * @since 1.0.0
 */

type EccLevel = 'L' | 'M' | 'Q' | 'H';

/* ------------------------------------------------------------------ 常量表（索引 0 为占位，版本从 1 开始） */

/** 每块纠错码字数（ECC 级别 × 版本）。 */
const ECC_CODEWORDS_PER_BLOCK: Record<EccLevel, number[]> = {
  L: [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  M: [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
  Q: [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  H: [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30]
};

/** 纠错块数（ECC 级别 × 版本）。 */
const NUM_ERROR_CORRECTION_BLOCKS: Record<EccLevel, number[]> = {
  L: [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
  M: [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
  Q: [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
  H: [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81]
};

/** 格式信息中 ECC 级别的指示位。 */
const ECC_FORMAT_BITS: Record<EccLevel, number> = { L: 1, M: 0, Q: 3, H: 2 };

const PENALTY_N1 = 3;
const PENALTY_N3 = 40;

/* ------------------------------------------------------------------ 容量计算 */

function getNumRawDataModules(version: number): number {
  let result = (16 * version + 128) * version + 64;
  if (version >= 2) {
    const numAlign = Math.floor(version / 7) + 2;
    result -= (25 * numAlign - 10) * numAlign - 55;
    if (version >= 7) result -= 36;
  }
  return result;
}

function getNumDataCodewords(version: number, ecc: EccLevel): number {
  return Math.floor(getNumRawDataModules(version) / 8) - ECC_CODEWORDS_PER_BLOCK[ecc][version] * NUM_ERROR_CORRECTION_BLOCKS[ecc][version];
}

function getAlignmentPatternPositions(version: number): number[] {
  if (version === 1) return [];
  const numAlign = Math.floor(version / 7) + 2;
  const step = version === 32 ? 26 : Math.ceil((version * 4 + 4) / (numAlign * 2 - 2)) * 2;
  const result = [6];
  for (let pos = version * 4 + 10; result.length < numAlign; pos -= step) result.splice(1, 0, pos);
  return result;
}

/* ------------------------------------------------------------------ Reed-Solomon 纠错（GF(2^8)，本原多项式 0x11d） */

function rsMultiply(x: number, y: number): number {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z & 0xff;
}

/** 计算次数为 degree 的 RS 生成多项式。 */
function rsComputeDivisor(degree: number): number[] {
  const result: number[] = new Array<number>(degree).fill(0);
  result[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < degree; j++) {
      result[j] = rsMultiply(result[j], root);
      if (j + 1 < degree) result[j] ^= result[j + 1];
    }
    root = rsMultiply(root, 2);
  }
  return result;
}

/** 计算一段数据的 RS 纠错码字。 */
function rsGetRemainder(data: number[], divisor: number[]): number[] {
  const result = divisor.map(() => 0);
  for (const b of data) {
    const factor = b ^ (result.shift() as number);
    result.push(0);
    divisor.forEach((coef, i) => { result[i] ^= rsMultiply(coef, factor); });
  }
  return result;
}

/* ------------------------------------------------------------------ 工具 */

function getBit(x: number, i: number): boolean { return ((x >>> i) & 1) !== 0; }

function maskBit(mask: number, x: number, y: number): boolean {
  switch (mask) {
    case 0: return (x + y) % 2 === 0;
    case 1: return y % 2 === 0;
    case 2: return x % 3 === 0;
    case 3: return (x + y) % 3 === 0;
    case 4: return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0;
    case 5: return (x * y) % 2 + (x * y) % 3 === 0;
    case 6: return ((x * y) % 2 + (x * y) % 3) % 2 === 0;
    default: return ((x + y) % 2 + (x * y) % 3) % 2 === 0;
  }
}

/* ------------------------------------------------------------------ 矩阵构建 */

export interface QrMatrix { readonly size: number; get(x: number, y: number): boolean; }

class MatrixBuilder {
  readonly size: number;
  private readonly modules: boolean[][];
  private readonly isFunction: boolean[][];

  constructor(private version: number) {
    this.size = version * 4 + 17;
    this.modules = Array.from({ length: this.size }, () => new Array<boolean>(this.size).fill(false));
    this.isFunction = Array.from({ length: this.size }, () => new Array<boolean>(this.size).fill(false));
  }

  private setFunctionModule(x: number, y: number, dark: boolean): void {
    this.modules[y][x] = dark;
    this.isFunction[y][x] = true;
  }

  /** 定位图形（含周围分隔区的留白）。 */
  private drawFinderPattern(x: number, y: number): void {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const dist = Math.max(Math.abs(dx), Math.abs(dy));
        const px = x + dx;
        const py = y + dy;
        if (px >= 0 && px < this.size && py >= 0 && py < this.size) this.setFunctionModule(px, py, dist !== 2 && dist !== 4);
      }
    }
  }

  /** 时序图形、定位图形、格式/版本信息等固定结构（先时序后定位，覆盖关系见下）。 */
  drawFunctionPatterns(): void {
    // 时序图形先画（贯穿全图），随后三个定位图形会覆盖其在自身区域内的部分。
    for (let i = 0; i < this.size; i++) {
      this.setFunctionModule(6, i, i % 2 === 0);
      this.setFunctionModule(i, 6, i % 2 === 0);
    }
    this.drawFinderPattern(3, 3);
    this.drawFinderPattern(this.size - 4, 3);
    this.drawFinderPattern(3, this.size - 4);
    this.drawAlignmentPatterns();
    this.drawFormatBits(0); // 先以 mask 0 占位，选定掩码后重绘
    this.drawVersion();
  }

  private drawAlignmentPatterns(): void {
    const positions = getAlignmentPatternPositions(this.version);
    const count = positions.length;
    for (let i = 0; i < count; i++) {
      for (let j = 0; j < count; j++) {
        if ((i === 0 && j === 0) || (i === 0 && j === count - 1) || (i === count - 1 && j === 0)) continue;
        for (let dy = -2; dy <= 2; dy++) {
          for (let dx = -2; dx <= 2; dx++) {
            this.setFunctionModule(positions[i] + dx, positions[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
          }
        }
      }
    }
  }

  drawFormatBits(mask: number): void {
    const data = ECC_FORMAT_BITS.M << 3 | mask;
    let rem = data;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    const bits = ((data << 10) | rem) ^ 0x5412;
    // 第一份：环绕左上定位图形
    for (let i = 0; i <= 5; i++) this.setFunctionModule(8, i, getBit(bits, i));
    this.setFunctionModule(8, 7, getBit(bits, 6));
    this.setFunctionModule(8, 8, getBit(bits, 7));
    this.setFunctionModule(7, 8, getBit(bits, 8));
    for (let i = 9; i < 15; i++) this.setFunctionModule(14 - i, 8, getBit(bits, i));
    // 第二份：拆分在右上与左下
    for (let i = 0; i < 8; i++) this.setFunctionModule(this.size - 1 - i, 8, getBit(bits, i));
    for (let i = 8; i < 15; i++) this.setFunctionModule(8, this.size - 15 + i, getBit(bits, i));
    this.setFunctionModule(8, this.size - 8, true); // 固定黑模块
  }

  private drawVersion(): void {
    if (this.version < 7) return;
    let rem = this.version;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const bits = (this.version << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const bit = getBit(bits, i);
      const a = this.size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      this.setFunctionModule(a, b, bit);
      this.setFunctionModule(b, a, bit);
    }
  }

  drawCodewords(data: number[]): void {
    if (data.length !== Math.floor(getNumRawDataModules(this.version) / 8)) throw new Error('码字长度不匹配');
    let i = 0;
    // 右起两列为一组，蛇形自下而上/自上而下填充；第 6 列为时序图形需跳过。
    for (let right = this.size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (let vert = 0; vert < this.size; vert++) {
        for (let j = 0; j < 2; j++) {
          const x = right - j;
          const upward = ((right + 1) & 2) === 0;
          const y = upward ? this.size - 1 - vert : vert;
          if (!this.isFunction[y][x] && i < data.length * 8) {
            this.modules[y][x] = getBit(data[i >>> 3], 7 - (i & 7));
            i++;
          }
        }
      }
    }
  }

  applyMask(mask: number): void {
    for (let y = 0; y < this.size; y++) {
      for (let x = 0; x < this.size; x++) {
        if (!this.isFunction[y][x] && maskBit(mask, x, y)) this.modules[y][x] = !this.modules[y][x];
      }
    }
  }

  /* ---------------- 掩码罚分（四条规则） ---------------- */

  private finderPenaltyAddHistory(currentRunLength: number, runHistory: number[]): void {
    if (runHistory[0] === 0) currentRunLength += this.size; // 初始段补上浅色边框
    runHistory.pop();
    runHistory.unshift(currentRunLength);
  }

  private finderPenaltyCountPatterns(runHistory: number[]): number {
    const n = runHistory[1];
    const core = n > 0 && runHistory[2] === n && runHistory[3] === n * 3 && runHistory[4] === n && runHistory[5] === n;
    return (core && runHistory[0] >= n * 4 && runHistory[6] >= n ? 1 : 0) +
      (core && runHistory[6] >= n * 4 && runHistory[0] >= n ? 1 : 0);
  }

  private finderPenaltyTerminateAndCount(currentRunColor: boolean, currentRunLength: number, runHistory: number[]): number {
    if (currentRunColor) {
      this.finderPenaltyAddHistory(currentRunLength, runHistory);
      currentRunLength = 0;
    }
    currentRunLength += this.size; // 末段补上浅色边框
    this.finderPenaltyAddHistory(currentRunLength, runHistory);
    return this.finderPenaltyCountPatterns(runHistory);
  }

  getPenaltyScore(): number {
    let result = 0;
    const size = this.size;
    const m = this.modules;

    // 规则 1（行/列连续同色 ≥5）与规则 3（类定位图形比例）融合扫描。
    for (let y = 0; y < size; y++) {
      let runColor = false;
      let runLen = 0;
      const history = [0, 0, 0, 0, 0, 0, 0];
      for (let x = 0; x < size; x++) {
        if (m[y][x] === runColor) {
          runLen++;
          if (runLen === 5) result += PENALTY_N1;
          else if (runLen > 5) result += 1;
        } else {
          result += this.finderPenaltyTerminateAndCount(runColor, runLen, history) * PENALTY_N3;
          runColor = m[y][x];
          runLen = 1;
        }
      }
      result += this.finderPenaltyTerminateAndCount(runColor, runLen, history) * PENALTY_N3;
    }
    for (let x = 0; x < size; x++) {
      let runColor = false;
      let runLen = 0;
      const history = [0, 0, 0, 0, 0, 0, 0];
      for (let y = 0; y < size; y++) {
        if (m[y][x] === runColor) {
          runLen++;
          if (runLen === 5) result += PENALTY_N1;
          else if (runLen > 5) result += 1;
        } else {
          result += this.finderPenaltyTerminateAndCount(runColor, runLen, history) * PENALTY_N3;
          runColor = m[y][x];
          runLen = 1;
        }
      }
      result += this.finderPenaltyTerminateAndCount(runColor, runLen, history) * PENALTY_N3;
    }

    // 规则 2：2×2 同色块。
    for (let y = 0; y < size - 1; y++) {
      for (let x = 0; x < size - 1; x++) {
        const c = m[y][x];
        if (c === m[y][x + 1] && c === m[y + 1][x] && c === m[y + 1][x + 1]) result += PENALTY_N1;
      }
    }

    // 规则 4：黑白色比例偏差。
    let dark = 0;
    for (const row of m) for (const cell of row) if (cell) dark++;
    const total = size * size;
    const k = Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1;
    result += k * 10;
    return result;
  }

  build(): QrMatrix {
    return { size: this.size, get: (x, y) => this.modules[y][x] };
  }
}

/* ------------------------------------------------------------------ 主流程 */

/**
 * 把 UTF-8 文本编码为 QR 码矩阵：byte 模式、ECC M、最小可容纳版本、最优掩码。
 */
export function encodeTextToMatrix(text: string): QrMatrix {
  const data = Buffer.from(text, 'utf8');

  // 选择能容纳的最小版本（byte 模式字符数指示：v1-9 用 8 位，v10+ 用 16 位）。
  let version = 0;
  for (let v = 1; v <= 40; v++) {
    const neededBits = 4 + (v < 10 ? 8 : 16) + data.length * 8;
    if (neededBits <= getNumDataCodewords(v, 'M') * 8) { version = v; break; }
  }
  if (!version) throw new Error('内容过长，无法生成二维码');

  // 构造比特流：模式指示 + 字符数 + 数据 + 终止符 + 补齐到字节 + 填充字节。
  const capacityBits = getNumDataCodewords(version, 'M') * 8;
  const bb: number[] = [];
  const appendBits = (val: number, len: number): void => {
    for (let i = len - 1; i >= 0; i--) bb.push((val >>> i) & 1);
  };
  appendBits(4, 4); // byte 模式指示符 0100
  appendBits(data.length, version < 10 ? 8 : 16);
  for (const b of data) appendBits(b, 8);
  appendBits(0, Math.min(4, capacityBits - bb.length)); // 终止符（最多 4 位）
  while (bb.length % 8 !== 0) bb.push(0);
  for (let padByte = 0xec; bb.length < capacityBits; padByte ^= 0xec ^ 0x11) appendBits(padByte, 8);

  const dataCodewords: number[] = [];
  for (let i = 0; i < bb.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j++) byte = (byte << 1) | bb[i + j];
    dataCodewords.push(byte);
  }

  // 分块 + RS 纠错码字 + 标准交织。
  const numBlocks = NUM_ERROR_CORRECTION_BLOCKS.M[version];
  const blockEccLen = ECC_CODEWORDS_PER_BLOCK.M[version];
  const rawCodewords = Math.floor(getNumRawDataModules(version) / 8);
  const numShortBlocks = numBlocks - (rawCodewords % numBlocks);
  const shortBlockLen = Math.floor(rawCodewords / numBlocks);

  const blocks: number[][] = [];
  const rsDivisor = rsComputeDivisor(blockEccLen);
  for (let i = 0, k = 0; i < numBlocks; i++) {
    const dat = dataCodewords.slice(k, k + shortBlockLen - blockEccLen + (i < numShortBlocks ? 0 : 1));
    k += dat.length;
    const ecc = rsGetRemainder(dat, rsDivisor);
    if (i < numShortBlocks) dat.push(0); // 短块补一个占位字节对齐交织位置
    blocks.push([...dat, ...ecc]);
  }

  const codewords: number[] = [];
  for (let i = 0; i < blocks[0].length; i++) {
    blocks.forEach((block, blockIdx) => {
      // 仅跳过短块在数据段末尾的占位字节（长块同位置是真实数据）。
      if (i !== shortBlockLen - blockEccLen || blockIdx >= numShortBlocks) codewords.push(block[i]);
    });
  }

  // 选掩码：绘制功能图形后逐一尝试，取罚分最低者。
  let best: MatrixBuilder | null = null;
  let bestPenalty = Infinity;
  for (let mask = 0; mask < 8; mask++) {
    const builder = new MatrixBuilder(version);
    builder.drawFunctionPatterns();
    builder.drawCodewords(codewords);
    builder.applyMask(mask);
    builder.drawFormatBits(mask);
    const penalty = builder.getPenaltyScore();
    if (penalty < bestPenalty) {
      bestPenalty = penalty;
      best = builder;
    }
  }
  if (!best) throw new Error('QR 编码失败');
  return best.build();
}

/** 渲染为内联 SVG（黑色模块 + 白底，含 border 个模块静区）。 */
export function renderQrSvg(text: string, border = 4): string {
  const qr = encodeTextToMatrix(text);
  const size = qr.size + border * 2;
  let path = '';
  for (let y = 0; y < qr.size; y++) {
    for (let x = 0; x < qr.size; x++) {
      if (qr.get(x, y)) path += `M${x + border},${y + border}h1v1h-1z`;
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="${size * 8}" height="${size * 8}" shape-rendering="crispEdges">` +
    `<rect width="${size}" height="${size}" fill="#ffffff"/><path d="${path}" fill="#111111"/></svg>`;
}
