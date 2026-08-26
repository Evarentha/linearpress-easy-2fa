/*
 * Author: MoyuZJ
 * Team: LinearTeam
 * Contact: linearteam@foxmail.com
 * Made by MoyuZJ in China with ♥
 */

/**
 * WebAuthn（通行密钥）服务端验证，仅依赖 node:crypto + 内置 CBOR 解码器。
 *
 * 支持范围与主流平台认证器对齐：
 * - 算法：ES256（EC2/P-256，alg -7）为主；RS256（RSA，alg -257）为辅。
 * - 证明格式：'none'（多数平台同步器密钥）与 'packed'（自证/证书链均接受签名结构，
 *   本插件不校验 attestation 证书链——注册信任基于 origin/rpId/challenge 校验）。
 * - 断言校验：challenge / origin / rpIdHash / UP 用户在场 / signCount 计数器防克隆。
 *
 * 注意：WebAuthn 要求安全上下文（HTTPS 或 localhost）。
 */

import { createHash, createPublicKey, randomBytes, verify as cryptoVerify, type KeyObject } from 'node:crypto';
import { CborDecoder, cborDecode } from './cbor.js';

/* ------------------------------------------------------------ Base64URL 工具 */

export function toBase64Url(buffer: Buffer | Uint8Array): string {
  return Buffer.from(buffer).toString('base64url');
}

export function fromBase64Url(value: string): Buffer {
  return Buffer.from(value, 'base64url');
}

/** 生成 32 字节挑战（Base64URL）。 */
export function generateChallenge(): string {
  return toBase64Url(randomBytes(32));
}

/* ------------------------------------------------------------ clientDataJSON */

interface ClientData { type: string; challenge: string; origin: string; }

function parseClientData(clientDataJson: string, expectedType: string, expectedChallenge: string, expectedOrigin: string): ClientData {
  const data = JSON.parse(clientDataJson) as Partial<ClientData>;
  if (data.type !== expectedType) throw new Error('WebAuthn 操作类型不匹配。');
  if (data.challenge !== expectedChallenge) throw new Error('WebAuthn 挑战不匹配，请重试。');
  if (!data.origin || normalizeOrigin(data.origin) !== normalizeOrigin(expectedOrigin)) {
    throw new Error(`WebAuthn 来源不合法：${data.origin}`);
  }
  return data as ClientData;
}

function normalizeOrigin(origin: string): string {
  try {
    const url = new URL(origin);
    return `${url.protocol}//${url.host}`;
  } catch {
    return origin.replace(/\/+$/, '');
  }
}

/* ------------------------------------------------------------ authData 解析 */

export interface ParsedAuthData {
  rpIdHash: Buffer;
  /** UP（0x01）用户在场；UV（0x04）用户已验证；AT（0x40）含新凭证；ED（0x80）含扩展。 */
  flags: number;
  signCount: number;
  /** 仅注册响应存在：新凭证的 ID 与 COSE 公钥映射。 */
  credentialId?: Buffer;
  coseKey?: Map<unknown, unknown>;
  /** COSE 公钥的原始 CBOR 字节（原样存储，认证时重新解析）。 */
  coseKeyBytes?: Buffer;
  /** 凭证数据之后的剩余字节（扩展区起点）。 */
  restOffset: number;
}

export function parseAuthData(authData: Buffer): ParsedAuthData {
  if (authData.length < 37) throw new Error('authenticatorData 过短。');
  const rpIdHash = authData.subarray(0, 32);
  const flags = authData[32];
  const signCount = authData.readUInt32BE(33);
  const result: ParsedAuthData = { rpIdHash, flags, signCount, restOffset: 37 };
  if (flags & 0x40) { // AT：包含新凭证数据
    if (authData.length < 37 + 18) throw new Error('attestedCredentialData 过短。');
    const credIdLen = authData.readUInt16BE(37 + 16);
    const credStart = 37 + 18;
    if (authData.length < credStart + credIdLen) throw new Error('credentialId 长度不合法。');
    result.credentialId = Buffer.from(authData.subarray(credStart, credStart + credIdLen));
    const decoded = CborDecoder.decodeAt(authData, credStart + credIdLen);
    if (!(decoded.value instanceof Map)) throw new Error('COSE 公钥解析失败。');
    result.coseKey = decoded.value;
    result.coseKeyBytes = Buffer.from(authData.subarray(credStart + credIdLen, credStart + credIdLen + decoded.bytesConsumed));
    result.restOffset = credStart + credIdLen + decoded.bytesConsumed;
  }
  return result;
}

function checkRpIdHash(authData: ParsedAuthData, rpId: string): void {
  const expected = createHash('sha256').update(rpId, 'utf8').digest();
  if (!authData.rpIdHash.equals(expected)) throw new Error('RP ID 哈希不匹配。');
}

/* ------------------------------------------------------------ COSE 公钥 → KeyObject */

const COSE_KTY = 1, COSE_ALG = 3;
const COSE_CRV = -1, COSE_X = -2, COSE_Y = -3, COSE_N = -1, COSE_E = -2;

/** 把 COSE 密钥映射转换为 Node KeyObject（支持 EC2/P-256 ES256 与 RSA RS256）。 */
export function coseToPublicKey(cose: Map<unknown, unknown>): KeyObject {
  const kty = cose.get(COSE_KTY);
  const alg = cose.get(COSE_ALG);
  if (kty === 2 && alg === -7) { // EC2 + ES256
    const crv = cose.get(COSE_CRV);
    const x = cose.get(COSE_X);
    const y = cose.get(COSE_Y);
    if (crv !== 1 || !(x instanceof Buffer) || !(y instanceof Buffer)) throw new Error('不支持的 EC2 曲线或坐标缺失。');
    return createPublicKey({
      key: { kty: 'EC', crv: 'P-256', x: toBase64Url(x), y: toBase64Url(y) },
      format: 'jwk'
    });
  }
  if (kty === 3 && alg === -257) { // RSA + RS256
    const n = cose.get(COSE_N);
    const e = cose.get(COSE_E);
    if (!(n instanceof Buffer) || !(e instanceof Buffer)) throw new Error('RSA 公钥参数缺失。');
    return createPublicKey({
      key: { kty: 'RSA', n: toBase64Url(n), e: toBase64Url(e) },
      format: 'jwk'
    });
  }
  throw new Error(`不支持的公钥类型/算法：kty=${String(kty)} alg=${String(alg)}（本插件支持 ES256 与 RS256）。`);
}

/* ------------------------------------------------------------ 注册（attestation）验证 */

export interface RegistrationResponse {
  clientDataJSON: string;
  attestationObject: string;
}

export interface VerifiedRegistration {
  credentialId: string; // Base64URL
  publicKeyCose: string; // 完整 COSE 映射的 CBOR 字节（Base64URL 存储）
  signCount: number;
}

/**
 * 校验注册响应并提取凭证。信任建立依据：challenge 一次性、origin 匹配、rpIdHash 匹配、
 * UP 已置位；证明格式支持 none / packed（不校验 attestation 证书链，见模块注释）。
 */
export function verifyRegistration(response: RegistrationResponse, expectedChallenge: string, origin: string, rpId: string): VerifiedRegistration {
  parseClientData(response.clientDataJSON, 'webauthn.create', expectedChallenge, origin);

  const attestationObject = cborDecode(fromBase64Url(response.attestationObject));
  if (!(attestationObject instanceof Map)) throw new Error('attestationObject 解析失败。');
  const fmt = String(attestationObject.get('fmt') ?? '');
  const authDataBuffer = attestationObject.get('authData');
  if (!(authDataBuffer instanceof Buffer)) throw new Error('attestationObject 缺少 authData。');

  if (fmt !== 'none' && fmt !== 'packed') throw new Error(`不支持的证明格式：${fmt}。`);
  // packed 格式要求存在 attStmt（此处不校验其证书链/签名，仅要求字段齐全）。
  if (fmt === 'packed' && !(attestationObject.get('attStmt') instanceof Map)) throw new Error('packed 证明缺少 attStmt。');

  const authData = parseAuthData(authDataBuffer);
  checkRpIdHash(authData, rpId);
  if (!(authData.flags & 0x01)) throw new Error('认证器未确认用户在场（UP）。');
  if (!(authData.flags & 0x40) || !authData.credentialId || !authData.coseKey) throw new Error('注册响应未包含新凭证。');

  coseToPublicKey(authData.coseKey); // 提前验证可转换，避免存入不可用公钥

  return {
    credentialId: toBase64Url(authData.credentialId),
    publicKeyCose: toBase64Url(authData.coseKeyBytes!),
    signCount: authData.signCount
  };
}

/* ------------------------------------------------------------ 认证（assertion）验证 */

export interface AssertionResponse {
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
  userHandle?: string;
}

/**
 * 校验登录断言：challenge/origin/rpIdHash/UP(+可选 UV)/signCount，并用存储公钥验签
 * （签名覆盖 authenticatorData ‖ SHA-256(clientDataJSON)）。
 */
export function verifyAssertion(
  response: AssertionResponse,
  storedPublicKeyCose: string,
  storedSignCount: number,
  requireUserVerification: boolean,
  expectedChallenge: string,
  origin: string,
  rpId: string
): { newSignCount: number } {
  parseClientData(response.clientDataJSON, 'webauthn.get', expectedChallenge, origin);

  const authDataBuffer = fromBase64Url(response.authenticatorData);
  const authData = parseAuthData(authDataBuffer);
  checkRpIdHash(authData, rpId);
  if (!(authData.flags & 0x01)) throw new Error('认证器未确认用户在场（UP）。');
  if (requireUserVerification && !(authData.flags & 0x04)) throw new Error('认证器未确认用户身份（UV）。');

  if (storedSignCount > 0 || authData.signCount > 0) {
    if (authData.signCount <= storedSignCount) throw new Error('通行密钥计数器异常，可能被克隆，已拒绝本次登录。');
  }

  const signature = fromBase64Url(response.signature);
  const clientHash = createHash('sha256').update(Buffer.from(response.clientDataJSON, 'utf8')).digest();
  const publicKey = coseToPublicKey(cborDecode(fromBase64Url(storedPublicKeyCose)) as Map<unknown, unknown>);
  const ok = cryptoVerify(null, Buffer.concat([authDataBuffer, clientHash]), publicKey, signature);
  if (!ok) throw new Error('通行密钥签名校验失败。');
  return { newSignCount: authData.signCount };
}

/* ------------------------------------------------------------ 浏览器选项构造 */

export interface PublicKeyCredentialDescriptorParam { id: string; type: 'public-key'; transports?: string[]; }

/** 注册选项（PublicKeyCredentialCreationOptions 的 JSON 友好形态，前端转 BufferSource）。 */
export function buildCreationOptions(params: {
  rpName: string;
  rpId: string;
  origin: string;
  userName: string;
  userIdHandle: string; // 不含 PII 的稳定用户句柄（Base64URL）
  challenge: string;
  excludeCredentials: PublicKeyCredentialDescriptorParam[];
}): Record<string, unknown> {
  return {
    rp: { name: params.rpName, id: params.rpId },
    user: { id: params.userIdHandle, name: params.userName, displayName: params.userName },
    challenge: params.challenge,
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 },   // ES256 首选
      { type: 'public-key', alg: -257 }  // RS256 兜底
    ],
    timeout: 60_000,
    attestation: 'none',
    excludeCredentials: params.excludeCredentials,
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' }
  };
}

/** 认证选项（PublicKeyCredentialRequestOptions 形态）。 */
export function buildRequestOptions(params: {
  rpId: string;
  challenge: string;
  allowCredentials: PublicKeyCredentialDescriptorParam[];
}): Record<string, unknown> {
  return {
    rpId: params.rpId,
    challenge: params.challenge,
    timeout: 60_000,
    userVerification: 'preferred',
    allowCredentials: params.allowCredentials
  };
}
