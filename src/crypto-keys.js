// Ed25519 密钥与签名工具。公钥统一使用 JWK（OKP / Ed25519）表示，
// 仅保留 { kty, crv, x }，避免 use / key_ops 等可选字段干扰规范化。
import crypto from 'node:crypto';

export class KeyFormatError extends Error {
  constructor(detail) {
    super(detail);
    this.code = 'invalid-public-key';
  }
}

export function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    publicJwk: normalizePublicJwk(publicKey.export({ format: 'jwk' })),
    privateJwk: normalizePrivateJwk(privateKey.export({ format: 'jwk' })),
  };
}

export function normalizePublicJwk(jwk) {
  if (!jwk || typeof jwk !== 'object') throw new KeyFormatError('公钥必须是 JWK 对象');
  const { kty, crv, x } = jwk;
  if (kty !== 'OKP' || crv !== 'Ed25519' || typeof x !== 'string') {
    throw new KeyFormatError('仅接受 OKP / Ed25519 公钥');
  }
  const raw = decodeB64Url(x);
  if (raw.length !== 32) throw new KeyFormatError('Ed25519 公钥原始长度必须为 32 字节');
  return { kty, crv, x };
}

export function normalizePrivateJwk(jwk) {
  if (!jwk || typeof jwk !== 'object' || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') {
    throw new KeyFormatError('私钥必须是 OKP / Ed25519 JWK');
  }
  decodeB64Url(jwk.x);
  decodeB64Url(jwk.d);
  return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, d: jwk.d };
}

// 公钥标识：x 本身即是 32 字节原始公钥的 base64url 编码，全局唯一。
export function keyId(publicJwk) {
  return normalizePublicJwk(publicJwk).x;
}

// 排序去重后的公钥集；重复公钥将被拒绝，避免成员表含混。
export function normalizeKeySet(list) {
  if (!Array.isArray(list)) throw new KeyFormatError('公钥集必须是数组');
  if (list.length < 2 || list.length > 5) {
    throw new KeyFormatError('设备域必须包含 2 至 5 把公钥');
  }
  const normalized = list.map(normalizePublicJwk);
  const seen = new Set();
  for (const jwk of normalized) {
    const id = jwk.x;
    if (seen.has(id)) throw new KeyFormatError('公钥集中存在重复成员');
    seen.add(id);
  }
  return normalized.sort((a, b) => (a.x < b.x ? -1 : a.x > b.x ? 1 : 0));
}

export function signDetached(privateJwk, messageBytes) {
  const key = crypto.createPrivateKey({ key: normalizePrivateJwk(privateJwk), format: 'jwk' });
  return crypto.sign(null, Buffer.from(messageBytes), key);
}

export function verifyDetached(publicJwk, messageBytes, signatureBytes) {
  try {
    const key = crypto.createPublicKey({ key: normalizePublicJwk(publicJwk), format: 'jwk' });
    return crypto.verify(null, Buffer.from(messageBytes), key, Buffer.from(signatureBytes));
  } catch {
    return false;
  }
}

export function encodeB64Url(buf) {
  return Buffer.from(buf).toString('base64url');
}

export function decodeB64Url(value) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new KeyFormatError('base64url 字段缺失');
  }
  let raw;
  try {
    raw = Buffer.from(value, 'base64url');
  } catch {
    throw new KeyFormatError('base64url 解码失败');
  }
  return new Uint8Array(raw);
}
