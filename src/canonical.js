// 规范化 JSON：对象键按码位递归排序，数组保持顺序，输出 UTF-8 字节。
// 签名与验签都只针对这份规范字节，载荷字段顺序不影响验签结果。

export function canonical(value) {
  return JSON.stringify(normalize(value));
}

export function canonicalBytes(value) {
  return Buffer.from(canonical(value), 'utf8');
}

function normalize(value) {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(normalize);
  const out = {};
  for (const key of Object.keys(value).sort()) {
    out[key] = normalize(value[key]);
  }
  return out;
}
