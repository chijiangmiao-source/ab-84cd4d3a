// 构建检查：无外部依赖项目的“构建”即语法/可加载性校验。
//  - 对所有 .js 执行 node --check（ESM 语法校验）
//  - 校验所有 .json 可解析
//  - 关键模块可成功导入
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function walk(dir, filter) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name.startsWith('.git')) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...walk(full, filter));
    } else if (filter(full)) {
      out.push(full);
    }
  }
  return out;
}

let failed = 0;

const jsFiles = walk(ROOT, (f) => f.endsWith('.js') || f.endsWith('.mjs'));
console.log(`[build] 语法检查 ${jsFiles.length} 个 JS 文件`);
for (const file of jsFiles) {
  try {
    execFileSync(process.execPath, ['--check', file], { stdio: 'pipe' });
    console.log(`  ✓ ${path.relative(ROOT, file)}`);
  } catch (err) {
    failed += 1;
    console.error(`  ✗ ${path.relative(ROOT, file)}`);
    console.error(String(err.stderr || err.message));
  }
}

const jsonFiles = walk(ROOT, (f) => f.endsWith('.json'));
console.log(`[build] JSON 校验 ${jsonFiles.length} 个文件`);
for (const file of jsonFiles) {
  try {
    JSON.parse(fs.readFileSync(file, 'utf8'));
    console.log(`  ✓ ${path.relative(ROOT, file)}`);
  } catch (err) {
    failed += 1;
    console.error(`  ✗ ${path.relative(ROOT, file)}：${err.message}`);
  }
}

console.log('[build] 关键模块导入检查');
// 注意：不导入 src/server.js，它在导入时即监听端口；服务可启动性由冒烟脚本覆盖。
try {
  const mod = await import('../src/rotation.js');
  if (typeof mod.RotationStore !== 'function') throw new Error('RotationStore 导出缺失');
  await import('../src/canonical.js');
  await import('../src/crypto-keys.js');
  console.log('  ✓ 纯逻辑模块均可导入，RotationStore 已导出');
} catch (err) {
  failed += 1;
  console.error(`  ✗ 模块导入失败：${err.message}`);
}

console.log('[build] 页面 DOM id 一致性检查');
try {
  const html = fs.readFileSync(path.join(ROOT, 'public', 'index.html'), 'utf8');
  const appJs = fs.readFileSync(path.join(ROOT, 'public', 'app.js'), 'utf8');
  const defined = new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]));
  const referenced = new Set([...appJs.matchAll(/\$\('([^']+)'\)/g)].map((m) => m[1]));
  const missing = [...referenced].filter((id) => !defined.has(id));
  if (missing.length > 0) {
    failed += missing.length;
    console.error(`  ✗ app.js 引用了 HTML 中不存在的 id：${missing.join(', ')}`);
  } else {
    console.log(`  ✓ ${referenced.size} 个页面 id 引用均在 index.html 中定义`);
  }
} catch (err) {
  failed += 1;
  console.error(`  ✗ DOM 检查失败：${err.message}`);
}

if (failed > 0) {
  console.error(`[build] 检查失败 ${failed} 项`);
  process.exit(1);
}
console.log('[build] 构建检查通过');
