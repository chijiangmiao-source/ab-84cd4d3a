// HTTP 冒烟验收：自启服务 → 建 2/2 设备域 → 分批两签激活 → 独立复核两份证据
// → 覆盖五类拒因与激活后竞争 → 重启一致性 → 健康与页面同源检查。
// 任一步骤失败即以非零码退出。
import { spawn } from 'node:child_process';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKeyPair, signDetached, verifyDetached } from '../src/crypto-keys.js';
import { buildProposalMessage } from '../src/rotation.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'rotation-smoke-'));
const DATA_FILE = path.join(DATA_DIR, 'state.json');

let failures = 0;
function check(name, cond, detail = '') {
  if (cond) {
    console.log(`  ✓ ${name}`);
  } else {
    failures += 1;
    console.error(`  ✗ ${name}${detail ? ` — ${detail}` : ''}`);
  }
}
function assert_(cond, msg) {
  if (!cond) throw new Error(msg);
}

async function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

function startServer(port) {
  const child = spawn(process.execPath, [path.join(ROOT, 'src', 'server.js')], {
    cwd: ROOT,
    env: { ...process.env, PORT: String(port), DATA_FILE },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', (d) => process.env.SMOKE_VERBOSE && process.stdout.write(`[srv] ${d}`));
  child.stderr.on('data', (d) => process.stderr.write(`[srv-err] ${d}`));
  child.stop = () =>
    new Promise((resolve) => {
      if (child.exitCode !== null) return resolve();
      const timer = setTimeout(() => {
        child.kill('SIGKILL');
      }, 3000);
      child.on('exit', () => {
        clearTimeout(timer);
        resolve();
      });
      child.kill('SIGTERM');
    });
  return child;
}

async function waitHealth(base) {
  for (let i = 0; i < 100; i++) {
    try {
      const res = await fetch(`${base}/health`);
      if (res.ok) return res.json();
    } catch {
      /* 等待服务就绪 */
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('服务健康检查在 10 秒内未就绪');
}

async function api(base, method, route, body) {
  const res = await fetch(`${base}${route}`, {
    method,
    headers: { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = await res.json();
  return { status: res.status, json };
}

const pub = (kp) => kp.publicJwk;
function signMessage(kp, message) {
  return signDetached(kp.privateJwk, Buffer.from(message, 'utf8')).toString('base64url');
}

async function main() {
  const port = await getFreePort();
  const base = `http://127.0.0.1:${port}`;
  console.log(`[smoke] 数据文件：${DATA_FILE}`);

  // ---------- 启动 ----------
  let server = startServer(port);
  const health0 = await waitHealth(base);
  check('服务启动且 /health 可用', health0.status === 'ok', JSON.stringify(health0));

  // ---------- 验收：创建二钥且门限为二的设备域 ----------
  const parents = [generateKeyPair(), generateKeyPair()];
  const nextPairs = [generateKeyPair(), generateKeyPair()];
  const nextKeys = nextPairs.map(pub).sort((a, b) => (a.x < b.x ? -1 : 1));

  const created = await api(base, 'POST', '/api/domains', {
    name: '验收设备域',
    keys: parents.map(pub),
    threshold: 2,
  });
  check('创建设备域返回 201', created.status === 201, `status=${created.status}`);
  const domainId = created.json.domain.id;
  const genesisDigest = created.json.head.digest;
  check('初始门限为 2 且成员为 2', created.json.head.threshold === 2 && created.json.head.keys.length === 2);
  check('初始代次为 0 且公钥已排序', created.json.head.epoch === 0);

  const proposal = {
    rotationId: 'rot-acceptance-001',
    parentDigest: genesisDigest,
    nextKeys,
    nextThreshold: 2,
  };

  // 预览规范消息（不写状态）
  const preview = await api(base, 'POST', `/api/domains/${domainId}/preview`, proposal);
  check('预览规范消息成功', preview.status === 200 && typeof preview.json.message === 'string');
  const message = preview.json.message;
  check('预览代次为下一代次 1', preview.json.epoch === 1);

  // 旁路候选：稍后用于验证激活后的 stale-parent
  const sideBody = {
    rotationId: 'rot-side',
    parentDigest: genesisDigest,
    nextKeys,
    nextThreshold: 2,
  };
  const sidePreview = await api(base, 'POST', `/api/domains/${domainId}/preview`, sideBody);

  // ---------- 第一批签名：1/2 待签 ----------
  const batch1 = await api(base, 'POST', `/api/domains/${domainId}/signatures`, {
    ...proposal,
    signerKey: pub(parents[0]),
    signature: signMessage(parents[0], message),
  });
  check('第一批签名被接受但未激活', batch1.json.results[0].accepted && !batch1.json.results[0].activated);
  check('候选处于待签且计数为 1', batch1.json.domain.pending[0]?.signatureCount === 1);
  check('链头仍停留在代次 0', batch1.json.domain.head.epoch === 0);

  // ---------- 拒因矩阵：均不得推进链头 ----------
  console.log('[smoke] 拒因矩阵：');

  // 1) 重传：重复签名
  const dup = await api(base, 'POST', `/api/domains/${domainId}/signatures`, {
    ...proposal,
    signerKey: pub(parents[0]),
    signature: signMessage(parents[0], message),
  });
  check('重传判定 duplicate-signature', dup.json.results[0].reason === 'duplicate-signature');

  // 2) 篡改载荷：同一轮换标识更换新公钥集（签名对新消息有效）
  const otherKeys = [generateKeyPair(), generateKeyPair()]
    .map(pub)
    .sort((a, b) => (a.x < b.x ? -1 : 1));
  const tamperedMessage = buildProposalMessage({
    domainId,
    ...proposal,
    nextKeys: otherKeys,
    epoch: 1,
  });
  const tampered = await api(base, 'POST', `/api/domains/${domainId}/signatures`, {
    ...proposal,
    nextKeys: otherKeys,
    signerKey: pub(parents[1]),
    signature: signMessage(parents[1], tamperedMessage),
  });
  check('篡改载荷判定 payload-tampered', tampered.json.results[0].reason === 'payload-tampered');

  // 3) 错误父摘要（全新轮换标识）
  const wrongParent = await api(base, 'POST', `/api/domains/${domainId}/signatures`, {
    ...proposal,
    rotationId: 'rot-wrong-parent',
    parentDigest: 'a'.repeat(64),
    signerKey: pub(parents[0]),
    signature: signMessage(
      parents[0],
      buildProposalMessage({
        domainId,
        ...proposal,
        rotationId: 'rot-wrong-parent',
        parentDigest: 'a'.repeat(64),
        epoch: 1,
      })
    ),
  });
  check(
    '错误父摘要判定 parent-digest-mismatch',
    wrongParent.json.results[0].reason === 'parent-digest-mismatch'
  );

  // 4) 非父成员签名
  const outsider = generateKeyPair();
  const foreign = await api(base, 'POST', `/api/domains/${domainId}/signatures`, {
    ...proposal,
    signerKey: pub(outsider),
    signature: signMessage(outsider, message),
  });
  check('非父成员判定 signer-not-parent-member', foreign.json.results[0].reason === 'signer-not-parent-member');

  // 5) 非法签名
  const badSig = await api(base, 'POST', `/api/domains/${domainId}/signatures`, {
    ...proposal,
    signerKey: pub(parents[1]),
    signature: Buffer.alloc(64, 7).toString('base64url'),
  });
  check('非法签名判定 bad-signature', badSig.json.results[0].reason === 'bad-signature');

  const midState = await api(base, 'GET', `/api/domains/${domainId}`);
  check('所有拒绝后链头未改变', midState.json.head.digest === genesisDigest && midState.json.head.epoch === 0);
  check('待签候选仍只有 1 份签名', midState.json.pending.find((c) => c.rotationId === proposal.rotationId)?.signatureCount === 1);
  check('已拒列表记录全部拒因', ['duplicate-signature', 'payload-tampered', 'parent-digest-mismatch', 'signer-not-parent-member', 'bad-signature'].every((r) => midState.json.rejected.some((a) => a.reason === r)));

  // 旁路候选先签 1/2（激活后再补第二签应得到 stale-parent）
  await api(base, 'POST', `/api/domains/${domainId}/signatures`, {
    ...sideBody,
    signerKey: pub(parents[0]),
    signature: signMessage(parents[0], sidePreview.json.message),
  });

  // ---------- 第二批签名：2/2 激活 ----------
  const batch2 = await api(base, 'POST', `/api/domains/${domainId}/signatures`, {
    ...proposal,
    signerKey: pub(parents[1]),
    signature: signMessage(parents[1], message),
  });
  check('第二批签名触发激活', batch2.json.results[0].activated === true);
  check('恰好生成一个新检查点', batch2.json.domain.history.length === 2);

  const active = await api(base, 'GET', `/api/domains/${domainId}`);
  const head = active.json.head;
  check('已激活链头代次为 1', head.epoch === 1);
  check('已激活链头固定父摘要为创世摘要', head.parentDigest === genesisDigest);
  check('新门限为 2', head.threshold === 2);
  check('排序后新公钥集与提案一致', JSON.stringify(head.keys) === JSON.stringify(nextKeys));
  check('链头携带两份签名证据', Array.isArray(head.signatures) && head.signatures.length === 2);
  const evidenceIds = head.signatures.map((s) => s.keyId).sort();
  check(
    '两份证据分别来自两名父成员',
    JSON.stringify(evidenceIds) === JSON.stringify(parents.map((p) => p.publicJwk.x).sort())
  );

  // ---------- 独立复核证据（不信任服务端判定） ----------
  const evidenceMessage = buildProposalMessage({
    domainId,
    rotationId: head.rotationId,
    parentDigest: head.parentDigest,
    epoch: head.epoch,
    nextKeys: head.keys,
    nextThreshold: head.threshold,
  });
  let allVerify = true;
  for (const ev of head.signatures) {
    const ok = verifyDetached(ev.signer, Buffer.from(evidenceMessage, 'utf8'), Buffer.from(ev.signature, 'base64url'));
    if (!ok) allVerify = false;
  }
  check('独立以规范 UTF-8 消息复核两份证据均通过', allVerify);
  const flipped = Buffer.from(head.signatures[0].signature, 'base64url');
  flipped[0] ^= 0xff;
  const tamperedVerify = verifyDetached(
    head.signatures[0].signer,
    Buffer.from(evidenceMessage, 'utf8'),
    flipped
  );
  check('篡改任一字节即验签失败', tamperedVerify === false);

  // ---------- 激活后的竞争候选 ----------
  const lateSame = await api(base, 'POST', `/api/domains/${domainId}/signatures`, {
    ...proposal,
    signerKey: pub(parents[0]),
    signature: signMessage(parents[0], message),
  });
  check(
    '激活后同标识竞争判定 rotation-already-activated',
    lateSame.json.results[0].reason === 'rotation-already-activated'
  );
  const stale = await api(base, 'POST', `/api/domains/${domainId}/signatures`, {
    ...sideBody,
    signerKey: pub(parents[1]),
    signature: signMessage(parents[1], sidePreview.json.message),
  });
  check('激活后陈旧父摘要的补签判定 stale-parent', stale.json.results[0].reason === 'stale-parent');

  // ---------- 链可继续延伸：由新活动成员签名进入第三代 ----------
  const epoch2Keys = parents.map(pub).sort((a, b) => (a.x < b.x ? -1 : 1));
  const rot2 = {
    rotationId: 'rot-acceptance-002',
    parentDigest: head.digest,
    nextKeys: epoch2Keys,
    nextThreshold: 2,
  };
  const preview2 = await api(base, 'POST', `/api/domains/${domainId}/preview`, rot2);
  check('第二轮换父摘要固定为第一代链头', preview2.json.parentDigest === head.digest && preview2.json.epoch === 2);
  const message2 = preview2.json.message;
  const r2a = await api(base, 'POST', `/api/domains/${domainId}/signatures`, {
    ...rot2,
    signerKey: pub(nextPairs.find((p) => p.publicJwk.x === head.keys[0].x)),
    signature: signMessage(nextPairs.find((p) => p.publicJwk.x === head.keys[0].x), message2),
  });
  check('第二代成员签名被接受（签名者以当前链头成员为准）', r2a.json.results[0].accepted && !r2a.json.results[0].activated);
  // 旧父代成员已不再是当前成员：对第二轮换签名应被拒
  const oldMemberSign = await api(base, 'POST', `/api/domains/${domainId}/signatures`, {
    ...rot2,
    signerKey: pub(parents[0]),
    signature: signMessage(parents[0], message2),
  });
  check('旧父代成员对新一轮换签名判定 signer-not-parent-member', oldMemberSign.json.results[0].reason === 'signer-not-parent-member');
  const r2b = await api(base, 'POST', `/api/domains/${domainId}/signatures`, {
    ...rot2,
    signerKey: pub(nextPairs.find((p) => p.publicJwk.x === head.keys[1].x)),
    signature: signMessage(nextPairs.find((p) => p.publicJwk.x === head.keys[1].x), message2),
  });
  check('第二名当前成员补齐门限后第三代激活', r2b.json.results[0].activated === true);

  const finalLive = await api(base, 'GET', `/api/domains/${domainId}`);
  check('竞争与第二轮换后只有一个活动检查点（共三代）', finalLive.json.history.length === 3 && finalLive.json.head.epoch === 2);
  check('第三代父摘要指向第一代链头', finalLive.json.head.parentDigest === head.digest);
  check('第三代同样携带两份证据', finalLive.json.head.signatures.length === 2);

  // ---------- 健康反映设备域状态 ----------
  const health1 = await api(base, 'GET', '/health');
  check(
    '/health 反映设备域与活动检查点',
    health1.json.status === 'ok' && health1.json.domains >= 1 && health1.json.activeCheckpoints >= 1,
    JSON.stringify(health1.json)
  );

  // ---------- 页面同源检查 ----------
  const pageRes = await fetch(`${base}/`);
  const html = await pageRes.text();
  check('页面可访问且包含轮换链要素', /设备域密钥轮换授权链/.test(html) && /门限/.test(html) && /分批提交签名/.test(html));
  const appJs = await fetch(`${base}/app.js`);
  const appJsText = await appJs.text();
  check('页面脚本通过同一接口读取链头与证据', /\/api\/domains\//.test(appJsText) && /signatures/.test(appJsText));
  const css = await fetch(`${base}/styles.css`);
  check('页面样式可访问', css.status === 200);
  // 页面与接口同源：页面直接消费 /api/domains/:id 返回的 head/signatures 字段
  check(
    '页面字段与接口一致（head.digest / signatures / pending / rejected）',
    /headDigest/.test(appJsText) && /signatureCount/.test(appJsText) && /renderStatePanel/.test(appJsText)
  );

  // ---------- 重启一致性 ----------
  console.log('[smoke] 重启服务进程…');
  await server.stop();
  server = startServer(port);
  await waitHealth(base);
  const reloaded = await api(base, 'GET', `/api/domains/${domainId}`);
  check('重启后活动链头摘要一致', reloaded.json.head.digest === finalLive.json.head.digest);
  check('重启后代次与门限一致', reloaded.json.head.epoch === 2 && reloaded.json.head.threshold === 2);
  check('重启后历史检查点数量一致', reloaded.json.history.length === finalLive.json.history.length);
  check(
    '重启后签名证据逐字节一致',
    JSON.stringify(reloaded.json.head.signatures) === JSON.stringify(finalLive.json.head.signatures)
  );
  check(
    '重启后完整历史一致',
    JSON.stringify(reloaded.json.history) === JSON.stringify(finalLive.json.history)
  );
  check(
    '重启后拒因审计保持一致',
    reloaded.json.rejected.length === finalLive.json.rejected.length
  );
  const health2 = await api(base, 'GET', '/health');
  check('重启后健康仍反映设备域', health2.json.domains >= 1 && health2.json.activeCheckpoints >= 1);

  await server.stop();

  console.log('');
  if (failures > 0) {
    console.error(`[smoke] 失败 ${failures} 项`);
    process.exitCode = 1;
  } else {
    console.log('[smoke] 全部冒烟检查通过');
  }
}

main().catch((err) => {
  console.error('[smoke] 致命错误：', err);
  process.exit(1);
});
