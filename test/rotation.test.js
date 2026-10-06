// 轮换规则测试：规范 UTF-8 验签、门限去重、拒因、并发收敛、重启持久化。
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { RotationStore, buildProposalMessage } from '../src/rotation.js';
import { canonical, canonicalBytes } from '../src/canonical.js';
import { generateKeyPair, signDetached, keyId } from '../src/crypto-keys.js';

let tmpDir;
let fileIndex = 0;

function newFile() {
  return path.join(tmpDir, `state-${process.pid}-${fileIndex++}.json`);
}

function newStore() {
  return RotationStore.load(newFile());
}

function pub(kp) {
  return kp.publicJwk;
}

function signProposal(kp, proposalFields) {
  const message = buildProposalMessage(proposalFields);
  return signDetached(kp.privateJwk, Buffer.from(message, 'utf8')).toString('base64url');
}

function sig(kp, domainId, fields) {
  return signProposal(kp, { domainId, ...fields });
}

function proposalBase(domainState, rotationId, nextKeyPairs, nextThreshold) {
  // 与服务端一致：新公钥集按 x 排序后进入规范消息。
  const sortedNext = nextKeyPairs.map(pub).sort((a, b) => (a.x < b.x ? -1 : a.x > b.x ? 1 : 0));
  return {
    rotationId,
    parentDigest: domainState.head.digest,
    nextKeys: sortedNext,
    nextThreshold,
  };
}

async function submit(store, domainId, body, kp, epoch) {
  return store.submitSignatures(domainId, {
    ...body,
    signerKey: pub(kp),
    signature: sig(kp, domainId, { ...body, epoch }),
  });
}

async function activate(store, domainId, body, parents, epoch) {
  for (const p of parents) {
    await submit(store, domainId, body, p, epoch);
  }
  return store.getDomainState(domainId);
}

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rotation-test-'));
});

test('规范化 JSON：键顺序无关，数组保序，输出为 UTF-8 字节', () => {
  const a = canonical({ b: 1, a: '中文字段 ✓', c: [3, 1, 2] });
  const b = canonical({ c: [3, 1, 2], a: '中文字段 ✓', b: 1 });
  assert.equal(a, b);
  assert.deepEqual(canonicalBytes({ a: '✓' }), Buffer.from('{"a":"✓"}', 'utf8'));
  assert.notEqual(canonical([2, 1]), canonical([1, 2]));
});

test('创建设备域：2~5 把公钥，超界、重复、门限非法均拒绝', async () => {
  const pairs = Array.from({ length: 5 }, () => generateKeyPair());
  const store = newStore();

  const created = await store.createDomain({
    name: '域',
    keys: [pub(pairs[1]), pub(pairs[0])],
    threshold: 2,
  });
  assert.equal(created.head.epoch, 0);
  assert.equal(created.head.keys.length, 2);
  // 排序后公钥集
  assert.deepEqual(created.head.keys.map((k) => k.x), [pub(pairs[0]).x, pub(pairs[1]).x].sort());
  assert.equal(created.head.threshold, 2);
  assert.equal(created.head.parentDigest, null);
  assert.equal(created.head.signatures.length, 0);

  await assert.rejects(
    store.createDomain({ name: 'x', keys: [pub(pairs[0])], threshold: 1 }),
    /2 至 5/
  );
  await assert.rejects(
    store.createDomain({ name: 'x', keys: pairs.map(pub), threshold: 6 }),
    /门限/
  );
  await assert.rejects(
    store.createDomain({ name: 'x', keys: [pub(pairs[0]), pub(pairs[0])], threshold: 2 }),
    /重复/
  );
});

test('分批补齐门限签名后激活：固定父摘要、下一代次、排序新公钥集、两份证据', async () => {
  const parents = [generateKeyPair(), generateKeyPair()];
  const next = [generateKeyPair(), generateKeyPair()];
  const store = newStore();
  const domain = await store.createDomain({
    name: '远端设备域',
    keys: parents.map(pub),
    threshold: 2,
  });
  const id = domain.domain.id;
  const body = proposalBase(domain, 'rot-1', next, 2);

  // 第一批：仅 1/2 → 待签
  const first = await submit(store, id, body, parents[0], 1);
  assert.equal(first.results[0].accepted, true);
  assert.equal(first.results[0].activated, false);
  assert.equal(first.results[0].candidate.status, 'pending');
  assert.equal(first.domain.head.epoch, 0);
  assert.equal(first.domain.pending.length, 1);
  assert.equal(first.domain.pending[0].signatureCount, 1);

  // 第二批：第 2 个去重父成员 → 激活
  const second = await submit(store, id, body, parents[1], 1);
  assert.equal(second.results[0].activated, true);
  const head = second.domain.head;
  assert.equal(head.epoch, 1);
  assert.equal(head.parentDigest, domain.head.digest); // 固定父摘要
  assert.deepEqual(head.keys.map((k) => k.x), next.map((p) => p.publicJwk.x).sort());
  assert.equal(head.threshold, 2);
  assert.equal(head.signatures.length, 2); // 两份证据
  const evidenceIds = head.signatures.map((s) => s.keyId).sort();
  assert.deepEqual(evidenceIds, parents.map((p) => keyId(pub(p))).sort());
  for (const ev of head.signatures) {
    assert.equal(ev.signature.length, 86); // base64url(64B)
  }
  assert.equal(second.domain.history.length, 2);
  assert.equal(second.domain.head.digest, head.digest);
  assert.equal(second.domain.candidates[0].status, 'activated');
  assert.equal(second.domain.candidates[0].checkpointDigest, head.digest);
});

test('未达门限停留待签；重传/重复签名幂等不计数不推进', async () => {
  const parents = [generateKeyPair(), generateKeyPair(), generateKeyPair()];
  const next = [generateKeyPair(), generateKeyPair()];
  const store = newStore();
  const d = await store.createDomain({ name: 'd', keys: parents.map(pub), threshold: 3 });
  const body = proposalBase(d, 'rot-2', next, 2);

  const r1 = await submit(store, d.domain.id, body, parents[0], 1);
  assert.equal(r1.results[0].candidate.signatureCount, 1);

  // 完全相同的重传：duplicate-signature，计数仍为 1，链头不变
  const r2 = await submit(store, d.domain.id, body, parents[0], 1);
  assert.equal(r2.results[0].accepted, false);
  assert.equal(r2.results[0].reason, 'duplicate-signature');
  assert.equal(r2.results[0].candidate.signatureCount, 1);
  assert.equal(r2.domain.head.epoch, 0);
  assert.equal(store.getDomainState(d.domain.id).head.digest, d.head.digest);
});

test('错误父摘要被拒且不推进链头；链头推进后待签候选再补签给出 stale-parent', async () => {
  const parents = [generateKeyPair(), generateKeyPair()];
  const next = [generateKeyPair(), generateKeyPair()];
  const store = newStore();
  const d = await store.createDomain({ name: 'd', keys: parents.map(pub), threshold: 2 });
  const body = proposalBase(d, 'rot-3', next, 2);

  // 全新轮换标识但父摘要错误 → parent-digest-mismatch（签名对错误摘要有效也无效，
  // 因为父摘要校验先于验签；这里直接给任意签名即可验证拒因顺序）
  const wrong = await store.submitSignatures(d.domain.id, {
    ...body,
    parentDigest: 'a'.repeat(64),
    signerKey: pub(parents[0]),
    signature: sig(parents[0], d.domain.id, { ...body, parentDigest: 'a'.repeat(64), epoch: 1 }),
  });
  assert.equal(wrong.results[0].accepted, false);
  assert.equal(wrong.results[0].reason, 'parent-digest-mismatch');
  assert.equal(store.getDomainState(d.domain.id).head.digest, d.head.digest);

  // 先留一个只签了 1/2 的待签候选 rot-pending
  const pendingBody = proposalBase(d, 'rot-pending', next, 2);
  const half = await submit(store, d.domain.id, pendingBody, parents[0], 1);
  assert.equal(half.results[0].candidate.status, 'pending');

  // 另一轮换 rot-3 补齐两签并激活，链头推进
  await activate(store, d.domain.id, body, parents, 1);
  const after = store.getDomainState(d.domain.id);
  assert.equal(after.head.epoch, 1);

  // 旧待签候选再来补签：父摘要已陈旧 → stale-parent，链头不变
  const stale = await submit(store, d.domain.id, pendingBody, parents[1], 1);
  assert.equal(stale.results[0].reason, 'stale-parent');
  assert.equal(store.getDomainState(d.domain.id).head.digest, after.head.digest);
});

test('篡改载荷（同一轮换标识更换新公钥集）被拒，候选载荷保持不变', async () => {
  const parents = [generateKeyPair(), generateKeyPair()];
  const nextA = [generateKeyPair(), generateKeyPair()];
  const nextB = [generateKeyPair(), generateKeyPair()];
  const store = newStore();
  const d = await store.createDomain({ name: 'd', keys: parents.map(pub), threshold: 2 });
  const body = proposalBase(d, 'rot-fixed', nextA, 2);

  await submit(store, d.domain.id, body, parents[0], 1);

  // 同 rotationId 换载荷，签名对新消息有效，但应判 payload-tampered
  const tampered = { ...body, nextKeys: nextB.map(pub) };
  const r = await store.submitSignatures(d.domain.id, {
    ...tampered,
    signerKey: pub(parents[1]),
    signature: sig(parents[1], d.domain.id, { ...tampered, epoch: 1 }),
  });
  assert.equal(r.results[0].reason, 'payload-tampered');
  const state = store.getDomainState(d.domain.id);
  assert.equal(state.head.epoch, 0);
  assert.deepEqual(state.pending[0].nextKeys.map((k) => k.x), nextA.map((p) => p.publicJwk.x).sort());
  assert.equal(state.pending[0].signatureCount, 1);
});

test('非法签名与非父成员均被拒', async () => {
  const parents = [generateKeyPair(), generateKeyPair()];
  const outsider = generateKeyPair();
  const next = [generateKeyPair(), generateKeyPair()];
  const store = newStore();
  const d = await store.createDomain({ name: 'd', keys: parents.map(pub), threshold: 2 });
  const body = proposalBase(d, 'rot-sig', next, 2);

  const bad = await store.submitSignatures(d.domain.id, {
    ...body,
    signerKey: pub(parents[0]),
    signature: Buffer.from(crypto.randomBytes(64)).toString('base64url'),
  });
  assert.equal(bad.results[0].reason, 'bad-signature');

  const foreign = await store.submitSignatures(d.domain.id, {
    ...body,
    signerKey: pub(outsider),
    signature: sig(outsider, d.domain.id, { ...body, epoch: 1 }),
  });
  assert.equal(foreign.results[0].reason, 'signer-not-parent-member');

  assert.equal(store.getDomainState(d.domain.id).pending.length, 0);
});

test('激活后的竞争候选一律拒绝，链头不变', async () => {
  const parents = [generateKeyPair(), generateKeyPair()];
  const next = [generateKeyPair(), generateKeyPair()];
  const store = newStore();
  const d = await store.createDomain({ name: 'd', keys: parents.map(pub), threshold: 2 });
  const body = proposalBase(d, 'rot-win', next, 2);
  const activated = await activate(store, d.domain.id, body, parents, 1);
  const headDigest = activated.head.digest;

  // 对同一 rotationId 迟到的任何提交
  const lateSame = await submit(store, d.domain.id, body, parents[0], 1);
  assert.equal(lateSame.results[0].reason, 'rotation-already-activated');
  assert.equal(store.getDomainState(d.domain.id).head.digest, headDigest);
});

test('并发补签收敛为唯一活动检查点；并发竞争只有一个候选激活', async () => {
  // 3-of-3：三个签名并发到达
  const parents = [generateKeyPair(), generateKeyPair(), generateKeyPair()];
  const next = [generateKeyPair(), generateKeyPair(), generateKeyPair()];
  const store = newStore();
  const d = await store.createDomain({ name: 'd', keys: parents.map(pub), threshold: 3 });
  const body = proposalBase(d, 'rot-conc', next, 3);

  const attempts = parents.map((p) => submit(store, d.domain.id, body, p, 1));
  const rs = await Promise.all(attempts);
  const activations = rs.filter((x) => x.results[0].activated);
  assert.equal(activations.length, 1);
  const state = store.getDomainState(d.domain.id);
  assert.equal(state.history.length, 2);
  assert.equal(state.head.epoch, 1);
  assert.equal(new Set(state.head.signatures.map((s) => s.keyId)).size, 3);

  // 激活后的并发重传全部拒绝为 rotation-already-activated
  const dup = await Promise.all(parents.map((p) => submit(store, d.domain.id, body, p, 1)));
  for (const x of dup) assert.equal(x.results[0].reason, 'rotation-already-activated');
  assert.equal(store.getDomainState(d.domain.id).head.digest, state.head.digest);

  // 两个不同轮换标识竞争下一父位（2-of-2），恰有一个激活
  const p2 = [generateKeyPair(), generateKeyPair()];
  const store2 = newStore();
  const d2 = await store2.createDomain({ name: 'd2', keys: p2.map(pub), threshold: 2 });
  const nextPairs = [generateKeyPair(), generateKeyPair()];
  const b1 = proposalBase(d2, 'race-1', nextPairs, 2);
  const b2 = proposalBase(d2, 'race-2', nextPairs, 2);
  await submit(store2, d2.domain.id, b1, p2[0], 1);
  await submit(store2, d2.domain.id, b2, p2[0], 1);
  const race = await Promise.all([
    submit(store2, d2.domain.id, b1, p2[1], 1),
    submit(store2, d2.domain.id, b2, p2[1], 1),
  ]);
  const reasons = race.map((x) => (x.results[0].activated ? 'activated' : x.results[0].reason));
  assert.ok(reasons.includes('stale-parent'), `应恰有一个竞争候选失败，实际：${reasons.join(', ')}`);
  const finalState = store2.getDomainState(d2.domain.id);
  assert.equal(finalState.history.length, 2);
  assert.equal(finalState.head.epoch, 1);

  // 收敛：竞争失败的待签候选在赢家激活时即被级联标记为陈旧拒绝
  const race1 = finalState.candidates.find((c) => c.rotationId === 'race-1');
  const race2 = finalState.candidates.find((c) => c.rotationId === 'race-2');
  const statuses = [race1.status, race2.status].sort();
  assert.deepEqual(statuses, ['activated', 'rejected']);
  const loser = race1.status === 'rejected' ? race1 : race2;
  assert.equal(loser.rejectReason, 'stale-parent');
  assert.equal(finalState.pending.length, 0);
  assert.ok(finalState.rejected.some((a) => a.reason === 'stale-parent'));
});

test('重启后活动链头、历史检查点与签名证据完全一致', async () => {
  const parents = [generateKeyPair(), generateKeyPair()];
  const next = [generateKeyPair(), generateKeyPair()];
  const file = newFile();
  const store1 = RotationStore.load(file);
  const d = await store1.createDomain({ name: '持久域', keys: parents.map(pub), threshold: 2 });
  const body = proposalBase(d, 'rot-persist', next, 2);

  // 先制造一条拒绝记录，确认审计信息也持久化
  await store1.submitSignatures(d.domain.id, {
    ...body,
    parentDigest: 'f'.repeat(64),
    signerKey: pub(parents[0]),
    signature: sig(parents[0], d.domain.id, { ...body, parentDigest: 'f'.repeat(64), epoch: 1 }),
  });
  await activate(store1, d.domain.id, body, parents, 1);

  // 模拟进程重启：新实例从同一文件加载
  const store2 = RotationStore.load(file);
  const reloaded = store2.getDomainState(d.domain.id);
  const original = store1.getDomainState(d.domain.id);

  assert.equal(reloaded.head.digest, original.head.digest);
  assert.equal(reloaded.head.epoch, 1);
  assert.deepEqual(reloaded.history, original.history);
  assert.equal(reloaded.history[1].signatures.length, 2);
  assert.deepEqual(
    reloaded.history[1].signatures.map((s) => s.signature),
    original.history[1].signatures.map((s) => s.signature)
  );
  assert.ok(reloaded.rejected.some((a) => a.reason === 'parent-digest-mismatch'));
  assert.equal(reloaded.candidates.find((c) => c.rotationId === 'rot-persist').status, 'activated');

  // 落盘文件本身为合法 JSON，且包含证据
  const onDisk = JSON.parse(fs.readFileSync(file, 'utf8'));
  const diskDomain = onDisk.domains[d.domain.id];
  assert.equal(diskDomain.head.digest, original.head.digest);
  assert.equal(diskDomain.head.signatures.length, 2);
});
