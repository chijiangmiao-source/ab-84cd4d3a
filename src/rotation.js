// 设备域密钥轮换授权链核心。
//
// 不变量：
//  1. 每个检查点携带固定父摘要 parentDigest，摘要 = 规范 UTF-8 消息的 SHA-256；
//  2. 候选只接受“父链头当前有效成员”的 Ed25519 签名，签名经去重计数；
//  3. 去重后的父成员数达到父门限时，才在同一次持久化提交中写入新检查点并推进链头；
//  4. 错误父摘要 / 重复签名 / 篡改载荷 / 激活后的竞争候选一律记录拒因且不推进链头；
//  5. 所有变更经互斥串行化，并以临时文件 + rename 原子落盘，重启后状态一致。
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { canonical, canonicalBytes } from './canonical.js';
import { keyId, normalizeKeySet, normalizePublicJwk, verifyDetached } from './crypto-keys.js';

export const REJECT_REASONS = {
  'parent-digest-mismatch': '父摘要与当前活动链头不一致',
  'stale-parent': '候选所依据的父检查点已被后继取代',
  'rotation-already-activated': '该轮换标识已激活，拒绝激活后的竞争提交',
  'invalid-payload': '候选载荷非法（公钥集或门限不合规）',
  'payload-tampered': '提交载荷与该轮换标识已固定的候选载荷不一致',
  'bad-signature': '签名验签失败：未通过规范 UTF-8 消息校验',
  'signer-not-parent-member': '签名者不是父检查点密钥成员',
  'duplicate-signature': '重复签名：该父成员已提交过签名',
};

const PROPOSAL_LABEL = 'maintenance-network-key-rotation';

function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function nowIso() {
  return new Date().toISOString();
}

// 待签名的规范消息：固定父摘要、下一代次、排序后新公钥集、新门限。
export function buildProposalMessage({
  domainId,
  rotationId,
  parentDigest,
  epoch,
  nextKeys,
  nextThreshold,
}) {
  return canonical({
    label: PROPOSAL_LABEL,
    domainId,
    rotationId,
    parentDigest,
    epoch,
    nextKeys,
    nextThreshold,
  });
}

// 检查点摘要同样基于规范字节，字段顺序不影响摘要。
export function checkpointDigest({ domainId, rotationId, parentDigest, epoch, keys, threshold }) {
  return sha256Hex(
    canonicalBytes({ domainId, rotationId, parentDigest, epoch, keys, threshold })
  );
}

function validateThreshold(threshold, keyCount) {
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > keyCount) {
    const err = new Error(`门限必须为 1..${keyCount} 之间的整数`);
    err.code = 'invalid-threshold';
    throw err;
  }
}

export class RotationError extends Error {
  constructor(code, message, status = 400) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

export class RotationStore {
  constructor(dataFile) {
    this.dataFile = dataFile;
    this.state = { version: 1, domains: {} };
    this.chain = Promise.resolve();
  }

  static load(dataFile) {
    const store = new RotationStore(dataFile);
    if (fs.existsSync(dataFile)) {
      const parsed = JSON.parse(fs.readFileSync(dataFile, 'utf8'));
      if (!parsed || parsed.version !== 1 || typeof parsed.domains !== 'object') {
        throw new Error('持久化文件格式不受支持');
      }
      store.state = parsed;
    }
    return store;
  }

  // 互斥执行：并发补签/竞争提交被串行化，激活与落盘处于同一临界区。
  withLock(fn) {
    const run = this.chain.then(() => fn());
    this.chain = run.then(
      () => undefined,
      () => undefined
    );
    return run;
  }

  persist() {
    const dir = path.dirname(this.dataFile);
    fs.mkdirSync(dir, { recursive: true });
    const tmp = path.join(
      dir,
      `.state-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}.tmp`
    );
    fs.writeFileSync(tmp, JSON.stringify(this.state, null, 2), 'utf8');
    fs.renameSync(tmp, this.dataFile);
  }

  getDomainOrThrow(domainId) {
    const domain = this.state.domains[domainId];
    if (!domain) throw new RotationError('domain-not-found', '设备域不存在', 404);
    return domain;
  }

  listDomains() {
    return Object.values(this.state.domains).map((d) => this.summary(d));
  }

  summary(domain) {
    return {
      id: domain.id,
      name: domain.name,
      createdAt: domain.createdAt,
      headDigest: domain.head.digest,
      epoch: domain.head.epoch,
      threshold: domain.head.threshold,
      memberCount: domain.head.keys.length,
      pendingCount: Object.values(domain.candidates).filter((c) => c.status === 'pending').length,
      checkpointCount: domain.history.length,
    };
  }

  createDomain({ name, keys, threshold }) {
    return this.withLock(() => {
      if (typeof name !== 'string' || name.trim().length === 0) {
        throw new RotationError('invalid-name', '设备域名称不能为空');
      }
      const sortedKeys = normalizeKeySet(keys);
      validateThreshold(threshold, sortedKeys.length);

      const id = crypto.randomBytes(12).toString('hex');
      const createdAt = nowIso();
      const genesis = {
        domainId: id,
        rotationId: 'genesis',
        parentDigest: null,
        epoch: 0,
        keys: sortedKeys,
        threshold,
      };
      const checkpoint = {
        ...genesis,
        digest: checkpointDigest(genesis),
        activatedAt: createdAt,
        signatures: [],
      };
      this.state.domains[id] = {
        id,
        name: name.trim(),
        createdAt,
        head: checkpoint,
        history: [checkpoint],
        candidates: {},
        attempts: [],
      };
      this.persist();
      return this.getDomainState(id);
    });
  }

  // 预览待签名的规范消息，不写入任何状态。
  previewProposal(domainId, body) {
    const domain = this.getDomainOrThrow(domainId);
    const { rotationId, parentDigest, nextKeys, nextThreshold } = this.readProposalBody(body);
    if (parentDigest !== domain.head.digest) {
      throw new RotationError('parent-digest-mismatch', REJECT_REASONS['parent-digest-mismatch']);
    }
    const epoch = domain.head.epoch + 1;
    return {
      domainId,
      rotationId,
      parentDigest,
      epoch,
      nextKeys,
      nextThreshold,
      message: buildProposalMessage({ domainId, rotationId, parentDigest, epoch, nextKeys, nextThreshold }),
      encoding: 'utf-8',
    };
  }

  readProposalBody(body) {
    const rotationId = typeof body?.rotationId === 'string' ? body.rotationId.trim() : '';
    if (!rotationId) throw new RotationError('invalid-rotation-id', '轮换标识不能为空');
    const parentDigest = typeof body?.parentDigest === 'string' ? body.parentDigest : '';
    if (!/^[0-9a-f]{64}$/.test(parentDigest)) {
      throw new RotationError('invalid-parent-digest', '父摘要必须为 64 位十六进制 SHA-256');
    }
    let nextKeys;
    try {
      nextKeys = normalizeKeySet(body?.nextKeys);
    } catch (err) {
      throw new RotationError('invalid-payload', `${REJECT_REASONS['invalid-payload']}：${err.message}`);
    }
    const nextThreshold = body?.nextThreshold;
    if (!Number.isInteger(nextThreshold) || nextThreshold < 1 || nextThreshold > nextKeys.length) {
      throw new RotationError(
        'invalid-payload',
        `${REJECT_REASONS['invalid-payload']}：新门限必须为 1..${nextKeys.length} 的整数`
      );
    }
    return { rotationId, parentDigest, nextKeys, nextThreshold };
  }

  recordAttempt(domain, { rotationId, reason, signerKeyId }) {
    domain.attempts.push({
      rotationId,
      reason,
      message: REJECT_REASONS[reason] || reason,
      signerKeyId: signerKeyId ?? null,
      at: nowIso(),
    });
  }

  // 提交一批签名（每批至少一条；页面分批调用同一轮换标识）。
  submitSignatures(domainId, body) {
    return this.withLock(() => {
      const domain = this.getDomainOrThrow(domainId);
      const entries = Array.isArray(body?.signatures)
        ? body.signatures
        : [{ signerKey: body?.signerKey, signature: body?.signature }];

      const results = entries.map((entry) => this.submitOne(domain, body, entry));
      this.persist();
      return { results, domain: this.getDomainState(domain.id) };
    });
  }

  submitOne(domain, body, entry) {
    const reject = (reason, extra = {}) => {
      let signerKeyId = null;
      try {
        signerKeyId = entry?.signerKey ? keyId(normalizePublicJwk(entry.signerKey)) : null;
      } catch {
        signerKeyId = null;
      }
      this.recordAttempt(domain, { rotationId: body?.rotationId ?? 'unknown', reason, signerKeyId });
      return { accepted: false, reason, message: REJECT_REASONS[reason] || reason, ...extra };
    };

    let proposal;
    try {
      proposal = this.readProposalBody(body);
    } catch (err) {
      if (err instanceof RotationError) {
        return reject(err.code === 'invalid-payload' ? 'invalid-payload' : err.code, {
          detail: err.message,
        });
      }
      throw err;
    }
    const { rotationId, parentDigest, nextKeys, nextThreshold } = proposal;

    const existing = domain.candidates[rotationId];

    // 已激活轮换：任何迟到的竞争提交一律拒绝，链头不变。
    if (existing?.status === 'activated') {
      return reject('rotation-already-activated', {
        headDigest: domain.head.digest,
        checkpointDigest: existing.checkpointDigest,
      });
    }

    // 父摘要必须指向当前活动链头（固定父摘要）。
    if (parentDigest !== domain.head.digest) {
      // 存在同名候选记录意味着它曾锚定于某一父检查点：该父已被取代即陈旧；
      // 全新轮换标识的错误父摘要则为简单的父摘要不匹配。
      return reject(existing ? 'stale-parent' : 'parent-digest-mismatch', {
        headDigest: domain.head.digest,
      });
    }

    const epoch = domain.head.epoch + 1;
    const message = buildProposalMessage({
      domainId: domain.id,
      rotationId,
      parentDigest,
      epoch,
      nextKeys,
      nextThreshold,
    });

    // 解析签名者公钥。
    let signerJwk;
    try {
      signerJwk = normalizePublicJwk(entry?.signerKey);
    } catch (err) {
      return reject('bad-signature', { detail: err.message });
    }
    const signerId = keyId(signerJwk);

    // 签名者必须是父密钥成员（先于候选落定，外部成员不产生待签候选）。
    const parentMemberIds = new Set(domain.head.keys.map((k) => k.x));
    if (!parentMemberIds.has(signerId)) {
      return reject('signer-not-parent-member');
    }

    // 已固定的候选载荷不得变更（篡改载荷）：先于验签判定。
    if (existing && existing.status !== 'rejected' && existing.message !== message) {
      return reject('payload-tampered');
    }

    // 针对规范 UTF-8 消息验签（先于候选创建：非法签名不留下空候选）。
    const signature = typeof entry?.signature === 'string' ? entry.signature : '';
    let sigBytes;
    try {
      sigBytes = Buffer.from(signature, 'base64url');
    } catch {
      return reject('bad-signature', { detail: '签名不是合法 base64url' });
    }
    if (!verifyDetached(signerJwk, Buffer.from(message, 'utf8'), sigBytes)) {
      return reject('bad-signature');
    }

    // 落定候选（首次出现时创建）。
    let candidate = existing;
    if (!candidate) {
      candidate = {
        rotationId,
        parentDigest,
        epoch,
        nextKeys,
        nextThreshold,
        message,
        status: 'pending',
        rejectReason: null,
        signatures: [],
        createdAt: nowIso(),
        decidedAt: null,
        checkpointDigest: null,
      };
      domain.candidates[rotationId] = candidate;
    } else if (candidate.status === 'rejected') {
      // 以同一对象重置，保证后续更新直接作用于持久化状态。
      Object.assign(candidate, {
        parentDigest,
        epoch,
        nextKeys,
        nextThreshold,
        message,
        status: 'pending',
        rejectReason: null,
        signatures: [],
        createdAt: nowIso(),
        decidedAt: null,
        checkpointDigest: null,
      });
    }

    // 重复签名（含重传）：幂等返回，不重复计数，不推进链头；仍留拒因审计。
    if (candidate.signatures.some((s) => s.keyId === signerId)) {
      this.recordAttempt(domain, { rotationId, reason: 'duplicate-signature', signerKeyId: signerId });
      return {
        accepted: false,
        duplicate: true,
        reason: 'duplicate-signature',
        message: REJECT_REASONS['duplicate-signature'],
        candidate: this.candidateView(candidate),
      };
    }

    candidate.signatures.push({
      keyId: signerId,
      signer: signerJwk,
      signature,
      at: nowIso(),
    });

    // 去重后的父成员计数达到父门限 → 同一临界区内激活并落盘。
    const distinctParentMembers = new Set(
      candidate.signatures.map((s) => s.keyId).filter((id) => parentMemberIds.has(id))
    ).size;

    let activated = false;
    if (distinctParentMembers >= domain.head.threshold) {
      const checkpointBody = {
        domainId: domain.id,
        rotationId,
        parentDigest,
        epoch,
        keys: nextKeys,
        threshold: nextThreshold,
      };
      const checkpoint = {
        ...checkpointBody,
        digest: checkpointDigest(checkpointBody),
        activatedAt: nowIso(),
        signatures: candidate.signatures.map((s) => ({ ...s })),
      };
      domain.history.push(checkpoint);
      domain.head = checkpoint;
      candidate.status = 'activated';
      candidate.decidedAt = checkpoint.activatedAt;
      candidate.checkpointDigest = checkpoint.digest;
      activated = true;

      // 收敛：所有仍挂在旧父检查点上的其他待签候选不可能再激活，
      // 统一标记为陈旧拒绝，保证只存在一个活动检查点、待签列表无僵尸候选。
      for (const other of Object.values(domain.candidates)) {
        if (other === candidate || other.status !== 'pending') continue;
        if (other.parentDigest === parentDigest) {
          other.status = 'rejected';
          other.rejectReason = 'stale-parent';
          other.decidedAt = checkpoint.activatedAt;
          this.recordAttempt(domain, {
            rotationId: other.rotationId,
            reason: 'stale-parent',
            signerKeyId: null,
          });
        }
      }
    }

    return {
      accepted: true,
      activated,
      distinctParentMembers,
      parentThreshold: domain.head.threshold,
      candidate: this.candidateView(candidate),
    };
  }

  candidateView(candidate) {
    return {
      rotationId: candidate.rotationId,
      parentDigest: candidate.parentDigest,
      epoch: candidate.epoch,
      nextKeys: candidate.nextKeys,
      nextThreshold: candidate.nextThreshold,
      status: candidate.status,
      rejectReason: candidate.rejectReason ?? null,
      signatureCount: candidate.signatures.length,
      signerKeyIds: candidate.signatures.map((s) => s.keyId),
      createdAt: candidate.createdAt,
      decidedAt: candidate.decidedAt,
      checkpointDigest: candidate.checkpointDigest,
    };
  }

  checkpointView(checkpoint) {
    return {
      rotationId: checkpoint.rotationId,
      parentDigest: checkpoint.parentDigest,
      epoch: checkpoint.epoch,
      keys: checkpoint.keys,
      threshold: checkpoint.threshold,
      digest: checkpoint.digest,
      activatedAt: checkpoint.activatedAt,
      signatures: checkpoint.signatures.map((s) => ({
        keyId: s.keyId,
        signer: s.signer,
        signature: s.signature,
        at: s.at,
      })),
    };
  }

  getDomainState(domainId) {
    const domain = this.getDomainOrThrow(domainId);
    return {
      domain: this.summary(domain),
      head: this.checkpointView(domain.head),
      history: domain.history.map((cp) => this.checkpointView(cp)),
      candidates: Object.values(domain.candidates).map((c) => this.candidateView(c)),
      pending: Object.values(domain.candidates)
        .filter((c) => c.status === 'pending')
        .map((c) => this.candidateView(c)),
      rejected: domain.attempts.map((a) => ({ ...a })),
    };
  }

  health() {
    const domains = Object.values(this.state.domains);
    return {
      status: 'ok',
      persisted: fs.existsSync(this.dataFile),
      domains: domains.length,
      activeCheckpoints: domains.reduce((n, d) => n + (d.head ? 1 : 0), 0),
      pendingProposals: domains.reduce(
        (n, d) => n + Object.values(d.candidates).filter((c) => c.status === 'pending').length,
        0
      ),
    };
  }
}
