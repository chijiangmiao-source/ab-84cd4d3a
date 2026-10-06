// 运营页面逻辑：创建设备域 → 固定轮换候选 → 分批提交签名 → 渲染检查点/待签/已拒。
const $ = (id) => document.getElementById(id);

const state = {
  domains: [],
  current: null,
  proposal: null,
  keyCount: 2,
  nextKeyCount: 2,
  // 浏览器会话内保管的私钥 JWK：公钥 x -> private CryptoKey
  privateKeys: new Map(),
  lastBatch: null,
};

const api = {
  async get(path) {
    const res = await fetch(path);
    return unwrap(res);
  },
  async post(path, body) {
    const res = await fetch(path, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    return unwrap(res);
  },
};

async function unwrap(res) {
  let payload = null;
  try {
    payload = await res.json();
  } catch {
    /* ignore */
  }
  if (!res.ok) {
    const err = new Error((payload && (payload.message || payload.error)) || `HTTP ${res.status}`);
    err.payload = payload;
    err.status = res.status;
    throw err;
  }
  return payload;
}

function show(el, text, kind) {
  el.textContent = typeof text === 'string' ? text : JSON.stringify(text, null, 2);
  el.classList.remove('ok', 'bad');
  if (kind) el.classList.add(kind);
}

// ---------- JWK 编辑行 ----------
function renderKeyEditors(containerId, count, getter) {
  const container = $(containerId);
  const existing = [];
  container.querySelectorAll('textarea').forEach((t) => existing.push(t.value));
  container.innerHTML = '';
  for (let i = 0; i < count; i++) {
    const wrap = document.createElement('label');
    wrap.textContent = `公钥 #${i + 1} JWK`;
    const ta = document.createElement('textarea');
    ta.rows = 2;
    ta.placeholder = '{"kty":"OKP","crv":"Ed25519","x":"…"}';
    ta.value = existing[i] || (getter && getter(i)) || '';
    wrap.appendChild(ta);
    container.appendChild(wrap);
  }
}

function readJwks(containerId) {
  return [...$(containerId).querySelectorAll('textarea')].map((t) => {
    const raw = t.value.trim();
    if (!raw) throw new Error('存在未填写的公钥 JWK');
    try {
      const jwk = JSON.parse(raw);
      if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || !jwk.x) {
        throw new Error('不是 OKP/Ed25519 JWK');
      }
      return { kty: 'OKP', crv: 'Ed25519', x: jwk.x };
    } catch (err) {
      throw new Error(`公钥解析失败：${err.message}`);
    }
  });
}

// ---------- 浏览器 Ed25519 ----------
async function browserGenerate() {
  if (!globalThis.crypto?.subtle) throw new Error('浏览器不支持 WebCrypto');
  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
  const pub = await crypto.subtle.exportKey('jwk', pair.publicKey);
  return { publicJwk: { kty: 'OKP', crv: 'Ed25519', x: pub.x }, privateKey: pair.privateKey };
}

async function browserSign(privateCryptoKey, message) {
  const sig = await crypto.subtle.sign(
    { name: 'Ed25519' },
    privateCryptoKey,
    new TextEncoder().encode(message)
  );
  return b64url(new Uint8Array(sig));
}

function b64url(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ---------- 健康 ----------
async function refreshHealth() {
  try {
    const h = await api.get('/health');
    $('health').textContent = `健康：${h.status} · 设备域 ${h.domains} · 活动检查点 ${h.activeCheckpoints} · 待签候选 ${h.pendingProposals}${h.persisted ? '' : '（未持久化）'}`;
    $('health').classList.add('ok');
    $('health').classList.remove('bad');
  } catch (err) {
    $('health').textContent = `健康异常：${err.message}`;
    $('health').classList.add('bad');
  }
}

// ---------- 设备域列表 ----------
async function refreshDomains() {
  const data = await api.get('/api/domains');
  state.domains = data.domains;
  const sel = $('domainSelect');
  sel.innerHTML = '';
  if (state.domains.length === 0) {
    const opt = new Option('（暂无设备域）', '');
    sel.add(opt);
    return;
  }
  for (const d of state.domains) {
    sel.add(new Option(`${d.name} · epoch ${d.epoch} · 门限 ${d.threshold}/${d.memberCount}`, d.id));
  }
}

// ---------- 创建设备域 ----------
$('genKeysBtn').addEventListener('click', async () => {
  try {
    renderKeyEditors('keyEditors', state.keyCount);
    const tas = [...$('keyEditors').querySelectorAll('textarea')];
    for (let i = 0; i < tas.length; i++) {
      const { publicJwk, privateKey } = await browserGenerate();
      tas[i].value = JSON.stringify(publicJwk);
      state.privateKeys.set(publicJwk.x, privateKey);
    }
    show($('genStatus'), '已在浏览器内生成演示密钥对；私钥仅保留在本页会话内存中。', 'ok');
  } catch (err) {
    show($('genStatus'), `浏览器生成失败（${err.message}）。可手工粘贴公钥 JWK，或使用冒烟脚本在服务端侧签名。`, 'bad');
  }
});

$('addKeyBtn').addEventListener('click', () => {
  state.keyCount = Math.min(5, state.keyCount + 1);
  renderKeyEditors('keyEditors', state.keyCount);
});
$('removeKeyBtn').addEventListener('click', () => {
  state.keyCount = Math.max(2, state.keyCount - 1);
  renderKeyEditors('keyEditors', state.keyCount);
});

$('createDomainBtn').addEventListener('click', async () => {
  try {
    const keys = readJwks('keyEditors');
    const threshold = Number($('domainThreshold').value);
    const created = await api.post('/api/domains', {
      name: $('domainName').value,
      keys,
      threshold,
    });
    show($('createResult'), created, 'ok');
    await refreshDomains();
    $('domainSelect').value = created.domain.id;
    await loadDomain();
  } catch (err) {
    show($('createResult'), `创建失败：${err.message}\n${JSON.stringify(err.payload, null, 2)}`, 'bad');
  }
});

// ---------- 读取设备域 ----------
$('refreshListBtn').addEventListener('click', () => refreshDomains().catch((e) => alert(e.message)));
$('loadDomainBtn').addEventListener('click', () => loadDomain().catch((e) => alert(e.message)));

async function loadDomain() {
  const id = $('domainSelect').value;
  if (!id) return;
  state.current = await api.get(`/api/domains/${id}`);
  state.proposal = null;
  $('proposalPanel').classList.add('hidden');
  $('domainDetail').classList.remove('hidden');
  renderDomain();
}

function short(x) {
  return x.length > 16 ? `${x.slice(0, 8)}…${x.slice(-6)}` : x;
}

function esc(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderDomain() {
  const s = state.current;
  $('headDigest').textContent = s.head.digest;
  $('headEpoch').textContent = String(s.head.epoch);
  $('headThreshold').textContent = `${s.head.threshold} / ${s.head.keys.length}`;
  $('headKeys').innerHTML = '';
  for (const k of s.head.keys) {
    const div = document.createElement('div');
    div.textContent = `• ${k.x}`;
    $('headKeys').appendChild(div);
  }
  renderKeyEditors('nextKeyEditors', state.nextKeyCount, (i) =>
    s.head.keys[i] ? JSON.stringify(s.head.keys[i]) : ''
  );
  renderSignerSelect();
  renderStatePanel();
}

function renderSignerSelect() {
  const s = state.current;
  const sel = $('signerSelect');
  sel.innerHTML = '';
  for (const k of s.head.keys) {
    const has = state.privateKeys.has(k.x);
    sel.add(new Option(`${short(k.x)}${has ? '（会话内有私钥）' : '（无私钥，需手工签名）'}`, k.x));
  }
}

// ---------- 固定候选 ----------
$('useHeadKeysBtn').addEventListener('click', () => {
  state.nextKeyCount = state.current.head.keys.length;
  renderKeyEditors('nextKeyEditors', state.nextKeyCount, (i) =>
    JSON.stringify(state.current.head.keys[i])
  );
});
$('addNextKeyBtn').addEventListener('click', () => {
  state.nextKeyCount = Math.min(5, state.nextKeyCount + 1);
  renderKeyEditors('nextKeyEditors', state.nextKeyCount);
});
$('removeNextKeyBtn').addEventListener('click', () => {
  state.nextKeyCount = Math.max(2, state.nextKeyCount - 1);
  renderKeyEditors('nextKeyEditors', state.nextKeyCount);
});

$('fixProposalBtn').addEventListener('click', async () => {
  try {
    const s = state.current;
    const nextKeys = readJwks('nextKeyEditors');
    const body = {
      rotationId: $('rotationId').value.trim(),
      parentDigest: s.head.digest,
      nextKeys,
      nextThreshold: Number($('nextThreshold').value),
    };
    const preview = await api.post(`/api/domains/${s.domain.id}/preview`, body);
    state.proposal = { ...body, message: preview.message, epoch: preview.epoch };
    $('pParentDigest').textContent = preview.parentDigest;
    $('pEpoch').textContent = String(preview.epoch);
    $('pNextKeys').innerHTML = '';
    for (const k of preview.nextKeys) {
      const div = document.createElement('div');
      div.textContent = `• ${k.x}`;
      $('pNextKeys').appendChild(div);
    }
    $('pNextThreshold').textContent = String(preview.nextThreshold);
    $('pMessage').textContent = preview.message;
    $('proposalPanel').classList.remove('hidden');
    show($('submitResult'), '候选已固定，尚未写入任何状态；请分批收集签名。');
  } catch (err) {
    alert(`固定候选失败：${err.message}`);
  }
});

// ---------- 分批签名 ----------
$('browserSignBtn').addEventListener('click', async () => {
  try {
    if (!state.proposal) throw new Error('请先固定候选');
    const x = $('signerSelect').value;
    const priv = state.privateKeys.get(x);
    if (!priv) throw new Error('该成员私钥不在会话内，请使用手工签名栏');
    const sig = await browserSign(priv, state.proposal.message);
    $('manualSigner').value = JSON.stringify({ kty: 'OKP', crv: 'Ed25519', x });
    $('manualSignature').value = sig;
  } catch (err) {
    alert(`浏览器签名失败：${err.message}`);
  }
});

async function buildBatch() {
  if (!state.proposal) throw new Error('请先固定候选');
  const signerKey = JSON.parse($('manualSigner').value.trim());
  const signature = $('manualSignature').value.trim();
  if (!signature) throw new Error('缺少签名');
  return {
    rotationId: state.proposal.rotationId,
    parentDigest: state.proposal.parentDigest,
    nextKeys: state.proposal.nextKeys,
    nextThreshold: state.proposal.nextThreshold,
    signerKey: { kty: 'OKP', crv: 'Ed25519', x: signerKey.x },
    signature,
  };
}

$('submitBatchBtn').addEventListener('click', async () => {
  try {
    const batch = await buildBatch();
    state.lastBatch = batch;
    const result = await api.post(`/api/domains/${state.current.domain.id}/signatures`, batch);
    show($('submitResult'), result);
    await loadDomain();
    if (result.results?.some((r) => r.activated)) {
      show($('submitResult'), `候选已激活，活动链头已推进至 epoch ${result.domain.head.epoch}。\n\n${JSON.stringify(result, null, 2)}`, 'ok');
    }
  } catch (err) {
    show($('submitResult'), `提交被拒：${err.message}\n${JSON.stringify(err.payload, null, 2)}`, 'bad');
    await loadDomain().catch(() => undefined);
  }
});

$('resubmitBtn').addEventListener('click', async () => {
  try {
    if (!state.lastBatch) throw new Error('尚无已提交批次可重传');
    const result = await api.post(`/api/domains/${state.current.domain.id}/signatures`, state.lastBatch);
    show($('submitResult'), `重传结果（应仅出现 duplicate-signature，不产生新检查点）：\n\n${JSON.stringify(result, null, 2)}`);
    await loadDomain();
  } catch (err) {
    show($('submitResult'), `重传返回：${err.message}\n${JSON.stringify(err.payload, null, 2)}`, 'bad');
    await loadDomain().catch(() => undefined);
  }
});

// ---------- 状态面板：检查点/待签/已拒 ----------
function badge(status) {
  const map = { pending: '待签', activated: '已激活', rejected: '已拒' };
  return `<span class="badge ${status}">${map[status] || status}</span>`;
}

function renderStatePanel() {
  const s = state.current;
  const panel = $('statePanel');
  panel.innerHTML = '';

  const h3cp = document.createElement('h3');
  h3cp.textContent = `历史检查点（${s.history.length}）— 每个检查点附带签名证据`;
  panel.appendChild(h3cp);
  for (const cp of s.history) {
    const isHead = cp.digest === s.head.digest;
    const div = document.createElement('div');
    div.className = 'checkpoint';
    let evidenceHtml = '（创世无签名）';
    if (cp.signatures.length > 0) {
      const items = cp.signatures
        .map((ev) => `<div>• <span class="mono">${short(ev.keyId)}</span> sig=<span class="mono">${short(ev.signature)}</span></div>`)
        .join('');
      evidenceHtml = `${cp.signatures.length} 份：${items}`;
    }
    div.innerHTML = `
      <div class="line">
        <strong>epoch ${cp.epoch}</strong>
        ${isHead ? '<span class="badge head">活动链头</span>' : ''}
        rotationId=<span class="mono">${esc(cp.rotationId)}</span>
      </div>
      <dl class="grid">
        <dt>固定父摘要</dt><dd class="mono">${cp.parentDigest ?? '（创世，无父）'}</dd>
        <dt>本检查点摘要</dt><dd class="mono">${cp.digest}</dd>
        <dt>排序后公钥集</dt><dd class="mono">${cp.keys.map((k) => `• ${k.x}`).join('<br>')}</dd>
        <dt>门限</dt><dd>${cp.threshold} / ${cp.keys.length}</dd>
        <dt>签名证据</dt><dd class="evidence">${evidenceHtml}</dd>
        <dt>激活时间</dt><dd class="mono">${cp.activatedAt}</dd>
      </dl>`;
    panel.appendChild(div);
  }

  const h3pend = document.createElement('h3');
  h3pend.textContent = `待签候选（${s.pending.length}）`;
  panel.appendChild(h3pend);
  if (s.pending.length === 0) {
    panel.appendChild(Object.assign(document.createElement('p'), { className: 'hint', textContent: '无待签候选。' }));
  } else {
    const table = document.createElement('table');
    table.innerHTML = `<thead><tr><th>轮换标识</th><th>固定父摘要</th><th>代次</th><th>新公钥集</th><th>门限</th><th>已收集签名</th><th>签名者</th></tr></thead>`;
    const tb = document.createElement('tbody');
    for (const c of s.pending) {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td class="mono">${esc(c.rotationId)}</td><td class="mono">${short(c.parentDigest)}</td><td>${c.epoch}</td>
        <td class="mono">${c.nextKeys.map((k) => short(k.x)).join('<br>')}</td><td>${c.nextThreshold}/${c.nextKeys.length}</td>
        <td>${c.signatureCount}</td><td class="mono">${c.signerKeyIds.map(short).join('<br>')}</td>`;
      tb.appendChild(tr);
    }
    table.appendChild(tb);
    panel.appendChild(table);
  }

  const h3rej = document.createElement('h3');
  h3rej.textContent = `已拒提交（${s.rejected.length}）— 均未改变链头`;
  panel.appendChild(h3rej);
  if (s.rejected.length === 0) {
    panel.appendChild(Object.assign(document.createElement('p'), { className: 'hint', textContent: '无拒绝记录。' }));
  } else {
    const table = document.createElement('table');
    table.innerHTML = `<thead><tr><th>时间</th><th>轮换标识</th><th>拒因代码</th><th>说明</th><th>签名者</th></tr></thead>`;
    const tb = document.createElement('tbody');
    for (const r of s.rejected.slice().reverse()) {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td class="mono">${esc(r.at)}</td><td class="mono">${esc(r.rotationId)}</td>
        <td class="reason">${esc(r.reason)}</td><td>${esc(r.message || '')}</td>
        <td class="mono">${r.signerKeyId ? short(r.signerKeyId) : '—'}</td>`;
      tb.appendChild(tr);
    }
    table.appendChild(tb);
    panel.appendChild(table);
  }
}

// ---------- 初始化 ----------
renderKeyEditors('keyEditors', state.keyCount);
renderKeyEditors('nextKeyEditors', state.nextKeyCount);
refreshHealth();
refreshDomains().catch((err) => show($('createResult'), `初始列表失败：${err.message}`, 'bad'));
setInterval(refreshHealth, 5000);
