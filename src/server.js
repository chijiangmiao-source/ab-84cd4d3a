// HTTP 服务：设备域创建、规范消息预览、分批签名提交、状态与健康检查。
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import path from 'node:path';
import { RotationStore, RotationError } from './rotation.js';

const PORT = Number(process.env.PORT || 8080);
const DATA_FILE = process.env.DATA_FILE || path.join(process.cwd(), 'data', 'state.json');
const PUBLIC_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');

const store = RotationStore.load(DATA_FILE);

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
};

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  });
  res.end(body);
}

async function readJson(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 2_000_000) {
      throw new RotationError('payload-too-large', '请求体超过 2MB', 413);
    }
    chunks.push(chunk);
  }
  if (chunks.length === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new RotationError('invalid-json', '请求体不是合法 JSON', 400);
  }
}

function serveStatic(req, res, pathname) {
  let rel = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
  const filePath = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!filePath.startsWith(PUBLIC_DIR)) {
    sendJson(res, 403, { error: 'forbidden' });
    return;
  }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      sendJson(res, 404, { error: 'not-found', path: pathname });
      return;
    }
    res.writeHead(200, {
      'content-type': MIME[path.extname(filePath)] || 'application/octet-stream',
      'cache-control': 'no-store',
    });
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const { pathname } = url;

  try {
    if (req.method === 'GET' && pathname === '/health') {
      sendJson(res, 200, store.health());
      return;
    }

    if (req.method === 'GET' && pathname === '/api/domains') {
      sendJson(res, 200, { domains: store.listDomains() });
      return;
    }

    if (req.method === 'POST' && pathname === '/api/domains') {
      const body = await readJson(req);
      const state = await store.createDomain(body);
      sendJson(res, 201, state);
      return;
    }

    const domainMatch = pathname.match(/^\/api\/domains\/([A-Za-z0-9_-]+)(\/(preview|signatures))?$/);
    if (domainMatch) {
      const domainId = domainMatch[1];
      const action = domainMatch[3];

      if (req.method === 'GET' && !action) {
        sendJson(res, 200, store.getDomainState(domainId));
        return;
      }
      if (req.method === 'POST' && action === 'preview') {
        const body = await readJson(req);
        sendJson(res, 200, store.previewProposal(domainId, body));
        return;
      }
      if (req.method === 'POST' && action === 'signatures') {
        const body = await readJson(req);
        const result = await store.submitSignatures(domainId, body);
        sendJson(res, 200, result);
        return;
      }
    }

    if (req.method === 'GET') {
      serveStatic(req, res, pathname);
      return;
    }

    sendJson(res, 404, { error: 'not-found', path: pathname });
  } catch (err) {
    if (err instanceof RotationError) {
      sendJson(res, err.status, { error: err.code, message: err.message });
      return;
    }
    sendJson(res, 500, { error: 'internal-error', message: String(err && err.message || err) });
  }
});

server.listen(PORT, () => {
  const address = server.address();
  const realPort = typeof address === 'object' && address ? address.port : PORT;
  console.log(`[rotation-authority] listening on :${realPort} (data: ${DATA_FILE})`);
});

export { server, store };
