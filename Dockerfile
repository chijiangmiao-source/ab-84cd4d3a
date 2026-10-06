FROM node:20-alpine

WORKDIR /app

# 无第三方依赖：仅复制源码与验收资产。
COPY package.json ./
COPY src ./src
COPY public ./public
COPY test ./test
COPY scripts ./scripts
COPY verify ./verify

RUN chmod +x verify \
  && node --check src/server.js \
  && node --check scripts/smoke.mjs

ENV NODE_ENV=production \
  PORT=8080 \
  DATA_FILE=/data/state.json

VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=5s --timeout=3s --retries=12 --start-period=2s \
  CMD wget -q -O - http://127.0.0.1:8080/health || exit 1

CMD ["node", "src/server.js"]
