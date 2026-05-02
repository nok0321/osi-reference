# 教育用脆弱 victim アプリ — services/victim-web
# 関連設計書: DESIGN/32-victim-web-spec.md §6, DESIGN/34-safety-guardrails-live.md §4
FROM node:20-alpine
LABEL org.opencontainers.image.description="OSI Reference — vulnerable victim-web (educational simulation only)"

WORKDIR /app

# npm workspaces を活用: root の package.json + lock + victim-web のみビルド
COPY package.json package-lock.json* ./
COPY services/victim-web ./services/victim-web

RUN npm ci --workspace=@osi-ref/victim-web --include-workspace-root=false \
    && npm run build --workspace=@osi-ref/victim-web

# tmpfs マウントの書き込み先 (compose 側で /app/data に tmpfs を当てる)
RUN mkdir -p /app/data && chown node:node /app/data

USER node
EXPOSE 4001

HEALTHCHECK --interval=10s --timeout=2s --retries=3 \
    CMD wget -q -O- http://localhost:4001/health || exit 1

CMD ["node", "services/victim-web/dist/index.js"]
