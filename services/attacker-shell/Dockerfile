# 教育用 attacker-shell — Phase 2+ で辞書ブルートフォース等のループ実行に使用
# 関連設計書: DESIGN/30 §2.2, DESIGN/34 §4
# Phase 1 では起動のみで実機能なし。docker-compose の最小権限設定でコンテナ脱出耐性を実証する。
FROM alpine:3.20
LABEL org.opencontainers.image.description="OSI Reference — attacker-shell (educational simulation only)"

RUN apk add --no-cache curl openssl

# 非 root ユーザー
RUN addgroup -S attacker && adduser -S -G attacker attacker
USER attacker

# Phase 1 では idle (compose 側で `command: ["sleep", "infinity"]` を期待)
CMD ["sleep", "infinity"]
