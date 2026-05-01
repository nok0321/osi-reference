---
title: 攻撃デモカタログ — live 化アーキテクチャ
phase: design
audience: 開発者・教材執筆者
last-updated: 2026-05-02
safety-reviewed: false
---

# 30. 攻撃デモカタログ — live 化アーキテクチャ

## 1. 目的と背景

### 1.1 現状ナレーション型の課題

PR #6 (becc5fc) でリリースした攻撃デモカタログ (38 シナリオ) は、認証タブ内に Attacker View を追加し、
各攻撃の手順を `AttackStep[]` のタイムラインとして可視化する形式で実装した。
ユーザー評価では次の課題が指摘されている。

> 「文字列ベースでイメージが付きづらい。MD まとめで十分なレベル」

具体的な問題点は以下の通り。

| 問題 | 現状の挙動 | 学習者への影響 |
|------|-----------|--------------|
| リクエスト生成がサーバー側 | `POST /api/jwt/attack/alg-none` をサーバーが JWT を偽造して結果を返す | 「攻撃者がどのリクエストを組み立てるか」を体感できない |
| HTTP の生のやり取りが不可視 | DataFlowPanel に表示されるのはサーバー内部の _trace のみ | ヘッダ・ボディを見て脆弱性を発見する体験が欠ける |
| victim が orchestrator と同居 | 脆弱な実装と安全な実装が同一プロセスに混在 | 「このサーバーが脆弱なのか安全なのか」が曖昧 |
| 隔離がソフトウェア境界のみ | `localhost` への fetch を API 規約で制限しているだけ | OS レイヤでの egress 遮断がなく、概念実証として不完全 |

### 1.2 live 化の目的

学習者がブラウザから生 HTTP リクエストを自ら組み立て、Docker で隔離された脆弱 victim コンテナと
**実通信**して攻撃の成立を観察できる体験を提供する。これにより次の教育効果を実現する。

1. **リクエスト構築の体感**: `RawHttpComposer` コンポーネントでヘッダ・ボディを直接編集し、
   JWT ヘッダの `alg` を `none` に書き換える操作が学習者自身の手で起こる
2. **実 HTTP の可視化**: orchestrator がキャプチャした raw bytes とレイテンシを DataFlowPanel に表示し、
   パケットレベルで攻撃リクエストを確認できる
3. **victim の独立性**: 脆弱な実装を持つ `victim-web` コンテナが orchestrator と分離されており、
   「この victim は脆弱な設定のサーバーです」という文脈が明確になる
4. **OS レイヤ隔離の実証**: `victim-net: internal: true` により victim が外部通信不能であることを
   学習者に説明でき、安全制約の技術的根拠が実物で示せる

### 1.3 既存攻撃カタログ (PR #6) との関係

既存のナレーション型攻撃デモ (`server/routes/attack-*.ts` と `src/components/auth/attacks/`) は
**Phase 5 まで残置**する。C/D 区分のシナリオ 15 件は最終的にもナレーション型を維持し確定する。
A/B 区分の live 化が完了した時点でナレーション版に「live 版に移行済み」バッジを付与し、
Phase 5 で UI 整理を行う。

---

## 2. 全体アーキテクチャ — 案 C ハイブリッド採用

### 2.1 案の比較

| 観点 | 案 A (単一 victim 同居) | 案 B (protocol 別分割) | 案 C (ハイブリッド) |
|------|------------------------|----------------------|-------------------|
| victim コンテナ数 | 1 (orchestrator と同じ Hono プロセス) | 4+ (jwt-victim, oauth-victim, tls-proxy ...) | Phase 1-2: 1、Phase 4: 3 |
| 実装コスト (Phase 1) | 低 (コンテナ追加なし) | 高 (複数 victim 同時実装) | 低から中へ段階的 |
| 隔離の明確さ | 低 (同一プロセス内のシム) | 高 (protocol 専用コンテナ) | 中 → 高 (段階的強化) |
| DX (docker-compose) | なし | compose が複雑 | 段階的に compose が成長 |
| TLS/SAML 等の実化可否 | 不可 (共有 TLS 設定に干渉) | 可 | Phase 4 から可 |
| `dev:no-docker` フォールバック | 常時可 | 不可 | Phase 1-2 のみ維持 |

**採用理由**: Phase 1-2 は victim-web 単一コンテナで開始し、学習者・開発者双方の摩擦を最小化する。
TLS ダウングレードや SAML XSW など protocol 専用インフラが必要な B 群は Phase 4 で追加し、
案 B の恩恵を部分的に取り込む進化型アーキテクチャとする。

### 2.2 コンテナ構成図

```
┌─────────────────────────────────────────────────────────────────┐
│  ブラウザ (SolidJS, port 3000)                                   │
│    RawHttpComposer ─── DataFlowPanel ─── AttackResultBanner     │
└──────────────────────────────┬──────────────────────────────────┘
                               │ /api/orchestrator/exec
                               │ (Vite proxy → localhost:3001)
┌──────────────────────────────▼──────────────────────────────────┐
│  orchestrator (Hono, port 3001)                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  既存ルート: /api/jwt, /api/oauth, /api/rbac, ...        │   │
│  │  既存ナレーション攻撃: /api/jwt/attack/alg-none, ...     │   │
│  │  ─────────────────────────────────────────────────────   │   │
│  │  新規: POST /api/orchestrator/exec                        │   │
│  │    VICTIM_ALLOWLIST 検証                                  │   │
│  │    http.request → victim-net 内部へ転送                   │   │
│  │    raw bytes キャプチャ + elapsed ms 計測                 │   │
│  │    AttackResult + _trace (isAttackMode: true, mode: "live") │   │
│  └──────────────────────────────────────────────────────────┘   │
│  SQLite: server/db/data.sqlite (orchestrator 固有)               │
└──────────┬────────────────────────────────────────────────────┘
           │ victim-net (internal: true — OS レイヤ egress 遮断)
           ▼
┌──────────────────────────────────────────────────────────────────┐
│  victim-net (Docker bridge network, internal: true)              │
│                                                                  │
│  ┌───────────────────────────┐  ┌────────────────────────────┐  │
│  │ victim-web (Hono, :4001)  │  │ attacker-shell             │  │
│  │  脆弱エンドポイント群      │  │ (Alpine, read-only)        │  │
│  │  /login — rate limit なし │  │ 辞書ブルートフォース用     │  │
│  │  /jwt/verify-kid          │  │ --cap-drop=ALL             │  │
│  │  /oauth/authorize         │  │ --pids-limit=64            │  │
│  │  /session/login           │  │                            │  │
│  │  /rbac/resource/:id       │  └────────────────────────────┘  │
│  │  SQLite: victim-data.sqlite│                                  │
│  │  (tmpfs — 再起動でクリア) │                                  │
│  └───────────────────────────┘                                  │
│                                                                  │
│  ─── Phase 4 追加 ─────────────────────────────────────────     │
│  ┌───────────────────────────┐  ┌────────────────────────────┐  │
│  │ victim-tls-proxy          │  │ victim-saml-idp            │  │
│  │ (nginx, 旧 TLS 設定)      │  │ (SimpleSAMLphp または Hono │  │
│  │ TLSv1.0 強制対応           │  │  SAML 実装)                │  │
│  └───────────────────────────┘  └────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

### 2.3 ネットワーク方針

`docker-compose.yml` のネットワーク定義:

```yaml
networks:
  victim-net:
    driver: bridge
    internal: true   # victim-net からのインターネット egress を OS レイヤで遮断
```

orchestrator のみ `victim-net` と `host` ブリッジの二刀流構成とする。

```yaml
services:
  orchestrator:
    networks:
      - default        # ホスト (port 3001) 向け
      - victim-net     # victim-web への転送用
  victim-web:
    networks:
      - victim-net     # orchestrator からのみ到達可
```

### 2.4 DB 分離

| コンテナ | SQLite ファイル | 用途 |
|---------|----------------|------|
| orchestrator | `server/db/data.sqlite` (gitignored) | 既存 12 テーブル + attack_log |
| victim-web | `victim-data.sqlite` (tmpfs マウント — 再起動でリセット、CLAUDE.md「データはエフェメラル」方針と整合) | 脆弱シードユーザー・セッション・OTP |

`POST /api/reset` は orchestrator の DB のみリセットする。
victim-web の DB は tmpfs マウントのため `docker compose restart victim-web` で自動クリアされる。
専用の `POST /api/orchestrator/victim-reset` エンドポイントからも再起動をトリガーできる。

---

## 3. データフロー — alg=none を例に

### 3.1 end-to-end シーケンス

PoC 第 1 号 `jwt-alg-none` を例にフローを示す。

```
ブラウザ
  │
  │  1. 学習者が RawHttpComposer で JWT header と Body を編集
  │     header: { "alg": "none", "typ": "JWT" }
  │     payload: { "sub": "seed_alice", "role": "admin" }
  │     signature: ""   ← 署名を空文字列に
  │     → Body タブで {"token": "<偽造 JWT>"} を入力
  │
  │  POST /api/orchestrator/exec
  │  {
  │    "target": "victim-web",
  │    "method": "POST",
  │    "path": "/jwt/verify",
  │    "headers": { "Content-Type": "application/json" },
  │    "body": "{\"token\": \"eyJhbGciOiJub25lIn0....\"}"
  │  }
  ▼
orchestrator (port 3001)
  │
  │  2. VICTIM_ALLOWLIST 検証
  │     allowlist = Map { "victim-web" → "http://victim-web:4001" }
  │     target "victim-web" → 許可
  │
  │  3. http.request("http://victim-web:4001/jwt/verify", ...)
  │     victim-net 内部通信 (egress なし)
  │
  │  4. raw bytes キャプチャ (双方向)
  │     browserToOrchestrator.request.line: "POST /api/orchestrator/exec HTTP/1.1"
  │     orchestratorToVictim.request.line:  "POST /jwt/verify HTTP/1.1"
  │     orchestratorToVictim.response.line: "HTTP/1.1 200 OK"
  │     browserToOrchestrator.response.line: "HTTP/1.1 200 OK"
  │     elapsedMs: 12
  │
  │  5. AttackResult 構築
  │     {
  │       scenarioId: "jwt-alg-none",
  │       outcome: "succeeded",   ← victim が 200 を返した
  │       mode: "live",
  │       rawRequest, rawResponse, elapsedMs,
  │       ...
  │     }
  │
  │  6. _trace 付与
  │     { isAttackMode: true, mode: "live", attackSteps: [...] }
  │
  ▼
ブラウザ
  │
  │  7. DataFlowPanel 更新
  │     HTTP タブ: rawRequest / rawResponse を整形表示 (ヘッダ強調)
  │     Trace タブ: AttackStep タイムライン + 経過時間
  │     Sequence タブ: ブラウザ → orchestrator → victim の 3 段フロー図
  │
  ▼
  AttackResultBanner
    「この実装は alg 検証が省略されているため署名バイパスが成立しました」
    ↓ AttackDefensePanel 自動展開
    「防御: jwt.verify() の algorithms オプションに ["HS256"] を明示的に指定する」
```

### 3.2 ナレーション型との対比

| ステップ | ナレーション型 (現在) | live 型 (新規) |
|---------|---------------------|---------------|
| JWT 偽造 | orchestrator が `buildAlgNoneToken()` で生成 | 学習者が RawHttpComposer で直接編集 |
| victim への送信 | orchestrator 内の `verifyWithoutAlgCheck()` を呼ぶ | HTTP リクエストが victim-web コンテナに到達 (`POST /jwt/verify` body 内 token) |
| 脆弱性の場所 | サーバー内の分岐フラグ | victim-web の `/jwt/verify` 実装コード自体 (alg=none を受理) |
| raw bytes | 存在しない | browser⇄orchestrator / orchestrator⇄victim の双方向 raw bytes を DataFlowPanel に表示 |
| 隔離根拠 | API 規約 (ソフトウェア) | Docker network `internal: true` (OS レイヤ) |

---

## 4. 38 シナリオ分類 (A/B/C/D 区分)

### 4.1 区分定義

| 区分 | 定義 | 対応方針 |
|------|------|---------|
| **A** | 実化インパクト高。victim-web の HTTP エンドポイントと RawHttpComposer で体感可能 | Phase 2-3 で live 化する |
| **B** | 技術的に重い実化価値あり。専用コンテナ (victim-tls-proxy 等) が必要 | Phase 4 で live 化する |
| **C** | ナレーション型を維持確定。実 NW 条件依存・概念のみ・教材外の重い処理 | Phase 5 でバッジ整理 |
| **D** | 失敗デモ (攻撃が設計上成立しないことを示す)。一部 A 化できる部分を「部分 A」と注記 | ナレーション維持 + 部分 A を別途追加 |

### 4.2 全シナリオ分類表

| # | tabId | scenario-id | 区分 | 補足 |
|---|---|---|---|---|
| 1 | auth-methods | password-rainbow-vs-bcrypt | C | レインボーテーブル生成は重い + 教材外 |
| 2 | auth-methods | password-timing-string-compare | C | 実 NW では再現困難。概念のみ |
| 3 | auth-methods | password-bruteforce-no-rate-limit | A | victim-web `/login` で実 HTTP ループ (上限 20 回) |
| 4 | jwt | jwt-alg-none | A | **PoC 第 1 号**。RawHttpComposer 必須 |
| 5 | jwt | jwt-weak-secret-bruteforce | A | attacker-shell で辞書 200 件上限 |
| 6 | jwt | jwt-signature-stripping | A | alg=none と同基盤。RawHttpComposer 流用 |
| 7 | jwt | jwt-kid-injection | A | victim-web `/jwt/verify-kid` (path traversal 脆弱版) |
| 8 | oauth | oauth-state-csrf | A | Phase 2 PoC 第二候補 |
| 9 | oauth | oauth-redirect-uri-bypass | A | victim-web `/oauth/authorize` 部分一致検証 |
| 10 | oauth | oauth-code-via-referer | C | Referer 漏洩は実環境依存。ブラウザ制御不可 |
| 11 | session-vs-token | session-fixation | A | sid 強制 → ログイン → 再生成なし確認 |
| 12 | session-vs-token | session-xss-cookie-theft | A | victim-web に HttpOnly 無し Cookie 発行エンドポイント |
| 13 | session-vs-token | token-replay | A | jti 検証なしリフレッシュ口を victim-web に用意 |
| 14 | rbac | rbac-idor | A | Phase 2 PoC 第三候補 |
| 15 | rbac | rbac-horizontal-privilege-escalation | A | IDOR と同経路。user-id 差し替えのみ |
| 16 | rbac | rbac-vertical-privilege-escalation | A | role=user JWT 改竄 (alg=none と組合せ可) |
| 17 | rbac | rbac-abac-attribute-tampering | A | X-User-Dept ヘッダで属性偽装 |
| 18 | fido2 | fido2-phishing-origin-rejection | D | `fake.localhost:8081` を攻撃者 origin に設定。失敗デモ |
| 19 | fido2 | fido2-vs-password-phishing | D + 部分A | パスワード側のみ実フィッシング (3 と同基盤で部分 A 化) |
| 20 | fido2 | fido2-challenge-replay | D | Defender 強化で十分。失敗デモ |
| 21 | oidc-saml | saml-xsw | B | victim-saml-idp (Phase 4) が必要 |
| 22 | oidc-saml | saml-assertion-replay | A | 同一 assertion を 2 回 POST して victim が受け入れるか確認 |
| 23 | oidc-saml | oidc-id-token-spoofing | A | aud/iss 検証なし victim-web エンドポイント |
| 24 | kerberos | kerberos-pass-the-ticket | B (限定) | victim-web 内で完結する KDC なし簡略版で部分 B 化 |
| 25 | kerberos | kerberos-kerberoasting | C | 完全実化は KDC + impacket 必要。概念のみ |
| 26 | kerberos | kerberos-golden-ticket | C | krbtgt 偽造は概念のみ。実化不可 |
| 27 | tls-deep | tls-version-downgrade | B | victim-tls-proxy (Phase 4) が必要 |
| 28 | tls-deep | tls-self-signed-mitm | B | mitmproxy in attacker-shell (Phase 4) |
| 29 | tls-deep | tls-weak-cipher-negotiation | B | 27 と同基盤 |
| 30 | sso-idp-apikey | apikey-leakage | A | URL クエリで access_log 漏洩。victim-web `/resource?key=` |
| 31 | sso-idp-apikey | apikey-hmac-bypass | A | victim-web HMAC 検証省略版エンドポイント |
| 32 | sso-idp-apikey | apikey-replay-no-timestamp | A | 13 と同基盤。replay_nonce テーブルなし版 |
| 33 | mfa | mfa-otp-replay | A | **Phase 2 PoC 第五候補**。nonce/used フラグなし victim エンドポイント |
| 34 | mfa | mfa-time-window-too-wide | C | ネットワーク条件依存。概念説明で十分 |
| 35 | mfa | mfa-sms-swap | C | キャリアへの社会工学。技術実化不可 |
| 36 | passkey | passkey-phishing-resistance | D + 部分A | 18 同様 fake.localhost 化。失敗デモ |
| 37 | passkey | passkey-cloud-sync-compromise | C | クラウド側侵害は概念。実化不可 |
| 38 | passkey | passkey-cross-device-mitm | C | BLE/QR MITM 実化不可 |

**集計**: A=18、B=5、C=11、D=4 (D のうち 3 件は部分 A 化あり)。
A 群 18 件 + D 部分 A 3 件 = 実化対象約 21 件 (全体の約 55%)。

---

## 5. Phase 1-5 ロードマップ

### 5.1 Phase 一覧

| Phase | 内容 | 主な Deliverable | 想定期間 | 想定 PR 数 |
|-------|------|----------------|---------|-----------|
| 1 | インフラ整備 | docker-compose + victim-web スケルトン + orchestrator/exec + RawHttpComposer 基盤 + `dev:no-docker` | 1-2 週 | 2-3 |
| 2 | PoC 5 件 | jwt-alg-none, oauth-state-csrf, rbac-idor, session-fixation, mfa-otp-replay の live 化 | 2 週 | 5 |
| 3 | A 群残り 13 件 | テーマ別バンドル PR (jwt×3, oauth×1, session×2, rbac×3, oidc×2, sso×3) | 4 週 | 6-7 |
| 4 | B 群 5 件 | victim-tls-proxy + victim-saml-idp 追加、tls×3 + saml-xsw + pass-the-ticket 実化 | 3 週 | 4-5 |
| 5 | 整理 | C/D 群バッジ付与、ナレーション型 UI 統合、`is_attack_sim` 削除検討 | 1 週 | 1-2 |

**合計**: 約 11 週

### 5.2 Phase 1 詳細 (インフラ整備)

**Deliverable:**

- `docker-compose.yml` — orchestrator / victim-web / attacker-shell の 3 サービス定義
- `services/victim-web/` — 新規 Hono アプリ (脆弱エンドポイントスケルトン)
- `server/routes/orchestrator-exec.ts` — `POST /api/orchestrator/exec` ハンドラ
- `src/components/shared/RawHttpComposer.tsx` — リクエスト編集 UI
- `package.json` — `workspaces: ["services/*"]` 追加、`dev:no-docker` スクリプト追加
- `.github/workflows/ci.yml` — `services:` で victim-web を compose 起動

**リスク**: Windows 環境での Docker Desktop 必須化。`dev:no-docker` フォールバックで Phase 1-2 は
Docker なしでも既存ナレーション型デモが動作することを保証する。

### 5.3 Phase 2 詳細 (PoC 5 件)

| PoC | victim-web エンドポイント | 検証内容 |
|-----|--------------------------|---------|
| jwt-alg-none | `POST /jwt/verify` (request body 内 `{"token": "<JWT>"}`, alg 検証なし) | alg=none JWT で 200 が返ること |
| oauth-state-csrf | `GET /oauth/authorize` (state 未検証) | state パラメータ省略で認可コード発行されること |
| rbac-idor | `GET /rbac/resource/:id` (認可なし) | 他ユーザーの id で 200 が返ること |
| session-fixation | `POST /session/login` (ID 再生成なし) | ログイン後も同一 sid が使えること |
| mfa-otp-replay | `POST /mfa/verify` (used フラグなし) | 同一 OTP を 2 回送信して両方通ること |

### 5.4 Phase 4 追加コンテナ (案 B 進化)

```yaml
# docker-compose.yml Phase 4 追加分
services:
  victim-tls-proxy:
    build: services/victim-tls-proxy
    networks:
      - victim-net
    environment:
      - TLS_VERSION=TLSv1           # TLS 1.0 強制
      - CIPHER_SUITE=RC4-MD5        # 弱い暗号スイート

  victim-saml-idp:
    build: services/victim-saml-idp
    networks:
      - victim-net
    environment:
      - SAML_SIGNING=disabled       # 署名検証省略版
```

---

## 6. ナレーション型との共存方針

### 6.1 既存ルートの保持

`server/routes/attack-*.ts` の既存 `/attack/<scenario-id>` パスは Phase 5 まで変更しない。
同一 scenario-id に対して `mode: "narration"` と `mode: "live"` が並存する期間が発生する。

### 6.2 AttackScenarioMeta への mode フィールド追加

DESIGN/03 §1.5 の `AttackScenarioMeta` 型に `mode` フィールドを追加することを提案する。

```typescript
// shared/api-types.ts への追加提案 (DESIGN/03 §1.5 への拡張)
export interface AttackScenarioMeta {
  // ... 既存フィールド ...
  /** live = 実 victim コンテナと通信 / narration = orchestrator 内部シム */
  mode: "live" | "narration";
}
```

`AttackResult._trace` にも `mode` を伝播させる。

`traceMiddleware.isAttackPath` 判定の orchestrator パス対応は DESIGN/31 §7.1 を参照。

```typescript
// ServerTrace 拡張 (_trace レスポンス)
export interface ServerTrace {
  // ... 既存フィールド ...
  isAttackMode?: boolean;
  mode?: "live" | "narration";   // ← 追加
}
```

### 6.3 C/D 群の確定方針

C 群 11 件 + D 群 4 件はナレーション型を維持確定とし、Phase 5 で UI バッジを付与する。

| バッジ | 対象 | 色 |
|-------|------|-----|
| `LIVE` | A/B 群 live 化完了シナリオ | `#52c41a` (緑) |
| `SIMULATION` | C 群ナレーション維持 | `#8c8c8c` (グレー) |
| `DEFENSE DEMO` | D 群失敗デモ | `#1677ff` (青) |

### 6.4 既存テストの維持

`server/__tests__/*-attack.test.ts` 28 ファイルは現行のナレーション型エンドポイントをテストしており、
live 化の影響を受けない。live 版は `server/__tests__/*-live.test.ts` として別ファイルに追加する。

---

## 7. 開発体験 (DX)

### 7.1 npm scripts

```json
// package.json (workspaces 追加後)
{
  "workspaces": ["services/*"],
  "scripts": {
    "dev": "docker compose up -d victim-web attacker-shell && concurrently \"vite\" \"tsx watch server/index.ts\"",
    "dev:no-docker": "concurrently \"vite\" \"tsx watch server/index.ts\"",
    "dev:client": "vite",
    "dev:server": "tsx watch server/index.ts",
    "build": "tsc && vite build",
    "victim:reset": "docker compose restart victim-web",
    "victim:logs": "docker compose logs -f victim-web"
  }
}
```

`dev:no-docker` は Phase 1-2 のみ維持する。Phase 3+ では Docker が必須となり、
`dev` スクリプトが標準に昇格する。(本ファイル §7.1 を npm scripts の単一正本とする。DESIGN/32 §3 等で言及される dev 関連スクリプトはここを参照)

### 7.2 CI (GitHub Actions)

Phase 1 から CI に Docker を導入する。

```yaml
# .github/workflows/ci.yml への追加
jobs:
  test:
    services:
      victim-web:
        image: ghcr.io/${{ github.repository }}/victim-web:latest
        ports:
          - 4001:4001
    steps:
      - name: Run orchestrator tests
        run: npm test
      - name: Run live attack integration tests
        run: npm run test:live
```

victim-web イメージは各 PR でビルドして `ghcr.io` に push する workflow を別途設ける。

### 7.3 ディレクトリ構造 (Phase 1 追加分)

```
osi-reference/
├── docker-compose.yml              # Phase 1 追加
├── package.json                    # workspaces 追加
├── packages/                       # 将来: WASM 等の共有ライブラリ (現時点空)
├── services/
│   ├── victim-web/                 # Phase 1 追加
│   │   ├── package.json
│   │   ├── tsconfig.json
│   │   ├── Dockerfile
│   │   ├── src/
│   │   │   ├── index.ts            # Hono アプリ エントリポイント
│   │   │   ├── routes/
│   │   │   │   ├── jwt-vuln.ts     # /jwt/verify (alg=none 受理), /jwt/verify-kid
│   │   │   │   ├── oauth-vuln.ts   # /oauth/authorize (部分一致)
│   │   │   │   ├── session-vuln.ts # /session/login (ID 再生成なし)
│   │   │   │   ├── rbac-vuln.ts    # /rbac/resource/:id (認可なし)
│   │   │   │   └── mfa-vuln.ts     # /mfa/verify (used フラグなし)
│   │   │   └── db/
│   │   │       └── victim-schema.ts
│   │   └── victim-data.sqlite      # gitignored (volume マウント)
│   └── attacker-shell/             # Phase 1 追加
│       └── Dockerfile              # Alpine + curl + python3 のみ
├── server/
│   ├── routes/
│   │   ├── orchestrator-exec.ts    # Phase 1 追加: POST /api/orchestrator/exec
│   │   └── ... (既存 routes)
│   └── ... (既存)
└── src/
    └── components/
        └── shared/
            └── RawHttpComposer.tsx # Phase 1 追加
```

---

## 8. 将来拡張の余地 (L1/L2 深掘り)

### 8.1 services/ の汎用性

`services/` ディレクトリと npm workspaces + docker-compose の構造は、
攻撃デモ以外の教材モジュールにも適用可能な設計とする。

| 将来追加の候補 | services/ エントリ | 備考 |
|--------------|-------------------|------|
| NAND シミュレーター | `services/nand-sim/` | L1 物理層の論理回路教材 |
| ブレッドボード UI | `services/breadboard-ui/` | L1 配線教材 |
| NBIT CPU エミュレーター | `services/nbit-cpu/` | L2 データリンク層の ALU 教材 |
| パケットキャプチャ UI | `services/pcap-viewer/` | L2-L3 教材 |

これらは**現時点では未着手**であり、本シリーズ (DESIGN/30-34) のスコープ外とする。
`services/` の空ディレクトリ先行作成は行わない (Step A 設計確定後に Step B で実装)。

### 8.2 packages/ の将来計画

```
packages/
└── sim-core/     # 将来: WASM ベース sim core 等の共有ライブラリ
```

`packages/` も現時点では未作成。将来の WASM シミュレーター等の共有ライブラリを
npm workspaces の `packages/*` として配置できる設計上の余地として確保する。

---

## 9. 安全制約 (DESIGN/04 への参照と差分)

### 9.1 4 原則の live 化における強化

`DESIGN/04-safety-guardrails.md` の 4 原則は live 化においても維持し、一部を強化する。

| 原則 | ナレーション型の実装 | live 型での強化 |
|------|---------------------|----------------|
| **隔離** | API 規約で `/api/*` のみに fetch 先を制限 | `victim-net: internal: true` で OS レイヤ egress を物理遮断 |
| **明示** | `EducationalWarningBanner` + `isAttackMode: true` | `mode: "live"` バッジを DataFlowPanel に追加表示 |
| **簡略化** | 最終 exploit ステップを省略 | 各 live 化 PR で「`victim-web` 外で再利用できるか?」を必ず問う |
| **防御策併記** | `AttackDefensePanel` が自動展開 | live 型でも同コンポーネントを継続使用。victim の修正コードも表示 |

### 9.2 新規安全装置の概要

詳細仕様は `DESIGN/34-safety-guardrails-live.md` に分離する。以下に概要を示す。

| 安全装置 | 実装場所 | 目的 |
|---------|---------|------|
| `VICTIM_ALLOWLIST` | `server/routes/orchestrator-exec.ts` | `target` パラメータを事前定義済み名前に限定し、任意 URL への転送を防ぐ。target キー名は 1〜32 文字 (DESIGN/31 §3.1 zod スキーマで強制) |
| `victim-net: internal: true` | `docker-compose.yml` | victim コンテナからのインターネット egress を OS レイヤで遮断 |
| `--read-only --cap-drop=ALL --pids-limit=64` | attacker-shell コンテナ定義 | attacker-shell の権限を最小化し、ファイルシステム書き込みを禁止 |
| production guard | `server/routes/orchestrator-exec.ts` | `NODE_ENV === "production"` のとき 503 を返す |
| `Host` ヘッダ強制上書き | `server/routes/orchestrator-exec.ts` | RawHttpComposer からの `Host` を `victim-web:4001` に強制し DNS rebinding を防ぐ |
| RawHttpComposer export 無効 | `src/components/shared/RawHttpComposer.tsx` | 組み立てたリクエストのファイル持ち出しボタンを設けない |

### 9.3 禁止表現一覧の継続適用

`DESIGN/04 §2.3` の禁止表現一覧は live 化仕様書・victim-web ソースコード・UI ラベルすべてに適用する。
特に live 化により「実 HTTP が見える」ことで下記を誘発しやすくなるため注意する。

| 禁止表現 | live 化での誘発シーン |
|---------|---------------------|
| 「実環境で試せる」 | RawHttpComposer の説明文 |
| 「完全な乗っ取り」 | AttackResultBanner の成功表示 |
| 「ハッキング」 | victim-web ログ出力のラベル |

---

## 関連ファイル

### 本シリーズ (DESIGN/30-34)

| ファイル | 内容 |
|---------|------|
| `DESIGN/30-live-attack-architecture.md` | 本ファイル: 全体設計・アーキ選択・ロードマップ |
| `DESIGN/31-orchestrator-spec.md` | `POST /api/orchestrator/exec` API 仕様・VICTIM_ALLOWLIST 定義 |
| `DESIGN/32-victim-web-spec.md` | 脆弱 victim-web の全エンドポイント定義・DB スキーマ |
| `DESIGN/33-raw-http-composer.md` | RawHttpComposer フロント UI 仕様・SolidJS 実装方針 |
| `DESIGN/34-safety-guardrails-live.md` | DESIGN/04 への live 差分・新規安全装置の詳細実装 |

### 既存 DESIGN ファイル (参照・差分管理)

| ファイル | 本ファイルとの関係 |
|---------|----------------|
| `DESIGN/00-overview.md` | ナレーション型カタログ全体。本ファイルはこれを置き換えるのではなく live 化の上位設計として追加 |
| `DESIGN/01-architecture.md` | ナレーション型バックエンド構成。orchestrator 側は維持。victim-web が新たに追加される |
| `DESIGN/04-safety-guardrails.md` | 4 原則の基盤。live 型は §9.1 の差分のみ追加し、基盤原則は本ファイルから引用 |

### 実装ファイル (Phase 1 で新規作成)

| ファイルパス | 役割 |
|------------|------|
| `docker-compose.yml` | orchestrator / victim-web / attacker-shell サービス定義 |
| `services/victim-web/src/index.ts` | 脆弱 Hono アプリ エントリポイント |
| `services/victim-web/Dockerfile` | Node 22 Alpine ベースイメージ |
| `services/attacker-shell/Dockerfile` | Alpine + curl + python3 最小構成 |
| `server/routes/orchestrator-exec.ts` | `POST /api/orchestrator/exec` ハンドラ |
| `src/components/shared/RawHttpComposer.tsx` | リクエスト編集 UI コンポーネント |

### 作業状態

| ファイル | 用途 |
|---------|------|
| `CHECKPOINT.md` | Phase ロードマップ・確定意思決定・次アクション |
