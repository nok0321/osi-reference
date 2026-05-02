---
title: 攻撃デモカタログ — live モード安全装置 (DESIGN/04 への差分)
phase: design
audience: 開発者・コンテンツレビュアー
last-updated: 2026-05-02
safety-reviewed: false
---

# 34. live モード安全装置 (DESIGN/04 への差分仕様)

## 1. 目的とスコープ

### 1.1 本ファイルの位置付け

本ファイルは `DESIGN/04-safety-guardrails.md` (以下「DESIGN/04」) への**差分仕様**である。
DESIGN/04 の 4 原則・UI 文言ルール・ペイロード作成ルール・チェックリストはすべて有効なまま継続する。
本ファイルは `mode: "live"` シナリオ (Docker victim コンテナと実 HTTP 通信するシナリオ) に固有の
追加・強化装置のみを記述する。

### 1.2 適用対象

- **対象**: `AttackScenarioMeta.mode === "live"` のシナリオおよびそれを扱う PR
- **対象外**: `mode: "narration"` のシナリオ (既存のナレーション型は DESIGN/04 のみが適用される)

### 1.3 共存方針

Phase 1-5 の移行期間中、`mode: "live"` シナリオと `mode: "narration"` シナリオが並存する。
両方のシナリオで DESIGN/04 の安全装置が有効となり、live モードシナリオには追加で本ファイルの
安全装置が適用される。

### 1.4 読み方

DESIGN/04 を読了した上で本ファイルを参照すること。本ファイル単独では安全要件の全体像は把握できない。

---

## 2. 4 原則の live モード対応 (差分表)

各原則について「DESIGN/04 の規定 / live モードでの追加・強化 / 新規実装箇所」を示す。

### 2.1 隔離 (Isolation) — **強化**

| 項目 | DESIGN/04 の規定 | live モードでの追加・強化 | 実装箇所 |
|------|----------------|------------------------|---------|
| fetch 宛先制限 | `/api/<area>/attack/<scenario>` または相対パスのみ | `/api/orchestrator/exec` も許可 (victim への中継専用) | `src/api/client.ts` |
| 外部通信遮断 | API 規約 (ソフトウェア境界) で制限 | `victim-net: internal: true` による OS レイヤ物理遮断 | `docker-compose.yml` |
| 攻撃者 → victim 直接通信 | 設計上不可 (orchestrator 経由) | ブラウザ → victim 直接通信が**構造的に不可能** (victim はホスト公開ポートを持たない) | `docker-compose.yml` |
| URL 偽造防止 | なし (ナレーション型はパス検証のみ) | `VICTIM_ALLOWLIST` (Map 構造) でキー一致のみ許可。ブラウザが URL を直接指定する手段を持たない | `server/routes/orchestrator-exec.ts` |
| victim DB の混入防止 | `is_attack_sim` 列で正常系を保護 | victim-web が専用 `victim-data.sqlite` を持ち、orchestrator の DB と物理分離。tmpfs マウントのため再起動で確実にクリア | `services/victim-web/Dockerfile` + tmpfs マウント |

**live モードでの OK/NG 例 (DESIGN/04 §1.1 の更新差分):**

```typescript
// OK: live モードの宛先パターン (新規)
const res = await apiPost<OrchestratorExecResponse>(
  "/api/orchestrator/exec",
  {
    scenarioId: "jwt-alg-none",
    target: "victim-web",            // ← VICTIM_ALLOWLIST のキー文字列のみ有効
    request: { method: "POST", path: "/jwt/verify", headers: { "Content-Type": "application/json" }, body: '{"token":"eyJhbGciOiJub25lIn0..."}' },
  },
  SCOPE,
);

// NG: victim URL を直接指定する (設計上できない・リクエストスキーマで拒否)
const res = await fetch("http://victim-web:4001/jwt/verify", { ... });   // 403

// NG: VICTIM_ALLOWLIST 外のキー (orchestrator が 403 を返す)
const res = await apiPost("/api/orchestrator/exec", { target: "http://evil.example", ... }, SCOPE);
```

### 2.2 明示 (Explicit framing) — **強化**

| 項目 | DESIGN/04 の規定 | live モードでの追加・強化 | 実装箇所 |
|------|----------------|------------------------|---------|
| バナー常時表示 | `EducationalWarningBanner` を Attacker View 最上部に固定 | 変更なし (継続必須) | 既存コンポーネント |
| LIVE バッジ | なし | `mode: "live"` シナリオで `EducationalWarningBanner` 右端に `[LIVE]` バッジを追加表示 | `EducationalWarningBanner.tsx` |
| シナリオセレクタ | なし | 各エントリに `[LIVE]` / `[SIMULATION]` / `[DEFENSE DEMO]` バッジを表示 | シナリオセレクタコンポーネント |
| DataFlowPanel Trace タブ | `isAttackMode: true` で赤色ハイライト | `mode: "live"` エントリは追加で赤縁表示 (ハイライト強化) | `DataFlowPanel.tsx` |
| Sequence タブ | 存在しない | `mode: "live"` シナリオでのみ Sequence タブを表示 (ブラウザ → orchestrator → victim の 3 段フロー図) | `DataFlowPanel.tsx` |
| victimNote | なし | `_trace.victimNote` として「victim 内部クエリは観測不能」の旨を常に付与 | `server/middleware/trace-logger.ts` |

**LIVE バッジの視覚要件:**

| プロパティ | 仕様 |
|-----------|------|
| 背景色 | `#52c41a` (緑) |
| テキスト色 | `#fff` |
| テキスト | `LIVE` |
| 表示条件 | `mode === "live"` シナリオでのみ表示 |
| `dismissable` | 禁止 (DESIGN/04 §6.2 と同様) |

### 2.3 簡略化 (Simplification) — **要再評価**

| 項目 | DESIGN/04 の規定 | live モードでの判断追加 |
|------|----------------|----------------------|
| exploit ステップ省略 | 最終 exploit ステップを省略し「条件が揃った状態」を示す | 継続必須 |
| ブルートフォース上限 | サーバー側で判定、フロントでループ禁止 | orchestrator 側で bruteforce ループ上限 **20 回**・辞書サイズ **200 件** を強制 (フロント側の制限に加えてサーバー側でも二重ガード) |
| victim 外利用可能性チェック | 「省略の基準: 教材範囲を超えた実際の攻撃に再利用できるか」を問う | live 化 PR ごとに「**この victim エンドポイントを `victim-web` 外で再利用できるか?**」を必ず問う |
| Phase 4 TLS / SAML | 規定なし (Phase 4 以降) | TLS ダウングレードデモは TLS 1.0 までに制限。SSLv3 等の実装は victim-tls-proxy にも含めない |
| live 化の説明文言 | 規定なし | 「実 HTTP が走る」「外部ネットワークには到達しない」の旨を CWE/CAPEC 行の下に必ず併記 |

### 2.4 防御策併記 (Defense pairing) — **維持、live 化対応を追加**

| 項目 | DESIGN/04 の規定 | live モードでの追加 |
|------|----------------|-------------------|
| `AttackDefensePanel` 自動展開 | 攻撃完了後に自動展開 | live モードでも継続 (変更なし) |
| 防御コードリンク | `server/routes/<area>.ts` の堅牢実装への参照 | victim-web の修正コード (`services/victim-web/src/routes/<area>-vuln.ts` の該当箇所) も表示 |
| 副ボタン (将来) | なし | Phase 3 以降検討: 「同じ raw HTTP を堅牢版エンドポイントに送って 401 を見る」副ボタン |

---

## 3. 開発レビューチェックリスト §4.1〜4.5 の更新差分

DESIGN/04 §4 のチェックリストに対して、`mode: "live"` を含む PR で適用される追加項目を以下に示す。
DESIGN/04 §4 の全項目は引き続き必須であり、本節はそれに追加する形で適用する。

### 3.1 §4.1 隔離チェック (差分)

- [ ] `apiPost` / `apiGet` の宛先が `/api/orchestrator/exec` または `/api/<area>/attack/<scenario>` (ナレーション型維持シナリオ) のいずれか
- [ ] orchestrator の Request に渡す `target` 値が `VICTIM_ALLOWLIST` に登録済みのキー文字列
- [ ] `docker network inspect victim-net` で `Internal: true` が確認できる
- [ ] `docker compose ps` で victim コンテナの公開ポート列が空 (ホストへの公開なし)
- [ ] `services/<victim-name>/Dockerfile` に外部 URL への `RUN curl` / `RUN wget` が含まれない
- [ ] 攻撃シナリオで発生した victim 側書き込みが orchestrator の `server/db/data.sqlite` に混入しない設計になっている
- [ ] (Phase 1-2 のみ) `dev:no-docker` フォールバックで当該シナリオが `LIVE モード未対応` と明示エラーを出す

### 3.2 §4.2 表示・文言チェック (差分)

- [ ] `EducationalWarningBanner` の右端に `[LIVE]` バッジが `mode: "live"` シナリオでのみ表示される
- [ ] バッジが `mode: "narration"` シナリオで表示されないことを確認 (誤表示チェック)
- [ ] シナリオセレクタの各エントリに mode バッジが正しく表示される
- [ ] DataFlowPanel に Sequence タブが `mode: "live"` シナリオでのみ表示される
- [ ] DataFlowPanel の Trace タブで `mode: "live"` 由来のエントリに赤縁表示が適用される
- [ ] シナリオ説明文に「実 HTTP が走る」「外部ネットワークには到達しない」の旨が CWE/CAPEC 行の下に記載されている

### 3.3 §4.3 教育内容チェック (差分)

DESIGN/04 §4.3 の項目を継続。追加:

- [ ] live モード時に「実 HTTP が走る」「外部ネットワークには到達しない」の旨が CWE/CAPEC 行の直下に 1 文以上で記述されている
- [ ] `_trace.victimNote` が「victim コンテナ内部の DB クエリ・暗号操作は orchestrator から観測不能です」に相当する文言で設定されている

### 3.4 §4.4 ペイロードチェック (差分)

- [ ] `RawHttpComposer` に export ボタンが**存在しない** (ペイロード持ち出し阻止)
- [ ] `RawHttpComposer` に copy-to-clipboard ボタンが**存在しない**
- [ ] `orchestrator-exec.ts` の `attack_log` 書き込みが `scenarioId`, `outcome`, `elapsedMs`, `targetResolvedTo` の summary のみ (raw bytes 非永続化)
- [ ] `RawHttpComposer` の編集中コンテンツが `localStorage` / `sessionStorage` に保存されない
- [ ] bruteforce 系シナリオで orchestrator 側のループ上限が 20 回・辞書サイズが 200 件を超えていない
- [ ] Phase 4 の TLS 系シナリオで victim-tls-proxy が TLS 1.0 より古いプロトコルを有効にしていない

### 3.5 §4.5 ログ・デバッグチェック (差分)

DESIGN/04 §4.5 の項目を継続。追加:

- [ ] `orchestrator-exec.ts` の `console.log` に raw bytes が出力されない
- [ ] `_trace` の `victimNote` が `mode: "live"` 時に常に設定されている
- [ ] victim-web コンテナのログに実ユーザーの認証情報が出力されない設計になっている

---

## 4. 新規安全装置一覧 (live モード固有)

| 装置 | 実装場所 | 理由 | 検証方法 |
|------|---------|------|---------|
| `victim-net: internal: true` | `docker-compose.yml` | OS レイヤで victim からのインターネット egress を物理遮断 | `docker network inspect victim-net` → `"Internal": true` 確認 |
| `VICTIM_ALLOWLIST` (ReadonlyMap 構造) | `server/routes/orchestrator-exec.ts` | URL 偽造防止: target はキー文字列一致のみ許可、baseUrl は allowlist から取得 | unit test で不在キー → 403 `target_not_in_allowlist` |
| victim ホストポート非公開 | `docker-compose.yml` の victim サービス定義 | ブラウザから victim への直接通信を構造上不可にする | `docker compose ps` で victim の PORTS 列が空 |
| `attacker-shell` 最小権限 | `docker-compose.yml` の attacker-shell サービス定義 | コンテナ脱出耐性: `--read-only --cap-drop=ALL --pids-limit=64 --security-opt no-new-privileges:true` | `docker inspect attacker-shell` で各設定確認 |
| Production guard (`productionGuard` middleware) | `server/middleware/production-guard.ts` (新規) | `NODE_ENV === "production"` で 503 返却、本番誤起動防止 | unit test で `NODE_ENV=production` 設定時に 503 |
| `Host` ヘッダ強制上書き | `server/routes/orchestrator-exec.ts` の `proxyToVictim()` 内 | DNS rebinding 予防。ブラウザ送信の Host を破棄し baseUrl の hostname:port に強制置換 | unit test でブラウザ指定の偽 Host → allowlist 値に上書きされることを確認 |
| `attack_log` 永続化禁止 (raw bytes) | `server/routes/orchestrator-exec.ts` の DB 書き込みロジック | PII・クレデンシャルの DB 流入防止。双方向 raw bytes (browser⇄orchestrator + orchestrator⇄victim) を全てリクエスト処理中のメモリのみで保持し、`attack_log` テーブルには summary のみ書込み | DB schema 確認 + `attack_log` INSERT SQL に raw bytes 列が存在しないことを確認 |
| `RawHttpComposer` 持ち出し阻止 | `src/components/shared/RawHttpComposer.tsx` | export ボタン・copy-to-clipboard・sessionStorage 保存を実装しない | UI test で各機能の不在確認 |
| `victim-data.sqlite` 物理分離 | `services/victim-web/Dockerfile` + tmpfs マウント (再起動で確実にクリア、PII / 攻撃データ流入の永続化を物理的に防止) | orchestrator DB との混入防止。ボリューム永続化なし | コンテナ内 `ls` で `/app/victim-data.sqlite` のみ存在、orchestrator DB と別パスであること。`docker inspect victim-web` でマウントタイプが `tmpfs` であることを確認 |
| Healthcheck (`GET /health`) | `services/victim-web/src/index.ts` + `docker-compose.yml` の `healthcheck` | orchestrator が victim 起動を待機し、起動失敗を早期検出 | `docker compose ps` で STATUS が `healthy` であることを確認 |
| `shared/api-types.ts` のみ import 許可 | `services/victim-web/` の eslint 設定 | victim から orchestrator の内部実装 (`server/routes/*`) への参照禁止 | lint rule `no-restricted-imports` で `server/` パスへの import をエラー化 |
| `timeoutMs` 上限強制 | `server/routes/orchestrator-exec.ts` の zod スキーマ | victim に対する意図的な長時間接続を防止。最大 10000 ms | zod バリデーション + unit test |
| Phase guard (`phaseAvailable` 検証) | `server/routes/orchestrator-exec.ts` | 未実装 Phase の victim を誤って呼び出すことを防止 | unit test: `LIVE_ATTACK_PHASE=1` で `victim-tls-proxy` を指定 → 503 `phase_not_reached` |

---

## 5. `is_attack_sim` フラグの将来削除検討 (Phase 5)

### 5.1 現状 (DESIGN/04 §5.3)

DESIGN/04 §5.3 では、以下の 6 テーブルに `is_attack_sim INTEGER NOT NULL DEFAULT 0` 列を追加し、
正常系クエリは `WHERE is_attack_sim = 0` で攻撃データを除外する設計としている。

| テーブル |
|---------|
| `sessions` |
| `oauth_codes` |
| `oauth_tokens` |
| `api_keys` |
| `kerberos_tickets` |
| `refresh_tokens` |

### 5.2 live 化による状況変化

live モードでは victim-web が専用の `victim-data.sqlite` を持つため、
live シナリオによる攻撃データが orchestrator 側の DB に書き込まれない。
つまり、**live 化が完了したシナリオについては `is_attack_sim` 列が不要になる**。

### 5.3 Phase 5 の判断ポイント

| 状況 | 方針 |
|------|------|
| A/B 群 23 件が全て live 化完了 | `is_attack_sim` 列削除の DDL マイグレーションを検討 |
| C 群 11 件がナレーション型を維持 | ナレーション型が DB 書き込みを伴わない設計に再評価できるか検証し、削除可否を判断 |

### 5.4 削除する場合のマイグレーション戦略

SQLite は `ALTER TABLE DROP COLUMN` が 3.35.0 以降でのみ利用可能であり、古い環境向けには
テーブル再構築 (CREATE → INSERT → DROP → RENAME) が必要。Phase 5 設計時に better-sqlite3 の
対象バージョンを確認し、idempotent なマイグレーション関数を `server/db/schema.ts` に追加する。
DESIGN/04 §5.3.4 の `WHERE is_attack_sim = 0` 句が適用される 12 件超のクエリ箇所 (`server/db/queries.ts`, `server/index.ts`, `server/routes/{token-auth,session-auth,oauth-sim,sso-apikey,kerberos-sim}.ts`) も同時に修正対象。

---

## 6. PR テンプレート反映 (差分)

`.github/pull_request_template.md` (Phase 1 で新規作成) に以下のセクションを含める。

```markdown
## live モード PR チェックリスト

> このセクションは `AttackScenarioMeta.mode === "live"` のシナリオを含む PR にのみ適用する。
> ナレーション型のみの PR はこのセクションをスキップし「N/A」と記入する。

### DESIGN/34 §3 チェックリスト
- [ ] §3.1 隔離チェック (差分) — 全項目
- [ ] §3.2 表示・文言チェック (差分) — 全項目
- [ ] §3.3 教育内容チェック (差分) — 全項目
- [ ] §3.4 ペイロードチェック (差分) — 全項目
- [ ] §3.5 ログ・デバッグチェック (差分) — 全項目

### victim-web 変更時の追加確認
- [ ] `services/victim-web/` への変更がある場合、対応するシナリオの堅牢実装リンクが `AttackDefensePanel` から表示できる
- [ ] `docker compose up -d` 後に `docker compose ps` で victim コンテナの PORTS 列が空 (ホストへの公開なし)
- [ ] `docker network inspect victim-net` で `"Internal": true`

### Docker 環境確認
- [ ] `docker compose up -d` で全コンテナが `healthy` 状態になる
- [ ] (Phase 3+) `npm run dev:no-docker` 廃止後の動作確認方法を PR 説明に記載

### DESIGN/04 既存チェックリスト
- [ ] §4.1〜4.5 の全項目 (DESIGN/04-safety-guardrails.md を参照)
```

---

## 7. safety-reviewed フラグの運用 (拡張)

### 7.1 DESIGN/30-34 への適用

DESIGN/30-34 の各ファイルは `safety-reviewed: false` で初期化されており、
DESIGN/04 §4.6 と同じフローで `safety-reviewed: true` への移行を管理する。

| ファイル | safety-reviewed の条件 |
|---------|----------------------|
| `DESIGN/30-live-attack-architecture.md` | アーキテクチャ設計の安全性をチームでレビュー完了後 |
| `DESIGN/31-orchestrator-spec.md` | VICTIM_ALLOWLIST・production guard・Host 強制の実装が unit test で検証済み後 |
| `DESIGN/32-victim-web-spec.md` | victim エンドポイントが「教材外で再利用できない」判断を経た後 |
| `DESIGN/33-raw-http-composer.md` | export/copy/persist 全禁止の UI 実装確認後 |
| `DESIGN/34-safety-guardrails-live.md` (本ファイル) | §4 の全安全装置の実装が確認された後 |

### 7.2 live 化 PR 時の既存ファイルのリセット

既存の `DESIGN/10-21` 各タブ別ファイルに対して live 化対応 PR が出る際は、
対象ファイルの `safety-reviewed` を `false` にリセットし、live 版の安全レビューが完了した後に
改めて `true` に設定する。

```yaml
# live 化 PR マージ前のリセット例
---
safety-reviewed: false   # live 版の安全レビューが必要
---
```

---

## 8. 将来拡張への影響

### 8.1 L1/L2 深掘りへの適用

NAND シミュレーター・ブレッドボード UI・NBIT CPU エミュレーター等の将来追加モジュールは
本仕様のスコープ外だが、`services/` 同枠で追加される場合は以下のパターンを踏襲することを推奨する。

| 安全装置パターン | 適用推奨 |
|---------------|---------|
| `victim-net` 同等の internal network | 外部への通信が発生し得るコンテナに適用 |
| target allowlist (Map 構造) | orchestrator 経由でコンテナを操作する場合に適用 |
| production guard | 教育用ローカル専用のルートすべてに適用 |
| ホストポート非公開 | 学習者がブラウザから直接到達すべきでないコンテナに適用 |

### 8.2 victim 数増加時の `VICTIM_ALLOWLIST` 管理

将来 victim コンテナ数が増えた場合 (Phase 4 の `victim-tls-proxy`, `victim-saml-idp` 等)、
以下の管理手順を別途文書化することを推奨する。

- allowlist エントリ追加時の単体テスト (不在キー → 403 を保証)
- 新規 victim の `phaseAvailable` 設定レビュー
- CI での `docker compose ps` によるヘルスチェック確認

---

## 9. 既存 DESIGN/04 への変更要否

### 9.1 基本方針

本ファイルは差分仕様であり、**DESIGN/04 本体は基本的に変更しない**。

### 9.2 DESIGN/04 §2.3 禁止表現一覧への追記検討

live 化で以下の表現が誘発されやすくなるため、DESIGN/04 §2.3 への追記を推奨する。

| 追記候補の禁止表現 | live 化での誘発シーン | 代替表現 |
|-----------------|---------------------|---------|
| 「実際にハックする」 | RawHttpComposer の説明文や操作ガイド | 「実 HTTP リクエストを組み立てて概念実証を確認する」 |
| 「本物の HTTP で攻撃」 | AttackResultBanner の成功表示 | 「脆弱な設定のエンドポイントに対して HTTP リクエストを送信し、攻撃が成立する条件を確認しました」 |
| 「Docker があれば本物の攻撃ができる」 | シナリオの導入文 | 「教育用に隔離された環境でプロトコルの脆弱性を体験します」 |

### 9.3 DESIGN/04 §4.6 への追記推奨

DESIGN/04 §4.6 (safety-reviewed フラグ運用) に以下の一文の追加を推奨する。

> 「DESIGN/30-34 (live 化仕様シリーズ) も同じレビューフローを適用し、各ファイルの `safety-reviewed` フラグを管理する。」

---

## 10. 関連ファイル

| 種別 | ファイル | 関係 |
|------|---------|------|
| 基底 | `DESIGN/04-safety-guardrails.md` | 本ファイルが拡張する基盤仕様。本ファイル単独では不完全 |
| 上流アーキテクチャ | `DESIGN/30-live-attack-architecture.md` | 本ファイルが安全装置を提供する対象の全体設計 |
| 同列 | `DESIGN/31-orchestrator-spec.md` | VICTIM_ALLOWLIST・production guard・Host 強制の詳細実装仕様 |
| 同列 | `DESIGN/32-victim-web-spec.md` | victim-web 隔離方針・エンドポイント定義 |
| 同列 | `DESIGN/33-raw-http-composer.md` | RawHttpComposer UI 安全制約 (export 禁止・persist 禁止) |
| 既存実装 | `server/db/schema.ts` | `is_attack_sim` 列定義 (§5 の削除検討対象) |
| 既存実装 | `server/middleware/trace-logger.ts` | `_trace` 付与・`setLiveMode()` 追加対象 |
| 既存実装 | `src/components/shared/EducationalWarningBanner.tsx` | LIVE バッジ追加対象 |
| 既存実装 | `src/components/shared/DataFlowPanel.tsx` | Sequence タブ追加・赤縁表示強化対象 |
| 将来 | `.github/pull_request_template.md` | §6 の PR チェックリスト反映先 |
| 作業状態 | `CHECKPOINT.md` | Phase ロードマップ・確定意思決定の管理ファイル |
