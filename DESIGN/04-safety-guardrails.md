---
title: 攻撃デモカタログ — 教育安全装置
phase: design
last-updated: 2026-04-26
---

# 04. 教育安全装置

本設計書は「攻撃デモカタログ」機能が教材としての健全性を保つための安全装置を定義する。技術仕様の前にコンテンツポリシーとして機能する文書であり、新規攻撃シナリオを実装する開発者・コンテンツ執筆者が守るべき原則・ルール・判断基準を記す。

---

## 1. 4 つの原則

### 1.1 隔離 (Isolation)

攻撃シミュレーションは完全にローカル環境の中で完結しなければならない。

- 全ての攻撃リクエストの宛先は `/api/<area>/attack/<scenario-id>` 形式のみ。`fetch` / `XMLHttpRequest` の送信先は `localhost` または相対パスに限定する
- 外部 URL (`http://attacker.example`, `https://evil.example` 等) への実リクエストは生成しない。URL を「表示するだけ」のシミュレーションは許可するが、`fetch` でその URL に接触してはならない
- 実認証情報は使わない。固定のシードユーザー (`seed_user_alice`, `seed_user_bob` 等) と固定の検証鍵のみ使用する
- 実 CVE のエクスプロイトコード (実際の exploit PoC コード、バイナリシェルコード等) は含めない。攻撃の「概念」を示す最小限のシミュレーションのみ許可する
- `server/db/data.sqlite` は gitignored のため永続化しない。`POST /api/reset` で attack_log を含むシード状態に復元できることを前提とする

**OK な例:**
```typescript
// ローカルへの攻撃リクエスト送信
const res = await apiPost("/api/jwt/attack/alg-none", { token: manipulatedToken }, SCOPE);
```

**NG な例:**
```typescript
// 外部 URL への実リクエスト (隔離違反)
const res = await fetch("https://target-bank.example/login", { ... });
```

---

### 1.2 明示 (Explicit framing)

攻撃シミュレーションであることを学習者が常に認識できる状態を維持する。

- Attacker View を表示する画面では、画面最上部に `EducationalWarningBanner` コンポーネントを常時表示する
- バナーは `dismissable` (閉じられる) にしてはならない。`display: none` にするアニメーション・CSS は実装禁止
- 各攻撃シナリオの説明文には「これは **CWE-xxx** / **CAPEC-xxx** の概念実証です」の一文を必ず含める
- 攻撃ステップの UI ラベルは「攻撃者視点でのみ意味を持つ操作」を明示する (例: 「JWT ヘッダを改竄する」「署名を削除する」)
- `_trace` の `isAttackMode: true` フラグにより、DataFlowPanel はトレースパネルに赤色ハイライトを表示する (既存実装と同様の視覚的区別)

**ja/en バナーテキスト:**

| 言語 | 文言 |
|------|------|
| 日本語 | `教育用シミュレーション — 実環境を攻撃するためのコードではありません` |
| English | `Educational simulation — not for use against real systems` |

---

### 1.3 簡略化 (Simplification)

教材として「攻撃の本質を理解させる」ことに集中し、実際の攻撃ツールと同等の完成度を持たせない。

- 実際の攻撃の最終ステップ (パスワード解読・シェル奪取・データ持ち出し等) は省略する。「攻撃が成立する条件が揃った状態」を示すにとどめる
- ブルートフォース系シナリオは「サーバー側で攻撃成立を判定して結果を返す」形式とし、実際の試行ループはフロントエンドで実行しない
- Kerberoasting のような多段階攻撃は工程を分解して「ここまでが成立した」を学ぶ構造にする (Hashcat 相当のオフライン解読は省略し、「ハッシュ抽出済み・弱パスワード一致」とサーバー側で表示する)
- バイナリ操作・メモリ破壊・RCE に相当するペイロードは含めない
- SQL インジェクションや OS コマンドインジェクションは本カタログのスコープ外

**省略の基準:**
「これを実装することで、教材用途を超えた実際の攻撃に再利用できるか」を問い、YESならば省略する。

---

### 1.4 防御策併記 (Defense pairing)

攻撃の理解は防御実装とセットでなければ教育効果を持たない。

- 攻撃シナリオが完了した (成功・ブロック問わず) 直後に、`AttackDefensePanel` が自動展開される
- `AttackDefensePanel` には以下の3要素を含める:
  1. 「この攻撃が成立した/しなかった理由」を 1〜3 文で説明
  2. 防御を実装している既存ファイルへの参照 (例: `server/routes/jwt-ops.ts` の検証処理)
  3. 「これを防ぐ実装」の具体的なコードスニペット (15行以内)
- 攻撃が「ブロックされた (防御が機能した)」シナリオでも解説パネルは省略しない。「なぜ防御が機能したか」を示すことが目的のため

---

## 2. UI 文言ルール

### 2.1 攻撃成立時の表現

攻撃が成立したとき、実装または設定の問題を指摘する言い回しとする。攻撃者を称賛する表現は使わない。

| 種別 | 文言パターン |
|------|-------------|
| NG (誇張) | 「攻撃に成功しました」「ハックに成功しました」 |
| OK (実装評価) | 「この実装は脆弱です: 攻撃が成立しました」 |
| OK (シナリオ限定) | 「このシナリオでは `alg` 検証が省略されているため署名バイパスが成立しました」 |

**必須修飾語:** 攻撃成立を示す文には「この実装は」または「このシナリオでは」のいずれかで始めること。

---

### 2.2 防御成立時の表現

防御が機能したとき、実装の具体的な機能名を主語にする。

| 種別 | 文言パターン |
|------|-------------|
| NG (主体不明) | 「攻撃を防ぎました」「守られました」 |
| OK (機能強調) | 「防御が機能しました: alg 検証が none を拒否しました」 |
| OK (実装明示) | 「`jwt-ops.ts` の `algorithm` ホワイトリスト検証が機能し、リクエストを拒否しました」 |

`AttackResult.blockedBy` フィールドに防御機能名を設定し、UI は `防御が機能しました: <blockedBy>` のフォーマットで表示する。

---

### 2.3 禁止表現一覧

以下の表現はすべての攻撃デモ UI・ドキュメント・コメントに含めてはならない。

| 禁止表現 | 理由 | 代替表現 |
|---------|------|---------|
| 「ハッキング」「クラッキング」 | センセーショナル・負のイメージ強調 | 「攻撃」「脆弱性の悪用」 |
| 「実環境で試せる」「本物の攻撃」 | 悪用誘導 | 「概念実証」「教育用シミュレーション」 |
| 特定の実在企業・サービス名 | 誹謗中傷リスク・不正確 | `example.com`, `attacker.example`, `idp.example` |
| 「簡単に破れる」「誰でもできる」 | 技術への軽視・悪用ハードル誤認 | 「防御がない場合に成立する」 |
| 「完全な乗っ取り」「全データが漏洩」 | 誇大表現 | 「認証バイパスが可能になります」「セッションが窃取される可能性があります」 |
| `root` / `admin` などの実在っぽいテストユーザー名 | 実運用と混同させる | `seed_alice`, `seed_bob`, `attacker_charlie` |

---

### 2.4 推奨表現一覧

| 場面 | 推奨表現 |
|------|---------|
| シナリオ説明文の冒頭 | 「これは **CWE-xxx** の概念実証です。」 |
| 攻撃ステップの説明 | 「攻撃者は〜を操作してリクエストを送信します。」 |
| 攻撃成立後 | 「この実装は〜という設計上の欠陥があります。」 |
| 防御策説明 | 「**RFC xxxx** の規約では〜が要求されています。」 |
| 教材的まとめ | 「この脆弱性を防ぐには〜の実装が必要です。」 |

---

## 3. ペイロード作成ルール

### 3.1 簡略化の指針

攻撃ペイロードは「攻撃の本質的なメカニズム」だけを示す最小単位とする。

**alg=none 攻撃の例 (適切な簡略化):**

```
// 実装してよいもの: alg=none + 署名削除
header: { "alg": "none", "typ": "JWT" }
payload: { "sub": "alice", "role": "admin" }
signature: ""  // 空文字列
→ サーバーに送信して検証バイパスを確認
```

```
// 実装してはならないもの: 実際のエクスプロイトの完全チェーン
// 例: 実際のシステムへの接続情報生成、セッション固定後の権限昇格チェーン全体
```

**Kerberoasting の例 (適切な簡略化):**

```
// 実装してよいもの: SPN ハッシュ抽出 + 弱パスワード一致の表示
// サーバー側で「SPNアカウントのサービスチケットのハッシュ: $krb5tgs$... (抽出済み)」
// 「辞書検索の結果: password123 が一致しました」と表示するにとどめる
```

```
// 実装してはならないもの: Hashcat / John the Ripper 相当のオフライン解読処理
// または実際のキー導出アルゴリズムをフロントエンドで実行する処理
```

---

### 3.2 機微情報の扱い

| 情報の種類 | 扱い方針 |
|-----------|---------|
| bcrypt ハッシュ | 固定シードデータのハッシュのみ表示。ソルトラウンドは教材用に 4 に設定し、その旨を「教材用低コスト設定 (本番は 12 以上推奨)」と表示する |
| JWT 秘密鍵 | `CLAUDE.md` 既出の方針に従い教材として表示可。`"secret"` / `"weak-key"` 等の明示的に弱い値を使用。本番環境用の鍵生成ガイドを隣接して表示する |
| HMAC 鍵 | 固定のシード鍵のみ表示。実運用と混同しないよう `demo-hmac-key-do-not-use-in-production` 等の命名を使用 |
| TLS 証明書/秘密鍵 | 自己署名の教材用証明書のみ使用。実 CA 発行の証明書・鍵は含めない |
| Kerberos 鍵 | 固定シードの AES 鍵のみ。実 KDC との互換性を持たせない |
| OTP シード | 固定シードユーザーの TOTP シークレットのみ表示 |

---

### 3.3 リアルワールド外挿の防止

以下の攻撃パターンを実装する場合は、必ず括弧内の「実環境との差異」説明を攻撃結果または解説パネルに表示する。

| 攻撃パターン | 必須の付記 |
|------------|-----------|
| ブルートフォース系 | 「実環境では IP レート制限・WAF・CAPTCHA・アカウントロックアウトにより阻止されます」 |
| alg=none バイパス | 「現代のほとんどの JWT ライブラリはデフォルトで none を拒否するよう更新されています」 |
| セッション固定攻撃 | 「現代のフレームワークは認証後に自動的にセッション ID を再生成します」 |
| タイミング攻撃 | 「実環境では測定誤差・ネットワーク遅延により再現が困難です。このデモは概念的な差異を誇張して表示しています」 |
| Kerberoasting | 「実環境では強力なパスワードポリシーおよびサービスアカウントの管理策により成立しにくくなります」 |
| Golden Ticket | 「実環境での再現には krbtgt アカウントのハッシュ取得 (DC への侵害が前提) が必要であり、このデモは概念シミュレーションです」 |
| SMS SIM スワップ | 「実環境での SIM スワップには携帯キャリアへの Social Engineering が必要です。このデモは SMS OTP の脆弱性の概念を示します」 |

---

## 4. 開発レビューチェックリスト (PR 前)

新規攻撃シナリオを含む PR をマージする前に、以下をすべて確認する。PR テンプレートにこのチェックリストを埋め込むこと。

### 4.1 隔離チェック
- [ ] Attacker View 内のすべての `fetch` / `apiPost` / `apiGet` 呼び出しが `/api/<area>/attack/<scenario-id>` パターンまたは相対パスのみを宛先としている
- [ ] 外部ドメイン (`http://`, `https://` で始まる非 localhost URL) へのリクエストが生成されていない
- [ ] 固定シードデータのみを対象としており、任意ユーザーデータへの攻撃が設計上不可能である
- [ ] `POST /api/reset` 実行後にシナリオが正常に動作することを確認した

### 4.2 表示・文言チェック
- [ ] Attacker View が表示されているすべての画面で `EducationalWarningBanner` が最上部に固定表示されている
- [ ] バナーが `display: none` / `visibility: hidden` になるコード・CSS が存在しない
- [ ] 攻撃成立時の文言が「この実装は」または「このシナリオでは」で始まっている
- [ ] `2.3 禁止表現一覧` に該当する文字列がコンポーネント・コメント・型定義中に存在しない

### 4.3 教育内容チェック
- [ ] CWE ID が `AttackScenarioMeta.cweId` に設定されている
- [ ] CAPEC ID が `AttackScenarioMeta.capecId` に設定されている
- [ ] `ja` / `en` 両言語の文言が `AttackScenarioMeta.descriptionJa` / `AttackStep.detailJa` / `AttackResult.summaryJa` に用意されている
- [ ] 攻撃完了後に `AttackDefensePanel` が自動展開される

### 4.4 ペイロードチェック
- [ ] 攻撃ペイロードが「攻撃の本質を示す最小単位」にとどまっており、完全なエクスプロイトチェーンを含んでいない
- [ ] `3.3 リアルワールド外挿の防止` の表に該当するパターンを含む場合、必須の付記が解説パネルに記載されている
- [ ] サーバー側のシミュレーション処理が `localhost` 内で完結しており、外部ネットワーク呼び出しがない

### 4.5 ログ・デバッグチェック
- [ ] 攻撃ステップの詳細が `console.log` / `console.warn` に出力されていない
- [ ] 攻撃の可視化は DataFlowPanel の Trace タブのみで完結している

### 4.6 safety-reviewed フラグの運用フロー

各 1X DESIGN ファイル (`DESIGN/10-*.md` 〜 `DESIGN/21-*.md`) の frontmatter には `safety-reviewed: false` が初期値として設定されている。以下の手順でレビューを完了させること。

1. PR 上でこのチェックリスト §4.1〜4.5 を全項目チェック済みにする
2. レビュアーが安全性を確認した後、対象 DESIGN ファイルの frontmatter を `safety-reviewed: true` に更新する
3. `safety-reviewed: true` になるまでは実装への反映を保留することを推奨する

```yaml
# レビュー完了後の frontmatter 更新例
---
safety-reviewed: true  # ← false から true に変更
---
```

---

## 5. シード値とリセット

### 5.1 シードユーザー定義

全攻撃シナリオは以下の固定シードユーザー・鍵に対して実行する。実在するユーザーデータは使用しない。

| 識別子 | 役割 | 用途 |
|-------|------|------|
| `seed_alice` | 正規ユーザー (攻撃対象) | セッション固定・トークン窃取の被害者側 |
| `seed_bob` | 低権限ユーザー | 権限昇格攻撃の起点 |
| `seed_admin` | 管理者ユーザー | 権限昇格の到達目標 (攻撃成立の判定基準) |
| `attacker_charlie` | 攻撃者 | 攻撃リクエストの送信者 |

シードユーザーのパスワードは固定値 (`Passw0rd!`, `hunter2` 等の弱パスワード) を意図的に使用し、「なぜ弱いパスワードが危険か」を体感させる目的に使う。

### 5.2 リセット仕様

`POST /api/reset` は以下のテーブルを初期シード状態に戻す。攻撃デモ追加に伴い、次のテーブルも対象に含める。

| テーブル | リセット内容 |
|---------|------------|
| `attack_log` | 全行削除 |
| `sessions` | 攻撃シナリオで生成されたセッションを削除 (seed ユーザーのシードセッションは保持) |
| `oauth_codes` | 攻撃シナリオで生成された認可コードを削除 |
| `api_keys` | 攻撃シナリオで生成された API キーを削除 |

### 5.3 状態の独立性

攻撃デモで生成されたデータが正常系デモに影響しないよう、以下を保証する。

- 攻撃ルート (`/api/<area>/attack/*`) が更新するレコードには `is_attack_sim INTEGER NOT NULL DEFAULT 0` 列を設定する
- 正常系ルート (`/api/password-auth/*` 等) のクエリは `WHERE is_attack_sim = 0` で攻撃データを除外する

#### 5.3.1 E-3 対象テーブル一覧 (Phase 2 第一コミット時点)

以下 6 テーブルに `is_attack_sim` 列を追加する。`server/db/schema.ts` の `migrateSchema()` が
idempotent な ALTER TABLE で既存 `data.sqlite` にも遡及適用する (ROB-FIND-001 対応)。

| テーブル | 攻撃シナリオで更新されるか | 備考 |
|---------|--------------------------|------|
| `sessions` | session-token 攻撃で更新 | `cleanExpiredSessions()` も `WHERE is_attack_sim = 0` で除外 |
| `oauth_codes` | oauth 攻撃で更新 | TABLE_QUERIES にも WHERE 句追加 |
| `oauth_tokens` | oauth 攻撃で更新 | 同上 |
| `api_keys` | sso-apikey 攻撃で更新 | 同上 |
| `kerberos_tickets` | kerberos 攻撃で更新 | 同上 |
| `refresh_tokens` | session-token / oauth 攻撃で更新 (Phase 2 後続) | SEC FINDING-6 で追加。`token-auth.ts` UPDATE クエリにも WHERE 句追加 |

#### 5.3.2 DDL (CREATE TABLE 時)

```sql
CREATE TABLE IF NOT EXISTS sessions (
  -- ... 既存列 ...
  is_attack_sim INTEGER NOT NULL DEFAULT 0
);
-- 同様に oauth_codes, oauth_tokens, api_keys, kerberos_tickets, refresh_tokens にも追加
```

#### 5.3.3 既存 DB へのマイグレーション (idempotent)

```typescript
// server/db/schema.ts
function migrateSchema(db: Database.Database) {
  const tablesNeedingFlag = [
    "sessions", "oauth_codes", "oauth_tokens",
    "api_keys", "kerberos_tickets", "refresh_tokens",
  ] as const;
  for (const tbl of tablesNeedingFlag) {
    const cols = db.prepare(`PRAGMA table_info(${tbl})`).all() as { name: string }[];
    if (!cols.some((c) => c.name === "is_attack_sim")) {
      db.exec(`ALTER TABLE ${tbl} ADD COLUMN is_attack_sim INTEGER NOT NULL DEFAULT 0`);
    }
  }
}
```

#### 5.3.4 正常系ルート側の WHERE 句適用箇所

| ファイル | 関数 / SQL | 用途 |
|---------|----------|------|
| `server/db/queries.ts` | `cleanExpiredSessions()` | `DELETE FROM sessions WHERE expires_at < datetime('now') AND is_attack_sim = 0` |
| `server/index.ts` | `TABLE_QUERIES.sessions` 等 5 件 | `/api/debug/tables/:name` の SELECT に `WHERE is_attack_sim = 0` を付与 |
| `server/routes/token-auth.ts` | `/refresh` の UPDATE | `WHERE jti = ? AND revoked = 0 AND expires_at > datetime('now') AND is_attack_sim = 0` |
| `server/routes/session-auth.ts` | セッション SELECT/UPDATE/DELETE | `WHERE is_attack_sim = 0` を付与 (Phase 2 本体で session 攻撃導入時) |
| `server/routes/oauth-sim.ts` | code/token SELECT | 同上 (Phase 2 本体で oauth 攻撃導入時) |
| `server/routes/sso-apikey.ts` | api_keys SELECT | 同上 (Phase 2 本体で apikey 攻撃導入時) |
| `server/routes/kerberos-sim.ts` | tickets SELECT | 同上 (Phase 2 本体で kerberos 攻撃導入時) |

---

## 6. 警告ヘッダの実装パターン

### 6.1 `EducationalWarningBanner` コンポーネント

```typescript
// src/components/shared/EducationalWarningBanner.tsx
import { useI18n } from "../../i18n/context";

function EducationalWarningBanner() {
  const { t } = useI18n();
  return (
    <div
      class="edu-warning-banner"
      role="note"
      aria-live="polite"
      aria-label={t("教育用シミュレーション警告", "Educational simulation warning")}
      {/* 教育用バナー: role="note" + aria-live="polite" で統一 (DESIGN/02 §12.3 準拠) */}
    >
      <span class="edu-icon" aria-hidden="true">⚠</span>
      <span>
        {t(
          "教育用シミュレーション — 実環境を攻撃するためのコードではありません",
          "Educational simulation — not for use against real systems"
        )}
      </span>
    </div>
  );
}

export default EducationalWarningBanner;
```

### 6.2 視覚要件

バナーは視覚的に「通常 UI とは別のコンテキスト」として明確に区別されなければならない。

| プロパティ | 仕様 |
|-----------|------|
| 背景色 | `var(--color-warning)` またはそれに準ずる警告色 (`#ff4d4f` ベース) |
| テキスト色 | `#fff` (白、コントラスト比 4.5:1 以上を確保) |
| 表示位置 | Attacker View コンテンツの最上部固定 (`position: sticky; top: 0; z-index: 100`) |
| `dismissable` | 禁止 (閉じるボタンを実装しない) |
| フォントウェイト | `font-weight: 700` |
| アイコン | `⚠` を `aria-hidden="true"` で装飾的に使用 |
| 最小高さ | `44px` (タッチターゲットサイズ確保) |

### 6.3 CSS 定義

```css
/* src/styles/attack-demo.css (新規作成) */
.edu-warning-banner {
  position: sticky;
  top: 0;
  z-index: 100;
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 16px;
  background-color: var(--color-warning, #ff4d4f);
  color: #fff;
  font-weight: 700;
  font-size: 0.875rem;
  min-height: 44px;
  border-bottom: 2px solid rgba(0, 0, 0, 0.2);
}

.edu-icon {
  font-size: 1.1rem;
  flex-shrink: 0;
}
```

### 6.4 CWE/CAPEC 表示パターン

各攻撃シナリオの説明には CWE・CAPEC ID を含む定型フレーズを付与する。

```typescript
// AttackScenarioMeta の descriptionJa / description フィールドの先頭に付与するパターン
const cwePrefix = (cweId: string, capecId: string) =>
  t(
    `これは ${cweId} / ${capecId} の概念実証です。`,
    `This is a proof-of-concept for ${cweId} / ${capecId}.`
  );
```

実際の表示例:
> これは **CWE-347** / **CAPEC-196** の概念実証です。`alg` フィールドを `none` に書き換えることで、署名検証なしにサーバーを騙すことができる状況をシミュレーションします。

---

## 7. ログ出力規約

### 7.1 フロントエンド側

- 攻撃ステップの入力値・ペイロード・レスポンスを `console.log` / `console.warn` / `console.error` に出力してはならない
- 攻撃デモに関する全ての可視化は `DataFlowPanel` の HTTP タブ・Trace タブ内で完結させる
- `scopeId` は `"attack-{tabId}"` 形式を使用する (例: `"attack-jwt"`, `"attack-oauth"`)
- ブラウザの `localStorage` / `sessionStorage` に攻撃用のトークン・キーを保存しない (メモリ上の Signal のみ)

### 7.2 バックエンド側

- 攻撃ルート (`server/routes/attack-*.ts`) のログは `_trace` の `SessionOp` または `CryptoOp` として構造化する
- `console.log` 等への生ログ出力は行わない (本番環境の混乱防止)
- `_trace` の `isAttackMode: true` フラグにより、フロントエンドが攻撃ログを視覚的に区別できるようにする

```typescript
// server/middleware/trace-logger.ts 拡張例 (概念)
const traceContext = {
  dbQueries: [] as DbQuery[],
  cryptoOps: [] as CryptoOp[],
  sessionOps: [] as SessionOp[],
  isAttackMode: c.req.path.includes("/attack/"), // 攻撃ルートを自動検出 (/api/<area>/attack/<id> パターン)
};
```

---

## 8. 教育目的の文書化

### 8.1 各タブ詳細設計書 (DESIGN/10-*.md 〜 21-*.md) の冒頭規約

各タブの攻撃詳細設計書は以下の冒頭ブロックを必ず含める。

```markdown
---
title: 攻撃デモカタログ — <タブ名> 攻撃詳細
phase: design
last-updated: YYYY-MM-DD
safety-reviewed: false  ← レビュー完了後に true に変更
---

## 教育目的

本ファイルは **教育用シミュレーション** の実装設計である。
記載された攻撃手法は `localhost` 上の固定シードデータに対してのみ動作するよう設計されており、
実環境への攻撃を意図したものではない。

攻撃シミュレーションはすべて「この防御がなぜ必要か」を体感するための概念実証であり、
各シナリオには必ず防御策の解説と実装例が対になっている。
```

### 8.2 攻撃ルートファイル冒頭コメント規約

`server/routes/attack-*.ts` の先頭には以下のコメントブロックを必ず含める。

```typescript
/**
 * 攻撃デモルート: <タブ名>
 *
 * 【教育目的専用】
 * このファイルは OSI 参照アプリの教材機能として、
 * ローカル環境の固定シードデータに対する攻撃シミュレーションを提供します。
 *
 * - 外部ネットワークへのリクエストは行いません
 * - 実 CVE のエクスプロイトコードは含みません
 * - 本番環境での使用は想定していません
 *
 * 対象 CWE: CWE-xxx, CWE-yyy
 * 対象 CAPEC: CAPEC-xxx
 * 関連設計書: DESIGN/04-safety-guardrails.md
 */
```

### 8.3 「1秒で分かる」コンテキスト

学習者がこのコードを初めて読んだとき、「これは教育用である」と即座に判断できるよう以下を保証する。

- ファイル冒頭のコメント (8.2) が最初に目に入る
- 型定義 (`AttackScenarioMeta`, `AttackResult`) に `// 教育用シミュレーション専用型` のインラインコメントを付与
- `attack-scenarios.ts` の先頭に教育目的の説明を含む JSDoc を配置
- 固定シードデータの変数名に `SEED_` プレフィックスを付ける (例: `SEED_ALICE_TOKEN`, `SEED_WEAK_JWT_SECRET`)

---

## 9. 特殊ケースと判断基準

### 9.1 「攻撃が成立しないことを示す」シナリオ (Info 深刻度)

FIDO2/Passkey の origin binding など、「攻撃が設計上成立しないことを教える」シナリオは特別扱いとする。

- `AttackResult.outcome` は `"blocked"` を使用する
- バナーは赤ではなく緑 (`var(--color-success)`) で表示し、「プロトコル設計により防御されました」と示す
- 防御パネルには「なぜこのプロトコルはこの攻撃に耐性があるか」を優先的に解説する

### 9.2 段階的な攻撃シナリオ (Critical 深刻度)

複数ステップが必要な Critical 攻撃 (alg=none, SAML XSW, Golden Ticket 等) は以下の方針とする。

- 各ステップの完了時に `EducationalWarningBanner` の下に「現在のステップ: X / Y」インジケーターを表示する
- 最終ステップの実行ボタンは「最後のステップです。攻撃成立結果を確認します」のラベルにする
- 全ステップ完了後に `AttackDefensePanel` が自動展開される

### 9.3 「わざと脆弱な実装」と「防御された実装」の並列比較

Session vs Token タブのように左右並列で「脆弱版 vs 防御版」を比較するシナリオでは:

- 脆弱版パネルの上端に `EducationalWarningBanner` を配置する
- 防御版パネルには同じ位置に緑色の「防御実装済み」バナーを配置する
- 両パネルのバナーの高さ・位置を揃えて視覚的に対比させる

---

## 10. 関連ファイル

### 設計書内参照

- [DESIGN/00-overview.md](./00-overview.md) — 全体概要・攻撃カタログマトリクス・4原則の概要
- [DESIGN/01-architecture.md](./01-architecture.md) — バックエンドルート構成・新規ファイル一覧
- [DESIGN/02-ui-spec.md](./02-ui-spec.md) — ViewModeToggle / AttackStepTimeline / AttackResultBanner / AttackDefensePanel の UI 詳細仕様
- [DESIGN/03-data-model.md](./03-data-model.md) — AttackScenarioMeta / AttackStep / AttackResult 型定義

### タブ別攻撃詳細設計書

- [DESIGN/10-auth-methods.md](./10-auth-methods.md) — パスワード認証攻撃 (3シナリオ)
- [DESIGN/11-jwt.md](./11-jwt.md) — JWT 攻撃 (4シナリオ)
- [DESIGN/12-oauth.md](./12-oauth.md) — OAuth 2.0 攻撃 (3シナリオ)
- [DESIGN/13-session-vs-token.md](./13-session-vs-token.md) — セッション vs トークン攻撃 (3シナリオ)
- [DESIGN/14-rbac.md](./14-rbac.md) — アクセス制御攻撃 (4シナリオ)
- [DESIGN/15-fido2.md](./15-fido2.md) — FIDO2/WebAuthn フィッシング耐性デモ (1シナリオ)
- [DESIGN/16-oidc-saml.md](./16-oidc-saml.md) — OIDC & SAML 攻撃 (3シナリオ)
- [DESIGN/17-kerberos.md](./17-kerberos.md) — Kerberos 攻撃 (3シナリオ)
- [DESIGN/18-tls-deep.md](./18-tls-deep.md) — TLS 攻撃 (3シナリオ)
- [DESIGN/19-sso-idp-apikey.md](./19-sso-idp-apikey.md) — SSO / API Key 攻撃 (3シナリオ)
- [DESIGN/20-mfa.md](./20-mfa.md) — MFA/TOTP 攻撃 (3シナリオ)
- [DESIGN/21-passkey.md](./21-passkey.md) — パスキーフィッシング耐性デモ (1シナリオ)

### 既存実装ファイル (安全装置が依拠するもの)

| ファイルパス | 役割 |
|------------|------|
| `src/i18n/context.tsx` | `t(ja, en)` ヘルパー — バナー文言の ja/en 切替に使用 |
| `src/api/client.ts` | fetch ラッパー — 攻撃リクエストのキャプチャ (scopeId 経由) |
| `src/components/shared/DataFlowPanel.tsx` | HTTP/Trace/DB 可視化 — 攻撃デモの可視化出力先 |
| `server/middleware/trace-logger.ts` | `_trace` 付与 — `isAttackMode` フラグ拡張の対象 |
| `server/db/schema.ts` | SQLite スキーマ — `attack_log` テーブル追加対象 |

---

## 付録 A: OK / NG 早見表

### A.1 実装の OK / NG

| # | 観点 | OK 例 | NG 例 |
|---|------|-------|-------|
| 1 | fetch 宛先 | `/api/jwt/attack/alg-none` (相対パス) | `https://target.example/api/login` |
| 2 | テストユーザー名 | `seed_alice`, `attacker_charlie` | `admin`, `root`, `john` |
| 3 | JWT 秘密鍵表示 | `"weak-key-for-demo"` と注記付きで表示 | 鍵生成ガイドなしに実用的な鍵を表示 |
| 4 | ブルートフォース実装 | サーバー側で「N 回試行で一致」を返す | フロントエンドで実際のループを実行 |
| 5 | console 出力 | なし (DataFlowPanel のみ) | 攻撃ペイロードを `console.log` に出力 |
| 6 | 攻撃成立文言 | 「この実装は脆弱です: alg 検証が省略されています」 | 「攻撃に成功しました！」 |
| 7 | バナー表示 | `position: sticky` で常時表示 | `isVisible` Signal でトグル可能 |

### A.2 文言の OK / NG

| # | 場面 | OK | NG |
|---|------|----|----|
| 1 | 攻撃成立 | 「このシナリオでは rate limit が設定されていないため、ブルートフォースが成立しました」 | 「パスワードを破りました」 |
| 2 | 防御成立 | 「防御が機能しました: origin 検証が別ドメインからのリクエストを拒否しました」 | 「攻撃が失敗しました」 |
| 3 | シナリオ説明 | 「これは CWE-347 の概念実証です。JWT の alg フィールドが検証されない場合に成立します」 | 「JWT を簡単にハックする方法です」 |
| 4 | 実環境との差異 | 「実環境では IP レート制限により阻止されます」 | 「実環境でも試してみましょう」 |
| 5 | ドメイン例示 | `attacker.example`, `evil.example` | `attacker-google.com`, 実在する企業名 |

---

## 付録 B: 各原則の責任範囲

| 原則 | 実装責任者 | レビュー責任者 | 検証方法 |
|------|-----------|-------------|---------|
| 隔離 (Isolation) | 各攻撃ルート実装者 | PR レビュアー | チェックリスト 4.1 |
| 明示 (Explicit framing) | 各タブコンポーネント実装者 | PR レビュアー | チェックリスト 4.2 |
| 簡略化 (Simplification) | 攻撃ペイロード設計者 | コンテンツレビュアー | チェックリスト 4.4 |
| 防御策併記 (Defense pairing) | 各攻撃ルート実装者 + コンテンツ執筆者 | PR レビュアー | チェックリスト 4.2 |

新規攻撃シナリオ追加時の最終的なコンテンツ・ペイロードの妥当性は開発者の責任とする。本文書は判断基準を提供するが、すべてのケースを網羅するものではない。判断に迷う場合は「これを実装することで教材の範囲を超えた実際の攻撃に再利用できるか」を基準に判断すること。
