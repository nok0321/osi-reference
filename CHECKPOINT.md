# Checkpoint: セキュリティ批評修正
Updated: 2026-04-10T21:18:00+09:00
Session: 936dfe5e-e13e-4e60-b00a-4229449a9e50

## 目標
批評で指摘されたセキュリティ・品質問題を修正する

## 完了済み
- [x] #1 seedDb() に NODE_ENV !== "production" ガード追加 (server/index.ts)
- [x] #2 POST /register レスポンスから password_hash を除外 (server/routes/password-auth.ts)
- [x] #3 GET /users エンドポイントに本番ガード追加 (server/routes/password-auth.ts)
- [x] #4 MfaFlow の TOTP secret をデフォルト非表示に変更、トグル+コピーボタン追加 (src/components/auth/MfaFlow.tsx + .css)
- [x] #5 code_challenge_method を z.enum(["S256","plain"]) に制限、code_challenge に長さ制約追加 (server/validation.ts)
- [x] #6 PasskeyFlow Conditional UI に WebAuthnAbortService.cancelCeremony() で onCleanup 追加 (src/components/auth/PasskeyFlow.tsx)
- [x] #7 TOTP 純粋関数を server/utils/totp.ts に分離し、13件のユニットテスト追加 (server/utils/totp.test.ts)

## 進行中
なし

## 未着手
なし（全タスク完了）

## 重要な決定事項
- Refresh Token Rotation: oauth-sim.ts 既に実装済みにつき修正不要
- PKCE verification: oidc-saml-sim.ts 既に実装済みにつき修正不要
- vitest: environmentMatchGlobs で server/ → node、src/ → jsdom を使い分け

## 環境状態
- ブランチ: master
- 未コミット変更: あり（上記ファイル群）
- ビルド状態: tsc --noEmit 成功、vitest run 74/74 テスト通過

## 次のセッションへの申し送り
全修正が完了。コミットしてリポジトリを更新すること。
