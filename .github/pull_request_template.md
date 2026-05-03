<!--
osi-reference PR テンプレート
- live モードを含まない PR でもチェックリストは残してください (各項目は N/A 可)。
- DESIGN/34 §6 由来の live モード PR チェックリストを最後に含みます。
-->

## 概要 / Summary

<!-- 1-3 行で「何を」「なぜ」変更したか。 -->

## 関連 Issue / Linked issues

- closes #
- refs #

## 変更点 / Changes

<!-- ファイル単位ではなく、機能単位で箇条書きにしてください。 -->

-

## スクリーンショット (UI 変更時) / Screenshots

<!-- 認証タブ、攻撃パネル、SequenceDiagramView など UI に触れる場合は前後の差分を貼ってください。 -->

## テスト方法 / How to test

- [ ] `npm run dev` (もしくは `npm run dev:no-docker`) でフロント:3000 + バックエンド:3001 を起動
- [ ] `curl http://localhost:3001/api/health` が `{"status":"ok"}` を返す
- [ ] 影響範囲のタブで正常系デモが動作する
- [ ] 影響範囲のタブで攻撃シナリオが期待どおり成功 / 防御される

## DESIGN ⇄ 実装 整合性 / Design ↔ Implementation alignment

- [ ] 関連 DESIGN/*.md を読み、本 PR が逸脱していないことを確認した
- [ ] 仕様変更を含む場合は対応 DESIGN/*.md を更新した
- [ ] CLAUDE.md の「DESIGN ⇄ 実装 対応表」に新規ファイルを追加した (新規ファイルがある場合のみ)

---

## live モード PR チェックリスト / Live-mode PR checklist

> このセクションは `AttackScenarioMeta.mode === "live"` のシナリオを追加 / 変更する PR、
> または `services/victim-web/`・`server/routes/orchestrator-exec.ts`・`docker-compose.yml`・
> `RawHttpComposer` / `SequenceDiagramView` のいずれかに変更がある PR で記入する。
> 該当しない PR は `N/A` と記入してチェックリストごとスキップして構わない。
>
> 出典: [DESIGN/34 §3, §6](../DESIGN/34-safety-guardrails-live.md)

### DESIGN/34 §3 チェックリスト / Safety guardrails

- [ ] §3.1 隔離チェック (差分) — 全項目を確認した
- [ ] §3.2 表示・文言チェック (差分) — 全項目を確認した
- [ ] §3.3 教育内容チェック (差分) — 全項目を確認した
- [ ] §3.4 ペイロードチェック (差分) — 全項目を確認した
- [ ] §3.5 ログ・デバッグチェック (差分) — 全項目を確認した

### victim-web 変更時の追加確認 / victim-web changes

- [ ] `services/victim-web/` の変更で堅牢実装の参照リンクが `AttackDefensePanel` から表示できる
- [ ] `docker compose ps` で victim コンテナの PORTS 列が空 (ホストへの公開なし)
- [ ] (Phase 3+) `docker network inspect victim-net` の `"Internal"` が `true`
- [ ] (Phase 1-2 暫定) `internal: true` を無効化したまま運用する根拠を PR 本文に記載

### Docker 環境確認 / Docker environment

- [ ] `docker compose up -d` 後に全コンテナが `healthy` になる
- [ ] (Phase 3+) `npm run dev:no-docker` 廃止後の動作確認方法を PR 本文に記載

### live UI 確認 / Live attack UI

- [ ] `EducationalWarningBanner` の `LIVE` バッジが live シナリオ選択時のみ表示される
- [ ] `AttackScenarioSelector` の各シナリオに `LIVE` / `NARRATION` バッジが付く
- [ ] `RawHttpComposer` の Host ヘッダ入力欄が編集不可 (`disabled`) になっている
- [ ] `RawHttpComposer` に export / copy / persist 系ボタンが追加されていない
- [ ] `DataFlowPanel` の `Sequence` タブが live シナリオ選択時のみ露出する
- [ ] `SequenceDiagramView` の矢印クリックで raw bytes ポップアップが開く
- [ ] `localStorage` / `sessionStorage` への書き込みが追加されていない

### DESIGN/04 既存チェックリスト

- [ ] §4.1〜4.5 の全項目 (`DESIGN/04-safety-guardrails.md` を参照)
