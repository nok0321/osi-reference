/**
 * 攻撃シナリオ共通ランナー (SEC-12 / ROB-FIND-011 統合)。
 *
 * Phase 2 の 11 タブ × 3-4 シナリオ展開 (合計 30+) で、4 ルートに重複している
 * 「parseBody → insertAttackLog → 5 ステップ recordStep → AttackResult 生成 → finalize / 二重例外保護」
 * のボイラープレートを 1 箇所に集約する。
 *
 * 教育用安全装置 (DESIGN/04):
 * - SEC FINDING-5: payload_json に保存する秘密値は `maskSecret()` でマスク化してから渡す
 * - SEC FINDING-3: 攻撃者制御文字列は `sanitizeForDisplay()` で制御文字除去 + 長さ制限
 * - ROB-FIND-004: payload_json / steps_json は `MAX_PAYLOAD_JSON_BYTES` で SSoT 化されたサイズ上限を持つ
 *
 * 設計判断 (E-2): 各シナリオは 1 リクエストで両モード並列実行のため、`outcome` は常に "succeeded"。
 * "blocked" は AttackStep.status = "blocked" (堅牢ステップ 5) で表現する。
 */
import type { Context } from "hono";
import type { z } from "zod";
import { parseBody } from "../validation.js";
import { getDb } from "../db/schema.js";
import { insertAttackLog, finalizeAttackLog } from "../db/queries.js";
import type { AttackResult, AttackStep } from "../../shared/api-types.js";
import type { TraceCollector } from "../middleware/trace-logger.js";

/**
 * payload_json / steps_json の保存サイズ上限 (バイト)。
 * ROB-FIND-004 SSoT。超過時は `clipJson()` が末尾に "…(truncated)" マーカ付きで切り詰める。
 * 8KB は教育デモのトレース 30 ステップ程度を余裕で収容する想定値。
 */
export const MAX_PAYLOAD_JSON_BYTES = 8 * 1024;

/** ハンドラに渡される実行コンテキスト。 */
export interface AttackRunContext<TBody> {
  body: TBody;
  trace: TraceCollector;
  db: ReturnType<typeof getDb>;
  /**
   * ステップを記録 (timestamp 共有 / `_trace.attackSteps` と `data.steps` 双方に追加)。
   * ROB-FIND-009: 同一 timestamp を両者で共有することで時系列突合が容易になる。
   */
  recordStep: (step: Omit<AttackStep, "timestamp">) => void;
}

/**
 * ハンドラが返すシナリオメタデータ。
 * 5 ステップ完全形 (probe → tamper → forge → exploit → verify) を `recordStep` 経由で
 * 既に投入済みであることを前提とし、サマリ・防御指標・extra フィールドのみを返却する。
 */
export interface AttackRunResult<TExtra = Record<string, never>> {
  /** 堅牢モード (ステップ 5) で発動した防御識別子。常に必須。 */
  blockedBy: string;
  /** 英語サマリー (両モード結果の比較)。 */
  summary: string;
  /** 日本語サマリー (両モード結果の比較)。 */
  summaryJa: string;
  /** シナリオ固有の追加データ (E-1 ジェネリック)。`AttackResult.extra` に格納される。 */
  extra?: TExtra;
  /**
   * `attack_log.payload_json` に保存するシナリオ固有データ。
   * `{ params, result }` 構造を推奨 (SEC-9)。helper が `mode: "both"` を自動付与する。
   * 機密情報 (秘密鍵、平文パスワード、API キー等) は `maskSecret()` でマスク化してから渡すこと。
   */
  payload?: { params?: Record<string, unknown>; result?: Record<string, unknown> };
}

/**
 * 攻撃シナリオ共通ランナー。
 *
 * 標準パイプライン:
 * 1. `parseBody` で zod 検証 (失敗時 400 で早期 return)
 * 2. `insertAttackLog` で attack_log 行作成 (logId 取得)
 * 3. ハンドラ実行 (5 ステップ recordStep + AttackRunResult 返却)
 * 4. `AttackResult` 生成 + `finalizeAttackLog` (payload_json は `clipJson` でサイズ制限)
 * 5. 例外時は二重例外保護 (logId 未取得時は finalize スキップ、finalize 自体の例外は握り潰し)
 *
 * @template TSchema  リクエスト body の zod スキーマ型
 * @template TExtra   `AttackResult.extra` に格納するシナリオ固有型 (デフォルト: extra なし)
 */
export async function runAttackScenario<
  TSchema extends z.ZodTypeAny,
  TExtra = Record<string, never>,
>(
  c: Context,
  args: {
    schema: TSchema;
    scenarioId: string;
    tabId: string;
    handler: (ctx: AttackRunContext<z.infer<TSchema>>) => Promise<AttackRunResult<TExtra>>;
  },
): Promise<Response> {
  const parsed = await parseBody(c, args.schema);
  if ("error" in parsed) return parsed.error;

  const trace = c.get("trace");
  const startedAt = Date.now();
  const db = getDb();
  // ROB-FIND-008: insertAttackLog 自体が失敗した場合は logId が undefined のまま
  // catch に到達する。catch 側で `logId !== undefined` ガードして finalize スキップ。
  let logId: number | undefined;
  const stepsCollected: AttackStep[] = [];

  const recordStep = (step: Omit<AttackStep, "timestamp">) => {
    const stamped: AttackStep = { ...step, timestamp: Date.now() };
    trace.addAttackStep(stamped);
    stepsCollected.push(stamped);
  };

  try {
    logId = insertAttackLog(db, { scenarioId: args.scenarioId, tabId: args.tabId });
    const meta = await args.handler({ body: parsed.data, trace, db, recordStep });

    const finishedAt = Date.now();
    const result: AttackResult<TExtra> = {
      scenarioId: args.scenarioId,
      outcome: "succeeded",
      startedAt,
      finishedAt,
      steps: stepsCollected,
      blockedBy: meta.blockedBy,
      summary: meta.summary,
      summaryJa: meta.summaryJa,
      logId,
      extra: meta.extra,
    };

    finalizeAttackLog(db, logId, {
      success: true,
      blockedBy: meta.blockedBy,
      stepsJson: clipJson(JSON.stringify(stepsCollected)),
      payloadJson: clipJson(JSON.stringify({ mode: "both", ...meta.payload })),
    });

    return c.json({ success: true, data: result }, 200);
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : "Unknown error";
    if (logId !== undefined) {
      try {
        finalizeAttackLog(db, logId, {
          success: false,
          stepsJson: clipJson(JSON.stringify(stepsCollected)),
          payloadJson: clipJson(JSON.stringify({ mode: "both", error: errorMessage })),
        });
      } catch {
        // 二重例外回避: finalize 失敗は握り潰す (元の例外を優先するため)
      }
    }
    return c.json(
      {
        success: false,
        error: errorMessage,
        data: {
          scenarioId: args.scenarioId,
          outcome: "error" as const,
          startedAt,
          finishedAt: Date.now(),
          steps: stepsCollected,
          logId,
        },
      },
      500,
    );
  }
}

/**
 * JSON 文字列を `MAX_PAYLOAD_JSON_BYTES` で切り詰め (ROB-FIND-004)。
 * 超過時は末尾に `…(truncated)` マーカを付与する。JSON 構造としての妥当性は崩れるが、
 * `attack_log.payload_json` は教育用ログのため人間可読性を優先する。
 *
 * UTF-8 中途切断を回避するため、置換不能文字 (U+FFFD) を末尾から除去してから連結する。
 */
export function clipJson(s: string): string {
  if (Buffer.byteLength(s, "utf8") <= MAX_PAYLOAD_JSON_BYTES) return s;
  const reservedForMarker = 16;
  const buf = Buffer.from(s, "utf8").subarray(0, MAX_PAYLOAD_JSON_BYTES - reservedForMarker);
  const safe = buf.toString("utf8").replace(/�+$/, "");
  return `${safe}…(truncated)`;
}

/**
 * 秘密文字列を `payload_json` に保存する際のマスキング (SEC FINDING-5)。
 * クラックされた秘密鍵を平文で attack_log に残さないため、長さ情報のみ保持する。
 *
 * 例: `maskSecret("secret")` → `"s***t (len=6)"`
 *     `maskSecret(null)` → `null`
 *
 * 注意: ハンドラが返す `AttackResult.extra` は教育表示用のため平文 (マスクなし) で OK。
 *       `payload_json` (DB 保存) のみマスクする。
 */
export function maskSecret(s: string | null | undefined): string | null {
  if (s === null || s === undefined) return null;
  if (s.length <= 2) return "***";
  return `${s[0]}***${s[s.length - 1]} (len=${s.length})`;
}

/**
 * 攻撃者制御文字列を表示用に正規化 (SEC FINDING-3 防御深層)。
 * 制御文字 (0x00-0x1F, 0x7F) を `?` に置換し、表示長を `maxLen` に切り詰める。
 * フロントエンドが textContent で描画していても、ログ閲覧時の可読性破壊を防ぐ。
 *
 * 例: `sanitizeForDisplay("../public/key.pem")` → `"../public/key.pem"` (printable ASCII は透過)
 *     `sanitizeForDisplay("kid\x00with\x01ctrl")` → `"kid?with?ctrl"`
 */
export function sanitizeForDisplay(input: string, maxLen = 256): string {
  // eslint-disable-next-line no-control-regex
  const cleaned = input.replace(/[\x00-\x1F\x7F]/g, "?");
  return cleaned.length > maxLen ? `${cleaned.slice(0, maxLen)}…` : cleaned;
}
