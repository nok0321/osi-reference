/**
 * AttackStoryboard (DESIGN/35 §7) — RawExchangeRef 解決ヘルパー。
 *
 * 設計判断: scenario データは静的 (*-scenarios.ts) なのでシリアライズ可能な
 * 構造体参照を採用。resolver 関数や JSON pointer は不採用 (DESIGN/35 §7.1)。
 *
 * - header lookup は case-insensitive (HTTP 仕様準拠)
 * - 解決失敗 (rawExchange null / pair 不在 / header 不在) は undefined を返す
 * - 警告ログは出さない (シナリオ作者の意図的選択もある)
 */
import type { RawExchange, RawExchangeRef } from "../../shared/api-types";

export function resolveRawRef(
  ref: RawExchangeRef,
  exchange: RawExchange | null | undefined,
): string | undefined {
  if (!exchange) return undefined;
  const pair = exchange[ref.pair];
  if (!pair) return undefined;
  const sideObj = pair[ref.side] as
    | { line: string; headers: Record<string, string>; body: string | null }
    | undefined;
  if (!sideObj) return undefined;

  if (ref.field === "line") return sideObj.line;
  if (ref.field === "body") return sideObj.body ?? undefined;

  if (typeof ref.field === "object" && "header" in ref.field) {
    const target = ref.field.header.toLowerCase();
    for (const [k, v] of Object.entries(sideObj.headers)) {
      if (k.toLowerCase() === target) return v;
    }
    return undefined;
  }
  return undefined;
}
