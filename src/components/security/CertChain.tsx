import { For, Show, createSignal, type JSX } from "solid-js";
import { useI18n } from "../../i18n/context";
import { selectedCertNode, setSelectedCertNode } from "../../state/security-state";
import { CERTIFICATE_CHAIN, EXPIRED_CERTIFICATE_CHAIN } from "../../data/certificate-data";
import type { CertificateNode } from "../../types/security";
import "./CertChain.css";

export default function CertChain() {
  const { t } = useI18n();
  const [showExpired, setShowExpired] = createSignal(false);

  const chain = () => showExpired() ? EXPIRED_CERTIFICATE_CHAIN : CERTIFICATE_CHAIN;

  function isExpired(cert: CertificateNode): boolean {
    return new Date(cert.validTo) < new Date();
  }

  function flattenChain(node: CertificateNode): CertificateNode[] {
    const result: CertificateNode[] = [node];
    if (node.children) {
      for (const child of node.children) {
        result.push(...flattenChain(child));
      }
    }
    return result;
  }

  function renderNode(node: CertificateNode, depth: number): JSX.Element {
    const expired = isExpired(node);
    const isSelected = () => selectedCertNode() === node.subject;

    return (
      <div class="cert-node-wrapper" style={{ "padding-left": `${depth * 1.2}rem` }}>
        <div
          class="cert-node"
          classList={{
            root: node.type === "root",
            intermediate: node.type === "intermediate",
            leaf: node.type === "leaf",
            expired: expired,
            selected: isSelected(),
          }}
          tabindex="0"
          onClick={() => setSelectedCertNode(prev => prev === node.subject ? null : node.subject)}
          onKeyDown={(e: KeyboardEvent) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setSelectedCertNode(prev => prev === node.subject ? null : node.subject); } }}
        >
          <div class="cert-node-header">
            <span class="cert-type-badge mono">{node.type.toUpperCase()}</span>
            <span class="cert-subject">{node.subject}</span>
            <Show when={expired}>
              <span class="cert-expired-badge">EXPIRED</span>
            </Show>
          </div>

          <Show when={isSelected()}>
            <div class="cert-detail">
              <div class="cert-field">
                <span class="cf-label mono">{t("発行者", "Issuer")}</span>
                <span class="cf-value">{node.issuer}</span>
              </div>
              <div class="cert-field">
                <span class="cf-label mono">{t("有効期間", "Validity")}</span>
                <span class="cf-value">{node.validFrom} → {node.validTo}</span>
              </div>
              <div class="cert-field">
                <span class="cf-label mono">{t("アルゴリズム", "Algorithm")}</span>
                <span class="cf-value">{node.algorithm}</span>
              </div>
              <div class="cert-field">
                <span class="cf-label mono">{t("鍵サイズ", "Key Size")}</span>
                <span class="cf-value">{node.keySize} bits</span>
              </div>
            </div>
          </Show>
        </div>

        {/* Trust chain line */}
        <Show when={node.children && node.children.length > 0}>
          <div class="trust-line" classList={{ "trust-valid": !expired, "trust-broken": expired }} />
        </Show>

        <Show when={node.children}>
          <For each={node.children!}>
            {(child) => renderNode(child, depth + 1)}
          </For>
        </Show>
      </div>
    );
  }

  return (
    <div class="cert-chain">
      <div class="cc-header">
        <span class="cc-title mono">{t("証明書チェーン", "Certificate Chain")}</span>
        <button
          class="cc-toggle"
          classList={{ active: showExpired() }}
          onClick={() => { setShowExpired(prev => !prev); setSelectedCertNode(null); }}
        >
          {showExpired() ? t("有効な証明書", "Valid Certs") : t("期限切れ表示", "Show Expired")}
        </button>
      </div>

      <div class="cc-legend">
        <span class="legend-item">
          <span class="ld root" /> {t("ルートCA", "Root CA")}
        </span>
        <span class="legend-item">
          <span class="ld intermediate" /> {t("中間CA", "Intermediate")}
        </span>
        <span class="legend-item">
          <span class="ld leaf" /> {t("リーフ", "Leaf")}
        </span>
      </div>

      <div class="cc-tree">
        {renderNode(chain(), 0)}
      </div>

      <div class="cc-info">
        <p class="cc-info-text">
          {t(
            "信頼チェーン: ブラウザはリーフ証明書 → 中間CA → ルートCAの順に署名を検証し、信頼を確立します。",
            "Trust chain: Browser verifies signatures from leaf → intermediate → root CA to establish trust."
          )}
        </p>
      </div>
    </div>
  );
}
