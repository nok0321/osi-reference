import type { Protocol, LayerNumber } from "../types";

/** Extended protocol details beyond what's in layers.ts */
export const PROTOCOL_DETAILS: Record<string, {
  fullName: string;
  fullNameJa: string;
  layer: LayerNumber;
  rfc?: string;
  securityNote?: string;
  securityNoteJa?: string;
}> = {
  "HTTP/HTTPS": {
    fullName: "HyperText Transfer Protocol (Secure)",
    fullNameJa: "ハイパーテキスト転送プロトコル（セキュア版）",
    layer: 7,
    rfc: "RFC 9110",
    securityNote: "HTTPS adds TLS encryption at L6",
    securityNoteJa: "HTTPSはL6でTLS暗号化を追加",
  },
  DNS: {
    fullName: "Domain Name System",
    fullNameJa: "ドメインネームシステム",
    layer: 7,
    rfc: "RFC 1035",
    securityNote: "DNS over HTTPS (DoH) / DNS over TLS (DoT) for privacy",
    securityNoteJa: "プライバシー保護にDoH/DoTを使用",
  },
  TCP: {
    fullName: "Transmission Control Protocol",
    fullNameJa: "伝送制御プロトコル",
    layer: 4,
    rfc: "RFC 9293",
    securityNote: "SYN flood attacks target the 3-way handshake",
    securityNoteJa: "SYNフラッド攻撃は3ウェイハンドシェイクを標的とする",
  },
  UDP: {
    fullName: "User Datagram Protocol",
    fullNameJa: "ユーザデータグラムプロトコル",
    layer: 4,
    rfc: "RFC 768",
    securityNote: "Used in amplification attacks (DNS, NTP)",
    securityNoteJa: "増幅攻撃（DNS, NTP）に悪用される",
  },
  "TLS/SSL": {
    fullName: "Transport Layer Security",
    fullNameJa: "トランスポート層セキュリティ",
    layer: 6,
    rfc: "RFC 8446 (TLS 1.3)",
    securityNote: "Foundation of HTTPS; certificate-based authentication",
    securityNoteJa: "HTTPSの基盤、証明書ベースの認証",
  },
  IPv4: {
    fullName: "Internet Protocol version 4",
    fullNameJa: "インターネットプロトコル バージョン4",
    layer: 3,
    rfc: "RFC 791",
    securityNote: "No built-in authentication; IPsec adds it",
    securityNoteJa: "認証機能なし、IPsecで追加",
  },
  "Ethernet (802.3)": {
    fullName: "IEEE 802.3 Ethernet",
    fullNameJa: "IEEE 802.3 イーサネット",
    layer: 2,
    securityNote: "ARP spoofing allows L2 MITM attacks",
    securityNoteJa: "ARPスプーフィングによるL2中間者攻撃",
  },
  QUIC: {
    fullName: "Quick UDP Internet Connections",
    fullNameJa: "QUIC（UDP上の高速接続）",
    layer: 4,
    rfc: "RFC 9000",
    securityNote: "Built-in TLS 1.3; encrypts transport headers",
    securityNoteJa: "TLS 1.3内蔵、トランスポートヘッダも暗号化",
  },
};
