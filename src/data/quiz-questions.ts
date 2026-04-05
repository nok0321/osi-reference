import type { ViewType } from "../types";

export interface QuizQuestion {
  id: string;
  question: string;
  questionJa: string;
  options: Array<{ text: string; textJa: string }>;
  correctIndex: number;
  explanation: string;
  explanationJa: string;
  view: ViewType;
}

export const QUIZ_QUESTIONS: QuizQuestion[] = [
  // Overview
  {
    id: "q1", view: "overview",
    question: "Which OSI layer handles routing between networks?",
    questionJa: "ネットワーク間のルーティングを担当するOSI層はどれですか？",
    options: [
      { text: "Layer 2 - Data Link", textJa: "第2層 - データリンク" },
      { text: "Layer 3 - Network", textJa: "第3層 - ネットワーク" },
      { text: "Layer 4 - Transport", textJa: "第4層 - トランスポート" },
      { text: "Layer 5 - Session", textJa: "第5層 - セッション" },
    ],
    correctIndex: 1,
    explanation: "The Network layer (L3) handles logical addressing (IP) and routing packets between different networks.",
    explanationJa: "ネットワーク層(L3)は論理アドレッシング(IP)と異なるネットワーク間のパケットルーティングを担当します。",
  },
  {
    id: "q2", view: "overview",
    question: "What is the PDU (Protocol Data Unit) at Layer 4?",
    questionJa: "第4層のPDU（プロトコルデータユニット）は何ですか？",
    options: [
      { text: "Frame", textJa: "フレーム" },
      { text: "Packet", textJa: "パケット" },
      { text: "Segment", textJa: "セグメント" },
      { text: "Bits", textJa: "ビット" },
    ],
    correctIndex: 2,
    explanation: "Layer 4 (Transport) uses Segments (TCP) or Datagrams (UDP) as its PDU.",
    explanationJa: "第4層(トランスポート)はセグメント(TCP)またはデータグラム(UDP)をPDUとして使用します。",
  },
  // Auth
  {
    id: "q3", view: "auth",
    question: "In OAuth 2.0, what is exchanged for tokens in step 6?",
    questionJa: "OAuth 2.0のステップ6で、トークンと交換されるものは何ですか？",
    options: [
      { text: "Username and password", textJa: "ユーザー名とパスワード" },
      { text: "Authorization code", textJa: "認可コード" },
      { text: "Client ID only", textJa: "クライアントIDのみ" },
      { text: "Refresh token", textJa: "リフレッシュトークン" },
    ],
    correctIndex: 1,
    explanation: "The client exchanges the short-lived authorization code for access and refresh tokens.",
    explanationJa: "クライアントは短命の認可コードをアクセストークンとリフレッシュトークンに交換します。",
  },
  {
    id: "q4", view: "auth",
    question: "What algorithm does TLS 1.3 use for key exchange?",
    questionJa: "TLS 1.3が鍵交換に使用するアルゴリズムは何ですか？",
    options: [
      { text: "RSA key exchange", textJa: "RSA鍵交換" },
      { text: "Diffie-Hellman (DHE)", textJa: "Diffie-Hellman (DHE)" },
      { text: "ECDHE (Elliptic Curve DH)", textJa: "ECDHE (楕円曲線DH)" },
      { text: "Pre-shared key only", textJa: "事前共有鍵のみ" },
    ],
    correctIndex: 2,
    explanation: "TLS 1.3 mandates ECDHE or DHE for forward secrecy. RSA key exchange was removed.",
    explanationJa: "TLS 1.3は前方秘匿性のためにECDHEまたはDHEを義務付けています。RSA鍵交換は廃止されました。",
  },
  // Security
  {
    id: "q5", view: "security",
    question: "Which attack operates at OSI Layer 2?",
    questionJa: "OSI第2層で動作する攻撃はどれですか？",
    options: [
      { text: "SQL Injection", textJa: "SQLインジェクション" },
      { text: "ARP Spoofing", textJa: "ARPスプーフィング" },
      { text: "SYN Flood", textJa: "SYNフラッド" },
      { text: "IP Spoofing", textJa: "IPスプーフィング" },
    ],
    correctIndex: 1,
    explanation: "ARP Spoofing operates at Layer 2 (Data Link) by forging ARP replies to intercept traffic.",
    explanationJa: "ARPスプーフィングは第2層(データリンク)で偽のARP応答を送信してトラフィックを傍受します。",
  },
  {
    id: "q6", view: "scenario",
    question: "How many RTTs does a TLS 1.3 handshake require (after TCP)?",
    questionJa: "TLS 1.3ハンドシェイクに必要なRTT数は（TCP後）？",
    options: [
      { text: "0-RTT", textJa: "0-RTT" },
      { text: "1-RTT", textJa: "1-RTT" },
      { text: "2-RTT", textJa: "2-RTT" },
      { text: "3-RTT", textJa: "3-RTT" },
    ],
    correctIndex: 1,
    explanation: "TLS 1.3 achieves 1-RTT handshake by sending the key share in ClientHello upfront.",
    explanationJa: "TLS 1.3はClientHelloで鍵共有を先行送信することで1-RTTハンドシェイクを実現します。",
  },
];

export function getQuizByView(view: ViewType): QuizQuestion[] {
  return QUIZ_QUESTIONS.filter(q => q.view === view);
}
