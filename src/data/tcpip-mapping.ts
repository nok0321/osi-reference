import type { TcpIpMapping, LayerNumber } from "../types";

export const TCPIP_MAPPINGS: TcpIpMapping[] = [
  {
    tcpIpLayer: "Application",
    tcpIpLayerJa: "アプリケーション層",
    osiLayers: [7, 6, 5],
    note: "Combines OSI L5-L7. Handles session management, data formatting, and application protocols in a single layer.",
    noteJa: "OSI L5-L7を統合。セッション管理、データ形式、アプリケーションプロトコルを一つの層で処理。",
  },
  {
    tcpIpLayer: "Transport",
    tcpIpLayerJa: "トランスポート層",
    osiLayers: [4],
    note: "Direct 1:1 mapping. TCP provides reliable streams; UDP provides fast datagrams.",
    noteJa: "OSI L4と1:1対応。TCPは信頼性のあるストリーム、UDPは高速なデータグラムを提供。",
  },
  {
    tcpIpLayer: "Internet",
    tcpIpLayerJa: "インターネット層",
    osiLayers: [3],
    note: "Direct 1:1 mapping. IP handles logical addressing and routing. Includes ICMP and IGMP.",
    noteJa: "OSI L3と1:1対応。IPが論理アドレッシングとルーティングを担当。ICMPやIGMPを含む。",
  },
  {
    tcpIpLayer: "Network Access",
    tcpIpLayerJa: "ネットワークアクセス層",
    osiLayers: [2, 1],
    note: "Combines OSI L1-L2. Handles physical transmission and data link framing as a single layer.",
    noteJa: "OSI L1-L2を統合。物理伝送とデータリンクフレーミングを一つの層で処理。",
  },
];

export interface ComparisonItem {
  aspect: string;
  aspectJa: string;
  osi: string;
  osiJa: string;
  tcpIp: string;
  tcpIpJa: string;
}

export const MODEL_COMPARISON: ComparisonItem[] = [
  {
    aspect: "Layers",
    aspectJa: "層数",
    osi: "7 layers",
    osiJa: "7層",
    tcpIp: "4 layers",
    tcpIpJa: "4層",
  },
  {
    aspect: "Approach",
    aspectJa: "アプローチ",
    osi: "Theoretical reference model",
    osiJa: "理論的参照モデル",
    tcpIp: "Practical protocol suite",
    tcpIpJa: "実用的プロトコルスイート",
  },
  {
    aspect: "Development",
    aspectJa: "策定",
    osi: "ISO (1984)",
    osiJa: "ISO (1984年)",
    tcpIp: "DARPA/DoD (1970s)",
    tcpIpJa: "DARPA/DoD (1970年代)",
  },
  {
    aspect: "Session/Presentation",
    aspectJa: "セッション/プレゼンテーション",
    osi: "Separate L5, L6",
    osiJa: "独立したL5, L6",
    tcpIp: "Merged into Application",
    tcpIpJa: "アプリケーション層に統合",
  },
  {
    aspect: "Usage",
    aspectJa: "使用状況",
    osi: "Education & reference",
    osiJa: "教育・参照用",
    tcpIp: "Real-world Internet",
    tcpIpJa: "実際のインターネット",
  },
  {
    aspect: "Protocols",
    aspectJa: "プロトコル定義",
    osi: "Model-independent",
    osiJa: "モデルに依存しない",
    tcpIp: "TCP, IP, UDP built-in",
    tcpIpJa: "TCP, IP, UDPが組み込み",
  },
];
