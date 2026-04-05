import type { EncapStep, HeaderField } from "../types";

const tcpFields: HeaderField[] = [
  { name: "Source Port", bits: 16, description: "Sender port number (e.g., 49152)", descriptionJa: "送信元ポート番号 (例: 49152)" },
  { name: "Destination Port", bits: 16, description: "Receiver port number (e.g., 80)", descriptionJa: "宛先ポート番号 (例: 80)" },
  { name: "Sequence Number", bits: 32, description: "Byte stream position", descriptionJa: "バイトストリーム位置" },
  { name: "Acknowledgment", bits: 32, description: "Next expected byte", descriptionJa: "次に期待するバイト" },
  { name: "Data Offset", bits: 4, description: "Header length in 32-bit words", descriptionJa: "ヘッダ長 (32ビット単位)" },
  { name: "Flags", bits: 6, description: "SYN, ACK, FIN, RST, PSH, URG", descriptionJa: "SYN, ACK, FIN, RST, PSH, URG" },
  { name: "Window Size", bits: 16, description: "Flow control window", descriptionJa: "フロー制御ウィンドウ" },
  { name: "Checksum", bits: 16, description: "Error detection", descriptionJa: "エラー検出" },
];

const ipFields: HeaderField[] = [
  { name: "Version", bits: 4, description: "IP version (4)", descriptionJa: "IPバージョン (4)" },
  { name: "IHL", bits: 4, description: "Header length in 32-bit words", descriptionJa: "ヘッダ長 (32ビット単位)" },
  { name: "Total Length", bits: 16, description: "Total packet length in bytes", descriptionJa: "パケット全長 (バイト)" },
  { name: "TTL", bits: 8, description: "Time To Live / hop limit", descriptionJa: "生存時間 / ホップ制限" },
  { name: "Protocol", bits: 8, description: "Upper protocol (TCP=6, UDP=17)", descriptionJa: "上位プロトコル (TCP=6, UDP=17)" },
  { name: "Source IP", bits: 32, description: "Sender IP address", descriptionJa: "送信元IPアドレス" },
  { name: "Destination IP", bits: 32, description: "Receiver IP address", descriptionJa: "宛先IPアドレス" },
  { name: "Header Checksum", bits: 16, description: "Header error detection", descriptionJa: "ヘッダエラー検出" },
];

const ethernetFields: HeaderField[] = [
  { name: "Preamble", bits: 56, description: "Synchronization pattern", descriptionJa: "同期パターン" },
  { name: "SFD", bits: 8, description: "Start Frame Delimiter", descriptionJa: "フレーム開始デリミタ" },
  { name: "Dest MAC", bits: 48, description: "Destination MAC address", descriptionJa: "宛先MACアドレス" },
  { name: "Source MAC", bits: 48, description: "Source MAC address", descriptionJa: "送信元MACアドレス" },
  { name: "EtherType", bits: 16, description: "Upper protocol (0x0800 = IPv4)", descriptionJa: "上位プロトコル (0x0800 = IPv4)" },
  { name: "FCS", bits: 32, description: "Frame Check Sequence (trailer)", descriptionJa: "フレームチェックシーケンス (トレーラ)" },
];

export const ENCAP_STEPS_DOWN: EncapStep[] = [
  {
    layerNumber: 7,
    action: "add-header",
    headerName: "Application Data",
    headerBytes: 0,
    description: "User data created at the application layer (e.g., HTTP request body)",
    descriptionJa: "アプリケーション層でユーザデータを生成 (例: HTTPリクエストボディ)",
    fields: [
      { name: "HTTP Method", bits: 0, description: "GET, POST, PUT, DELETE, etc.", descriptionJa: "GET, POST, PUT, DELETE等" },
      { name: "Headers", bits: 0, description: "Host, Content-Type, Authorization, etc.", descriptionJa: "Host, Content-Type, Authorization等" },
      { name: "Body", bits: 0, description: "Request/response payload", descriptionJa: "リクエスト/レスポンスのペイロード" },
    ],
    resultPdu: "Data",
    resultPduJa: "データ",
  },
  {
    layerNumber: 4,
    action: "add-header",
    headerName: "TCP Header",
    headerBytes: 20,
    description: "Transport layer adds TCP header for reliable, ordered delivery with port multiplexing",
    descriptionJa: "トランスポート層がTCPヘッダを追加し、信頼性のある順序付き配送とポート多重化を実現",
    fields: tcpFields,
    resultPdu: "Segment",
    resultPduJa: "セグメント",
  },
  {
    layerNumber: 3,
    action: "add-header",
    headerName: "IP Header",
    headerBytes: 20,
    description: "Network layer adds IP header for logical addressing and routing between networks",
    descriptionJa: "ネットワーク層がIPヘッダを追加し、論理アドレッシングとネットワーク間ルーティングを実現",
    fields: ipFields,
    resultPdu: "Packet",
    resultPduJa: "パケット",
  },
  {
    layerNumber: 2,
    action: "add-header",
    headerName: "Ethernet Header + Trailer",
    headerBytes: 26,
    description: "Data link layer adds Ethernet frame header (14B) and FCS trailer (4B) for node-to-node transfer",
    descriptionJa: "データリンク層がEthernetフレームヘッダ(14B)とFCSトレーラ(4B)を追加し、ノード間転送を実現",
    fields: ethernetFields,
    resultPdu: "Frame",
    resultPduJa: "フレーム",
  },
  {
    layerNumber: 1,
    action: "add-header",
    headerName: "Physical Encoding",
    headerBytes: 0,
    description: "Physical layer converts frame into electrical signals, light pulses, or radio waves for transmission",
    descriptionJa: "物理層がフレームを電気信号、光パルス、電波に変換して伝送",
    fields: [
      { name: "Encoding", bits: 0, description: "Manchester, 4B/5B, 8B/10B, etc.", descriptionJa: "マンチェスタ、4B/5B、8B/10B等" },
      { name: "Signaling", bits: 0, description: "Voltage levels, light intensity, frequency", descriptionJa: "電圧レベル、光強度、周波数" },
    ],
    resultPdu: "Bits",
    resultPduJa: "ビット",
  },
];

export const ENCAP_STEPS_UP: EncapStep[] = ENCAP_STEPS_DOWN.slice().reverse().map(step => ({
  ...step,
  action: "remove-header" as const,
  description: step.description.replace("adds", "removes").replace("converts", "receives"),
  descriptionJa: step.descriptionJa.replace("追加", "除去").replace("変換", "受信"),
}));
