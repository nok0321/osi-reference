export type ViewType = "overview" | "encapsulation" | "scenario" | "comparison" | "auth" | "security";
export type LayerNumber = 1 | 2 | 3 | 4 | 5 | 6 | 7;
export type ScenarioType = "http" | "dns" | "tls" | "tls-deep";
export type EncapDirection = "down" | "up";

export interface OsiLayer {
  number: LayerNumber;
  name: string;
  nameJa: string;
  pdu: string;
  pduJa: string;
  role: string;
  roleJa: string;
  protocols: Protocol[];
  devices: string[];
  devicesJa: string[];
  color: string;
  headerFields?: HeaderField[];
}

export interface Protocol {
  name: string;
  description: string;
  descriptionJa: string;
  port?: number;
  layerNote?: string;
  layerNoteJa?: string;
}

export interface HeaderField {
  name: string;
  bits: number;
  description: string;
  descriptionJa: string;
}

export interface EncapStep {
  layerNumber: LayerNumber;
  action: "add-header" | "remove-header";
  headerName: string;
  headerBytes: number;
  description: string;
  descriptionJa: string;
  fields: HeaderField[];
  resultPdu: string;
  resultPduJa: string;
}

export interface ScenarioStep {
  stepNumber: number;
  layerNumber: LayerNumber;
  side: "sender" | "receiver" | "both";
  title: string;
  titleJa: string;
  description: string;
  descriptionJa: string;
  protocolAction: string;
  highlight: LayerNumber[];
}

export interface TcpIpMapping {
  tcpIpLayer: string;
  tcpIpLayerJa: string;
  osiLayers: LayerNumber[];
  note: string;
  noteJa: string;
}
