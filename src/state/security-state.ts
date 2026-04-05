import { createSignal } from "solid-js";
import type { LayerNumber } from "../types";

// Auth view state
export const [oauthStep, setOauthStep] = createSignal(0);
export const [jwtActiveSection, setJwtActiveSection] = createSignal<"header" | "payload" | "signature" | null>(null);
export const [tlsDeepStep, setTlsDeepStep] = createSignal(0);

// Security dashboard state
export const [packetFlowRunning, setPacketFlowRunning] = createSignal(false);
export const [selectedAttackLayer, setSelectedAttackLayer] = createSignal<LayerNumber | null>(null);
export const [firewallFilterLayer, setFirewallFilterLayer] = createSignal<LayerNumber | null>(null);
export const [selectedCertNode, setSelectedCertNode] = createSignal<string | null>(null);
