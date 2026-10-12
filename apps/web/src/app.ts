/**
 * Web client.
 *
 * Camera frames never leave this file's scope: the pipeline produces a
 * quantized embedding, the embedding is encrypted in the browser, and only the
 * ciphertext is sent (PRD P1). The UI mirrors the PRD's state machine exactly,
 * including the failure states, because "explicit failure instead of a silent
 * fallback to weaker authentication" is a product requirement, not a nicety.
 */

import {
  explainFailure,
  type FailureExplanation,
  type PipelineStage,
} from "@homobio/biometric-client";
import { isWebAuthnSupported } from "@homobio/webauthn";
import { announce, mount, type VNode } from "./ui.js";
import { CameraController } from "./camera.js";
import { FlowController } from "./flows.js";

interface AppState {
  stage: PipelineStage;
  tab: "onboard" | "authenticate" | "wallet" | "diagnostics";
  wallet: string;
  config: any;
  account: any;
  failure?: FailureExplanation;
  notice?: { kind: "success" | "error" | "warn"; text: string };
  session?: any;
  livenessInstruction?: string;
  progress?: number;
  busy: boolean;
}

const STAGES: Array<{ stage: PipelineStage; label: string }> = [
  { stage: "idle", label: "Idle" },
  { stage: "request_permission", label: "Camera permission" },
  { stage: "camera_ready", label: "Camera ready" },
  { stage: "face_detected", label: "Face detected" },
  { stage: "liveness_challenge", label: "Liveness challenge" },
  { stage: "face_quality_ok", label: "Capture quality" },
  { stage: "embedding_generated", label: "Embedding created" },
  { stage: "encrypting", label: "Encrypting (CKKS-compatible)" },
  { stage: "passkey_prompt", label: "Passkey confirmation" },
  { stage: "processing", label: "Encrypted comparison" },
  { stage: "proof_ready", label: "Authorization ready" },
  { stage: "submitting", label: "Submitting" },
  { stage: "success", label: "Complete" },
];

export class App {
  readonly state: AppState = {
    stage: "idle",
    tab: "onboard",
    wallet: "",
    config: null,
    account: null,
    busy: false,
  };

  readonly camera = new CameraController();
  readonly flows: FlowController;

  constructor(private readonly root: HTMLElement) {
    this.flows = new FlowController(this);
    this.restore();
  }

  /* --------------------------------- state ------------------------------- */

  set(patch: Partial<AppState>): void {
    Object.assign(this.state, patch);
    this.render();
    if (patch.failure) announce(`${patch.failure.title}. ${patch.failure.detail}`);
  }

  setStage(stage: PipelineStage, patch: Partial<AppState> = {}): void {
    this.set({ stage, ...patch });
  }

  fail(code: Parameters<typeof explainFailure>[0], detail?: string): void {
    this.set({ failure: explainFailure(code, detail), busy: false });
  }

  clearFailure(): void {
    this.set({ failure: undefined });
  }

  async refresh(): Promise<void> {
    if (!this.state.wallet) return;
    try {
      const response = await fetch(`/v1/wallet/${this.state.wallet}`);
      this.set({ account: response.ok ? await response.json() : null });
    } catch {
      this.set({ account: null });
    }
  }

  /* --------------------------------- views ------------------------------- */

  render(): void {
    const vnode: VNode = {
      tag: "div",
      children: [
        this.masthead(),
        this.tabs(),
        this.state.tab === "onboard" ? this.onboardView() : null,
        this.state.tab === "authenticate" ? this.authenticateView() : null,
        this.state.tab === "wallet" ? this.walletView() : null,
        this.state.tab === "diagnostics" ? this.diagnosticsView() : null,
        this.pipelineView(),
        this.footer(),
      ],
    };
    mount(this.root, vnode);
  }

  private masthead(): VNode {
    const config = this.state.config;
    return {
      tag: "header",
      className: "masthead",
      children: [
        { tag: "h1", children: "Homomorphic Biometric Passkeys" },
        {
          tag: "span",
          className: "chain",
          children: config
            ? `${config.chainName} Â· chain ${config.chainId} Â· EntryPoint ${short(config.entryPoint)}`
            : "connectingâ€¦",
        },
      ],
    };
  }

  private tabs(): VNode {
    const tabs: Array<[AppState["tab"], string]> = [
      ["onboard", "1 Â· Create wallet"],
      ["authenticate", "2 Â· Authenticate"],
      ["wallet", "3 Â· Wallet"],
      ["diagnostics", "Diagnostics"],
    ];
    return {
      tag: "div",
      className: "tabs",
      role: "tablist",
      children: tabs.map(([id, label]) => ({
        tag: "button",
        role: "tab",
        ariaSelected: this.state.tab === id ? "true" : "false",
        text: label,
        onClick: () => this.set({ tab: id, failure: undefined }),
      })),
    };
  }

  private consentCard(): VNode {
    return {
      tag: "section",
      className: "card",
      children: [
        { tag: "h2", children: "What happens to your face" },
        {
          tag: "p",
          className: "hint",
          children: "Read this before you start. It is the whole privacy story, and it is short on purpose.",
        },
        {
          tag: "ul",
          className: "notice-list",
          children: [
            { tag: "li", children: "Camera frames stay on this device and are discarded after each capture." },
            { tag: "li", children: "Your face is turned into a numeric vector locally, then encrypted before upload." },
            { tag: "li", children: "The backend compares encrypted vectors and never receives the plaintext." },
            { tag: "li", children: "Your passkey â€” not your face â€” is the cryptographic key to the wallet." },
            { tag: "li", children: "A decision needs your face, your passkey and the exact transaction, all together." },
          ],
        },
      ],
    };
  }

  private onboardView(): VNode {
    const account = this.state.account;
    const enrolled = Boolean(account?.biometric?.enrolled);
    const devices = account?.devices ?? [];

    return {
      tag: "div",
      className: "grid",
      children: [
        this.consentCard(),
        {
          tag: "section",
          className: "card",
          children: [
            { tag: "h2", children: "Wallet address" },
            { tag: "p", className: "hint", children: "Derived from your passkey. No seed phrase exists anywhere." },
            {
              tag: "div",
              className: "field",
              children: [
                { tag: "label", for: "wallet", children: "Smart account address" },
                {
                  tag: "input",
                  id: "wallet",
                  value: this.state.wallet,
                  placeholder: "0xâ€¦",
                  spellcheck: false,
                  onInput: (value: string) => {
                    this.state.wallet = value.trim();
                  },
                },
              ],
            },
            {
              tag: "div",
              className: "row",
              children: [
                {
                  tag: "button",
                  className: "primary",
                  text: this.state.busy ? "Workingâ€¦" : "Create passkey",
                  disabled: this.state.busy || !isWebAuthnSupported(),
                  onClick: () => void this.flows.registerPasskey(),
                },
                {
                  tag: "button",
                  className: "ghost",
                  text: "Use an existing address",
                  disabled: this.state.busy || this.state.wallet.length === 0,
                  onClick: () => void this.refresh(),
                },
              ],
            },
            !isWebAuthnSupported()
              ? {
                  tag: "div",
                  className: "alert error",
                  children: [
                    { tag: "strong", children: "Passkeys are not supported" },
                    {
                      tag: "span",
                      children:
                        "Use a recent Chrome, Safari, Edge or Firefox on a device with a screen lock. This is required: the passkey is the wallet's signing key.",
                    },
                  ],
                }
              : null,
          ],
        },
        {
          tag: "section",
          className: "card",
          children: [
            { tag: "h2", children: "Devices" },
            { tag: "p", className: "hint", children: "Every passkey that can authorize this wallet." },
            devices.length === 0
              ? { tag: "p", className: "hint", children: "No passkeys registered yet." }
              : {
                  tag: "dl",
                  className: "kv",
                  children: devices.flatMap((device: any) => [
                    { tag: "dt", children: device.label },
                    { tag: "dd", children: `${device.role} Â· ${short(device.credentialId)} Â· used ${timeAgo(device.lastUsedAt)}` },
                  ]),
                },
          ],
        },
        {
          tag: "section",
          className: "card",
          children: [
            { tag: "h2", children: "Biometric template" },
            {
              tag: "p",
              className: "hint",
              children: "Stored encrypted. Only the commitment is ever recorded on-chain.",
            },
            enrolled
              ? {
                  tag: "dl",
                  className: "kv",
                  children: [
                    { tag: "dt", children: "Status" },
                    { tag: "dd", children: `enrolled Â· v${account.biometric.templateVersion}` },
                    { tag: "dt", children: "Model" },
                    { tag: "dd", children: account.biometric.modelVersion },
                    { tag: "dt", children: "FHE key version" },
                    { tag: "dd", children: String(account.biometric.fheKeyVersion) },
                    { tag: "dt", children: "Commitment" },
                    { tag: "dd", children: short(account.biometric.commitment) },
                  ],
                }
              : { tag: "p", className: "hint", children: "Not enrolled yet." },
            {
              tag: "div",
              className: "row",
              children: [
                {
                  tag: "button",
                  className: "primary",
                  text: enrolled ? "Re-enroll face" : "Enroll face",
                  disabled: this.state.busy || devices.length === 0,
                  onClick: () => {
                    this.set({ tab: "onboard" });
                    void this.flows.enrollBiometric();
                  },
                },
                {
                  tag: "button",
                  className: "ghost",
                  text: "Recovery options",
                  onClick: () => void this.flows.startRecovery(),
                },
              ],
            },
            devices.length === 0
              ? {
                  tag: "p",
                  className: "hint",
                  children: "Register a passkey first â€” recovery must exist before a biometric template is created.",
                }
              : null,
          ],
        },
      ],
    };
  }

  private authenticateView(): VNode {
    return {
      tag: "div",
      className: "grid",
      children: [
        {
          tag: "section",
          className: "card",
          children: [
            { tag: "h2", children: "Authorize a transaction" },
            { tag: "p", className: "hint", children: "Face, passkey and the exact operation are all required." },
            {
              tag: "div",
              className: "field",
              children: [
                { tag: "label", for: "recipient", children: "Recipient address" },
                {
                  tag: "input",
                  id: "recipient",
                  value: "0x000000000000000000000000000000000000dEaD",
                  spellcheck: false,
                  onInput: () => undefined,
                },
              ],
            },
            {
              tag: "div",
              className: "row",
              children: [
                {
                  tag: "button",
                  className: "primary",
                  text: this.state.busy ? "Workingâ€¦" : "Authenticate and submit",
                  disabled: this.state.busy || !this.state.wallet,
                  onClick: () => void this.flows.authenticate(),
                },
                {
                  tag: "button",
                  className: "ghost",
                  text: "Replay the last authorization",
                  disabled: this.state.busy || !this.state.session,
                  onClick: () => void this.flows.replayLastAuthorization(),
                },
                {
                  tag: "button",
                  className: "ghost",
                  text: "Tamper with the recipient",
                  disabled: this.state.busy || !this.state.session,
                  onClick: () => void this.flows.tamperWithOperation(),
                },
              ],
            },
          ],
        },
        this.viewfinderCard(),
      ],
    };
  }

  private viewfinderCard(): VNode {
    return {
      tag: "section",
      className: "card",
      children: [
        { tag: "h2", children: "Camera" },
        {
          tag: "p",
          className: "hint",
          children: "Nothing here is uploaded. The overlay only reports what the local pipeline sees.",
        },
        {
          tag: "div",
          className: "viewfinder",
          children: [
            {
              tag: "video",
              id: "camera-preview",
              muted: true,
              playsInline: true,
              ariaLabel: "Live camera preview",
            },
            {
              tag: "div",
              className: "overlay",
              children: this.state.livenessInstruction ?? "Camera idle",
            },
          ],
        },
        this.state.progress !== undefined
          ? { tag: "progress", value: this.state.progress, max: 1, ariaLabel: "capture progress" }
          : null,
        {
          tag: "div",
          className: "row",
          children: [
            {
              tag: "button",
              text: this.camera.streaming ? "Stop camera" : "Start camera",
              onClick: () => void (this.camera.streaming ? this.camera.stop() : this.camera.start()),
            },
            {
              tag: "button",
              className: "ghost",
              text: "Simulate capture (no camera)",
              disabled: this.state.busy,
              onClick: () => void this.flows.simulateCapture(),
            },
          ],
        },
      ],
    };
  }

  private walletView(): VNode {
    const account = this.state.account;
    if (!account) {
      return {
        tag: "section",
        className: "card",
        children: [
          { tag: "h2", children: "Wallet" },
          { tag: "p", className: "hint", children: "Load an address on the Create wallet tab to see its state." },
        ],
      };
    }
    return {
      tag: "div",
      className: "grid",
      children: [
        {
          tag: "section",
          className: "card",
          children: [
            { tag: "h2", children: "Account" },
            {
              tag: "dl",
              className: "kv",
              children: [
                { tag: "dt", children: "Address" },
                { tag: "dd", children: account.wallet },
                { tag: "dt", children: "State" },
                { tag: "dd", children: stateBadge(account.state) },
                { tag: "dt", children: "Policy" },
                { tag: "dd", children: account.policyId },
                { tag: "dt", children: "Failed attempts" },
                { tag: "dd", children: String(account.failedAttempts) },
                {
                  tag: "dt",
                  children: "Locked until",
                },
                { tag: "dd", children: account.lockedUntil ? new Date(account.lockedUntil * 1000).toLocaleString() : "â€”" },
              ],
            },
          ],
        },
        {
          tag: "section",
          className: "card",
          children: [
            { tag: "h2", children: "Contract deployment" },
            {
              tag: "dl",
              className: "kv",
              children: [
                { tag: "dt", children: "Smart account" },
                { tag: "dd", children: account.contract.address },
                { tag: "dt", children: "EntryPoint" },
                { tag: "dd", children: account.contract.entryPoint },
                { tag: "dt", children: "Factory" },
                { tag: "dd", children: account.contract.factory ?? "not deployed in this environment" },
                { tag: "dt", children: "Verifier" },
                { tag: "dd", children: account.contract.verifier ?? "not deployed in this environment" },
              ],
            },
          ],
        },
      ],
    };
  }

  private diagnosticsView(): VNode {
    const config = this.state.config;
    return {
      tag: "section",
      className: "card",
      children: [
        { tag: "h2", children: "Cryptographic parameters in use" },
        { tag: "p", className: "hint", children: "These are the exact values the running system is using, not defaults." },
        config
          ? {
              tag: "dl",
              className: "kv",
              children: [
                { tag: "dt", children: "FHE engine" },
                { tag: "dd", children: config.fhe.engine ?? "unavailable" },
                { tag: "dt", children: "Ring dimension" },
                { tag: "dd", children: String(config.fhe.ringDimension ?? "â€”") },
                { tag: "dt", children: "Modulus" },
                { tag: "dd", children: String(config.fhe.modulus ?? "â€”") },
                { tag: "dt", children: "Fixed-point scale" },
                { tag: "dd", children: `2^${config.fhe.scaleBits ?? "â€”"}` },
                { tag: "dt", children: "Embedding dimension" },
                { tag: "dd", children: String(config.model.embeddingDimension) },
                { tag: "dt", children: "Model version" },
                { tag: "dd", children: config.model.modelVersion },
                { tag: "dt", children: "Key fingerprint" },
                { tag: "dd", children: String(config.fhe.fingerprint ?? "â€”") },
                { tag: "dt", children: "Error bound" },
                { tag: "dd", children: String(config.fhe.errorBound ?? "â€”") },
                { tag: "dt", children: "Decision program" },
                { tag: "dd", children: short(config.decisionProgramHash) },
                { tag: "dt", children: "Attestation committee" },
                { tag: "dd", children: config.committeeAddress ?? "â€”" },
              ],
            }
          : { tag: "p", className: "hint", children: "Gateway configuration is not loaded yet." },
      ],
    };
  }

  private pipelineView(): VNode {
    const order = STAGES.map((s) => s.stage);
    const currentIndex = order.indexOf(this.state.stage);
    return {
      tag: "section",
      className: "card",
      children: [
        { tag: "h2", children: "Authentication state" },
        {
          tag: "ol",
          className: "pipeline",
          children: STAGES.map((entry, index) => {
            const state =
              this.state.stage === "success" || index < currentIndex
                ? "done"
                : entry.stage === this.state.stage
                  ? "active"
                  : "pending";
            return {
              tag: "li",
              dataset: { state },
              children: [
                { tag: "span", className: "mark", children: state === "done" ? "âœ“" : state === "active" ? "â–¸" : "Â·" },
                { tag: "span", children: entry.label },
              ],
            };
          }),
        },
        this.state.notice
          ? {
              tag: "div",
              className: `alert ${this.state.notice.kind}`,
              children: [
                { tag: "strong", children: this.state.notice.kind === "success" ? "Done" : this.state.notice.kind === "error" ? "Problem" : "Heads up" },
                { tag: "span", children: this.state.notice.text },
              ],
            }
          : null,
        this.state.failure
          ? {
              tag: "div",
              className: "alert error",
              role: "alert",
              children: [
                { tag: "strong", children: this.state.failure.title },
                { tag: "span", children: this.state.failure.detail },
                { tag: "p", children: this.state.failure.action },
                {
                  tag: "div",
                  className: "row",
                  children: [
                    {
                      tag: "button",
                      className: "ghost",
                      text: "Dismiss",
                      onClick: () => this.clearFailure(),
                    },
                  ],
                },
              ],
            }
          : null,
      ],
    };
  }

  private footer(): VNode {
    return {
      tag: "p",
      className: "footer",
      children:
        "Passkey = cryptographic authority. Biometric match = authorization factor. Neither alone can spend from this wallet.",
    };
  }

  /* ------------------------------- persistence --------------------------- */

  private restore(): void {
    const saved = localStorage.getItem("homobio.wallet");
    if (saved) this.state.wallet = saved;
  }

  rememberWallet(): void {
    if (this.state.wallet) localStorage.setItem("homobio.wallet", this.state.wallet);
  }

  static create(root: HTMLElement): App {
    const app = new App(root);
    void (async () => {
      try {
        const response = await fetch("/v1/config");
        app.set({ config: await response.json() });
      } catch {
        app.set({ notice: { kind: "error", text: "Could not load the gateway configuration." } });
      }
      await app.refresh();
      app.render();
    })();
    return app;
  }
}

/* -------------------------------------------------------------------------- */

function short(value: string): string {
  if (!value) return "â€”";
  return value.length > 18 ? `${value.slice(0, 10)}â€¦${value.slice(-6)}` : value;
}

function stateBadge(state: string): VNode {
  const kind = state === "ACTIVE" ? "ok" : state === "LOCKED" || state === "REVOKED" ? "bad" : state === "RECOVERY" ? "warn" : "idle";
  return { tag: "span", className: `badge ${kind}`, text: `${state}` };
}

function timeAgo(seconds: number): string {
  if (!seconds) return "never";
  const delta = Math.max(0, Math.floor(Date.now() / 1000) - seconds);
  if (delta < 60) return `${delta}s ago`;
  if (delta < 3600) return `${Math.floor(delta / 60)}m ago`;
  return `${Math.floor(delta / 3600)}h ago`;
}
