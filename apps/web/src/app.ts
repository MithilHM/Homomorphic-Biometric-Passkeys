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
import { MeraSessionManager, type MeraKeyRole, type MeraSessionKey, MERA_KEY_PRESETS } from "@homobio/sdk";
import { PrivyPasskeyProvider } from "@homobio/privy-adapter";
import { announce, mount, type VNode } from "./ui.js";
import { ICONS } from "./icons.js";
import { CameraController } from "./camera.js";
import { FlowController } from "./flows.js";

interface AppState {
  stage: PipelineStage;
  tab: "onboard" | "authenticate" | "wallet" | "mera" | "diagnostics";
  wallet: string;
  config: any;
  account: any;
  failure?: FailureExplanation;
  notice?: { kind: "success" | "error" | "warn"; text: string };
  session?: any;
  livenessInstruction?: string;
  progress?: number;
  busy: boolean;
  authProvider: "privy" | "native";
  privyAppId: string;
  selectedMeraRole: MeraKeyRole;
  lastMeraTx?: { keyTitle: string; hash: string; gasSaved: string; durationMs: number; viaSessionKey: boolean };
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
    authProvider: "privy",
    privyAppId: "",
    selectedMeraRole: "trading",
  };

  readonly camera = new CameraController();
  readonly flows: FlowController;
  readonly mera = new MeraSessionManager();
  readonly privy = new PrivyPasskeyProvider();

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
    const wallet = this.state.wallet.trim();
    if (!wallet) return;
    if (!/^0x[0-9a-fA-F]{40}$/.test(wallet)) {
      this.set({
        account: null,
        notice: { kind: "error", text: "That doesn't look like an Ethereum address (0x followed by 40 hex characters)." },
      });
      return;
    }
    try {
      const response = await fetch(`/v1/wallet/${wallet}`);
      if (response.ok) {
        this.set({ account: await response.json() });
        this.rememberWallet();
        return;
      }
      const body = (await response.json().catch(() => null)) as { error?: string } | null;
      if (response.status === 404 || body?.error === "account_not_found") {
        this.set({
          account: null,
          notice: {
            kind: "warn",
            text: "No account exists for this address yet. Create a passkey above to register it — the wallet is created on first registration, not by pasting an address.",
          },
        });
      } else {
        this.set({
          account: null,
          notice: { kind: "error", text: `Could not load the wallet (${body?.error ?? response.status}).` },
        });
      }
    } catch {
      this.set({
        account: null,
        notice: { kind: "error", text: "Could not reach the gateway. Is the local stack still running?" },
      });
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
        this.state.tab === "mera" ? this.meraView() : null,
        this.state.tab === "diagnostics" ? this.diagnosticsView() : null,
        this.pipelineView(),
        this.footer(),
      ],
    };
    mount(this.root, vnode);
  }

  private masthead(): VNode {
    const config = this.state.config;
    const isPrivy = this.state.authProvider === "privy";
    const privyUser = isPrivy ? this.privy.getUser() : null;

    return {
      tag: "header",
      className: "masthead",
      children: [
        {
          tag: "div",
          className: "brand",
          children: [
            { tag: "span", className: "logo-mark", html: ICONS.scan },
            {
              tag: "div",
              children: [
                { tag: "div", className: "wordmark", children: ["homobio", { tag: "span", className: "slash", text: "/" }, "passkeys"] },
                {
                  tag: "h1",
                  children: [
                    "Your face unlocks your wallet. ",
                    { tag: "span", className: "hook", text: "Nobody sees your face." },
                  ],
                },
                {
                  tag: "div",
                  className: "chain-row",
                  children: config
                    ? [
                        { tag: "span", className: "badge ok", children: [{ tag: "span", className: "dot" }, `${config.chainName} · chain ${config.chainId}`] },
                        { tag: "span", className: "badge", text: `EntryPoint ${short(config.entryPoint)}` },
                        { tag: "span", className: "badge", text: `FHE ${config.fhe.engine} · N=${config.fhe.ringDimension}` },
                      ]
                    : [{ tag: "span", className: "badge", children: [{ tag: "span", className: "dot" }, "connecting…"] }],
                },
              ],
            },
          ],
        },
        {
          tag: "div",
          className: "row provider-bar",
          children: [
            {
              tag: "span",
              className: `badge ${isPrivy ? "privy" : "ok"}`,
              text: isPrivy ? "Privy Passkey (P-256 Enclave)" : "Native WebAuthn",
            },
            {
              tag: "button",
              className: "ghost provider-toggle-btn",
              text: isPrivy ? "Switch to Native" : "Switch to Privy",
              onClick: () => {
                const next = isPrivy ? "native" : "privy";
                this.set({ authProvider: next });
                localStorage.setItem("homobio.auth_provider", next);
              },
            },
            privyUser
              ? {
                  tag: "span",
                  className: "badge info",
                  text: `DID: ${short(privyUser.id)}`,
                }
              : null,
          ],
        },
      ],
    };
  }

  private tabs(): VNode {
    const tabs: Array<[AppState["tab"], string, string]> = [
      ["onboard", "1", "Create wallet"],
      ["authenticate", "2", "Authenticate"],
      ["wallet", "3", "Smart account"],
      ["mera", "4", "Mera (Many Keys)"],
      ["diagnostics", "✦", "Diagnostics"],
    ];
    return {
      tag: "div",
      className: "tabs",
      role: "tablist",
      children: tabs.map(([id, step, label]) => ({
        tag: "button",
        role: "tab",
        ariaSelected: this.state.tab === id ? "true" : "false",
        onClick: () => this.set({ tab: id, failure: undefined }),
        children: [
          { tag: "span", className: "step-num", text: step },
          { tag: "span", text: label },
        ],
      })),
    };
  }

  /* ------------------------------ card headers ---------------------------- */

  /** Eyebrow + icon heading shared by every card (marketing SectionHeading idiom). */
  private cardHead(icon: string, eyebrow: string, title: string): VNode[] {
    return [
      { tag: "p", className: "eyebrow", text: eyebrow },
      {
        tag: "h2",
        children: [
          { tag: "span", className: "icon", html: icon },
          { tag: "span", text: title },
        ],
      },
    ];
  }

  /** Section heading atop each tab view (marketing eyebrow + title + lede). */
  private viewHead(eyebrow: string, title: string, lede: string): VNode {
    return {
      tag: "div",
      className: "view-head",
      children: [
        { tag: "p", className: "eyebrow", text: eyebrow },
        { tag: "h2", className: "view-title", text: title },
        { tag: "p", className: "lede", text: lede },
      ],
    };
  }

  /** Copy-to-clipboard chip (marketing CopyButton idiom). */
  private copyButton(text: string): VNode {
    return {
      tag: "button",
      className: "ghost copy-btn",
      text: "Copy",
      ariaLabel: "Copy to clipboard",
      onClick: () => {
        const done = () => this.set({ notice: { kind: "success", text: "Copied to clipboard." } });
        if (navigator.clipboard?.writeText) navigator.clipboard.writeText(text).then(done).catch(done);
        else done();
      },
    };
  }

  private consentCard(): VNode {
    return {
      tag: "section",
      className: "card",
      children: [
        ...this.cardHead(ICONS.eyeOff, "Privacy", "What happens to your face"),
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
            { tag: "li", children: "Your passkey — not your face — is the cryptographic key to the wallet." },
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
        this.viewHead(
          "Step 1 · Onboard",
          "Create your wallet",
          "One passkey becomes the key. Your face becomes the gate — encrypted before it ever leaves this device.",
        ),
        this.consentCard(),
        {
          tag: "section",
          className: "card",
          children: [
            ...this.cardHead(ICONS.key, "Identity", "Wallet address"),
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
                  placeholder: "0x…",
                  spellcheck: false,
                  onInput: (value: string) => {
                    this.state.wallet = value.trim();
                    // No full re-render here: rebuilding the DOM mid-typing
                    // would drop input focus. Toggle the submit button directly;
                    // the next render derives the same state from scratch.
                    const btn = document.getElementById("use-existing");
                    if (btn instanceof HTMLButtonElement) btn.disabled = this.state.wallet.length === 0;
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
                  text: this.state.busy ? "Working…" : "Create passkey →",
                  disabled: this.state.busy || !isWebAuthnSupported(),
                  onClick: () => void this.flows.registerPasskey(),
                },
                {
                  tag: "button",
                  id: "use-existing",
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
            ...this.cardHead(ICONS.shieldCheck, "Devices", "Passkeys"),
            { tag: "p", className: "hint", children: "Every passkey that can authorize this wallet." },
            devices.length === 0
              ? { tag: "p", className: "hint", children: "No passkeys registered yet." }
              : {
                  tag: "dl",
                  className: "kv",
                  children: devices.flatMap((device: any) => [
                    { tag: "dt", children: device.label },
                    { tag: "dd", children: `${device.role} · ${short(device.credentialId)} · used ${timeAgo(device.lastUsedAt)}` },
                  ]),
                },
          ],
        },
        {
          tag: "section",
          className: "card",
          children: [
            ...this.cardHead(ICONS.fingerprint, "Biometrics", "Biometric template"),
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
                    { tag: "dd", children: `enrolled · v${account.biometric.templateVersion}` },
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
                  children: "Register a passkey first — recovery must exist before a biometric template is created.",
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
        this.viewHead(
          "Step 2 · Authenticate",
          "Authorize a transaction",
          "Face, passkey and the exact operation — all three together, every single time.",
        ),
        {
          tag: "section",
          className: "card",
          children: [
            ...this.cardHead(ICONS.lock, "Authorize", "Authorize a transaction"),
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
                  text: this.state.busy ? "Working…" : "Authenticate and submit →",
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
        ...this.cardHead(ICONS.camera, "Camera", "Capture"),
        {
          tag: "p",
          className: "hint",
          children: "Nothing here is uploaded. The overlay only reports what the local pipeline sees.",
        },
        {
          tag: "div",
          className: "viewfinder",
          dataset: { live: this.camera.streaming ? "true" : "false" },
          children: [
            {
              tag: "video",
              id: "camera-preview",
              muted: true,
              playsInline: true,
              ariaLabel: "Live camera preview",
            },
            { tag: "span", className: "corner tl" },
            { tag: "span", className: "corner tr" },
            { tag: "span", className: "corner bl" },
            { tag: "span", className: "corner br" },
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
          ...this.cardHead(ICONS.wallet, "Wallet", "No wallet loaded"),
          { tag: "p", className: "hint", children: "Load an address on the Create wallet tab to see its state." },
        ],
      };
    }
    return {
      tag: "div",
      className: "grid",
      children: [
        this.viewHead(
          "Step 3 · Smart account",
          "Account state",
          "Live on Monad testnet. Sessions are single-use, recovery is timelocked, and no seed phrase exists anywhere.",
        ),
        {
          tag: "section",
          className: "card",
          children: [
            ...this.cardHead(ICONS.wallet, "Wallet", "Account"),
            {
              tag: "dl",
              className: "kv",
              children: [
                { tag: "dt", children: "Address" },
                { tag: "dd", children: [account.wallet, this.copyButton(account.wallet)] },
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
                { tag: "dd", children: account.lockedUntil ? new Date(account.lockedUntil * 1000).toLocaleString() : "—" },
              ],
            },
          ],
        },
        {
          tag: "section",
          className: "card",
          children: [
            ...this.cardHead(ICONS.cpu, "Deployment", "Contract deployment"),
            {
              tag: "dl",
              className: "kv",
              children: [
                { tag: "dt", children: "Smart account" },
                { tag: "dd", children: [account.contract.address, this.copyButton(account.contract.address)] },
                { tag: "dt", children: "EntryPoint" },
                { tag: "dd", children: [account.contract.entryPoint, this.copyButton(account.contract.entryPoint)] },
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

  private meraView(): VNode {
    const keys = this.mera.listKeys();
    const presets = MERA_KEY_PRESETS;
    const selectedPreset = presets[this.state.selectedMeraRole] ?? presets.trading;

    return {
      tag: "div",
      className: "grid",
      children: [
        this.viewHead(
          "Step 4 · Mera",
          "One passkey, many keys",
          "Grant a scoped session key once — then transact instantly with zero face scans.",
        ),
        {
          tag: "section",
          className: "card mera-hero-card",
          children: [
            { tag: "p", className: "eyebrow", text: "Mera · One passkey, many keys" },
            {
              tag: "div",
              className: "row between",
              children: [
                { tag: "h2", children: "Monad Mera: One Passkey, Many Keys" },
                { tag: "span", className: "badge ok", text: "Monad EVM · ERC-4337 Session Keys" },
              ],
            },
            {
              tag: "p",
              className: "hint",
              children:
                "Demonstrating Monad Foundation's Mera architecture: One hardware passkey + homomorphic biometric template acts as the cryptographic root authority to issue and govern multiple specialized, ephemeral sub-keys (Trading, AI Agents, Gaming) without repetitive biometric prompts.",
            },
            {
              tag: "dl",
              className: "kv",
              children: [
                { tag: "dt", children: "Root Smart Account" },
                { tag: "dd", children: this.state.wallet || "Load address first" },
                { tag: "dt", children: "Root Authority" },
                {
                  tag: "dd",
                  children:
                    this.state.authProvider === "privy"
                      ? "Privy Hardware Passkey (P-256 Secure Enclave) + RLWE FHE Match"
                      : "Native WebAuthn + RLWE FHE Match",
                },
                { tag: "dt", children: "Session Protocol" },
                { tag: "dd", children: "MAGIC_SESSION (0x53 envelope) · Zero face scans needed" },
              ],
            },
          ],
        },
        {
          tag: "section",
          className: "card",
          children: [
            { tag: "p", className: "eyebrow", text: "Mera · Authorize" },
            { tag: "h2", children: "Authorize New Mera Sub-Key" },
            {
              tag: "p",
              className: "hint",
              children: "Requires root authorization (Privy passkey touch + FHE biometric scan) once to register on Monad.",
            },
            {
              tag: "div",
              className: "field",
              children: [
                { tag: "label", for: "mera-role-select", children: "Select Sub-Key Role Template" },
                {
                  tag: "select",
                  id: "mera-role-select",
                  value: this.state.selectedMeraRole,
                  onInput: (val: string) => {
                    this.set({ selectedMeraRole: val as MeraKeyRole });
                  },
                  children: [
                    { tag: "option", value: "trading", text: "⚡ High-Frequency Trading Key (DEX Swaps, 50 MON cap, 4h)" },
                    { tag: "option", value: "ai-agent", text: "🤖 Autonomous AI Agent Key (Agent Router, 5 MON cap, 24h)" },
                    { tag: "option", value: "gaming", text: "🎮 Instant Gaming Key (Micro-tx, 1 MON cap, 1h)" },
                  ],
                },
              ],
            },
            {
              tag: "div",
              className: "alert",
              children: [
                { tag: "strong", children: selectedPreset.title },
                { tag: "span", children: selectedPreset.description },
              ],
            },
            {
              tag: "div",
              className: "row",
              children: [
                {
                  tag: "button",
                  className: "primary",
                  text: this.state.busy ? "Authorizing on Monad…" : "🔑 Authorize Sub-Key (Passkey + Face Scan)",
                  disabled: this.state.busy || !this.state.wallet,
                  onClick: () => void this.flows.grantMeraKey(this.state.selectedMeraRole),
                },
              ],
            },
          ],
        },
        {
          tag: "section",
          className: "card mera-keys-list",
          children: [
            { tag: "p", className: "eyebrow", text: "Mera · Active keys" },
            { tag: "h2", children: `Active Sub-Keys (${keys.length})` },
            {
              tag: "p",
              className: "hint",
              children: "Once granted on-chain, transactions signed by these keys execute instantly with 0 face scans.",
            },
            keys.length === 0
              ? { tag: "p", className: "hint", children: "No sub-keys generated yet. Authorize a key above to test 'One Passkey, Many Keys'." }
              : {
                  tag: "div",
                  className: "key-cards-list",
                  children: keys.map((key) => ({
                    tag: "div",
                    className: "card subkey-item",
                    children: [
                      {
                        tag: "div",
                        className: "row between",
                        children: [
                          { tag: "strong", children: key.title },
                          {
                            tag: "span",
                            className: `badge ${key.status === "active" ? "ok" : "bad"}`,
                            text: key.status.toUpperCase(),
                          },
                        ],
                      },
                      {
                        tag: "dl",
                        className: "kv",
                        children: [
                          { tag: "dt", children: "Key Address" },
                          { tag: "dd", children: short(key.address) },
                          { tag: "dt", children: "Valid Until" },
                          { tag: "dd", children: new Date(key.validUntil * 1000).toLocaleTimeString() },
                          { tag: "dt", children: "Limit per Tx" },
                          { tag: "dd", children: `${(Number(key.maxValuePerTxWei) / 1e18).toFixed(1)} MON` },
                          { tag: "dt", children: "Executions" },
                          { tag: "dd", children: `${key.txCount} txs` },
                        ],
                      },
                      {
                        tag: "div",
                        className: "row",
                        children: [
                          {
                            tag: "button",
                            className: "primary",
                            text: this.state.busy ? "Executing…" : "⚡ Instant Execute (0x53 Envelope)",
                            disabled: this.state.busy || key.status !== "active",
                            onClick: () => void this.flows.executeWithMeraKey(key.id),
                          },
                          {
                            tag: "button",
                            className: "ghost",
                            text: "Revoke",
                            disabled: this.state.busy || key.status !== "active",
                            onClick: () => this.flows.revokeMeraKey(key.id),
                          },
                        ],
                      },
                    ],
                  })),
                },
          ],
        },
        this.state.lastMeraTx
          ? {
              tag: "section",
              className: "card mera-receipt-card",
              children: [
                {
                  tag: "div",
                  className: "row between",
                  children: [
                    { tag: "h2", children: "⚡ Sub-Key Execution Verified on Monad" },
                    { tag: "span", className: "badge ok", text: "Zero Biometric Scans" },
                  ],
                },
                {
                  tag: "dl",
                  className: "kv",
                  children: [
                    { tag: "dt", children: "Key Used" },
                    { tag: "dd", children: this.state.lastMeraTx.keyTitle },
                    { tag: "dt", children: "UserOp Hash" },
                    { tag: "dd", children: [this.state.lastMeraTx.hash, this.copyButton(this.state.lastMeraTx.hash)] },
                    { tag: "dt", children: "Execution Mode" },
                    { tag: "dd", children: "0x53 MAGIC_SESSION envelope" },
                    { tag: "dt", children: "Execution Latency" },
                    { tag: "dd", children: `${this.state.lastMeraTx.durationMs}ms (Instant)` },
                    { tag: "dt", children: "Biometric Overhead Saved" },
                    { tag: "dd", children: "100% saved (no webcam capture or FHE encryption needed)" },
                    { tag: "dt", children: "Gas Saved" },
                    { tag: "dd", children: this.state.lastMeraTx.gasSaved },
                  ],
                },
              ],
            }
          : null,
      ],
    };
  }

  private diagnosticsView(): VNode {
    const config = this.state.config;
    const stats = (entries: Array<[string, string]>): VNode => ({
      tag: "dl",
      className: "stats",
      children: entries.map(([label, value]) => ({
        tag: "div",
        className: "stat",
        children: [
          { tag: "dt", children: label },
          { tag: "dd", children: value },
        ],
      })),
    });
    return {
      tag: "div",
      className: "grid",
      children: [
        this.viewHead(
          "Diagnostics",
          "Live parameters",
          "Exactly what the running stack is using — committee, FHE parameters, EntryPoint. Not defaults.",
        ),
        {
          tag: "section",
          className: "card",
          children: [
            ...this.cardHead(ICONS.activity, "Diagnostics", "Cryptographic parameters in use"),
            { tag: "p", className: "hint", children: "These are the exact values the running system is using, not defaults." },
            config
              ? stats([
                  ["FHE engine", config.fhe.engine ?? "unavailable"],
                  ["Ring dimension", String(config.fhe.ringDimension ?? "—")],
                  ["Modulus", String(config.fhe.modulus ?? "—")],
                  ["Fixed-point scale", `2^${config.fhe.scaleBits ?? "—"}`],
                  ["Embedding dim", String(config.model.embeddingDimension)],
                  ["Model", config.model.modelVersion],
                  ["Key fingerprint", short(config.fhe.fingerprint ?? "—")],
                  ["Error bound", String(config.fhe.errorBound ?? "—")],
                  ["Decision program", short(config.decisionProgramHash)],
                  ["Committee", short(config.committeeAddress ?? "—")],
                ])
              : { tag: "p", className: "hint", children: "Gateway configuration is not loaded yet." },
          ],
        },
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
        ...this.cardHead(ICONS.activity, "Pipeline", "Authentication state"),
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
                { tag: "span", className: "mark", children: state === "done" ? "✓" : state === "active" ? "▸" : "·" },
                { tag: "span", children: entry.label },
              ],
            };
          }),
        },
        this.state.livenessInstruction
          ? {
              tag: "div",
              className: "alert info liveness-banner",
              role: "status",
              children: [
                { tag: "strong", children: "Do this now" },
                { tag: "span", children: this.state.livenessInstruction },
              ],
            }
          : null,
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
      tag: "footer",
      className: "footer",
      children: [
        {
          tag: "span",
          children: "Passkey = cryptographic authority. Biometric match = authorization factor. Neither alone can spend from this wallet.",
        },
        { tag: "span", className: "mono", text: "homobio/passkeys · Monad chain 143" },
      ],
    };
  }

  /* ------------------------------- persistence --------------------------- */

  private restore(): void {
    const saved = localStorage.getItem("homobio.wallet");
    if (saved) this.state.wallet = saved;
    const provider = localStorage.getItem("homobio.auth_provider") as "privy" | "native" | null;
    if (provider) this.state.authProvider = provider;
    const appId = localStorage.getItem("homobio.privy_app_id");
    if (appId) {
      this.state.privyAppId = appId;
      this.privy.setAppId(appId);
    }
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
  if (!value) return "—";
  return value.length > 18 ? `${value.slice(0, 10)}…${value.slice(-6)}` : value;
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
