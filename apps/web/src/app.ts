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
import { getPlatformAuthInfo, isWebAuthnSupported } from "@homobio/webauthn";
import { MeraSessionManager, type MeraKeyRole, type MeraSessionKey, MERA_KEY_PRESETS } from "@homobio/sdk";
import { PrivyPasskeyProvider } from "@homobio/privy-adapter";
import { announce, mount, type VNode } from "./ui.js";
import { ICONS } from "./icons.js";
import { CameraController } from "./camera.js";
import { FlowController, isDemoBypassHost } from "./flows.js";

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
  platformAuth?: { webauthn: boolean; platformUv: boolean; conditionalMediation: boolean };
  authProvider: "privy" | "native";
  privyAppId: string;
  selectedMeraRole: MeraKeyRole;
  lastMeraTx?: { keyTitle: string; hash: string; gasSaved: string; durationMs: number; viaSessionKey: boolean };
  pipelineOpen: boolean;
  /** O1: full credential list for the picker plus the explicit per-credential pick. */
  credentials: Array<{ credentialId: string; label?: string; role?: string; transports?: string[]; lastUsedAt?: number }>;
  selectedCredentialId: string;
  /** O2: pending recovery request being cancelled or completed. */
  recoveryRequestId: string;
  recoveryExecutableAt: number;
  recoveryNewPasskeyHash: string;
  /** Demo bypass (recordings only): skips enrollment face gates. Localhost-only, default off. */
  demoBypass: boolean;
}

const STAGES: Array<{ stage: PipelineStage; label: string }> = [  { stage: "idle", label: "Idle" },
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

/** Demo bypass restores ON only from an explicit localhost opt-in. */
function readDemoBypass(): boolean {
  try {
    if (typeof window === "undefined") return false;
    if (!isDemoBypassHost(window.location.hostname)) return false;
    return window.localStorage.getItem("homobio.demo_bypass") === "1";
  } catch {
    return false;
  }
}

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
    pipelineOpen: false,
    credentials: [],
    selectedCredentialId: "",
    recoveryRequestId: "",
    recoveryExecutableAt: 0,
    recoveryNewPasskeyHash: "",
    demoBypass: readDemoBypass(),
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
        credentials: [],
        selectedCredentialId: "",
        notice: { kind: "error", text: "That doesn't look like an Ethereum address (0x followed by 40 hex characters)." },
      });
      return;
    }
    try {
      const response = await fetch(`/v1/wallet/${wallet}`);
      if (response.ok) {
        this.set({ account: await response.json() });
        this.rememberWallet();
        await this.refreshCredentials();
        return;
      }
      const body = (await response.json().catch(() => null)) as { error?: string } | null;
      if (response.status === 404 || body?.error === "account_not_found") {
        this.set({
          account: null,
          credentials: [],
          selectedCredentialId: "",
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

  /** O1: best-effort credential list for the picker. Failure leaves the old
   *  list alone so auth can still fall back to the discoverable ceremony. */
  async refreshCredentials(): Promise<void> {
    const wallet = this.state.wallet.trim();
    if (!/^0x[0-9a-fA-F]{40}$/.test(wallet)) {
      this.set({ credentials: [], selectedCredentialId: "" });
      return;
    }
    try {
      const response = await fetch(`/v1/wallet/${wallet}/credentials`);
      if (!response.ok) return;
      const body = await response.json();
      const list = Array.isArray(body.credentials) ? body.credentials : [];
      const stillThere =
        this.state.selectedCredentialId.length > 0 &&
        list.some((c: { credentialId: string }) => c.credentialId === this.state.selectedCredentialId);
      this.set({ credentials: list, selectedCredentialId: stillThere ? this.state.selectedCredentialId : "" });
    } catch {
      // Picker stays stale; the authenticate flow refetches before signing.
    }
  }

  /* --------------------------------- views ------------------------------- */

  render(): void {
    const vnode: VNode = {
      tag: "div",
      children: [
        this.masthead(),
        this.tabs(),
        {
          tag: "main",
          id: "main",
          children: [
            this.state.tab === "onboard" ? this.onboardView() : null,
            this.state.tab === "authenticate" ? this.authenticateView() : null,
            this.state.tab === "wallet" ? this.walletView() : null,
            this.state.tab === "mera" ? this.meraView() : null,
            this.state.tab === "diagnostics" ? this.diagnosticsView() : null,
            this.pipelineView(),
          ],
        },
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
      className: "masthead beam-frame",
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
                    { tag: "span", className: "hook shiny", text: "Nobody sees your face." },
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
            this.state.demoBypass
              ? {
                  tag: "span",
                  className: "badge warn",
                  text: "DEMO — face checks bypassed",
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
    const order = tabs.map(([id]) => id);
    const onKey = (id: AppState["tab"]) => (event: KeyboardEvent) => {
      const idx = order.indexOf(id);
      if (event.key !== "ArrowRight" && event.key !== "ArrowLeft" && event.key !== "Home" && event.key !== "End") return;
      event.preventDefault();
      let next = idx;
      if (event.key === "ArrowRight") next = (idx + 1) % order.length;
      if (event.key === "ArrowLeft") next = (idx - 1 + order.length) % order.length;
      if (event.key === "Home") next = 0;
      if (event.key === "End") next = order.length - 1;
      const nextId = order[next]!;
      this.set({ tab: nextId, failure: undefined });
      window.setTimeout(() => {
        document.querySelector<HTMLElement>(`[data-tab="${nextId}"]`)?.focus();
      }, 0);
    };
    return {
      tag: "div",
      className: "tabs",
      role: "tablist",
      ariaLabel: "Wallet sections",
      children: tabs.map(([id, step, label]) => ({
        tag: "button",
        role: "tab",
        id: `tab-${id}`,
        dataset: { tab: id },
        ariaSelected: this.state.tab === id ? "true" : "false",
        ariaControls: `panel-${id}`,
        tabIndex: this.state.tab === id ? "0" : "-1",
        onClick: () => this.set({ tab: id, failure: undefined }),
        onKeydown: onKey(id),
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
      className: "card consent-hero beam-card",
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
        {
          tag: "div",
          className: "trust-row",
          children: [
            { tag: "span", className: "badge ok", children: [{ tag: "span", className: "dot" }, "frames never leave"] },
            { tag: "span", className: "badge", text: "CKKS · N=8192" },
            { tag: "span", className: "badge", text: "ERC-4337" },
          ],
        },
      ],
    };
  }

  /** Onboarding stepper: passkey → face → spend. Derived from live account state. */
  private onboardSteps(): VNode {
    const devices = this.state.account?.devices ?? [];
    const enrolled = Boolean(this.state.account?.biometric?.enrolled);
    const passkeyDone = devices.length > 0;
    const steps = [
      { n: "1", label: "Passkey", done: passkeyDone, active: !passkeyDone },
      { n: "2", label: "Face", done: enrolled, active: passkeyDone && !enrolled },
      { n: "3", label: "Spend", done: Boolean(this.state.session), active: enrolled && !this.state.session },
    ];
    return {
      tag: "ol",
      className: "onboard-steps",
      ariaLabel: "Onboarding progress",
      children: steps.map((s) => ({
        tag: "li",
        dataset: { state: s.done ? "done" : s.active ? "active" : "pending" },
        children: [
          { tag: "span", className: "step-dot", children: s.done ? "✓" : s.n },
          { tag: "span", className: "step-label", text: s.label },
        ],
      })),
    };
  }

  private onboardView(): VNode {
    const account = this.state.account;
    const enrolled = Boolean(account?.biometric?.enrolled);
    const devices = account?.devices ?? [];

    return {
      tag: "div",
      className: "onboard",
      id: "panel-onboard",
      role: "tabpanel",
      ariaLabelledby: "tab-onboard",
      children: [
        this.viewHead(
          "Step 1 · Onboard",
          "Create your wallet",
          "One passkey becomes the key. Your face becomes the gate — encrypted before it ever leaves this device.",
        ),
        this.onboardSteps(),
        {
          tag: "div",
          className: "grid onboard-hero",
          children: [
            this.consentCard(),
            {
              tag: "section",
              className: "card wallet-cta",
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
                      autocomplete: "off",
                      inputmode: "text",
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
                      className: "primary btn-shimmer",
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
          ],
        },
        {
          tag: "div",
          className: "grid",
          children: [
            {
              tag: "section",
              className: "card",
              children: [
                ...this.cardHead(ICONS.shieldCheck, "Devices", "Passkeys"),
                { tag: "p", className: "hint", children: "Every passkey that can authorize this wallet." },
                devices.length === 0
                  ? {
                      tag: "div",
                      className: "empty-state",
                      children: [
                        { tag: "span", className: "empty-icon", html: ICONS.key },
                        { tag: "p", children: "No passkeys registered yet." },
                        { tag: "p", className: "hint", children: "Create one above — it takes ten seconds." },
                      ],
                    }
                  : {
                      tag: "ul",
                      className: "device-list",
                      children: devices.map((device: any) => ({
                        tag: "li",
                        className: "device-row",
                        children: [
                          {
                            tag: "div",
                            className: "device-meta",
                            children: [
                              { tag: "strong", children: device.label ?? "Passkey" },
                              {
                                tag: "p",
                                className: "hint",
                                children: `${device.role ?? "primary"} · ${short(device.credentialId)} · used ${timeAgo(device.lastUsedAt)}`,
                              },
                            ],
                          },
                          {
                            tag: "button",
                            className: "ghost device-revoke",
                            text: this.state.busy ? "Working…" : "Revoke",
                            disabled: this.state.busy,
                            ariaLabel: `Revoke ${device.label ?? "passkey"}`,
                            onClick: () => void this.flows.revokeCredential(device.credentialId),
                          },
                        ],
                      })),
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
                  : {
                      tag: "div",
                      className: "empty-state",
                      children: [
                        { tag: "span", className: "empty-icon", html: ICONS.fingerprint },
                        { tag: "p", children: "Not enrolled yet." },
                        { tag: "p", className: "hint", children: "Your face becomes math, then ciphertext — never a photo." },
                      ],
                    },
                {
                  tag: "div",
                  className: "row",
                  children: [
                    {
                      tag: "button",
                      className: "primary btn-shimmer",
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
            // Enrollment captures on this tab, so the preview must live here too:
            // the overlay carries the live capture feedback (samples, blockers).
            this.viewfinderCard(),
          ],
        },
      ],
    };
  }

  private authenticateView(): VNode {
    return {
      tag: "div",
      className: "grid auth-grid",
      id: "panel-authenticate",
      role: "tabpanel",
      ariaLabelledby: "tab-authenticate",
      children: [
        this.viewHead(
          "Step 2 · Authenticate",
          "Authorize a transaction",
          "Face, passkey and the exact operation — all three together, every single time.",
        ),
        {
          tag: "section",
          className: "card auth-card beam-card",
          children: [
            ...this.cardHead(ICONS.lock, "Authorize", "Authorize a transaction"),
            { tag: "p", className: "hint", children: "Face, passkey and the exact operation are all required." },
            this.credentialPicker(),
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
                  className: "primary btn-shimmer",
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

  /** O1: per-credential picker. With many credentials the OS account chooser
   *  is noisy, so the user picks one id up front and auth uses an allow-list
   *  for it; clearing the pick keeps the discoverable ceremony instead. */
  private credentialPicker(): VNode {
    const list = this.state.credentials.length > 0 ? this.state.credentials : (this.state.account?.devices ?? []);
    const selected = this.state.selectedCredentialId;
    if (list.length === 0) {
      return { tag: "p", className: "hint", children: "No passkeys found for this wallet yet." };
    }
    return {
      tag: "div",
      className: "field",
      children: [
        { tag: "label", children: `Which passkey signs (${list.length} registered)` },
        {
          tag: "ul",
          className: "device-list",
          children: list.map((c: { credentialId: string; label?: string }) => ({
            tag: "li",
            className: "device-row",
            dataset: { selected: selected === c.credentialId ? "true" : "false" },
            children: [
              {
                tag: "div",
                className: "device-meta",
                children: [
                  { tag: "strong", children: c.label ?? "Passkey" },
                  { tag: "p", className: "hint", children: short(c.credentialId) },
                ],
              },
              selected === c.credentialId
                ? { tag: "span", className: "badge ok", text: "Selected" }
                : {
                    tag: "button",
                    className: "ghost",
                    text: "Use this",
                    disabled: this.state.busy,
                    onClick: () => this.set({ selectedCredentialId: c.credentialId }),
                  },
            ],
          })),
        },
        list.length > 1 && selected.length > 0
          ? {
              tag: "button",
              className: "ghost",
              text: "Let the browser choose instead",
              onClick: () => this.set({ selectedCredentialId: "" }),
            }
          : null,
        list.length >= 6
          ? {
              tag: "p",
              className: "hint",
              children: "Many passkeys: picking one skips the crowded browser account chooser.",
            }
          : null,
      ],
    };
  }

  private viewfinderCard(): VNode {
    const live = this.camera.streaming;
    return {
      tag: "section",
      className: "card capture-card",
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
          dataset: { live: live ? "true" : "false" },
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
            { tag: "div", className: "face-oval", ariaHidden: "true" },
            live ? { tag: "span", className: "live-pill", children: [{ tag: "span", className: "dot" }, "LIVE"] } : null,
            {
              tag: "div",
              className: "overlay",
              children: this.state.livenessInstruction ?? "Camera idle",
            },
          ],
        },
        this.state.progress !== undefined
          ? {
              tag: "div",
              className: "capture-meter",
              children: [
                { tag: "progress", value: this.state.progress, max: 1, ariaLabel: "capture progress" },
                {
                  tag: "span",
                  className: "meter-label",
                  text: `${Math.round(this.state.progress * 7)}/7 samples`,
                },
              ],
            }
          : null,
        {
          tag: "div",
          className: "row",
          children: [
            {
              tag: "button",
              text: live ? "Stop camera" : "Start camera",
              onClick: () => void (live ? this.camera.stop() : this.camera.start()),
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
        this.recoveryCard(),
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

  /** O2: recovery cancel + complete. Starting only begins a timelocked
   *  request; cancel stops it and complete finishes it after the wait. */
  private recoveryCard(): VNode {
    const pending = this.state.account?.state === "RECOVERY";
    return {
      tag: "section",
      className: "card",
      children: [
        ...this.cardHead(ICONS.shieldCheck, "Recovery", "Account recovery"),
        {
          tag: "p",
          className: "hint",
          children: pending
            ? "Recovery is pending. Nothing moves until the waiting period ends. Cancel stops it; Complete finishes it after the wait."
            : "Lost every passkey? Start recovery to lock the wallet and begin the waiting period.",
        },
        {
          tag: "div",
          className: "field",
          children: [
            { tag: "label", for: "recovery-request", children: "Recovery request id" },
            {
              tag: "input",
              id: "recovery-request",
              value: this.state.recoveryRequestId,
              placeholder: "Returned when recovery starts",
              spellcheck: false,
              autocomplete: "off",
              onInput: (value: string) => {
                // Direct assignment, no re-render: same focus-preserving
                // pattern as the wallet address field above.
                this.state.recoveryRequestId = value.trim();
              },
            },
          ],
        },
        {
          tag: "div",
          className: "field",
          children: [
            { tag: "label", for: "recovery-new-passkey", children: "New passkey hash (needed to finish)" },
            {
              tag: "input",
              id: "recovery-new-passkey",
              value: this.state.recoveryNewPasskeyHash,
              placeholder: "0x followed by 64 hex characters",
              spellcheck: false,
              autocomplete: "off",
              onInput: (value: string) => {
                this.state.recoveryNewPasskeyHash = value.trim();
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
              text: "Start recovery",
              disabled: this.state.busy || !this.state.wallet,
              onClick: () => void this.flows.startRecovery(),
            },
            {
              tag: "button",
              className: "ghost",
              text: "Cancel recovery",
              disabled: this.state.busy || this.state.recoveryRequestId.length === 0,
              onClick: () => void this.flows.cancelRecovery(),
            },
            {
              tag: "button",
              className: "ghost",
              text: "Complete recovery",
              disabled: this.state.busy || this.state.recoveryRequestId.length === 0,
              onClick: () => void this.flows.completeRecovery(),
            },
          ],
        },
        this.state.recoveryExecutableAt > 0
          ? {
              tag: "p",
              className: "hint",
              children: `Cannot complete before ${new Date(this.state.recoveryExecutableAt * 1000).toLocaleString()}.`,
            }
          : null,
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
    const platform = this.state.platformAuth;
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
        {
          tag: "section",
          className: "card",
          children: [
            ...this.cardHead(ICONS.key, "Browser", "This browser"),
            {
              tag: "p",
              className: "hint",
              children: "Whether this browser can do a local passkey ceremony right now. If the platform row says no, the OS picker can only offer a phone or security key.",
            },
            platform
              ? stats([
                  ["WebAuthn", platform.webauthn ? "available" : "unavailable"],
                  ["Platform UV", platform.platformUv ? "available (Hello / Touch ID)" : "unavailable — no Hello PIN visible to the browser"],
                  ["Conditional mediation", platform.conditionalMediation ? "available" : "unavailable"],
                ])
              : { tag: "p", className: "hint", children: "Probing the browser…" },
            {
              tag: "ul",
              className: "notice-list",
              children: [
                {
                  tag: "li",
                  children:
                    "Passkeys stay in this browser profile. They will not appear in Incognito windows or other profiles — register a separate passkey there if you need one.",
                },
                {
                  tag: "li",
                  children:
                    "No this-device option in the sign-in picker usually means no Windows Hello PIN or fingerprint is set up. Add one in Windows Settings, then reopen this page.",
                },
              ],
            },
          ],
        },
        {
          tag: "section",
          className: "card",
          children: [
            ...this.cardHead(ICONS.bolt, "Demo mode", "Recordings only"),
            {
              tag: "p",
              className: "hint",
              children:
                "Skips the face-quality and liveness gates during enrollment so a recording never stalls on lighting or motion. Encryption and server enrollment stay fully real. Localhost only, off by default — never use for a real wallet.",
            },
            {
              tag: "div",
              className: "row",
              children: [
                {
                  tag: "button",
                  className: this.state.demoBypass ? "ghost" : "primary",
                  text: this.state.demoBypass ? "Turn demo bypass OFF" : "Bypass face checks for this recording",
                  onClick: () => this.toggleDemoBypass(),
                },
              ],
            },
            this.state.demoBypass
              ? {
                  tag: "p",
                  className: "hint",
                  children: "ON: enrollment accepts any visible face. The masthead badge stays up while it lasts.",
                }
              : null,
          ],
        },
        {
      tag: "section",
      className: "card",
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
        },
      ],
    };
  }

  private pipelineView(): VNode {
    const order = STAGES.map((s) => s.stage);
    const currentIndex = order.indexOf(this.state.stage);
    const doneCount = this.state.stage === "success" ? order.length : Math.max(0, currentIndex);
    const open = this.state.pipelineOpen || this.state.busy || Boolean(this.state.failure);
    const stageLabel = STAGES[currentIndex]?.label ?? "Idle";
    return {
      tag: "section",
      className: "card pipeline-card",
      children: [
        {
          tag: "div",
          className: "row between pipeline-head",
          children: [
            {
              tag: "div",
              children: [
                { tag: "p", className: "eyebrow", text: "Pipeline" },
                {
                  tag: "h2",
                  children: [
                    { tag: "span", className: "icon", html: ICONS.activity },
                    { tag: "span", text: `Authentication state · ${doneCount}/${order.length}` },
                  ],
                },
              ],
            },
            {
              tag: "button",
              className: "ghost pipeline-toggle",
              ariaExpanded: open ? "true" : "false",
              text: open ? "Hide steps" : `Show steps · ${stageLabel}`,
              onClick: () => this.set({ pipelineOpen: !open }),
            },
          ],
        },
        {
          tag: "div",
          className: "pipeline-progress",
          children: [{ tag: "progress", value: doneCount, max: order.length, ariaLabel: "authentication progress" }],
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
        open
          ? {
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

  /** Demo bypass toggle (Diagnostics card). Localhost-only, default off. */
  toggleDemoBypass(): void {
    if (this.state.demoBypass) {
      this.set({ demoBypass: false });
      try {
        localStorage.removeItem("homobio.demo_bypass");
      } catch {
        // Storage unavailable: in-memory state is already off.
      }
      return;
    }
    let local = false;
    try {
      local = typeof window !== "undefined" && isDemoBypassHost(window.location.hostname);
    } catch {
      local = false;
    }
    if (!local) {
      this.set({
        notice: {
          kind: "error",
          text: "Demo bypass is available on localhost only. It refuses to engage anywhere else.",
        },
      });
      return;
    }
    console.warn(
      "DEMO MODE ON: enrollment face-quality and liveness gates are bypassed. " +
        "Encryption + server enrollment stay real. Never use for real wallets.",
    );
    this.set({
      demoBypass: true,
      notice: {
        kind: "warn",
        text: "Demo bypass is ON: enrollment skips face checks on this machine only. Turn it off afterwards.",
      },
    });
    try {
      localStorage.setItem("homobio.demo_bypass", "1");
    } catch {
      // Storage unavailable: the in-memory flag still governs this session.
    }
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
      try {
        app.set({ platformAuth: await getPlatformAuthInfo() });
      } catch {
        app.set({ platformAuth: { webauthn: false, platformUv: false, conditionalMediation: false } });
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
