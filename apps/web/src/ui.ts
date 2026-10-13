/**
 * Minimal view layer.
 *
 * A virtual-node renderer rather than a framework: the whole client is one
 * auditable bundle with no third-party runtime code, which is a supply-chain
 * decision as much as a size one (PRD section 29, compromised frontend).
 */

export type VChild = string | number | boolean | null | undefined | VNode;

export interface VNode {
  tag: string;
  className?: string;
  text?: string;
  children?: VChild | VChild[];
  onClick?: () => void;
  onInput?: (value: string) => void;
  onKeydown?: (event: KeyboardEvent) => void;
  dataset?: Record<string, string>;
  id?: string;
  role?: string;
  /** Any other HTML attribute; rendered verbatim as a string. */
  [attribute: string]: unknown;
}

const propertyMap: Record<string, string> = {
  className: "class",
  for: "htmlFor",
  spellcheck: "spellcheck",
  tabIndex: "tabindex",
  ariaLabel: "aria-label",
  ariaSelected: "aria-selected",
  ariaExpanded: "aria-expanded",
  ariaControls: "aria-controls",
  ariaLabelledby: "aria-labelledby",
  ariaHidden: "aria-hidden",
  autocomplete: "autocomplete",
  inputmode: "inputmode",
  playsInline: "playsinline",
  muted: "muted",
};

export function render(node: VNode | string | number): Node {
  if (typeof node !== "object" || node === null) return document.createTextNode(String(node));

  const element = document.createElement(node.tag);
  for (const [key, value] of Object.entries(node)) {
    if (key === "children" || key === "onClick" || key === "onInput" || key === "onKeydown" || key === "dataset") continue;
    if (value === undefined || value === null || value === false) continue;

    const attribute = propertyMap[key] ?? key;
    if (attribute === "value" && (element instanceof HTMLInputElement || element instanceof HTMLSelectElement)) {
      element.value = String(value);
      continue;
    }
    if (attribute === "max" && element instanceof HTMLProgressElement) {
      element.max = Number(value);
      continue;
    }
    if (key === "text") {
      element.textContent = String(value);
      continue;
    }
    // Trusted inline markup (icons). Only ever set from static strings in
    // `icons.ts` — never from network or user data.
    if (key === "html") {
      element.innerHTML = String(value);
      continue;
    }
    element.setAttribute(attribute, String(value));
  }

  if (node.dataset) {
    for (const [key, value] of Object.entries(node.dataset)) element.dataset[key] = value;
  }
  if (node.onClick) element.addEventListener("click", node.onClick);
  if (node.onKeydown) element.addEventListener("keydown", node.onKeydown as EventListener);
  if (node.onInput) {
    const handler = (event: Event) => {
      const target = event.target as HTMLInputElement | HTMLSelectElement | null;
      node.onInput?.(target?.value ?? "");
    };
    element.addEventListener("input", handler);
    element.addEventListener("change", handler);
  }

  for (const child of childrenOf(node)) {
    if (child === undefined || child === null || child === false) continue;
    element.appendChild(typeof child === "object" ? render(child) : document.createTextNode(String(child)));
  }
  return element;
}

function childrenOf(node: VNode): VChild[] {
  if (node.children === undefined || node.children === null) return [];
  return Array.isArray(node.children) ? node.children : [node.children];
}

/**
 * Replace a container's contents.
 *
 * Media elements are preserved across renders: recreating <video> would drop
 * the camera stream on every state change.
 */
export function mount(container: HTMLElement, node: VNode): void {
  // Preserve live media across renders, wherever they are nested: recreating
  // <video> would drop the camera stream on every state change (U1). Save the
  // stream bindings by id, then reattach them to the freshly rendered nodes.
  const streams = new Map<string, MediaProvider | null>();
  for (const child of Array.from(container.querySelectorAll("video, canvas"))) {
    if (child.id && child instanceof HTMLVideoElement) streams.set(child.id, child.srcObject);
  }
  const keep = new Map<string, Element>();
  for (const child of Array.from(container.querySelectorAll("video, canvas"))) {
    if (child.id) keep.set(child.id, child);
  }

  const build = (child: VChild): Node => {
    if (child === undefined || child === null || child === false) return document.createComment("");
    if (typeof child !== "object") return document.createTextNode(String(child));
    if (child.id && keep.has(child.id)) {
      const original = keep.get(child.id)!;
      keep.delete(child.id);
      return original;
    }
    return render(child);
  };

  const fragment = document.createDocumentFragment();
  for (const child of childrenOf(node)) fragment.appendChild(build(child));

  container.replaceChildren(fragment);
  // Reattach saved streams to the new elements with the same ids, so a
  // mid-capture progress render never starves the pipeline.
  for (const [id, srcObject] of streams) {
    const next = container.querySelector(`#${CSS.escape(id)}`);
    if (next instanceof HTMLVideoElement && srcObject) {
      if (next.srcObject !== srcObject) {
        next.srcObject = srcObject;
        next.play().catch(() => undefined);
      }
    }
  }
  container.setAttribute("aria-busy", "false");
}

/** Announce a message to assistive technology without stealing focus. */
export function announce(message: string): void {
  const region = document.getElementById("live-region");
  if (!region) return;
  region.textContent = "";
  window.setTimeout(() => {
    region.textContent = message;
  }, 30);
}
