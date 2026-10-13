"""Structural checks on the Kubernetes manifests.

`kubectl --dry-run` needs a live cluster to fetch the OpenAPI schema, which is
not available in most local environments. These assertions catch the mistakes
that actually happen when hand-writing manifests: a missing securityContext, an
egress rule with `from`, a container with no resource limits.

Run: python infra/k8s/validate.py
"""

import sys
import yaml

FAILURES: list[str] = []


def fail(message: str) -> None:
    FAILURES.append(message)


def load(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as handle:
        return [doc for doc in yaml.safe_load_all(handle) if doc]


def check_network_policies(docs: list[dict]) -> None:
    for doc in docs:
        if doc.get("kind") != "NetworkPolicy":
            continue
        name = doc["metadata"]["name"]
        spec = doc.get("spec", {})
        for direction, wrong, right in (
            ("ingress", "to", "from"),
            ("egress", "from", "to"),
        ):
            for rule in spec.get(direction) or []:
                if wrong in rule:
                    fail(f"NetworkPolicy/{name}: {direction} rule uses `{wrong}`; only `{right}` is valid")
        # An empty podSelector is exactly how "deny everything" is spelled.
        if "podSelector" not in spec:
            fail(f"NetworkPolicy/{name}: no podSelector")


def check_workloads(docs: list[dict]) -> None:
    workload_kinds = {"Deployment", "StatefulSet", "DaemonSet", "Job"}
    names: set[str] = set()

    for doc in docs:
        if doc.get("kind") not in workload_kinds:
            continue
        workload = doc["metadata"]["name"]
        pod_spec = doc["spec"]["template"]["spec"]

        pod_labels = doc["spec"]["template"]["metadata"].get("labels", {})
        names.add(pod_labels.get("app.kubernetes.io/name", workload))

        if not pod_spec.get("serviceAccountName"):
            fail(f"{workload}: no serviceAccountName")

        pod_sc = pod_spec.get("securityContext") or {}
        if pod_sc.get("runAsNonRoot") is not True:
            fail(f"{workload}: runAsNonRoot is not true")
        if pod_sc.get("seccompProfile", {}).get("type") != "RuntimeDefault":
            fail(f"{workload}: seccompProfile is not RuntimeDefault")

        for container in pod_spec["containers"]:
            cname = container["name"]
            where = f"{workload}/{cname}"

            if not container.get("resources", {}).get("limits"):
                fail(f"{where}: no resource limits")
            if not container.get("resources", {}).get("requests"):
                fail(f"{where}: no resource requests")

            sc = container.get("securityContext") or {}
            if sc.get("allowPrivilegeEscalation") is not False:
                fail(f"{where}: allowPrivilegeEscalation is not false")
            if sc.get("readOnlyRootFilesystem") is not True:
                fail(f"{where}: readOnlyRootFilesystem is not true")
            if "ALL" not in (sc.get("capabilities") or {}).get("drop", []):
                fail(f"{where}: capabilities are not dropped")

            if not container.get("livenessProbe"):
                fail(f"{where}: no livenessProbe")
            if not container.get("startupProbe"):
                fail(f"{where}: no startupProbe")

            for env in container.get("env", []):
                value = str(env.get("value", ""))
                if "REPLACE_ME" in value:
                    fail(f"{where}: env {env['name']} is still a placeholder")

            # A secret must come from secretKeyRef, never an inline value.
            if env.get("name", "").endswith(("TOKEN", "SECRET", "PEM")) and "value" in env:
                fail(f"{where}: secret {env['name']} is set inline")

    print(f"workloads checked: {sorted(names)}")


def check_service_selectors(docs: list[dict]) -> None:
    """Every Service selector must match some workload's pod labels."""
    selectors = [
        (d["metadata"]["name"], d["spec"].get("selector", {}))
        for d in docs
        if d.get("kind") == "Service"
    ]
    pod_label_sets = [
        d["spec"]["template"]["metadata"].get("labels", {})
        for d in docs
        if d.get("kind") in {"Deployment", "StatefulSet", "DaemonSet"}
    ]

    for name, selector in selectors:
        if not selector:
            fail(f"Service/{name}: no selector")
            continue
        if not any(all(labels.get(k) == v for k, v in selector.items()) for labels in pod_label_sets):
            fail(f"Service/{name}: selector {selector} matches no workload")

    print(f"services checked: {[n for n, _ in selectors]}")


def check_no_public_coprocessor(docs: list[dict]) -> None:
    """The FHE coprocessor must never be reachable from outside the cluster."""
    for doc in docs:
        if doc.get("kind") != "Service":
            continue
        if doc["metadata"]["name"] != "fhe-coprocessor":
            continue
        stype = doc["spec"].get("type", "ClusterIP")
        if stype != "ClusterIP":
            fail(f"Service/fhe-coprocessor: type is {stype}; it must be ClusterIP")


def check_singleton_gateway(docs: list[dict]) -> None:
    """The challenge/session store is in-process: a second gateway replica
    believes consumed challenges are unspent (replay protection diverges), and
    a minAvailable: 1 PDB on one replica only hangs node drains. So the
    gateway must stay exactly one replica with no HPA and no PDB."""
    for doc in docs:
        if doc.get("kind") == "Deployment" and doc["metadata"]["name"] == "gateway":
            if doc["spec"].get("replicas", 1) != 1:
                fail("Deployment/gateway: replicas must be 1 until the store is externalised")
        if doc.get("kind") == "HorizontalPodAutoscaler":
            target = (doc.get("spec", {}).get("scaleTargetRef", {}) or {}).get("name", "")
            if target == "gateway":
                fail("HorizontalPodAutoscaler scales the singleton gateway; remove it")
        if doc.get("kind") == "PodDisruptionBudget":
            selector = (doc.get("spec", {}).get("selector", {}) or {}).get("matchLabels", {})
            if selector.get("app.kubernetes.io/name") == "gateway":
                fail("PodDisruptionBudget selects the singleton gateway; remove it")


def check_overlay() -> None:
    """The production overlay must contribute exactly the TLS ingress (and no
    HPA/PDB resurrected beside it). Extra YAML documents appended to a
    kustomization.yaml are silently ignored by kustomize, so the ingress must
    live in its own file listed under `resources`."""
    with open("infra/k8s/overlays/production/kustomization.yaml", encoding="utf-8") as handle:
        overlay = yaml.safe_load(handle)
    resources = overlay.get("resources", [])
    if "../../base" not in resources:
        fail("overlay kustomization does not include ../../base")
    if "ingress.yaml" not in resources:
        fail("overlay kustomization does not include ingress.yaml")
    with open("infra/k8s/overlays/production/ingress.yaml", encoding="utf-8") as handle:
        ingress = yaml.safe_load(handle)
    if ingress.get("kind") != "Ingress":
        fail("overlay ingress.yaml is not an Ingress")
    tls_hosts = [h for t in (ingress.get("spec", {}).get("tls", {}) or []) for h in (t.get("hosts", []) or [])]
    if not tls_hosts:
        fail("overlay Ingress has no TLS hosts; WebAuthn requires a secure context")


def main() -> int:
    docs = load("infra/k8s/base/base.yaml")
    print(f"loaded {len(docs)} documents from infra/k8s/base/base.yaml")

    check_network_policies(docs)
    check_workloads(docs)
    check_service_selectors(docs)
    check_no_public_coprocessor(docs)
    check_singleton_gateway(docs)
    check_overlay()

    if FAILURES:
        print(f"\n{len(FAILURES)} violation(s):")
        for failure in FAILURES:
            print(f"  - {failure}")
        return 1

    print("\nall manifest checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())