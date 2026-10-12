# Kubernetes resources for the Homomorphic Biometric Passkeys tier.
#
# Applied with `terraform apply`. The Solidity contracts are NOT deployed here:
# deploying to Monad testnet needs a funded deployer key, and the deployment
# order matters (registry -> verifier -> factory). Use the scripts in
# `infra/terraform/scripts/` for that, and record the addresses back here.

# ---------------------------------------------------------------------------
# Namespace and service accounts
# ---------------------------------------------------------------------------

resource "kubernetes_namespace" "homobio" {
  metadata {
    name   = "${var.project}-${var.environment}"
    labels = local.common_labels
  }
}

# The coprocessor never talks to the Kubernetes API.
resource "kubernetes_service_account" "coprocessor" {
  metadata {
    name      = "fhe-coprocessor"
    namespace = kubernetes_namespace.homobio.metadata[0].name
    labels    = local.common_labels
  }
  automount_service_account_token = false
}

resource "kubernetes_service_account" "gateway" {
  metadata {
    name      = "gateway"
    namespace = kubernetes_namespace.homobio.metadata[0].name
    labels    = local.common_labels
  }
  automount_service_account_token = false
}

# ---------------------------------------------------------------------------
# Configuration
#
# Secrets (FHE_SERVICE_TOKEN, CUSTODY_UNLOCK_SECRET,
# PROOF_SERVICE_SECRET_PEM) are intentionally NOT created here. Anything in the
# Terraform state is readable by anyone with state access. Use an external
# secrets manager and pre-create the Secret it writes.
# ---------------------------------------------------------------------------

resource "kubernetes_config_map" "config" {
  metadata {
    name      = "${var.project}-config"
    namespace = kubernetes_namespace.homobio.metadata[0].name
    labels    = local.common_labels
  }

  data = local.config
}

# ---------------------------------------------------------------------------
# Key material volume
#
# Holds the FHE key set and committee shares 0 and 1. Encrypted at rest, and
# backed up: losing it orphans every enrolled template irreversibly.
# ---------------------------------------------------------------------------

resource "kubernetes_persistent_volume_claim" "key_material" {
  metadata {
    name      = "fhe-key-material"
    namespace = kubernetes_namespace.homobio.metadata[0].name
    labels    = local.common_labels
  }

  spec {
    access_modes = ["ReadWriteOnce"]
    resources {
      requests = {
        storage = "${var.key_material_gib}Gi"
      }
    }
  }
}

# ---------------------------------------------------------------------------
# FHE coprocessor
#
# One replica by design: the key set lives on its volume, and two writers would
# generate divergent key material. Scaling the decision path horizontally is not
# yet supported by the threshold protocol.
# ---------------------------------------------------------------------------

resource "kubernetes_service" "coprocessor" {
  metadata {
    name      = "fhe-coprocessor"
    namespace = kubernetes_namespace.homobio.metadata[0].name
    labels    = local.common_labels
  }

  spec {
    selector = { "app.kubernetes.io/name" = "fhe-coprocessor" }
    port {
      name        = "http"
      port        = 5001
      target_port = "http"
    }
    # ClusterIP only: the coprocessor has no public ingress path.
    type = "ClusterIP"
  }
}

resource "kubernetes_deployment" "coprocessor" {
  metadata {
    name      = "fhe-coprocessor"
    namespace = kubernetes_namespace.homobio.metadata[0].name
    labels    = local.common_labels
  }

  spec {
    replicas = 1
    strategy {
      type = "Recreate"
    }
    selector {
      match_labels = { "app.kubernetes.io/name" = "fhe-coprocessor" }
    }

    template {
      metadata {
        labels = { "app.kubernetes.io/name" = "fhe-coprocessor" }
      }

      spec {
        service_account_name            = kubernetes_service_account.coprocessor.name
        automount_service_account_token = false

        security_context {
          run_as_non_root = true
          run_as_user     = 1000
          fs_group        = 1000
          seccomp_profile {
            type = "RuntimeDefault"
          }
        }

        container {
          name              = "coprocessor"
          image             = var.coprocessor_image
          image_pull_policy = "IfNotPresent"

          port {
            name           = "http"
            container_port = 5001
          }

          env = [
            { name = "FHE_PORT", value = "5001" },
            { name = "HOMOBIO_DATA_DIR", value = "/app/.data" },
          ]

          env_from {
            config_map_ref {
              name = kubernetes_config_map.config.metadata[0].name
            }
          }

          volume_mount {
            name       = "key-material"
            mount_path = "/app/.data"
          }

          # Startup probe, not liveness: a restart mid-key-generation must not
          # thrash. Liveness only engages once the process is up.
          startup_probe {
            http_get {
              path = "/health"
              port = "http"
            }
            period_seconds    = 2
            failure_threshold = 30
          }

          liveness_probe {
            http_get {
              path = "/health"
              port = "http"
            }
            period_seconds = 20
            timeout_seconds = 5
          }

          resources {
            requests = {
              cpu    = "2"
              memory = "2Gi"
            }
            limits = {
              cpu    = "8"
              memory = "8Gi"
            }
          }

          security_context {
            allow_privilege_escalation = false
            read_only_root_filesystem   = true
            capabilities {
              drop = ["ALL"]
            }
          }
        }

        volume {
          name = "key-material"
          persistent_volume_claim {
            claim_name = kubernetes_persistent_volume_claim.key_material.metadata[0].name
          }
        }
      }
    }
  }
}

# ---------------------------------------------------------------------------
# Gateway
# ---------------------------------------------------------------------------

resource "kubernetes_service" "gateway" {
  metadata {
    name      = "gateway"
    namespace = kubernetes_namespace.homobio.metadata[0].name
    labels    = local.common_labels
  }

  spec {
    selector = { "app.kubernetes.io/name" = "gateway" }
    port {
      name        = "http"
      port        = 5000
      target_port = "http"
    }
    type = "ClusterIP"
  }
}

resource "kubernetes_deployment" "gateway" {
  metadata {
    name      = "gateway"
    namespace = kubernetes_namespace.homobio.metadata[0].name
    labels    = local.common_labels
  }

  spec {
    # The challenge store is in-process. Two replicas would each believe an
    # already-consumed challenge was unspent, so this stays at 1 until the
    # store is externalised. See docs/threat-model.md.
    replicas = 1

    selector {
      match_labels = { "app.kubernetes.io/name" = "gateway" }
    }

    strategy {
      type = "RollingUpdate"
      rolling_update {
        max_surge       = 0
        max_unavailable = 1
      }
    }

    template {
      metadata {
        labels = { "app.kubernetes.io/name" = "gateway" }
      }

      spec {
        service_account_name            = kubernetes_service_account.gateway.name
        automount_service_account_token = false

        security_context {
          run_as_non_root = true
          run_as_user     = 1000
          fs_group        = 1000
          seccomp_profile {
            type = "RuntimeDefault"
          }
        }

        container {
          name              = "gateway"
          image             = var.gateway_image
          image_pull_policy = "IfNotPresent"

          port {
            name           = "http"
            container_port = 5000
          }

          env = [
            { name = "PORT", value = "5000" },
            { name = "HOMOBIO_DATA_DIR", value = "/app/.data" },
            { name = "FHE_SERVICE_URL", value = "http://fhe-coprocessor:5001" },
          ]

          # Only non-secret configuration comes from the ConfigMap.
          env_from {
            config_map_ref {
              name = kubernetes_config_map.config.metadata[0].name
            }
          }

          # Secrets are referenced, never created here.
          dynamic "env" {
            for_each = [
              "FHE_SERVICE_TOKEN",
              "CUSTODY_UNLOCK_SECRET",
              "CUSTODY_UNLOCK_ON_BOOT",
              "PROOF_SERVICE_SECRET_PEM",
              "WEBAUTHN_RP_ID",
              "WEBAUTHN_ORIGIN",
              "ALLOWED_ORIGINS",
              "ACCOUNT_FACTORY_ADDRESS",
              "AUTHORIZATION_VERIFIER_ADDRESS",
              "PROOF_VERIFIER_REGISTRY_ADDRESS",
            ]
            content {
              name = env.value
              value_from {
                secret_key_ref {
                  name = local.secret_name
                  key  = env.value
                }
              }
            }
          }

          volume_mount {
            name   = "tmp"
            mount_path = "/tmp"
          }

          startup_probe {
            http_get {
              path = "/v1/health"
              port = "http"
            }
            period_seconds    = 2
            failure_threshold = 30
          }

          readiness_probe {
            http_get {
              path = "/v1/health"
              port = "http"
            }
            period_seconds = 10
            timeout_seconds = 5
          }

          liveness_probe {
            http_get {
              path = "/v1/health"
              port = "http"
            }
            period_seconds  = 20
            timeout_seconds = 5
          }

          resources {
            requests = {
              cpu    = "500m"
              memory = "512Mi"
            }
            limits = {
              cpu    = "2"
              memory = "2Gi"
            }
          }

          security_context {
            allow_privilege_escalation = false
            read_only_root_filesystem   = true
            capabilities {
              drop = ["ALL"]
            }
          }
        }

        volume {
          name = "tmp"
          empty_dir {}
        }
      }
    }
  }
}

# ---------------------------------------------------------------------------
# Ingress
# ---------------------------------------------------------------------------

resource "kubernetes_ingress_v1" "gateway" {
  metadata {
    name      = "gateway"
    namespace = kubernetes_namespace.homobio.metadata[0].name
    labels    = local.common_labels

    annotations = {
      "cert-manager.io/cluster-issuer"                = "letsencrypt-prod"
      "nginx.ingress.kubernetes.io/ssl-redirect"      = "true"
      # The gateway streams no uploads; this bounds everything else.
      "nginx.ingress.kubernetes.io/proxy-body-size"   = "1m"
    }
  }

  spec {
    ingress_class_name = "nginx"

    tls {
      hosts       = [var.domain]
      secret_name = "${var.project}-tls"
    }

    rule {
      host = var.domain

      http {
        path = "/"
        path_type = "Prefix"

        backend {
          service {
            name = kubernetes_service.gateway.metadata[0].name
            port {
              number = 5000
            }
          }
        }
      }
    }
  }
}

# ---------------------------------------------------------------------------
# Network policies: default deny, then the two allowed paths.
# ---------------------------------------------------------------------------

resource "kubernetes_network_policy" "default_deny" {
  metadata {
    name      = "default-deny"
    namespace = kubernetes_namespace.homobio.metadata[0].name
    labels    = local.common_labels
  }

  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]
  }
}

resource "kubernetes_network_policy" "coprocessor_ingress" {
  metadata {
    name      = "coprocessor-ingress"
    namespace = kubernetes_namespace.homobio.metadata[0].name
    labels    = local.common_labels
  }

  spec {
    pod_selector {
      match_labels = { "app.kubernetes.io/name" = "fhe-coprocessor" }
    }
    policy_types = ["Ingress"]

    ingress {
      from {
        pod_selector {
          match_labels = { "app.kubernetes.io/name" = "gateway" }
        }
      }
      port {
        protocol = "TCP"
        port     = 5001
      }
    }
  }
}

resource "kubernetes_network_policy" "gateway_egress" {
  metadata {
    name      = "gateway-egress"
    namespace = kubernetes_namespace.homobio.metadata[0].name
    labels    = local.common_labels
  }

  spec {
    pod_selector {
      match_labels = { "app.kubernetes.io/name" = "gateway" }
    }
    policy_types = ["Egress"]

    egress {
      # Only the coprocessor, only on its port.
      to {
        pod_selector {
          match_labels = { "app.kubernetes.io/name" = "fhe-coprocessor" }
        }
      }
      port {
        protocol = "TCP"
        port     = 5001
      }
    }

    # Cluster DNS.
    egress {
      to {
        namespace_selector {}
      }
      port {
        protocol = "UDP"
        port     = 53
      }
    }

    # Outbound HTTPS: the Monad RPC endpoint and any secret manager.
    egress {
      port {
        protocol = "TCP"
        port     = 443
      }
    }

    # A self-hosted bundler, if one is used instead of a hosted endpoint.
    egress {
      port {
        protocol = "TCP"
        port     = 8545
      }
    }
  }
}

resource "kubernetes_network_policy" "gateway_ingress" {
  metadata {
    name      = "gateway-ingress"
    namespace = kubernetes_namespace.homobio.metadata[0].name
    labels    = local.common_labels
  }

  spec {
    pod_selector {
      match_labels = { "app.kubernetes.io/name" = "gateway" }
    }
    policy_types = ["Ingress"]

    ingress {
      from {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "ingress-nginx"
          }
        }
      }
      port {
        protocol = "TCP"
        port     = 5000
      }
    }
  }
}

# ---------------------------------------------------------------------------
# Availability
# ---------------------------------------------------------------------------

resource "kubernetes_pod_disruption_budget_v1" "gateway" {
  metadata {
    name      = "gateway"
    namespace = kubernetes_namespace.homobio.metadata[0].name
    labels    = local.common_labels
  }

  spec {
    min_available = 1
    selector {
      match_labels = { "app.kubernetes.io/name" = "gateway" }
    }
  }
}

variable "key_material_gib" {
  description = "Size of the key-material volume. Grows with enrolled templates."
  type        = number
  default     = 5
}