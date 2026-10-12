# Terraform for the Homomorphic Biometric Passkeys off-chain tier.
#
#   terraform init
#   terraform plan -var-file=production.tfvars
#   terraform apply
#
# SCOPE: the Kubernetes cluster, the container registry and the L7 ingress.
# The FHE key material and the custody share are deliberately NOT provisioned
# here — see `docs/threat-model.md` (T-9). Anything Terraform can read, the
# cloud provider can read, so key material belongs in an HSM or an external
# custody service that this stack can only call.
#
# This configuration is a reference implementation, not a drop-in: replace the
# provider block and variable defaults for your cloud.

terraform {
  required_version = ">= 1.6"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.30"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.13"
    }
  }
}

provider "kubernetes" {
  host                   = var.k8s_endpoint
  cluster_ca_certificate = base64decode(var.cluster_ca_certificate)
  token                  = var.k8s_token
}

# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------

variable "project" {
  description = "Short project identifier used for naming and tagging."
  type        = string
  default     = "homobio"
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "environment" {
  description = "One of: staging, production."
  type        = string
  default     = "staging"

  validation {
    condition     = contains(["staging", "production"], var.environment)
    error_message = "environment must be staging or production."
  }
}

variable "k8s_endpoint" {
  description = "Kubernetes API server URL."
  type        = string
}

variable "k8s_ca_certificate" {
  description = "Base64-encoded cluster CA certificate."
  type        = string
  sensitive   = true
}

variable "k8s_token" {
  description = "Kubernetes API token. Prefer a short-lived exec credential."
  type        = string
  sensitive   = true
}

variable "gateway_image" {
  type    = string
  default = "ghcr.io/example/homobio-gateway:v2.0.0"
}

variable "coprocessor_image" {
  type    = string
  default = "ghcr.io/example/homobio-fhe-coprocessor:v2.0.0"
}

variable "domain" {
  description = "Public hostname. Must be a registrable suffix of the WebAuthn rpId."
  type        = string
  default     = "app.example.com"
}

variable "chain_id" {
  type    = number
  default = 143
}

variable "monad_rpc" {
  type    = string
  default = "https://testnet-rpc.monad.xyz"
}

# ---------------------------------------------------------------------------
# Locals
# ---------------------------------------------------------------------------

locals {
  common_labels = {
    app.kubernetes.io/part-of = "homomorphic-biometric-passkeys"
    app.kubernetes.io/name    = var.project
    environment               = var.environment
    managed-by                = "terraform"
  }

  # Secrets are referenced from an external source, never generated here.
  # `homobio-secrets` is expected to exist already (External Secrets Operator,
  # Vault agent, or the cloud's secret manager). Terraform only consumes it.
  secret_name = "${var.project}-secrets"

  config = {
    NODE_ENV   = "production"
    LOG_LEVEL  = "info"
    CHAIN_ID   = tostring(var.chain_id)
    CHAIN_NAME = "Monad Testnet"
    MONAD_RPC  = var.monad_rpc
    # ERC-4337 v0.7 EntryPoint on the target network. Confirm against the exact
    # network version: every userOpHash depends on it.
    MONAD_ENTRY_POINT = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"
    # The engine's documented error bound. It sizes the `indeterminate` band:
    # a comparison landing inside it is refused rather than decided.
    FHE_ERROR_BOUND = "0.001953125"
    # Never regenerate the key set on restart, or every enrolled template
    # becomes undecryptable.
    FHE_REUSE_KEYS   = "true"
    RELAYER_DRY_RUN  = var.bundler_url == "" ? "true" : "false"
    BUNDLER_URL      = var.bundler_url
    WEBAUTHN_RP_ID   = var.domain
    WEBAUTHN_ORIGIN  = "https://${var.domain}"
    ALLOWED_ORIGINS  = "https://${var.domain}"
  }

  bundler_url = ""
}

variable "bundler_url" {
  description = "ERC-4337 bundler endpoint. Empty keeps the relayer in dry-run."
  type        = string
  default     = ""
}