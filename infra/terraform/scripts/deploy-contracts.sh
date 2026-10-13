#!/usr/bin/env bash
# Deploy the Solidity contracts to Monad testnet in dependency order:
#   ProofVerifierRegistry -> AuthorizationVerifier -> BiometricAccountFactory
#
# The registry and verifier addresses are then recorded back into the
# Terraform variables / cluster Secret (AUTHORIZATION_VERIFIER_ADDRESS,
# PROOF_VERIFIER_REGISTRY_ADDRESS, ACCOUNT_FACTORY_ADDRESS).
#
# Usage:
#   RPC_URL=https://testnet-rpc.monad.xyz PRIVATE_KEY=0x... ./deploy-contracts.sh
#
# Requires: forge, cast. The EntryPoint address must match the network version
# (every userOpHash depends on it); the default below is Monad testnet.
set -euo pipefail

ENTRY_POINT="${ENTRY_POINT:-0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789}"
CHAIN_ID="${CHAIN_ID:-143}"
: "${RPC_URL:?set RPC_URL}"
: "${PRIVATE_KEY:?set PRIVATE_KEY}"
GOVERNANCE="$(cast wallet address "$PRIVATE_KEY")"

echo "deployer: $GOVERNANCE (chain $CHAIN_ID)"

echo "1/3 ProofVerifierRegistry..."
REGISTRY=$(forge create contracts/validators/ProofVerifierRegistry.sol:ProofVerifierRegistry \
  --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" \
  --constructor-args "$GOVERNANCE" \
  --json | python3 -c "import sys,json; print(json.load(sys.stdin)['deployedTo'])")
echo "  registry: $REGISTRY"

echo "2/3 AuthorizationVerifier..."
VERIFIER=$(forge create contracts/validators/AuthorizationVerifier.sol:AuthorizationVerifier \
  --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" \
  --constructor-args "$GOVERNANCE" "$REGISTRY" 1 600 \
  --json | python3 -c "import sys,json; print(json.load(sys.stdin)['deployedTo'])")
echo "  verifier: $VERIFIER"

echo "3/3 BiometricAccountFactory..."
FACTORY=$(forge create contracts/factory/BiometricAccountFactory.sol:BiometricAccountFactory \
  --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" \
  --constructor-args "$ENTRY_POINT" "$VERIFIER" 700000 \
  --json | python3 -c "import sys,json; print(json.load(sys.stdin)['deployedTo'])")
echo "  factory: $FACTORY"

cat <<EOF

Record these back into Terraform / the cluster Secret:
  PROOF_VERIFIER_REGISTRY_ADDRESS=$REGISTRY
  AUTHORIZATION_VERIFIER_ADDRESS=$VERIFIER
  ACCOUNT_FACTORY_ADDRESS=$FACTORY
EOF
