#!/usr/bin/env bash
# End-to-end local setup: brings up anvil + IPFS, deploys BsecSecretRegistry,
# configures bitbid, and creates + funds the bitbid wallet against the local stack.
#
# Requirements: docker (compose). Foundry (forge) runs via the foundry docker image,
# so no host install is needed. The bitbid release binary is built from source.
#
# Notes on the environment this was validated against (macOS / Docker Desktop):
#   - The foundry image ENTRYPOINT is ["/bin/sh","-c"], so the forge command is passed as a
#     SINGLE string argument (a list would make sh swallow the flags).
#   - Containers reach the host-published anvil via host.docker.internal.
#   - forge writes build artifacts to its workdir, so -w /tmp gives it a writable one.
#
# Usage:
#   ./scripts/e2e-setup.sh
#   BITBID_HOME=~/.bitbid BITBID_E2E=1 cargo test --locked -p bitbid-cli    # run gated integration flows against this stack
set -euo pipefail

RPC_URL="http://localhost:8545"
ANVIL_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ANVIL_ACCT0="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
FOUNDRY_IMG="ghcr.io/foundry-rs/foundry:latest"
BIN="./target/release/bitbid"
# Let the CLI choose canonical/legacy homes by presence, including blank/error cases.
# Do not default with ${VAR:-...}: a present blank BITBID_HOME must fail.
INIT_OUT=$(mktemp "${TMPDIR:-/tmp}/bitbid-init.XXXXXX")
trap 'rm -f "$INIT_OUT"' EXIT

rpc() { # rpc <json-body>
  curl -s -X POST "$RPC_URL" -H 'content-type: application/json' -d "$1"
}

echo "==> Building bitbid release binary"
cargo build --locked --release -p bitbid-cli --bin bitbid --quiet

# Resolve the selected root before any local stack mutation.
"$BIN" config --show >/dev/null

echo "==> Starting anvil + IPFS"
docker compose up -d

echo "==> Waiting for anvil RPC"
for _ in $(seq 1 30); do
  if [ -n "$(rpc '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}')" ]; then
    echo "    anvil up"; break
  fi
  sleep 1
done

echo "==> Deploying BsecSecretRegistry to anvil"
DEPLOY_OUT=$(docker run --rm -w /tmp -v "$PWD/contracts:/contracts" "$FOUNDRY_IMG" \
  "forge create /contracts/BsecSecretRegistry.sol:BsecSecretRegistry \
   --rpc-url http://host.docker.internal:8545 --private-key $ANVIL_KEY --broadcast")
REGISTRY=$(echo "$DEPLOY_OUT" | grep -Eo 'Deployed to: 0x[0-9a-fA-F]{40}' | awk '{print $3}')
echo "    registry: $REGISTRY"

echo "==> Configuring bitbid for local stack"
$BIN config --network local --rpc "$RPC_URL" --registry "$REGISTRY" \
  --ipfs-gateway "http://localhost:8080/ipfs/" >/dev/null

echo "==> Initializing wallet"
$BIN init --overwrite >"$INIT_OUT" 2>/dev/null
WALLET=$(awk '/Address:/ {print $2}' "$INIT_OUT")
echo "    wallet: $WALLET"

echo "==> Funding wallet with 10 ETH from anvil account #0"
rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_sendTransaction\",\"params\":[{\"from\":\"$ANVIL_ACCT0\",\"to\":\"$WALLET\",\"value\":\"0x8ac7230489e80000\"}]}" >/dev/null
sleep 2
BAL=$(rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getBalance\",\"params\":[\"$WALLET\",\"latest\"]}")
echo "    balance: $BAL"

echo "==> Done. Local stack ready. Try:"
echo "    $BIN share --content 'hello' --to public --ttl 1h --max-reads 3"
echo "    $BIN view <secret_id>"
