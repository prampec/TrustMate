#!/bin/sh
# End-to-end runner for the TrustMate field-test Bruno collection.
#
# Runs every folder that only needs static input in one pass, then derives
# the OCSP fixtures that depend on certificates minted *during* that pass
# (their serials aren't known ahead of time), then runs the folders that
# need those derived fixtures, then demonstrates the RBAC boundary by
# re-running two requests under a different client identity.
#
# Usage (from anywhere):
#   docs/bruno/scripts/run-all.sh [baseUrl]
#
# baseUrl defaults to https://test.me:8182 (the documented sandbox
# hostname -- see docs/bruno/README.md for why). Point it at any other
# live deployment by passing its base URL instead, e.g.:
#   docs/bruno/scripts/run-all.sh https://your-host:8443
#
# Requires: bru (Bruno CLI), openssl, jq, python3.

set -eu

BASE_URL="${1:-https://test.me:8182}"
HOST="$(printf '%s' "$BASE_URL" | sed -E 's#^[a-zA-Z]+://##; s#[:/].*$##')"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BRUNO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$BRUNO_DIR/../.." && pwd)"
GEN="$BRUNO_DIR/generated"
CACERT="$REPO_ROOT/work/root.pem"

cd "$BRUNO_DIR"
mkdir -p "$GEN"
rm -f "$GEN"/*.pem "$GEN"/*.der "$GEN"/*.csr "$GEN"/*.json 2>/dev/null || true

echo "==> Target: $BASE_URL (host: $HOST)"
echo "==> CA trust anchor: $CACERT"

echo "==> [0/4] Generating throwaway CSRs (document-signing x2, manager client)"
openssl ecparam -name prime256v1 -genkey -noout -out "$GEN/leaf-good-key.pem"
openssl req -new -key "$GEN/leaf-good-key.pem" \
  -subj "/CN=fieldtest-signer-good/O=TrustMate Field Test" -out "$GEN/document-signing.csr"

openssl ecparam -name prime256v1 -genkey -noout -out "$GEN/leaf-revoke-key.pem"
openssl req -new -key "$GEN/leaf-revoke-key.pem" \
  -subj "/CN=fieldtest-signer-revoke/O=TrustMate Field Test" -out "$GEN/revoke-me.csr"

openssl ecparam -name prime256v1 -genkey -noout -out "$GEN/manager-client-key.pem"
openssl req -new -key "$GEN/manager-client-key.pem" \
  -subj "/CN=fieldtest-manager-client/O=TrustMate Field Test" -out "$GEN/manager-client.csr"

csr_json() { python3 -c "import json,sys;print(json.dumps(open(sys.argv[1]).read()))" "$1"; }
CSR_DOC="$(csr_json "$GEN/document-signing.csr")"
CSR_REVOKE="$(csr_json "$GEN/revoke-me.csr")"
CSR_MGR="$(csr_json "$GEN/manager-client.csr")"

echo "==> [1/4] Main pass: health, ca, profiles, clients, certificates, tsa, acme, audit"
bru run 01-health 02-ca-distribution 03-profiles 04-clients 05-certificates 08-tsa 09-acme 06-audit -r \
  --env sandbox \
  --env-var baseUrl="$BASE_URL" \
  --env-var certDomain="$HOST" \
  --env-var csrDocumentSigning="$CSR_DOC" \
  --env-var csrRevokeMe="$CSR_REVOKE" \
  --env-var csrManagerClient="$CSR_MGR" \
  --cacert "$CACERT" \
  -o "$GEN/report-main.json" --format json

echo "==> [2/4] Deriving OCSP fixtures for the certs just issued/revoked"
python3 - "$GEN" <<'PYEOF'
import json, sys, pathlib
gen = pathlib.Path(sys.argv[1])
report = json.loads((gen / "report-main.json").read_text())
results = {r["path"]: r for r in report[0]["results"]}
good = results["05-certificates/issue-good"]["response"]["data"]
revoke = results["05-certificates/issue-for-revocation"]["response"]["data"]
mgr = results["04-clients/add-client"]["response"]["data"]
(gen / "leaf-good.pem").write_text(good["pem"])
(gen / "leaf-revoke.pem").write_text(revoke["pem"])
(gen / "manager-client.pem").write_text(mgr["pem"])
print("good serial:   ", good["serial"])
print("revoked serial:", revoke["serial"])
print("manager serial:", mgr["serial"])
PYEOF

openssl ocsp -issuer "$REPO_ROOT/work/intermediate.pem" -cert "$GEN/leaf-good.pem" \
  -reqout "$GEN/ocsp-req-good.der" -no_nonce
openssl ocsp -issuer "$REPO_ROOT/work/intermediate.pem" -cert "$GEN/leaf-revoke.pem" \
  -reqout "$GEN/ocsp-req-revoked.der" -no_nonce

echo "==> [3/4] Revocation pass: CRL, OCSP (good/revoked/unknown/error cases)"
bru run 07-revocation -r \
  --env sandbox \
  --env-var baseUrl="$BASE_URL" \
  --env-var certDomain="$HOST" \
  --cacert "$CACERT" \
  -o "$GEN/report-revocation.json" --format json

echo "==> [4/4] RBAC boundary demo: no cert / manager-allowed / manager-forbidden"
bru run 10-auth/no-client-cert.bru \
  --env sandbox \
  --env-var baseUrl="$BASE_URL" \
  --env-var certDomain=unused.invalid \
  --cacert "$CACERT"

bru run 10-auth/manager-role-allowed.bru \
  --env sandbox \
  --env-var baseUrl="$BASE_URL" \
  --env-var certDomain="$HOST" \
  --env-var certFile=generated/manager-client.pem \
  --env-var certKeyFile=generated/manager-client-key.pem \
  --cacert "$CACERT"

bru run 10-auth/manager-role-forbidden.bru \
  --env sandbox \
  --env-var baseUrl="$BASE_URL" \
  --env-var certDomain="$HOST" \
  --env-var certFile=generated/manager-client.pem \
  --env-var certKeyFile=generated/manager-client-key.pem \
  --cacert "$CACERT"

echo "==> Done. Reports in $GEN/report-*.json; generated/ is gitignored (ephemeral, run-specific)."
