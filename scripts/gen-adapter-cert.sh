#!/usr/bin/env bash
set -euo pipefail

# Issue an individual MQTTS mTLS client certificate whose CN matches <adapterId>.
FORCE=false
ADAPTER_ID=""
CERT_DIR="./certs"
CA_DIR=""

while [ $# -gt 0 ]; do
  case "$1" in
    --force)
      FORCE=true
      shift
      ;;
    --id)
      ADAPTER_ID="${2:?--id requires an adapterId}"
      shift 2
      ;;
    --certs-dir)
      CERT_DIR="${2:?--certs-dir requires a directory}"
      shift 2
      ;;
    --ca-dir)
      CA_DIR="${2:?--ca-dir requires a directory}"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 [--force] [--certs-dir ./certs] [--ca-dir ./ca-private] [--id] <adapterId>"
      exit 0
      ;;
    *)
      if [ -z "${ADAPTER_ID}" ]; then
        ADAPTER_ID="$1"
        shift
      else
        echo "Unexpected argument: $1" >&2
        exit 1
      fi
      ;;
  esac
done

if [ -z "${ADAPTER_ID}" ]; then
  echo "Usage: $0 [--force] [--certs-dir ./certs] [--ca-dir ./ca-private] [--id] <adapterId>" >&2
  exit 1
fi

if ! [[ "${ADAPTER_ID}" =~ ^[A-Za-z0-9_-]{1,64}$ ]]; then
  echo "Invalid adapterId '${ADAPTER_ID}': must match ^[A-Za-z0-9_-]{1,64}$" >&2
  exit 1
fi

case "${ADAPTER_ID}" in
  ca|broker|backend|locker-backend)
    echo "Reserved name '${ADAPTER_ID}' cannot be used as an adapterId" >&2
    exit 1
    ;;
esac

if [ -z "${CA_DIR}" ]; then
  CA_DIR="$(dirname "${CERT_DIR}")/ca-private"
fi

if [ ! -f "${CERT_DIR}/ca.crt" ] || [ ! -f "${CA_DIR}/ca.key" ]; then
  echo "CA files missing (${CERT_DIR}/ca.crt or ${CA_DIR}/ca.key). Run ./scripts/gen-certs.sh first." >&2
  exit 1
fi

KEY_PATH="${CERT_DIR}/${ADAPTER_ID}.key"
CERT_PATH="${CERT_DIR}/${ADAPTER_ID}.crt"
CSR_PATH="${CERT_DIR}/${ADAPTER_ID}.csr"
EXT_PATH="${CERT_DIR}/${ADAPTER_ID}.ext"

if [ "${FORCE}" != "true" ] && { [ -e "${KEY_PATH}" ] || [ -e "${CERT_PATH}" ]; }; then
  echo "Existing certificate for '${ADAPTER_ID}' found in ${CERT_DIR}. Pass --force to overwrite." >&2
  exit 1
fi

cat > "${EXT_PATH}" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

openssl genrsa -out "${KEY_PATH}" 2048
openssl req -new -key "${KEY_PATH}" -subj "/CN=${ADAPTER_ID}" -out "${CSR_PATH}"
openssl x509 -req -in "${CSR_PATH}" -CA "${CERT_DIR}/ca.crt" -CAkey "${CA_DIR}/ca.key" \
  -CAcreateserial -out "${CERT_PATH}" -days 825 -sha256 -extfile "${EXT_PATH}"

rm -f "${CSR_PATH}" "${EXT_PATH}" "${CERT_DIR}/ca.srl" "${CA_DIR}/ca.srl"
chmod 644 "${CERT_PATH}" "${KEY_PATH}"

echo "Issued adapter mTLS certificate: ${CERT_PATH} and ${KEY_PATH} (CN=${ADAPTER_ID})"
