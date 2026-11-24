#!/usr/bin/env bash
set -euo pipefail
umask 077

# Generate private CA, EMQX Broker server cert, Backend client cert, and sample Adapter cert for MQTTS / mTLS.
FORCE=false
if [ "${1:-}" = "--force" ]; then
  FORCE=true
  shift
fi

CERT_DIR="${1:-./certs}"
CA_DIR="${2:-$(dirname "${CERT_DIR}")/ca-private}"

if [ "${FORCE}" != "true" ] && { [ -e "${CERT_DIR}/ca.crt" ] || [ -e "${CA_DIR}/ca.key" ]; }; then
  echo "Existing CA/certificates detected in ${CERT_DIR} or ${CA_DIR}. Pass --force to overwrite." >&2
  exit 1
fi

mkdir -p "${CERT_DIR}" "${CA_DIR}"
chmod 700 "${CA_DIR}"
rm -f "${CERT_DIR}/ca.key" "${CERT_DIR}/broker.key" "${CERT_DIR}/broker.crt" \
  "${CERT_DIR}/backend.key" "${CERT_DIR}/backend.crt" \
  "${CERT_DIR}/adapter-demo.key" "${CERT_DIR}/adapter-demo.crt"

echo "[1/4] Generating Root CA..."
openssl genrsa -out "${CA_DIR}/ca.key" 4096
chmod 600 "${CA_DIR}/ca.key"
openssl req -x509 -new -nodes -key "${CA_DIR}/ca.key" -sha256 -days 3650 \
  -subj "/CN=Locker-MQTT-Root-CA" \
  -out "${CERT_DIR}/ca.crt"

cat > "${CERT_DIR}/broker.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = broker
DNS.2 = emqx
DNS.3 = localhost
IP.1 = 127.0.0.1
EOF

echo "[2/4] Generating EMQX Broker server certificate..."
openssl genrsa -out "${CERT_DIR}/broker.key" 2048
openssl req -new -key "${CERT_DIR}/broker.key" -subj "/CN=broker" -out "${CERT_DIR}/broker.csr"
openssl x509 -req -in "${CERT_DIR}/broker.csr" -CA "${CERT_DIR}/ca.crt" -CAkey "${CA_DIR}/ca.key" \
  -CAcreateserial -out "${CERT_DIR}/broker.crt" -days 825 -sha256 -extfile "${CERT_DIR}/broker.ext"

cat > "${CERT_DIR}/client.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

echo "[3/4] Generating Backend MQTTS client certificate..."
openssl genrsa -out "${CERT_DIR}/backend.key" 2048
openssl req -new -key "${CERT_DIR}/backend.key" -subj "/CN=locker-backend" -out "${CERT_DIR}/backend.csr"
openssl x509 -req -in "${CERT_DIR}/backend.csr" -CA "${CERT_DIR}/ca.crt" -CAkey "${CA_DIR}/ca.key" \
  -CAcreateserial -out "${CERT_DIR}/backend.crt" -days 825 -sha256 -extfile "${CERT_DIR}/client.ext"

echo "[4/4] Generating sample Adapter client certificate (adapter-demo)..."
openssl genrsa -out "${CERT_DIR}/adapter-demo.key" 2048
openssl req -new -key "${CERT_DIR}/adapter-demo.key" -subj "/CN=adapter-demo" -out "${CERT_DIR}/adapter-demo.csr"
openssl x509 -req -in "${CERT_DIR}/adapter-demo.csr" -CA "${CERT_DIR}/ca.crt" -CAkey "${CA_DIR}/ca.key" \
  -CAcreateserial -out "${CERT_DIR}/adapter-demo.crt" -days 825 -sha256 -extfile "${CERT_DIR}/client.ext"

rm -f "${CERT_DIR}"/*.csr "${CERT_DIR}"/*.ext "${CERT_DIR}"/*.srl "${CA_DIR}"/*.srl
chmod 644 "${CERT_DIR}"/*.crt
chmod 600 "${CERT_DIR}"/*.key

echo "Done! Certificates generated in ${CERT_DIR} (CA private key isolated in ${CA_DIR}/ca.key)"
