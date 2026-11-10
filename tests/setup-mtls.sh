#!/usr/bin/env bash
# Generates the test CA, client certificates (valid, revoked, and self-signed),
# CRL bundle, and Docker Compose environment file used to verify server-side
# mutual TLS in tests/docker-compose.mtls.yml.
set -euo pipefail

script_dir="$(cd "$(dirname "${0}")" && pwd)"
certs_dir="${script_dir}/mtls-certs"
target="${1:-${TARGET:-}}"

rm -rf "${certs_dir}"
mkdir -p "${certs_dir}/ca-db/newcerts"

# A test CA, a client certificate it accepts, and one it revokes
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "${certs_dir}/ca.key" -out "${certs_dir}/ca.crt" \
  -subj "/CN=mtls-ca" 2>/dev/null

for name in client rejected; do
  openssl req -newkey rsa:2048 -nodes \
    -keyout "${certs_dir}/${name}.key" -out "${certs_dir}/${name}.csr" \
    -subj "/CN=mtls-${name}" 2>/dev/null
  openssl x509 -req -days 1 \
    -in "${certs_dir}/${name}.csr" \
    -CA "${certs_dir}/ca.crt" -CAkey "${certs_dir}/ca.key" \
    -CAcreateserial -out "${certs_dir}/${name}.crt" 2>/dev/null
done

# A self-signed client certificate not issued by the test CA (used both as an
# untrusted certificate in strict mode and as an unverified certificate in
# optional_no_ca mode)
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "${certs_dir}/selfsigned.key" -out "${certs_dir}/selfsigned.crt" \
  -subj "/CN=mtls-selfsigned" 2>/dev/null

# Revoke rejected.crt and generate the PEM CRL bundle
touch "${certs_dir}/ca-db/index.txt"
echo 1000 > "${certs_dir}/ca-db/serial"
echo 1000 > "${certs_dir}/ca-db/crlnumber"
cat > "${certs_dir}/ca.cnf" <<EOF
[ca]
default_ca = CA_default
[CA_default]
database = ${certs_dir}/ca-db/index.txt
new_certs_dir = ${certs_dir}/ca-db/newcerts
serial = ${certs_dir}/ca-db/serial
crlnumber = ${certs_dir}/ca-db/crlnumber
default_md = sha256
default_days = 1
default_crl_days = 1
policy = policy_anything
[policy_anything]
commonName = supplied
EOF

openssl ca -batch -config "${certs_dir}/ca.cnf" \
  -cert "${certs_dir}/ca.crt" -keyfile "${certs_dir}/ca.key" \
  -revoke "${certs_dir}/rejected.crt" 2>/dev/null
openssl ca -batch -config "${certs_dir}/ca.cnf" \
  -cert "${certs_dir}/ca.crt" -keyfile "${certs_dir}/ca.key" \
  -gencrl -out "${certs_dir}/ca.crl" 2>/dev/null

chmod 644 "${certs_dir}"/*.crt "${certs_dir}"/*.key "${certs_dir}"/*.crl

if [ -n "${target}" ]; then
  verify="on"
  cert_dir="/etc/nginx/ssl"
  if grep -q "apache" <<< "${target}"; then
    verify="require"
    cert_dir="/usr/local/apache2/conf"
  fi

  env_file="../${target}.env"
  if [ ! -f "${script_dir}/${env_file}" ]; then
    touch "${certs_dir}/empty.env"
    env_file="./mtls-certs/empty.env"
  fi

  cat > "${script_dir}/.env" <<EOF
MTLS_IMAGE=${MTLS_IMAGE:-${target}-verification}
MTLS_ENV_FILE=${env_file}
SSL_VERIFY=${verify}
MTLS_CERT_DIR=${cert_dir}
EOF
fi
