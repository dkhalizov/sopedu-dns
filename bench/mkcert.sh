#!/usr/bin/env bash
# Throwaway CA + leaf for the benchmark DoH upstream (examples/upstream_mock.rs).
# Usage: bench/mkcert.sh OUTDIR [SAN ...]   e.g. IP:127.0.0.1 DNS:upstream
# Writes ca.pem (trust it with SSL_CERT_FILE), cert.der and key.der (PKCS#8).
set -euo pipefail
out=$1; shift
san=$(IFS=,; echo "${*:-IP:127.0.0.1}")
mkdir -p "$out"; cd "$out"
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=bench-ca \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign \
  -keyout ca.key -out ca.pem 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj /CN=bench-upstream -keyout leaf.key -out leaf.csr 2>/dev/null
printf 'subjectAltName=%s\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' "$san" > leaf.ext
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 30 \
  -extfile leaf.ext -out leaf.pem 2>/dev/null
openssl x509 -in leaf.pem -outform DER -out cert.der
openssl pkcs8 -topk8 -nocrypt -in leaf.key -outform DER -out key.der
rm -f leaf.csr leaf.ext ca.srl
