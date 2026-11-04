#!/bin/sh
# Regenerates the TLS fixtures for tests/ops.rs (needs OpenSSL 3.4 or later
# for -not_before). Valid 2020-2120, so test machines with a slightly wrong
# clock still pass. CA keys are thrown away; only the leaf key is needed.
set -eu
cd "$(dirname "$0")"
OPENSSL=${OPENSSL:-openssl}
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
from=20200101000000Z
until=21200101000000Z

ca() { # name cn
  "$OPENSSL" req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$t/$1.key" -out "$1.pem" -subj "/CN=$2" -not_before $from -not_after $until \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign"
}
ca ca sopedu-test-ca
ca other-ca sopedu-other-ca

"$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out leaf.key
leaf() { # name san
  "$OPENSSL" req -new -key leaf.key -subj /CN=sopedu-test-upstream -out "$t/$1.csr"
  printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n' "$2" >"$t/$1.ext"
  "$OPENSSL" x509 -req -in "$t/$1.csr" -CA ca.pem -CAkey "$t/ca.key" -CAcreateserial \
    -CAserial "$t/ca.srl" -not_before $from -not_after $until -extfile "$t/$1.ext" -out "$1.pem"
}
leaf leaf IP:127.0.0.1
leaf wrong-name DNS:wrong.example
