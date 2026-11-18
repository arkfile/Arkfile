#!/bin/sh
# Mint the lab CA and the two server certificates. The CA private key is
# created under /tmp and removed before this process exits.
set -eu

if [ -f /ca-public/ca.crt ] && [ -f /tls-arkfile/arkfile.crt ] && [ -f /tls-bitcart/bitcart.crt ]; then
    echo "lab certificates already present"
    exit 0
fi

apk add --no-cache openssl ca-certificates >/dev/null

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

cat > "$workdir/ca.cnf" <<'EOF'
[req]
distinguished_name=dn
x509_extensions=v3_ca
prompt=no
[dn]
CN=Arkfile paylab CA
[v3_ca]
basicConstraints=critical,CA:true
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
nameConstraints=critical,permitted;DNS:arkfile.lab,permitted;DNS:bitcart.lab,permitted;DNS:localhost,permitted;IP:127.0.0.1/255.255.255.255
EOF

openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$workdir/ca.key" -out "$workdir/ca.crt" \
    -days 825 -config "$workdir/ca.cnf" -extensions v3_ca

issue() {
    name=$1
    cn=$2
    san=$3
    outdir=$4
    cat > "$workdir/${name}.cnf" <<EOF
[req]
distinguished_name=dn
req_extensions=v3_req
prompt=no
[dn]
CN=${cn}
[v3_req]
subjectAltName=${san}
basicConstraints=CA:false
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF
    openssl req -newkey rsa:2048 -nodes \
        -keyout "$workdir/${name}.key" -out "$workdir/${name}.csr" \
        -config "$workdir/${name}.cnf"
    openssl x509 -req -in "$workdir/${name}.csr" \
        -CA "$workdir/ca.crt" -CAkey "$workdir/ca.key" -CAcreateserial \
        -out "$workdir/${name}.crt" -days 825 \
        -extfile "$workdir/${name}.cnf" -extensions v3_req
    install -m 0644 "$workdir/${name}.crt" "${outdir}/${name}.crt"
    install -m 0640 "$workdir/${name}.key" "${outdir}/${name}.key"
}

issue arkfile arkfile.lab "DNS:arkfile.lab,DNS:localhost,IP:127.0.0.1" /tls-arkfile
issue bitcart bitcart.lab "DNS:bitcart.lab,DNS:localhost,IP:127.0.0.1" /tls-bitcart

install -m 0644 "$workdir/ca.crt" /ca-public/ca.crt
cat /etc/ssl/certs/ca-certificates.crt /ca-public/ca.crt > /ca-public/ca-bundle.crt
chmod 0644 /ca-public/ca-bundle.crt

rm -f "$workdir/ca.key"
echo "lab certificates written"
