#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
TLS_DIR="/opt/arkfile/etc/keys/tls"
USER="arkfile"
GROUP="arkfile"
DOMAIN="${ARKFILE_DOMAIN:-localhost}"
VALIDITY_DAYS=365

echo -e "${GREEN}Setting up TLS certificates...${NC}"

# Check if TLS directory exists
if [ ! -d "${TLS_DIR}" ]; then
    echo -e "${RED}Error: TLS directory ${TLS_DIR} does not exist${NC}"
    echo "Please run setup-directories.sh first"
    exit 1
fi

# Check if CA already exists
if [ -f "${TLS_DIR}/ca/ca.crt" ]; then
    echo -e "${YELLOW}TLS certificates already exist. Skipping generation.${NC}"
    echo "To regenerate certificates, remove existing files first:"
    echo "  sudo rm -rf ${TLS_DIR}/ca/* ${TLS_DIR}/*/server.*"
    exit 0
fi

echo "Generating TLS certificates for internal services..."
echo "Domain: ${DOMAIN}"
echo "Validity: ${VALIDITY_DAYS} days"

# Create CA private key
echo "Creating CA private key..."
sudo -u ${USER} openssl genpkey -algorithm RSA -pkcs8 -out "${TLS_DIR}/ca/ca.key" -pkeyopt rsa_keygen_bits:4096

# Create CA certificate
echo "Creating CA certificate..."
sudo -u ${USER} openssl req -new -x509 -key "${TLS_DIR}/ca/ca.key" -out "${TLS_DIR}/ca/ca.crt" \
    -days ${VALIDITY_DAYS} -subj "/CN=Arkfile Internal CA/O=Arkfile/C=US"

# Create rqlite server private key
echo "Creating rqlite server private key..."
sudo -u ${USER} openssl genpkey -algorithm RSA -pkcs8 -out "${TLS_DIR}/rqlite/server.key" -pkeyopt rsa_keygen_bits:2048

# Create rqlite certificate signing request
echo "Creating rqlite certificate signing request..."
sudo -u ${USER} openssl req -new -key "${TLS_DIR}/rqlite/server.key" -out "${TLS_DIR}/rqlite/server.csr" \
    -subj "/CN=rqlite.${DOMAIN}/O=Arkfile/C=US"

# Create rqlite server certificate
echo "Creating rqlite server certificate..."
sudo -u ${USER} openssl x509 -req -in "${TLS_DIR}/rqlite/server.csr" -CA "${TLS_DIR}/ca/ca.crt" \
    -CAkey "${TLS_DIR}/ca/ca.key" -CAcreateserial -out "${TLS_DIR}/rqlite/server.crt" -days ${VALIDITY_DAYS} \
    -extensions v3_req -extfile <(cat << EOF
[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = rqlite.${DOMAIN}
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF
)

# Create MinIO server private key
echo "Creating MinIO server private key..."
sudo -u ${USER} openssl genpkey -algorithm RSA -pkcs8 -out "${TLS_DIR}/minio/server.key" -pkeyopt rsa_keygen_bits:2048

# Create MinIO certificate signing request
echo "Creating MinIO certificate signing request..."
sudo -u ${USER} openssl req -new -key "${TLS_DIR}/minio/server.key" -out "${TLS_DIR}/minio/server.csr" \
    -subj "/CN=minio.${DOMAIN}/O=Arkfile/C=US"

# Create MinIO server certificate
echo "Creating MinIO server certificate..."
sudo -u ${USER} openssl x509 -req -in "${TLS_DIR}/minio/server.csr" -CA "${TLS_DIR}/ca/ca.crt" \
    -CAkey "${TLS_DIR}/ca/ca.key" -CAcreateserial -out "${TLS_DIR}/minio/server.crt" -days ${VALIDITY_DAYS} \
    -extensions v3_req -extfile <(cat << EOF
[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = minio.${DOMAIN}
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF
)

# Clean up CSR files
sudo rm -f "${TLS_DIR}/rqlite/server.csr" "${TLS_DIR}/minio/server.csr"

# Set proper permissions
echo "Setting file permissions..."
sudo chown -R ${USER}:${GROUP} ${TLS_DIR}
sudo chmod 600 ${TLS_DIR}/ca/ca.key
sudo chmod 644 ${TLS_DIR}/ca/ca.crt
sudo chmod 600 ${TLS_DIR}/rqlite/server.key
sudo chmod 644 ${TLS_DIR}/rqlite/server.crt
sudo chmod 600 ${TLS_DIR}/minio/server.key
sudo chmod 644 ${TLS_DIR}/minio/server.crt

echo -e "${GREEN}✓ TLS certificates generated and secured${NC}"
echo "CA Certificate: ${TLS_DIR}/ca/ca.crt"
echo "rqlite Certificate: ${TLS_DIR}/rqlite/server.crt"
echo "MinIO Certificate: ${TLS_DIR}/minio/server.crt"

# Create certificate metadata
echo "Creating certificate metadata..."
sudo -u ${USER} bash -c "cat > '${TLS_DIR}/metadata.json' << EOF
{
  \"ca\": {
    \"subject\": \"CN=Arkfile Internal CA,O=Arkfile,C=US\",
    \"created\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
    \"expires\": \"$(date -u -d '+${VALIDITY_DAYS} days' +%Y-%m-%dT%H:%M:%SZ)\",
    \"algorithm\": \"RSA-4096\"
  },
  \"rqlite\": {
    \"subject\": \"CN=rqlite.${DOMAIN},O=Arkfile,C=US\",
    \"created\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
    \"expires\": \"$(date -u -d '+${VALIDITY_DAYS} days' +%Y-%m-%dT%H:%M:%SZ)\",
    \"algorithm\": \"RSA-2048\"
  },
  \"minio\": {
    \"subject\": \"CN=minio.${DOMAIN},O=Arkfile,C=US\",
    \"created\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
    \"expires\": \"$(date -u -d '+${VALIDITY_DAYS} days' +%Y-%m-%dT%H:%M:%SZ)\",
    \"algorithm\": \"RSA-2048\"
  }
}
EOF"

sudo chmod 644 ${TLS_DIR}/metadata.json

# Validate certificates
echo "Validating certificates..."
for service in rqlite minio; do
    cert_path="${TLS_DIR}/${service}/server.crt"
    key_path="${TLS_DIR}/${service}/server.key"
    
    if [ -f "${cert_path}" ] && [ -f "${key_path}" ]; then
        # Check certificate validity
        if sudo -u ${USER} openssl x509 -in "${cert_path}" -noout -checkend 0 >/dev/null 2>&1; then
            echo "  ✓ ${service}: Certificate valid"
        else
            echo -e "  ${RED}✗ ${service}: Certificate invalid${NC}"
        fi
        
        # Check if certificate matches private key
        cert_hash=$(sudo -u ${USER} openssl x509 -in "${cert_path}" -pubkey -noout | openssl md5)
        key_hash=$(sudo -u ${USER} openssl pkey -in "${key_path}" -pubout | openssl md5)
        
        if [ "${cert_hash}" = "${key_hash}" ]; then
            echo "  ✓ ${service}: Certificate matches private key"
        else
            echo -e "  ${RED}✗ ${service}: Certificate/key mismatch${NC}"
        fi
    else
        echo -e "  ${RED}✗ ${service}: Missing certificate or key${NC}"
    fi
done

echo -e "${GREEN}TLS certificate setup complete!${NC}"
echo ""
echo "Certificate details:"
echo "  Domain: ${DOMAIN}"
echo "  Validity: ${VALIDITY_DAYS} days"
echo "  CA: RSA-4096"
echo "  Services: RSA-2048"
echo ""
echo "Next steps:"
echo "  1. Configure rqlite to use ${TLS_DIR}/rqlite/server.{crt,key}"
echo "  2. Configure MinIO to use ${TLS_DIR}/minio/server.{crt,key}"
echo "  3. Distribute CA certificate to clients: ${TLS_DIR}/ca/ca.crt"
echo "  4. Set up certificate rotation before expiry"
