#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
TLS_DIR="/opt/arkfile/etc/keys/tls"
USER="arkfile"
GROUP="arkfile"
DOMAIN="${ARKFILE_DOMAIN:-localhost}"
VALIDITY_DAYS=365
PREFERRED_ALGORITHM="${ARKFILE_TLS_ALGORITHM:-ecdsa}"

# Service definitions: name|cn|alt_names
SERVICES=(
    "arkfile|arkfile.${DOMAIN}|DNS.1=arkfile.${DOMAIN},DNS.2=${DOMAIN},DNS.3=localhost,DNS.4=arkfile.internal,IP.1=127.0.0.1,IP.2=::1"
    "rqlite|rqlite.${DOMAIN}|DNS.1=rqlite.${DOMAIN},DNS.2=rqlite.internal,DNS.3=localhost,IP.1=127.0.0.1,IP.2=::1"
    "minio|minio.${DOMAIN}|DNS.1=minio.${DOMAIN},DNS.2=minio.internal,DNS.3=localhost,IP.1=127.0.0.1,IP.2=::1"
)

echo -e "${GREEN}Setting up TLS certificates with modern cryptography...${NC}"

# Function to detect OpenSSL version
detect_openssl_version() {
    local version=$(openssl version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
    echo "$version"
}

# Function to check if ECDSA is supported
check_ecdsa_support() {
    if openssl ecparam -list_curves | grep -q "secp384r1"; then
        return 0
    else
        return 1
    fi
}

# Function to generate ECDSA P-384 private key
generate_ecdsa_key() {
    local key_path="$1"
    local description="$2"
    
    echo "Generating ECDSA P-384 private key for ${description}..."
    sudo -u ${USER} openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "${key_path}"
    
    if [ $? -eq 0 ]; then
        echo -e "  ${GREEN}[OK] ECDSA P-384 key generated successfully${NC}"
        return 0
    else
        echo -e "  ${YELLOW}[WARNING] ECDSA generation failed, falling back to RSA${NC}"
        return 1
    fi
}

# Function to generate RSA private key (fallback)
generate_rsa_key() {
    local key_path="$1"
    local description="$2"
    local key_size="${3:-4096}"
    
    echo "Generating RSA ${key_size}-bit private key for ${description}..."
    sudo -u ${USER} openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:${key_size} -out "${key_path}"
    
    if [ $? -eq 0 ]; then
        echo -e "  ${GREEN}[OK] RSA ${key_size}-bit key generated successfully${NC}"
        return 0
    else
        echo -e "  ${RED}[X] RSA key generation failed${NC}"
        return 1
    fi
}

# Function to generate private key (with fallback)
generate_private_key() {
    local key_path="$1"
    local description="$2"
    local key_size="${3:-4096}"
    
    if [ "${PREFERRED_ALGORITHM}" = "ecdsa" ] && check_ecdsa_support; then
        if generate_ecdsa_key "${key_path}" "${description}"; then
            echo "ecdsa"
            return 0
        fi
    fi
    
    # Fallback to RSA
    if generate_rsa_key "${key_path}" "${description}" "${key_size}"; then
        echo "rsa"
        return 0
    fi
    
    echo -e "${RED}[X] Failed to generate private key for ${description}${NC}"
    return 1
}

# Function to create certificate with proper extensions
create_certificate() {
    local key_path="$1"
    local cert_path="$2"
    local cn="$3"
    local alt_names="$4"
    local ca_cert="${5:-}"
    local ca_key="${6:-}"
    local description="$7"
    
    echo "Creating certificate for ${description}..."
    
    local config_file=$(sudo -u ${USER} mktemp --tmpdir=/tmp)
    sudo -u ${USER} bash -c "cat > '${config_file}'" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN=${cn}
O=Arkfile
C=US

[v3_req]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment, keyAgreement
extendedKeyUsage = serverAuth, clientAuth
subjectKeyIdentifier = hash
subjectAltName = @alt_names

[alt_names]
$(echo "${alt_names}" | tr ',' '\n')

[v3_ca]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign, digitalSignature
subjectKeyIdentifier = hash
EOF

    if [ -n "${ca_cert}" ] && [ -n "${ca_key}" ]; then
        local csr_file=$(sudo -u ${USER} mktemp)
        sudo chmod 644 "${csr_file}"
        
        sudo -u ${USER} openssl req -new -key "${key_path}" -out "${csr_file}" -config "${config_file}" -extensions v3_req
        if [ $? -ne 0 ]; then
            echo -e "  ${RED}[X] Failed to create certificate request${NC}"
            rm -f "${config_file}" "${csr_file}"
            return 1
        fi
        
        sudo -u ${USER} openssl x509 -req -in "${csr_file}" -CA "${ca_cert}" -CAkey "${ca_key}" \
            -CAcreateserial -out "${cert_path}" -days ${VALIDITY_DAYS} -sha384 \
            -extensions v3_req -extfile "${config_file}"
        local sign_result=$?
        rm -f "${csr_file}"
    else
        sudo -u ${USER} openssl req -new -x509 -key "${key_path}" -out "${cert_path}" \
            -days ${VALIDITY_DAYS} -sha384 -config "${config_file}" -extensions v3_ca
        local sign_result=$?
    fi
    
    rm -f "${config_file}"
    
    if [ $sign_result -eq 0 ]; then
        echo -e "  ${GREEN}[OK] Certificate created successfully${NC}"
        return 0
    else
        echo -e "  ${RED}[X] Certificate creation failed${NC}"
        return 1
    fi
}

# Function to validate certificate
validate_certificate() {
    local cert_path="$1"
    local key_path="$2"
    local service_name="$3"
    
    if [ ! -f "${cert_path}" ] || [ ! -f "${key_path}" ]; then
        echo -e "  ${RED}[X] ${service_name}: Missing certificate or key${NC}"
        return 1
    fi
    
    if sudo -u ${USER} openssl x509 -in "${cert_path}" -noout -checkend 0 >/dev/null 2>&1; then
        echo -e "  ${GREEN}[OK] ${service_name}: Certificate valid${NC}"
    else
        echo -e "  ${RED}[X] ${service_name}: Certificate invalid or expired${NC}"
        return 1
    fi
    
    local cert_pubkey_hash=$(sudo -u ${USER} openssl x509 -in "${cert_path}" -pubkey -noout | openssl sha256)
    local key_pubkey_hash=$(sudo -u ${USER} openssl pkey -in "${key_path}" -pubout | openssl sha256)
    
    if [ "${cert_pubkey_hash}" = "${key_pubkey_hash}" ]; then
        echo -e "  ${GREEN}[OK] ${service_name}: Certificate matches private key${NC}"
    else
        echo -e "  ${RED}[X] ${service_name}: Certificate/key mismatch${NC}"
        return 1
    fi
    
    local algorithm=$(sudo -u ${USER} openssl x509 -in "${cert_path}" -noout -text | grep "Public Key Algorithm" | head -1 | awk -F': ' '{print $2}')
    local expires=$(sudo -u ${USER} openssl x509 -in "${cert_path}" -noout -enddate | cut -d= -f2)
    echo -e "  ${BLUE}ℹ ${service_name}: ${algorithm}, expires ${expires}${NC}"
    
    return 0
}

# ============================================================
# Main execution
# ============================================================

# Check prerequisites
if [ ! -d "${TLS_DIR}" ]; then
    echo -e "${RED}Error: TLS directory ${TLS_DIR} does not exist${NC}"
    echo "Please run setup-directories.sh first"
    exit 1
fi

if [ -f "${TLS_DIR}/ca/ca.crt" ]; then
    echo -e "${YELLOW}TLS certificates already exist. Skipping generation.${NC}"
    echo "To regenerate, remove existing files first:"
    echo "  sudo rm -rf ${TLS_DIR}/ca/* ${TLS_DIR}/*/server.*"
    exit 0
fi

echo "Domain: ${DOMAIN}"
echo "Validity: ${VALIDITY_DAYS} days"
echo "Preferred algorithm: ${PREFERRED_ALGORITHM}"
echo "OpenSSL version: $(detect_openssl_version)"

# Create Certificate Authority
echo ""
echo -e "${BLUE}Creating Certificate Authority${NC}"
ca_algorithm=$(generate_private_key "${TLS_DIR}/ca/ca.key" "Certificate Authority" 4096)
if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to generate CA private key${NC}"
    exit 1
fi

if create_certificate "${TLS_DIR}/ca/ca.key" "${TLS_DIR}/ca/ca.crt" \
    "Arkfile-CA" "DNS.1=ca.internal.arkfile,DNS.2=ca.${DOMAIN}" "" "" "Certificate Authority"; then
    echo -e "${GREEN}[OK] Certificate Authority created${NC}"
else
    echo -e "${RED}[X] Failed to create Certificate Authority${NC}"
    exit 1
fi

# Create service certificates, bundles
declare -A service_algorithms

for entry in "${SERVICES[@]}"; do
    IFS='|' read -r name cn alt_names <<< "$entry"
    
    echo ""
    echo -e "${BLUE}Creating ${name} Certificate${NC}"
    
    algorithm=$(generate_private_key "${TLS_DIR}/${name}/server.key" "${name}" 2048)
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to generate ${name} private key${NC}"
        exit 1
    fi
    service_algorithms[$name]="$algorithm"
    
    if create_certificate "${TLS_DIR}/${name}/server.key" "${TLS_DIR}/${name}/server.crt" \
        "${cn}" "${alt_names}" "${TLS_DIR}/ca/ca.crt" "${TLS_DIR}/ca/ca.key" "${name}"; then
        echo -e "${GREEN}[OK] ${name} certificate created${NC}"
    else
        echo -e "${RED}[X] Failed to create ${name} certificate${NC}"
        exit 1
    fi
    
    # Create certificate bundle (cert + CA chain)
    sudo -u ${USER} cat "${TLS_DIR}/${name}/server.crt" "${TLS_DIR}/ca/ca.crt" > "${TLS_DIR}/${name}/server-bundle.crt"
    echo -e "  ${GREEN}[OK] ${name} bundle created${NC}"
done

# Set permissions
echo ""
echo -e "${BLUE}Setting File Permissions${NC}"

sudo chown -R ${USER}:${GROUP} "${TLS_DIR}"
sudo chmod 600 "${TLS_DIR}/ca/ca.key"
sudo chmod 644 "${TLS_DIR}/ca/ca.crt"

for entry in "${SERVICES[@]}"; do
    IFS='|' read -r name _ _ <<< "$entry"
    sudo chmod 600 "${TLS_DIR}/${name}/server.key"
    sudo chmod 644 "${TLS_DIR}/${name}/server.crt"
    sudo chmod 644 "${TLS_DIR}/${name}/server-bundle.crt"
done

echo -e "  ${GREEN}[OK] File permissions set${NC}"

# Validate all certificates
echo ""
echo -e "${BLUE}Validating Certificates${NC}"
all_valid=true

validate_certificate "${TLS_DIR}/ca/ca.crt" "${TLS_DIR}/ca/ca.key" "Certificate Authority"
if [ $? -ne 0 ]; then all_valid=false; fi

for entry in "${SERVICES[@]}"; do
    IFS='|' read -r name _ _ <<< "$entry"
    validate_certificate "${TLS_DIR}/${name}/server.crt" "${TLS_DIR}/${name}/server.key" "${name}"
    if [ $? -ne 0 ]; then all_valid=false; fi
done

# Create certificate metadata
echo ""
echo -e "${BLUE}Creating Certificate Metadata${NC}"

# Build per-service JSON entries
service_json=""
for entry in "${SERVICES[@]}"; do
    IFS='|' read -r name cn _ <<< "$entry"
    expires=""
    if [ -f "${TLS_DIR}/${name}/server.crt" ]; then
        expires=$(sudo -u ${USER} openssl x509 -in "${TLS_DIR}/${name}/server.crt" -noout -enddate 2>/dev/null | cut -d= -f2 || echo "Unknown")
    fi
    [ -n "$service_json" ] && service_json="${service_json},"
    service_json="${service_json}
    \"${name}\": {
      \"subject\": \"CN=${cn},O=Arkfile,C=US\",
      \"algorithm\": \"${service_algorithms[$name]}\",
      \"key_file\": \"${name}/server.key\",
      \"cert_file\": \"${name}/server.crt\",
      \"bundle_file\": \"${name}/server-bundle.crt\",
      \"expires\": \"${expires}\"
    }"
done

ca_expires=""
if [ -f "${TLS_DIR}/ca/ca.crt" ]; then
    ca_expires=$(sudo -u ${USER} openssl x509 -in "${TLS_DIR}/ca/ca.crt" -noout -enddate 2>/dev/null | cut -d= -f2 || echo "Unknown")
fi

sudo -u ${USER} cat > "${TLS_DIR}/metadata.json" << EOF
{
  "generated": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "domain": "${DOMAIN}",
  "validity_days": ${VALIDITY_DAYS},
  "openssl_version": "$(detect_openssl_version)",
  "preferred_algorithm": "${PREFERRED_ALGORITHM}",
  "certificates": {
    "ca": {
      "subject": "CN=Arkfile-CA,O=Arkfile,C=US",
      "algorithm": "${ca_algorithm}",
      "key_file": "ca/ca.key",
      "cert_file": "ca/ca.crt",
      "expires": "${ca_expires}"
    },${service_json}
  }
}
EOF

if [ -f "${TLS_DIR}/metadata.json" ] && [ -s "${TLS_DIR}/metadata.json" ]; then
    sudo chmod 644 "${TLS_DIR}/metadata.json"
    echo -e "  ${GREEN}[OK] Certificate metadata created${NC}"
else
    echo -e "  ${YELLOW}[WARNING] Certificate metadata creation failed${NC}"
fi

# Summary
echo ""
if [ "$all_valid" = true ]; then
    echo -e "${GREEN}TLS certificate setup completed successfully!${NC}"
else
    echo -e "${YELLOW}[WARNING] TLS certificate setup completed with some issues${NC}"
fi

echo ""
echo -e "${BLUE}Certificate Summary:${NC}"
echo "========================================"
echo "Certificate Authority:"
echo "  Key:  ${TLS_DIR}/ca/ca.key"
echo "  Cert: ${TLS_DIR}/ca/ca.crt"
echo "  Algorithm: ${ca_algorithm^^}"
echo ""
echo "Services:"
for entry in "${SERVICES[@]}"; do
    IFS='|' read -r name _ _ <<< "$entry"
    echo "  ${name}:"
    echo "    Key:    ${TLS_DIR}/${name}/server.key"
    echo "    Cert:   ${TLS_DIR}/${name}/server.crt"
    echo "    Bundle: ${TLS_DIR}/${name}/server-bundle.crt"
    echo "    Algorithm: ${service_algorithms[$name]^^}"
done

echo ""
echo -e "${BLUE}Configuration:${NC}"
echo "========================================"
echo "Arkfile:  TLS_CERT_FILE=${TLS_DIR}/arkfile/server.crt"
echo "          TLS_KEY_FILE=${TLS_DIR}/arkfile/server.key"
echo "          TLS_CA_FILE=${TLS_DIR}/ca/ca.crt"
echo ""
echo "rqlite:   -node-cert=${TLS_DIR}/rqlite/server.crt"
echo "          -node-key=${TLS_DIR}/rqlite/server.key"
echo "          -node-ca-cert=${TLS_DIR}/ca/ca.crt"
echo ""
echo "MinIO:    MINIO_SERVER_CERT=${TLS_DIR}/minio/server.crt"
echo "          MINIO_SERVER_KEY=${TLS_DIR}/minio/server.key"
echo ""
echo "CA cert:  ${TLS_DIR}/ca/ca.crt"
echo ""
echo -e "${YELLOW}Lifecycle:${NC}"
echo "  Validity: ${VALIDITY_DAYS} days"
renewal_days=$((VALIDITY_DAYS - 30))
renewal_date=$(date -d "+${renewal_days} days" '+%Y-%m-%d' 2>/dev/null || echo "N/A")
echo "  Renewal needed before: ${renewal_date}"
echo "  Renew:   ./scripts/maintenance/renew-certificates.sh"
echo "  Monitor: ./scripts/maintenance/validate-certificates.sh"
echo ""
echo -e "${GREEN}[OK] TLS certificates ready for production use!${NC}"

exit 0
