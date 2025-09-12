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
        echo -e "  ${GREEN}✓ ECDSA P-384 key generated successfully${NC}"
        return 0
    else
        echo -e "  ${YELLOW}⚠ ECDSA generation failed, falling back to RSA${NC}"
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
        echo -e "  ${GREEN}✓ RSA ${key_size}-bit key generated successfully${NC}"
        return 0
    else
        echo -e "  ${RED}✗ RSA key generation failed${NC}"
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
    
    echo -e "${RED}✗ Failed to generate private key for ${description}${NC}"
    return 1
}

# Function to create certificate with proper extensions and shorter subject fields
create_certificate() {
    local key_path="$1"
    local cert_path="$2"
    local cn="$3"
    local alt_names="$4"
    local ca_cert="${5:-}"
    local ca_key="${6:-}"
    local description="$7"
    
    echo "Creating certificate for ${description}..."
    
    # Create temporary config file with proper permissions and shorter subject fields
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
${alt_names}

[v3_ca]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign, digitalSignature
subjectKeyIdentifier = hash
EOF

    if [ -n "${ca_cert}" ] && [ -n "${ca_key}" ]; then
        # Create signed certificate
        local csr_file=$(sudo -u ${USER} mktemp)
        sudo chmod 644 "${csr_file}"
        
        # Generate CSR
        sudo -u ${USER} openssl req -new -key "${key_path}" -out "${csr_file}" -config "${config_file}" -extensions v3_req
        if [ $? -ne 0 ]; then
            echo -e "  ${RED}✗ Failed to create certificate request${NC}"
            rm -f "${config_file}" "${csr_file}"
            return 1
        fi
        
        # Sign the certificate
        sudo -u ${USER} openssl x509 -req -in "${csr_file}" -CA "${ca_cert}" -CAkey "${ca_key}" \
            -CAcreateserial -out "${cert_path}" -days ${VALIDITY_DAYS} -sha384 \
            -extensions v3_req -extfile "${config_file}"
        local sign_result=$?
        rm -f "${csr_file}"
    else
        # Create self-signed certificate (for CA)
        sudo -u ${USER} openssl req -new -x509 -key "${key_path}" -out "${cert_path}" \
            -days ${VALIDITY_DAYS} -sha384 -config "${config_file}" -extensions v3_ca
        local sign_result=$?
    fi
    
    rm -f "${config_file}"
    
    if [ $sign_result -eq 0 ]; then
        echo -e "  ${GREEN}✓ Certificate created successfully${NC}"
        return 0
    else
        echo -e "  ${RED}✗ Certificate creation failed${NC}"
        return 1
    fi
}

# Function to validate certificate
validate_certificate() {
    local cert_path="$1"
    local key_path="$2"
    local service_name="$3"
    
    if [ ! -f "${cert_path}" ] || [ ! -f "${key_path}" ]; then
        echo -e "  ${RED}✗ ${service_name}: Missing certificate or key${NC}"
        return 1
    fi
    
    # Check certificate validity
    if sudo -u ${USER} openssl x509 -in "${cert_path}" -noout -checkend 0 >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓ ${service_name}: Certificate valid${NC}"
    else
        echo -e "  ${RED}✗ ${service_name}: Certificate invalid or expired${NC}"
        return 1
    fi
    
    # Verify certificate matches private key
    local cert_pubkey_hash=$(sudo -u ${USER} openssl x509 -in "${cert_path}" -pubkey -noout | openssl sha256)
    local key_pubkey_hash=$(sudo -u ${USER} openssl pkey -in "${key_path}" -pubout | openssl sha256)
    
    if [ "${cert_pubkey_hash}" = "${key_pubkey_hash}" ]; then
        echo -e "  ${GREEN}✓ ${service_name}: Certificate matches private key${NC}"
    else
        echo -e "  ${RED}✗ ${service_name}: Certificate/key mismatch${NC}"
        return 1
    fi
    
    # Show certificate details
    local algorithm=$(sudo -u ${USER} openssl x509 -in "${cert_path}" -noout -text | grep "Public Key Algorithm" | head -1 | awk -F': ' '{print $2}')
    local expires=$(sudo -u ${USER} openssl x509 -in "${cert_path}" -noout -enddate | cut -d= -f2)
    echo -e "  ${BLUE}ℹ ${service_name}: ${algorithm}, expires ${expires}${NC}"
    
    return 0
}

# Check if TLS directory exists
if [ ! -d "${TLS_DIR}" ]; then
    echo -e "${RED}Error: TLS directory ${TLS_DIR} does not exist${NC}"
    echo "Please run setup-directories.sh first"
    exit 1
fi

# Check if certificates already exist
if [ -f "${TLS_DIR}/ca/ca-cert.pem" ]; then
    echo -e "${YELLOW}TLS certificates already exist. Skipping generation.${NC}"
    echo "To regenerate certificates, remove existing files first:"
    echo "  sudo rm -rf ${TLS_DIR}/ca/* ${TLS_DIR}/*/server-* ${TLS_DIR}/*/client-*"
    exit 0
fi

echo "Generating modern TLS certificates for internal services..."
echo "Domain: ${DOMAIN}"
echo "Validity: ${VALIDITY_DAYS} days"
echo "Preferred algorithm: ${PREFERRED_ALGORITHM}"
echo "OpenSSL version: $(detect_openssl_version)"

# Create Certificate Authority
echo ""
echo -e "${BLUE}=== Creating Certificate Authority ===${NC}"
ca_algorithm=$(generate_private_key "${TLS_DIR}/ca/ca.key" "Certificate Authority" 4096)
if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to generate CA private key${NC}"
    exit 1
fi

# Create CA certificate with shorter subject
ca_cn="Arkfile-CA"
ca_alt_names="DNS.1=ca.internal.arkfile,DNS.2=ca.${DOMAIN}"

if create_certificate "${TLS_DIR}/ca/ca.key" "${TLS_DIR}/ca/ca.crt" \
    "${ca_cn}" "${ca_alt_names}" "" "" "Certificate Authority"; then
    echo -e "${GREEN}✓ Certificate Authority created successfully${NC}"
    
    # Create legacy filename copies for backward compatibility
    sudo -u ${USER} cp "${TLS_DIR}/ca/ca.crt" "${TLS_DIR}/ca/ca-cert.pem"
    sudo -u ${USER} cp "${TLS_DIR}/ca/ca.key" "${TLS_DIR}/ca/ca-key.pem"
    echo -e "${GREEN}✓ Legacy CA filenames created for compatibility${NC}"
else
    echo -e "${RED}✗ Failed to create Certificate Authority${NC}"
    exit 1
fi

# Create Arkfile application certificate
echo ""
echo -e "${BLUE}=== Creating Arkfile Application Certificate ===${NC}"
arkfile_algorithm=$(generate_private_key "${TLS_DIR}/arkfile/server-key.pem" "Arkfile Application" 2048)
if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to generate Arkfile private key${NC}"
    exit 1
fi

arkfile_cn="arkfile.${DOMAIN}"
arkfile_alt_names="DNS.1=arkfile.${DOMAIN},DNS.2=${DOMAIN},DNS.3=localhost,DNS.4=arkfile.internal,IP.1=127.0.0.1,IP.2=::1"

if create_certificate "${TLS_DIR}/arkfile/server-key.pem" "${TLS_DIR}/arkfile/server-cert.pem" \
    "${arkfile_cn}" "${arkfile_alt_names}" "${TLS_DIR}/ca/ca-cert.pem" "${TLS_DIR}/ca/ca-key.pem" "Arkfile Application"; then
    echo -e "${GREEN}✓ Arkfile certificate created successfully${NC}"
else
    echo -e "${RED}✗ Failed to create Arkfile certificate${NC}"
    exit 1
fi

# Create rqlite certificate
echo ""
echo -e "${BLUE}=== Creating rqlite Database Certificate ===${NC}"
rqlite_algorithm=$(generate_private_key "${TLS_DIR}/rqlite/server-key.pem" "rqlite Database" 2048)
if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to generate rqlite private key${NC}"
    exit 1
fi

rqlite_cn="rqlite.${DOMAIN}"
rqlite_alt_names="DNS.1=rqlite.${DOMAIN},DNS.2=rqlite.internal,DNS.3=localhost,IP.1=127.0.0.1,IP.2=::1"

if create_certificate "${TLS_DIR}/rqlite/server-key.pem" "${TLS_DIR}/rqlite/server-cert.pem" \
    "${rqlite_cn}" "${rqlite_alt_names}" "${TLS_DIR}/ca/ca.crt" "${TLS_DIR}/ca/ca.key" "rqlite Database"; then
    echo -e "${GREEN}✓ rqlite certificate created successfully${NC}"
    
    # Create health-check compatible filenames
    sudo -u ${USER} cp "${TLS_DIR}/rqlite/server-cert.pem" "${TLS_DIR}/rqlite/server.crt"
    sudo -u ${USER} cp "${TLS_DIR}/rqlite/server-key.pem" "${TLS_DIR}/rqlite/server.key"
    echo -e "${GREEN}✓ Health-check compatible rqlite filenames created${NC}"
else
    echo -e "${RED}✗ Failed to create rqlite certificate${NC}"
    exit 1
fi

# Create MinIO certificate
echo ""
echo -e "${BLUE}=== Creating MinIO Storage Certificate ===${NC}"
minio_algorithm=$(generate_private_key "${TLS_DIR}/minio/server-key.pem" "MinIO Storage" 2048)
if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to generate MinIO private key${NC}"
    exit 1
fi

minio_cn="minio.${DOMAIN}"
minio_alt_names="DNS.1=minio.${DOMAIN},DNS.2=minio.internal,DNS.3=localhost,IP.1=127.0.0.1,IP.2=::1"

if create_certificate "${TLS_DIR}/minio/server-key.pem" "${TLS_DIR}/minio/server-cert.pem" \
    "${minio_cn}" "${minio_alt_names}" "${TLS_DIR}/ca/ca.crt" "${TLS_DIR}/ca/ca.key" "MinIO Storage"; then
    echo -e "${GREEN}✓ MinIO certificate created successfully${NC}"
    
    # Create health-check compatible filenames
    sudo -u ${USER} cp "${TLS_DIR}/minio/server-cert.pem" "${TLS_DIR}/minio/server.crt"
    sudo -u ${USER} cp "${TLS_DIR}/minio/server-key.pem" "${TLS_DIR}/minio/server.key"
    echo -e "${GREEN}✓ Health-check compatible MinIO filenames created${NC}"
else
    echo -e "${RED}✗ Failed to create MinIO certificate${NC}"
    exit 1
fi

# Create certificate bundles
echo ""
echo -e "${BLUE}=== Creating Certificate Bundles ===${NC}"
for service in arkfile rqlite minio; do
    bundle_path="${TLS_DIR}/${service}/server-bundle.pem"
    echo "Creating certificate bundle for ${service}..."
    sudo -u ${USER} cat "${TLS_DIR}/${service}/server-cert.pem" "${TLS_DIR}/ca/ca-cert.pem" > "${bundle_path}"
    if [ $? -eq 0 ]; then
        echo -e "  ${GREEN}✓ ${service} bundle created${NC}"
    else
        echo -e "  ${RED}✗ ${service} bundle creation failed${NC}"
    fi
done

# Set proper permissions
echo ""
echo -e "${BLUE}=== Setting File Permissions ===${NC}"
echo "Setting secure file permissions..."

# Set ownership
sudo chown -R ${USER}:${GROUP} ${TLS_DIR}

# Set permissions for CA files (both naming conventions)
sudo chmod 600 ${TLS_DIR}/ca/ca.key ${TLS_DIR}/ca/ca-key.pem
sudo chmod 644 ${TLS_DIR}/ca/ca.crt ${TLS_DIR}/ca/ca-cert.pem

# Set permissions for service certificates (both naming conventions)
for service in arkfile rqlite minio; do
    if [ -d "${TLS_DIR}/${service}" ]; then
        # Original .pem files
        sudo chmod 600 ${TLS_DIR}/${service}/server-key.pem
        sudo chmod 644 ${TLS_DIR}/${service}/server-cert.pem
        sudo chmod 644 ${TLS_DIR}/${service}/server-bundle.pem
        
        # Health-check compatible files (only for rqlite and minio)
        if [ "$service" = "rqlite" ] || [ "$service" = "minio" ]; then
            [ -f "${TLS_DIR}/${service}/server.key" ] && sudo chmod 600 ${TLS_DIR}/${service}/server.key
            [ -f "${TLS_DIR}/${service}/server.crt" ] && sudo chmod 644 ${TLS_DIR}/${service}/server.crt
        fi
    fi
done

echo -e "  ${GREEN}✓ File permissions set securely${NC}"

# Validate all certificates
echo ""
echo -e "${BLUE}=== Validating Certificates ===${NC}"
all_valid=true

validate_certificate "${TLS_DIR}/ca/ca-cert.pem" "${TLS_DIR}/ca/ca-key.pem" "Certificate Authority"
if [ $? -ne 0 ]; then all_valid=false; fi

validate_certificate "${TLS_DIR}/arkfile/server-cert.pem" "${TLS_DIR}/arkfile/server-key.pem" "Arkfile Application"
if [ $? -ne 0 ]; then all_valid=false; fi

validate_certificate "${TLS_DIR}/rqlite/server-cert.pem" "${TLS_DIR}/rqlite/server-key.pem" "rqlite Database"
if [ $? -ne 0 ]; then all_valid=false; fi

validate_certificate "${TLS_DIR}/minio/server-cert.pem" "${TLS_DIR}/minio/server-key.pem" "MinIO Storage"
if [ $? -ne 0 ]; then all_valid=false; fi

# Create certificate metadata AFTER all certificates are generated
echo ""
echo -e "${BLUE}=== Creating Certificate Metadata ===${NC}"

# Extract certificate expiration dates safely
ca_expires=""
arkfile_expires=""
rqlite_expires=""
minio_expires=""

if [ -f "${TLS_DIR}/ca/ca-cert.pem" ]; then
    ca_expires=$(sudo -u ${USER} openssl x509 -in "${TLS_DIR}/ca/ca-cert.pem" -noout -enddate 2>/dev/null | cut -d= -f2 || echo "Unknown")
fi

if [ -f "${TLS_DIR}/arkfile/server-cert.pem" ]; then
    arkfile_expires=$(sudo -u ${USER} openssl x509 -in "${TLS_DIR}/arkfile/server-cert.pem" -noout -enddate 2>/dev/null | cut -d= -f2 || echo "Unknown")
fi

if [ -f "${TLS_DIR}/rqlite/server-cert.pem" ]; then
    rqlite_expires=$(sudo -u ${USER} openssl x509 -in "${TLS_DIR}/rqlite/server-cert.pem" -noout -enddate 2>/dev/null | cut -d= -f2 || echo "Unknown")
fi

if [ -f "${TLS_DIR}/minio/server-cert.pem" ]; then
    minio_expires=$(sudo -u ${USER} openssl x509 -in "${TLS_DIR}/minio/server-cert.pem" -noout -enddate 2>/dev/null | cut -d= -f2 || echo "Unknown")
fi

# Create metadata.json with proper variable expansion
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
      "key_file": "ca/ca-key.pem",
      "cert_file": "ca/ca-cert.pem",
      "expires": "${ca_expires}"
    },
    "arkfile": {
      "subject": "CN=${arkfile_cn},O=Arkfile,C=US",
      "algorithm": "${arkfile_algorithm}",
      "key_file": "arkfile/server-key.pem",
      "cert_file": "arkfile/server-cert.pem",
      "bundle_file": "arkfile/server-bundle.pem",
      "expires": "${arkfile_expires}"
    },
    "rqlite": {
      "subject": "CN=${rqlite_cn},O=Arkfile,C=US",
      "algorithm": "${rqlite_algorithm}",
      "key_file": "rqlite/server-key.pem",
      "cert_file": "rqlite/server-cert.pem",
      "bundle_file": "rqlite/server-bundle.pem",
      "expires": "${rqlite_expires}"
    },
    "minio": {
      "subject": "CN=${minio_cn},O=Arkfile,C=US",
      "algorithm": "${minio_algorithm}",
      "key_file": "minio/server-key.pem",
      "cert_file": "minio/server-cert.pem",
      "bundle_file": "minio/server-bundle.pem",
      "expires": "${minio_expires}"
    }
  }
}
EOF

# Validate metadata creation
if [ -f "${TLS_DIR}/metadata.json" ] && [ -s "${TLS_DIR}/metadata.json" ]; then
    sudo chmod 644 "${TLS_DIR}/metadata.json"
    echo -e "  ${GREEN}✓ Certificate metadata created successfully${NC}"
else
    echo -e "  ${YELLOW}⚠ Certificate metadata creation failed, continuing without metadata${NC}"
fi

# Final summary
echo ""
if [ "$all_valid" = true ]; then
    echo -e "${GREEN}TLS certificate setup completed successfully!${NC}"
else
    echo -e "${YELLOW}⚠️  TLS certificate setup completed with some issues${NC}"
fi

echo ""
echo -e "${BLUE}📋 Certificate Summary:${NC}"
echo "========================================"
echo "Certificate Authority:"
echo "  Key: ${TLS_DIR}/ca/ca-key.pem"
echo "  Certificate: ${TLS_DIR}/ca/ca-cert.pem"
echo "  Algorithm: ${ca_algorithm^^}"
echo ""
echo "Application Services:"
for service in arkfile rqlite minio; do
    service_var="${service}_algorithm"
    algorithm=${!service_var}
    echo "  ${service}:"
    echo "    Key: ${TLS_DIR}/${service}/server-key.pem"
    echo "    Certificate: ${TLS_DIR}/${service}/server-cert.pem"
    echo "    Bundle: ${TLS_DIR}/${service}/server-bundle.pem"
    echo "    Algorithm: ${algorithm^^}"
done

echo ""
echo -e "${BLUE}🔧 Configuration Instructions:${NC}"
echo "========================================"
echo "1. Configure Arkfile application:"
echo "   TLS_CERT_FILE=${TLS_DIR}/arkfile/server-cert.pem"
echo "   TLS_KEY_FILE=${TLS_DIR}/arkfile/server-key.pem"
echo "   TLS_CA_FILE=${TLS_DIR}/ca/ca-cert.pem"
echo ""
echo "2. Configure rqlite cluster:"
echo "   -node-cert=${TLS_DIR}/rqlite/server-cert.pem"
echo "   -node-key=${TLS_DIR}/rqlite/server-key.pem"
echo "   -node-ca-cert=${TLS_DIR}/ca/ca-cert.pem"
echo ""
echo "3. Configure MinIO storage:"
echo "   MINIO_SERVER_CERT=${TLS_DIR}/minio/server-cert.pem"
echo "   MINIO_SERVER_KEY=${TLS_DIR}/minio/server-key.pem"
echo ""
echo "4. Distribute CA certificate to clients:"
echo "   ${TLS_DIR}/ca/ca-cert.pem"
echo ""
echo -e "${YELLOW}⏰ Certificate Lifecycle:${NC}"
echo "========================================"
echo "• Validity: ${VALIDITY_DAYS} days"
renewal_days=$((VALIDITY_DAYS - 30))
renewal_date=$(date -d "+${renewal_days} days" '+%Y-%m-%d' 2>/dev/null || echo "N/A")
echo "• Renewal needed before: ${renewal_date}"
echo "• Use ./scripts/renew-certificates.sh for renewal"
echo "• Monitor expiration with ./scripts/validate-certificates.sh"
echo ""
echo -e "${GREEN}✅ Modern TLS certificates ready for production use!${NC}"

exit 0
