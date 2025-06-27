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
WARNING_DAYS=30

echo -e "${BLUE}🔍 Arkfile TLS Certificate Validation${NC}"
echo "========================================"

# Function to check certificate expiration
check_certificate_expiry() {
    local cert_path="$1"
    local service_name="$2"
    local warning_days="${3:-30}"
    
    if [ ! -f "${cert_path}" ]; then
        echo -e "  ${RED}✗ ${service_name}: Certificate not found${NC}"
        return 1
    fi
    
    # Get certificate expiration date
    local expiry_date=$(sudo -u ${USER} openssl x509 -in "${cert_path}" -noout -enddate 2>/dev/null | cut -d= -f2)
    if [ -z "${expiry_date}" ]; then
        echo -e "  ${RED}✗ ${service_name}: Cannot read certificate expiration${NC}"
        return 1
    fi
    
    # Convert to epoch time
    local expiry_epoch=$(date -d "${expiry_date}" +%s 2>/dev/null)
    local current_epoch=$(date +%s)
    local warning_epoch=$((current_epoch + warning_days * 24 * 3600))
    
    if [ ${expiry_epoch} -lt ${current_epoch} ]; then
        echo -e "  ${RED}✗ ${service_name}: Certificate EXPIRED (${expiry_date})${NC}"
        return 1
    elif [ ${expiry_epoch} -lt ${warning_epoch} ]; then
        local days_left=$(( (expiry_epoch - current_epoch) / 86400 ))
        echo -e "  ${YELLOW}⚠ ${service_name}: Certificate expires in ${days_left} days (${expiry_date})${NC}"
        return 2
    else
        local days_left=$(( (expiry_epoch - current_epoch) / 86400 ))
        echo -e "  ${GREEN}✓ ${service_name}: Certificate valid for ${days_left} days (${expiry_date})${NC}"
        return 0
    fi
}

# Function to validate certificate key pair
validate_key_pair() {
    local cert_path="$1"
    local key_path="$2"
    local service_name="$3"
    
    if [ ! -f "${cert_path}" ] || [ ! -f "${key_path}" ]; then
        echo -e "  ${RED}✗ ${service_name}: Missing certificate or key file${NC}"
        return 1
    fi
    
    # Get public key hashes
    local cert_hash=$(sudo -u ${USER} openssl x509 -in "${cert_path}" -pubkey -noout 2>/dev/null | openssl sha256 2>/dev/null)
    local key_hash=$(sudo -u ${USER} openssl pkey -in "${key_path}" -pubout 2>/dev/null | openssl sha256 2>/dev/null)
    
    if [ -z "${cert_hash}" ] || [ -z "${key_hash}" ]; then
        echo -e "  ${RED}✗ ${service_name}: Cannot read certificate or key${NC}"
        return 1
    fi
    
    if [ "${cert_hash}" = "${key_hash}" ]; then
        echo -e "  ${GREEN}✓ ${service_name}: Certificate and key match${NC}"
        return 0
    else
        echo -e "  ${RED}✗ ${service_name}: Certificate and key DO NOT match${NC}"
        return 1
    fi
}

# Function to get certificate details
get_certificate_details() {
    local cert_path="$1"
    local service_name="$2"
    
    if [ ! -f "${cert_path}" ]; then
        return 1
    fi
    
    echo -e "  ${BLUE}ℹ ${service_name} Details:${NC}"
    
    # Get subject
    local subject=$(sudo -u ${USER} openssl x509 -in "${cert_path}" -noout -subject 2>/dev/null | sed 's/subject=//')
    echo "    Subject: ${subject}"
    
    # Get issuer
    local issuer=$(sudo -u ${USER} openssl x509 -in "${cert_path}" -noout -issuer 2>/dev/null | sed 's/issuer=//')
    echo "    Issuer: ${issuer}"
    
    # Get serial number
    local serial=$(sudo -u ${USER} openssl x509 -in "${cert_path}" -noout -serial 2>/dev/null | cut -d= -f2)
    echo "    Serial: ${serial}"
    
    # Get algorithm
    local algorithm=$(sudo -u ${USER} openssl x509 -in "${cert_path}" -noout -text 2>/dev/null | grep "Public Key Algorithm" | head -1 | awk -F': ' '{print $2}')
    echo "    Algorithm: ${algorithm}"
    
    # Get key size
    local key_size=$(sudo -u ${USER} openssl x509 -in "${cert_path}" -noout -text 2>/dev/null | grep -A1 "Public Key Algorithm" | grep "Public-Key:" | awk '{print $2}')
    if [ -n "${key_size}" ]; then
        echo "    Key Size: ${key_size}"
    fi
    
    # Get SAN entries
    local san=$(sudo -u ${USER} openssl x509 -in "${cert_path}" -noout -text 2>/dev/null | grep -A1 "Subject Alternative Name" | tail -1 | sed 's/^ *//')
    if [ -n "${san}" ] && [ "${san}" != "Subject Alternative Name" ]; then
        echo "    SAN: ${san}"
    fi
    
    echo ""
}

# Function to check certificate chain
validate_certificate_chain() {
    local cert_path="$1"
    local ca_path="$2"
    local service_name="$3"
    
    if [ ! -f "${cert_path}" ] || [ ! -f "${ca_path}" ]; then
        return 1
    fi
    
    # Verify certificate against CA
    if sudo -u ${USER} openssl verify -CAfile "${ca_path}" "${cert_path}" >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓ ${service_name}: Certificate chain valid${NC}"
        return 0
    else
        echo -e "  ${RED}✗ ${service_name}: Certificate chain invalid${NC}"
        return 1
    fi
}

# Check if TLS directory exists
if [ ! -d "${TLS_DIR}" ]; then
    echo -e "${RED}Error: TLS directory ${TLS_DIR} does not exist${NC}"
    echo "Run ./scripts/setup-tls-certs.sh to generate certificates"
    exit 1
fi

# Check if metadata exists
if [ -f "${TLS_DIR}/metadata.json" ]; then
    echo -e "${BLUE}📋 Certificate Metadata:${NC}"
    if command -v jq >/dev/null 2>&1; then
        sudo -u ${USER} jq -r '
            "Generated: " + .generated + 
            "\nDomain: " + .domain + 
            "\nValidity: " + (.validity_days|tostring) + " days" + 
            "\nAlgorithm: " + .preferred_algorithm + 
            "\nOpenSSL: " + .openssl_version
        ' "${TLS_DIR}/metadata.json" | while read line; do
            echo "  ${line}"
        done
    else
        echo "  (install jq for detailed metadata display)"
    fi
    echo ""
fi

# Validation counters
total_checks=0
passed_checks=0
warning_checks=0
failed_checks=0

echo -e "${BLUE}🔐 Certificate Expiration Check:${NC}"
echo "========================================"

# Check CA certificate
total_checks=$((total_checks + 1))
if check_certificate_expiry "${TLS_DIR}/ca/ca-cert.pem" "Certificate Authority" ${WARNING_DAYS}; then
    case $? in
        0) passed_checks=$((passed_checks + 1)) ;;
        2) warning_checks=$((warning_checks + 1)) ;;
        *) failed_checks=$((failed_checks + 1)) ;;
    esac
else
    failed_checks=$((failed_checks + 1))
fi

# Check service certificates
for service in arkfile rqlite minio; do
    cert_path="${TLS_DIR}/${service}/server-cert.pem"
    if [ -f "${cert_path}" ]; then
        total_checks=$((total_checks + 1))
        if check_certificate_expiry "${cert_path}" "${service}" ${WARNING_DAYS}; then
            case $? in
                0) passed_checks=$((passed_checks + 1)) ;;
                2) warning_checks=$((warning_checks + 1)) ;;
                *) failed_checks=$((failed_checks + 1)) ;;
            esac
        else
            failed_checks=$((failed_checks + 1))
        fi
    fi
done

echo ""
echo -e "${BLUE}🔑 Certificate-Key Pair Validation:${NC}"
echo "========================================"

# Validate CA key pair
total_checks=$((total_checks + 1))
if validate_key_pair "${TLS_DIR}/ca/ca-cert.pem" "${TLS_DIR}/ca/ca-key.pem" "Certificate Authority"; then
    passed_checks=$((passed_checks + 1))
else
    failed_checks=$((failed_checks + 1))
fi

# Validate service key pairs
for service in arkfile rqlite minio; do
    cert_path="${TLS_DIR}/${service}/server-cert.pem"
    key_path="${TLS_DIR}/${service}/server-key.pem"
    if [ -f "${cert_path}" ] && [ -f "${key_path}" ]; then
        total_checks=$((total_checks + 1))
        if validate_key_pair "${cert_path}" "${key_path}" "${service}"; then
            passed_checks=$((passed_checks + 1))
        else
            failed_checks=$((failed_checks + 1))
        fi
    fi
done

echo ""
echo -e "${BLUE}🔗 Certificate Chain Validation:${NC}"
echo "========================================"

# Validate certificate chains
ca_cert="${TLS_DIR}/ca/ca-cert.pem"
if [ -f "${ca_cert}" ]; then
    for service in arkfile rqlite minio; do
        cert_path="${TLS_DIR}/${service}/server-cert.pem"
        if [ -f "${cert_path}" ]; then
            total_checks=$((total_checks + 1))
            if validate_certificate_chain "${cert_path}" "${ca_cert}" "${service}"; then
                passed_checks=$((passed_checks + 1))
            else
                failed_checks=$((failed_checks + 1))
            fi
        fi
    done
fi

# Show detailed certificate information if requested
if [ "$1" = "--details" ] || [ "$1" = "-d" ]; then
    echo ""
    echo -e "${BLUE}📄 Certificate Details:${NC}"
    echo "========================================"
    
    get_certificate_details "${TLS_DIR}/ca/ca-cert.pem" "Certificate Authority"
    
    for service in arkfile rqlite minio; do
        cert_path="${TLS_DIR}/${service}/server-cert.pem"
        if [ -f "${cert_path}" ]; then
            get_certificate_details "${cert_path}" "${service}"
        fi
    done
fi

# Summary
echo ""
echo -e "${BLUE}📊 Validation Summary:${NC}"
echo "========================================"
echo "Total checks: ${total_checks}"
echo -e "Passed: ${GREEN}${passed_checks}${NC}"
if [ ${warning_checks} -gt 0 ]; then
    echo -e "Warnings: ${YELLOW}${warning_checks}${NC}"
fi
if [ ${failed_checks} -gt 0 ]; then
    echo -e "Failed: ${RED}${failed_checks}${NC}"
fi

# Recommendations
echo ""
if [ ${failed_checks} -gt 0 ]; then
    echo -e "${RED}❌ Certificate validation failed!${NC}"
    echo -e "${YELLOW}Recommendations:${NC}"
    echo "• Regenerate failed certificates: sudo ./scripts/setup-tls-certs.sh"
    echo "• Check file permissions and ownership"
    echo "• Verify certificate authority integrity"
    exit 1
elif [ ${warning_checks} -gt 0 ]; then
    echo -e "${YELLOW}⚠️  Certificate renewal recommended${NC}"
    echo -e "${YELLOW}Recommendations:${NC}"
    echo "• Plan certificate renewal before expiration"
    echo "• Create calendar reminders for renewal"
    echo "• Consider automated renewal setup"
    exit 2
else
    echo -e "${GREEN}✅ All certificates are valid and healthy!${NC}"
    echo -e "${BLUE}Recommendations:${NC}"
    echo "• Set up automated monitoring"
    echo "• Schedule regular validation checks"
    echo "• Plan renewal process before expiration"
fi

echo ""
echo -e "${BLUE}📞 Support Commands:${NC}"
echo "========================================"
echo "• Regenerate certificates: sudo ./scripts/setup-tls-certs.sh"
echo "• Detailed validation: ./scripts/validate-certificates.sh --details"
echo "• Certificate renewal: ./scripts/renew-certificates.sh (when available)"
echo "• Emergency help: ./scripts/emergency-procedures.sh"

exit 0
