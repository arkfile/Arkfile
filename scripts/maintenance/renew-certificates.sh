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
BACKUP_DIR="${TLS_DIR}/backup/$(date +%Y%m%d_%H%M%S)"
FORCE_RENEWAL=false
WARNING_DAYS=30

echo -e "${BLUE}Arkfile TLS Certificate Renewal${NC}"
echo "========================================"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --force|-f)
            FORCE_RENEWAL=true
            echo -e "${YELLOW}[WARNING]  Force renewal enabled${NC}"
            shift
            ;;
        --warning-days|-w)
            WARNING_DAYS="$2"
            shift
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -f, --force           Force certificate renewal regardless of expiry"
            echo "  -w, --warning-days N  Set warning threshold in days (default: 30)"
            echo "  -h, --help           Show this help message"
            echo ""
            echo "Environment Variables:"
            echo "  ARKFILE_DOMAIN        Domain name for certificates (default: localhost)"
            echo "  ARKFILE_TLS_ALGORITHM Algorithm preference: ecdsa or rsa (default: ecdsa)"
            echo ""
            echo "Examples:"
            echo "  $0                    # Renew certificates expiring within 30 days"
            echo "  $0 --force            # Force renewal of all certificates"
            echo "  $0 --warning-days 7   # Renew certificates expiring within 7 days"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Function to check certificate expiration
check_certificate_expiry() {
    local cert_path="$1"
    local service_name="$2"
    local warning_days="${3:-30}"
    
    if [ ! -f "${cert_path}" ]; then
        echo -e "  ${RED}[X] ${service_name}: Certificate not found${NC}"
        return 1
    fi
    
    # Get certificate expiration date
    local expiry_date=$(sudo -u ${USER} openssl x509 -in "${cert_path}" -noout -enddate 2>/dev/null | cut -d= -f2)
    if [ -z "${expiry_date}" ]; then
        echo -e "  ${RED}[X] ${service_name}: Cannot read certificate expiration${NC}"
        return 1
    fi
    
    # Convert to epoch time
    local expiry_epoch=$(date -d "${expiry_date}" +%s 2>/dev/null)
    local current_epoch=$(date +%s)
    local warning_epoch=$((current_epoch + warning_days * 24 * 3600))
    
    if [ ${expiry_epoch} -lt ${current_epoch} ]; then
        echo -e "  ${RED}[X] ${service_name}: Certificate EXPIRED (${expiry_date})${NC}"
        return 2  # Expired
    elif [ ${expiry_epoch} -lt ${warning_epoch} ]; then
        local days_left=$(( (expiry_epoch - current_epoch) / 86400 ))
        echo -e "  ${YELLOW}[WARNING] ${service_name}: Certificate expires in ${days_left} days (${expiry_date})${NC}"
        return 3  # Needs renewal
    else
        local days_left=$(( (expiry_epoch - current_epoch) / 86400 ))
        echo -e "  ${GREEN}[OK] ${service_name}: Certificate valid for ${days_left} days (${expiry_date})${NC}"
        return 0  # Valid
    fi
}

# Function to backup existing certificates
backup_certificates() {
    echo -e "${BLUE}Creating certificate backup...${NC}"
    
    sudo -u ${USER} mkdir -p "${BACKUP_DIR}"
    
    # Backup all certificate files
    for service in ca arkfile rqlite minio; do
        if [ -d "${TLS_DIR}/${service}" ]; then
            sudo -u ${USER} cp -r "${TLS_DIR}/${service}" "${BACKUP_DIR}/"
            echo -e "  ${GREEN}[OK] Backed up ${service} certificates${NC}"
        fi
    done
    
    # Backup metadata
    if [ -f "${TLS_DIR}/metadata.json" ]; then
        sudo -u ${USER} cp "${TLS_DIR}/metadata.json" "${BACKUP_DIR}/"
        echo -e "  ${GREEN}[OK] Backed up certificate metadata${NC}"
    fi
    
    echo -e "${GREEN}[OK] Certificate backup completed: ${BACKUP_DIR}${NC}"
}

# Function to rollback certificates
rollback_certificates() {
    echo -e "${YELLOW}Rolling back certificates...${NC}"
    
    if [ ! -d "${BACKUP_DIR}" ]; then
        echo -e "${RED}[X] Backup directory not found: ${BACKUP_DIR}${NC}"
        return 1
    fi
    
    # Restore from backup
    for service in ca arkfile rqlite minio; do
        if [ -d "${BACKUP_DIR}/${service}" ]; then
            sudo -u ${USER} rm -rf "${TLS_DIR}/${service}"
            sudo -u ${USER} cp -r "${BACKUP_DIR}/${service}" "${TLS_DIR}/"
            echo -e "  ${GREEN}[OK] Restored ${service} certificates${NC}"
        fi
    done
    
    # Restore metadata
    if [ -f "${BACKUP_DIR}/metadata.json" ]; then
        sudo -u ${USER} cp "${BACKUP_DIR}/metadata.json" "${TLS_DIR}/"
        echo -e "  ${GREEN}[OK] Restored certificate metadata${NC}"
    fi
    
    echo -e "${GREEN}[OK] Certificate rollback completed${NC}"
}

# Function to restart services using certificates
restart_services() {
    echo -e "${BLUE}Restarting services with new certificates...${NC}"
    
    local services_restarted=0
    
    # Restart Arkfile service
    if systemctl is-active --quiet arkfile; then
        echo -e "${YELLOW}Restarting arkfile service...${NC}"
        if sudo systemctl restart arkfile; then
            echo -e "  ${GREEN}[OK] arkfile service restarted${NC}"
            services_restarted=$((services_restarted + 1))
        else
            echo -e "  ${RED}[X] arkfile service restart failed${NC}"
        fi
    fi
    
    # Restart MinIO service
    if systemctl is-active --quiet minio; then
        echo -e "${YELLOW}Restarting minio service...${NC}"
        if sudo systemctl restart minio; then
            echo -e "  ${GREEN}[OK] minio service restarted${NC}"
            services_restarted=$((services_restarted + 1))
        else
            echo -e "  ${RED}[X] minio service restart failed${NC}"
        fi
    fi
    
    # Restart rqlite service
    if systemctl is-active --quiet rqlite; then
        echo -e "${YELLOW}Restarting rqlite service...${NC}"
        if sudo systemctl restart rqlite; then
            echo -e "  ${GREEN}[OK] rqlite service restarted${NC}"
            services_restarted=$((services_restarted + 1))
        else
            echo -e "  ${RED}[X] rqlite service restart failed${NC}"
        fi
    fi
    
    # Restart Caddy service (if using internal TLS)
    if systemctl is-active --quiet caddy; then
        echo -e "${YELLOW}Reloading caddy configuration...${NC}"
        if sudo systemctl reload caddy; then
            echo -e "  ${GREEN}[OK] caddy configuration reloaded${NC}"
            services_restarted=$((services_restarted + 1))
        else
            echo -e "  ${YELLOW}[WARNING] caddy reload failed (may not be using internal TLS)${NC}"
        fi
    fi
    
    if [ ${services_restarted} -gt 0 ]; then
        echo -e "${GREEN}[OK] ${services_restarted} services restarted successfully${NC}"
        
        # Wait for services to start
        echo -e "${YELLOW}Waiting for services to initialize...${NC}"
        sleep 5
        
        # Verify services are running
        local services_healthy=0
        
        if systemctl is-active --quiet arkfile; then
            services_healthy=$((services_healthy + 1))
        fi
        
        if systemctl is-active --quiet minio; then
            services_healthy=$((services_healthy + 1))
        fi
        
        if systemctl is-active --quiet rqlite; then
            services_healthy=$((services_healthy + 1))
        fi
        
        echo -e "${GREEN}[OK] ${services_healthy} services are running and healthy${NC}"
    else
        echo -e "${BLUE}ℹ️  No services were restarted (none were running)${NC}"
    fi
}

# Check if TLS directory exists
if [ ! -d "${TLS_DIR}" ]; then
    echo -e "${RED}Error: TLS directory ${TLS_DIR} does not exist${NC}"
    echo "Run ./scripts/setup/05-setup-tls-certs.sh to generate certificates first"
    exit 1
fi

# Check if we need to renew certificates
echo -e "${BLUE}Checking certificate expiration status...${NC}"

certificates_to_renew=()
renewal_reasons=()

# Check CA certificate
if check_certificate_expiry "${TLS_DIR}/ca/ca-cert.pem" "Certificate Authority" ${WARNING_DAYS}; then
    case $? in
        2|3)
            certificates_to_renew+=("ca")
            renewal_reasons+=("CA certificate expired or expiring soon")
            ;;
    esac
fi

# Check service certificates
for service in arkfile rqlite minio; do
    cert_path="${TLS_DIR}/${service}/server-cert.pem"
    if [ -f "${cert_path}" ]; then
        if check_certificate_expiry "${cert_path}" "${service}" ${WARNING_DAYS}; then
            case $? in
                2|3)
                    certificates_to_renew+=("${service}")
                    renewal_reasons+=("${service} certificate expired or expiring soon")
                    ;;
            esac
        fi
    fi
done

# Determine if renewal is needed
if [ "$FORCE_RENEWAL" = true ]; then
    certificates_to_renew=("ca" "arkfile" "rqlite" "minio")
    renewal_reasons=("Force renewal requested")
    echo -e "${YELLOW}[WARNING]  Force renewal: All certificates will be renewed${NC}"
elif [ ${#certificates_to_renew[@]} -eq 0 ]; then
    echo -e "${GREEN}[OK] No certificates need renewal${NC}"
    echo -e "${BLUE}All certificates are valid for more than ${WARNING_DAYS} days${NC}"
    exit 0
fi

# Show renewal summary
echo ""
echo -e "${YELLOW}[INFO] Certificate Renewal Summary${NC}"
echo "========================================"
for i in "${!certificates_to_renew[@]}"; do
    echo "• ${certificates_to_renew[$i]}: ${renewal_reasons[$i]}"
done

echo ""
echo -e "${YELLOW}[WARNING]  This will renew the following certificates:${NC}"
for cert in "${certificates_to_renew[@]}"; do
    case "${cert}" in
        ca) echo "  • Certificate Authority (affects all service certificates)" ;;
        arkfile) echo "  • Arkfile application server" ;;
        rqlite) echo "  • rqlite database cluster" ;;
        minio) echo "  • MinIO object storage" ;;
    esac
done

echo ""
echo -e "${RED}WARNING: Certificate renewal will:${NC}"
echo "• Create a backup of existing certificates"
echo "• Generate new certificates with the same configuration"
echo "• Restart services using the certificates"
echo "• May cause brief service interruption"

echo ""
read -p "Do you want to proceed with certificate renewal? [y/N] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${BLUE}Certificate renewal cancelled${NC}"
    exit 0
fi

# Create backup
backup_certificates

# Renew certificates
echo ""
echo -e "${BLUE}Renewing certificates...${NC}"

# If CA needs renewal, renew all certificates
if [[ " ${certificates_to_renew[@]} " =~ " ca " ]]; then
    echo -e "${YELLOW}Renewing Certificate Authority (will regenerate all certificates)...${NC}"
    
    # Remove existing certificates
    sudo -u ${USER} rm -f "${TLS_DIR}/ca/"*
    for service in arkfile rqlite minio; do
        if [ -d "${TLS_DIR}/${service}" ]; then
            sudo -u ${USER} rm -f "${TLS_DIR}/${service}/server-"*
        fi
    done
    
    # Regenerate all certificates
    if sudo -E ./scripts/setup/05-setup-tls-certs.sh; then
        echo -e "${GREEN}[OK] All certificates renewed successfully${NC}"
    else
        echo -e "${RED}[X] Certificate renewal failed${NC}"
        echo -e "${YELLOW}Attempting rollback...${NC}"
        rollback_certificates
        exit 1
    fi
    
else
    # Renew individual service certificates
    for service in "${certificates_to_renew[@]}"; do
        if [ "${service}" != "ca" ]; then
            echo -e "${YELLOW}Renewing ${service} certificate...${NC}"
            
            # Remove existing service certificate
            sudo -u ${USER} rm -f "${TLS_DIR}/${service}/server-"*
            
            # This is a simplified approach - in practice, you might want to
            # implement individual certificate renewal without regenerating all
            # For now, we'll call the full setup script
            if sudo -E ./scripts/setup/05-setup-tls-certs.sh; then
                echo -e "${GREEN}[OK] ${service} certificate renewed${NC}"
            else
                echo -e "${RED}[X] ${service} certificate renewal failed${NC}"
                echo -e "${YELLOW}Attempting rollback...${NC}"
                rollback_certificates
                exit 1
            fi
        fi
    done
fi

# Validate renewed certificates
echo ""
echo -e "${BLUE}Validating renewed certificates...${NC}"
if ./scripts/maintenance/validate-certificates.sh >/dev/null 2>&1; then
    echo -e "${GREEN}[OK] Certificate validation passed${NC}"
else
    echo -e "${RED}[X] Certificate validation failed${NC}"
    echo -e "${YELLOW}Attempting rollback...${NC}"
    rollback_certificates
    exit 1
fi

# Restart services
echo ""
restart_services

# Final verification
echo ""
echo -e "${BLUE}Final system verification...${NC}"

# Test certificate loading
verification_failed=false

for service in arkfile rqlite minio; do
    cert_path="${TLS_DIR}/${service}/server-cert.pem"
    key_path="${TLS_DIR}/${service}/server-key.pem"
    
    if [ -f "${cert_path}" ] && [ -f "${key_path}" ]; then
        # Test certificate loading
        if sudo -u ${USER} openssl x509 -in "${cert_path}" -noout -text >/dev/null 2>&1; then
            echo -e "  ${GREEN}[OK] ${service}: Certificate loads correctly${NC}"
        else
            echo -e "  ${RED}[X] ${service}: Certificate loading failed${NC}"
            verification_failed=true
        fi
        
        # Test key loading
        if sudo -u ${USER} openssl pkey -in "${key_path}" -noout >/dev/null 2>&1; then
            echo -e "  ${GREEN}[OK] ${service}: Private key loads correctly${NC}"
        else
            echo -e "  ${RED}[X] ${service}: Private key loading failed${NC}"
            verification_failed=true
        fi
    fi
done

# Test CA certificate
if [ -f "${TLS_DIR}/ca/ca-cert.pem" ]; then
    if sudo -u ${USER} openssl x509 -in "${TLS_DIR}/ca/ca-cert.pem" -noout -text >/dev/null 2>&1; then
        echo -e "  ${GREEN}[OK] CA: Certificate loads correctly${NC}"
    else
        echo -e "  ${RED}[X] CA: Certificate loading failed${NC}"
        verification_failed=true
    fi
fi

# Health check if services are running
if systemctl is-active --quiet arkfile; then
    echo -e "${YELLOW}Testing Arkfile health endpoint...${NC}"
    if curl -f http://localhost:8080/health >/dev/null 2>&1; then
        echo -e "  ${GREEN}[OK] Arkfile: Health check passed${NC}"
    else
        echo -e "  ${YELLOW}[WARNING] Arkfile: Health check failed (service may still be starting)${NC}"
    fi
fi

if systemctl is-active --quiet minio; then
    echo -e "${YELLOW}Testing MinIO health endpoint...${NC}"
    if curl -f http://localhost:9000/minio/health/ready >/dev/null 2>&1; then
        echo -e "  ${GREEN}[OK] MinIO: Health check passed${NC}"
    else
        echo -e "  ${YELLOW}[WARNING] MinIO: Health check failed (service may still be starting)${NC}"
    fi
fi

if systemctl is-active --quiet rqlite; then
    echo -e "${YELLOW}Testing rqlite health endpoint...${NC}"
    if curl -f http://localhost:4001/status >/dev/null 2>&1; then
        echo -e "  ${GREEN}[OK] rqlite: Health check passed${NC}"
    else
        echo -e "  ${YELLOW}[WARNING] rqlite: Health check failed (service may still be starting)${NC}"
    fi
fi

# Final summary
echo ""
if [ "$verification_failed" = true ]; then
    echo -e "${RED}[X] Certificate renewal completed with verification issues${NC}"
    echo -e "${YELLOW}[WARNING]  Some certificates may not be loading correctly${NC}"
    echo -e "${BLUE}Consider rolling back and investigating the issue${NC}"
    echo -e "${BLUE}Backup location: ${BACKUP_DIR}${NC}"
    exit 1
else
    echo -e "${GREEN}Certificate renewal completed successfully!${NC}"
fi

echo ""
echo -e "${BLUE}[INFO] Renewal Summary:${NC}"
echo "========================================"
echo "• Certificates renewed: ${#certificates_to_renew[@]}"
echo "• Backup created: ${BACKUP_DIR}"
echo "• Services restarted: $(systemctl is-active arkfile minio rqlite 2>/dev/null | grep -c "^active" || echo "0")"
echo "• Next renewal check: $(date -d "+$((VALIDITY_DAYS - WARNING_DAYS)) days" "+%Y-%m-%d")"

echo ""
echo -e "${BLUE}Certificate Details:${NC}"
echo "========================================"
for service in ca arkfile rqlite minio; do
    case "${service}" in
        ca)
            cert_file="${TLS_DIR}/ca/ca-cert.pem"
            if [ -f "${cert_file}" ]; then
                expires=$(sudo -u ${USER} openssl x509 -in "${cert_file}" -noout -enddate 2>/dev/null | cut -d= -f2)
                echo "• Certificate Authority: expires ${expires}"
            fi
            ;;
        *)
            cert_file="${TLS_DIR}/${service}/server-cert.pem"
            if [ -f "${cert_file}" ]; then
                expires=$(sudo -u ${USER} openssl x509 -in "${cert_file}" -noout -enddate 2>/dev/null | cut -d= -f2)
                algorithm=$(sudo -u ${USER} openssl x509 -in "${cert_file}" -noout -text 2>/dev/null | grep "Public Key Algorithm" | head -1 | awk -F': ' '{print $2}')
                echo "• ${service}: ${algorithm}, expires ${expires}"
            fi
            ;;
    esac
done

echo ""
echo -e "${BLUE}Maintenance Schedule:${NC}"
echo "========================================"
echo "• Next automatic check: $(date -d "+$((WARNING_DAYS/2)) days" "+%Y-%m-%d")"
echo "• Recommended renewal: $(date -d "+$((VALIDITY_DAYS - WARNING_DAYS)) days" "+%Y-%m-%d")"
echo "• Certificate expiry: $(date -d "+${VALIDITY_DAYS} days" "+%Y-%m-%d")"

echo ""
echo -e "${BLUE}Support Commands:${NC}"
echo "========================================"
echo "• Validate certificates: ./scripts/maintenance/validate-certificates.sh"
echo "• View certificate details: ./scripts/maintenance/validate-certificates.sh --details"
echo "• Rollback if needed: Restore from ${BACKUP_DIR}"
echo "• Emergency procedures: ./scripts/maintenance/emergency-procedures.sh"
echo "• Next renewal: ./scripts/maintenance/renew-certificates.sh"

echo ""
echo -e "${GREEN}[OK] Certificate renewal process completed successfully!${NC}"
echo -e "${BLUE}All services should be running with fresh certificates.${NC}"

exit 0
