// security.js - Common security functions and TLS version checking

// Styles for the security banner
const bannerStyles = `
.security-banner {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    padding: 12px;
    background-color: #fff3cd;
    border-bottom: 1px solid #ffeeba;
    color: #856404;
    z-index: 1000;
    font-family: system-ui, -apple-system, sans-serif;
    display: none;
}

.security-banner.warning {
    background-color: #fff3cd;
    border-color: #ffeeba;
    color: #856404;
}

.banner-content {
    max-width: 1200px;
    margin: 0 auto;
    display: flex;
    align-items: center;
    gap: 12px;
}

.banner-icon {
    flex-shrink: 0;
}

.banner-message {
    flex-grow: 1;
}

.banner-learn-more {
    color: inherit;
    text-decoration: underline;
    margin-left: 12px;
}

.banner-dismiss {
    background: none;
    border: none;
    color: inherit;
    cursor: pointer;
    padding: 0 8px;
    font-size: 20px;
    opacity: 0.7;
}

.banner-dismiss:hover {
    opacity: 1;
}
`;

// Add styles to document
const styleSheet = document.createElement('style');
styleSheet.textContent = bannerStyles;
document.head.appendChild(styleSheet);

// Common password validation function
function validatePassword(password) {
    if (!password || password.length < 12) {
        return {
            valid: false,
            message: 'Password must be at least 12 characters long'
        };
    }

    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSymbol = /[^A-Za-z0-9]/.test(password);

    if (!hasUppercase || !hasLowercase || !hasNumber || !hasSymbol) {
        return {
            valid: false,
            message: 'Password must contain uppercase, lowercase, numbers, and symbols'
        };
    }

    return { valid: true };
}

// Update password strength UI for any password field
function updatePasswordStrengthUI(password, container) {
    if (!container) return;

    const requirements = {
        length: password.length >= 12,
        uppercase: /[A-Z]/.test(password),
        lowercase: /[a-z]/.test(password),
        number: /[0-9]/.test(password),
        symbol: /[^A-Za-z0-9]/.test(password)
    };

    // Update strength meter
    const strengthMeter = container.querySelector('.strength-meter');
    if (strengthMeter) {
        const strength = Object.values(requirements).filter(Boolean).length;
        const colors = ['#ff4d4d', '#ffaa00', '#ffdd00', '#00cc44', '#00aa44'];
        const labels = ['Very Weak', 'Weak', 'Moderate', 'Strong', 'Very Strong'];
        
        strengthMeter.style.width = `${(strength + 1) * 20}%`;
        strengthMeter.style.backgroundColor = colors[strength];
        strengthMeter.textContent = labels[strength];
    }

    // Update requirement indicators
    const requirementsList = container.querySelector('.requirements-list');
    if (requirementsList) {
        const items = requirementsList.getElementsByTagName('li');
        if (items[0]) items[0].classList.toggle('met', requirements.length);
        if (items[1]) items[1].classList.toggle('met', requirements.uppercase);
        if (items[2]) items[2].classList.toggle('met', requirements.lowercase);
        if (items[3]) items[3].classList.toggle('met', requirements.number);
        if (items[4]) items[4].classList.toggle('met', requirements.symbol);
    }
}

// Check TLS version from response headers
const checkTLSVersion = () => {
    const tlsVersion = document.querySelector('meta[name="x-tls-version"]')?.content ||
                      document.head.querySelector('[name="x-tls-version"]')?.content;

    // Show warning for TLS 1.2
    if (tlsVersion === '1.2' && !localStorage.getItem('tls-warning-dismissed')) {
        showSecurityBanner({
            message: 'Your connection is using TLS 1.2. For better security, ' +
                    'please use a modern browser with TLS 1.3 support.',
            level: 'warning',
            dismissible: true,
            learnMoreLink: '/docs/security#tls'
        });
    }
};

// Show security banner with provided options
const showSecurityBanner = (options) => {
    // Remove any existing banner
    const existingBanner = document.querySelector('.security-banner');
    if (existingBanner) {
        existingBanner.remove();
    }

    const banner = document.createElement('div');
    banner.className = `security-banner ${options.level}`;
    banner.innerHTML = `
        <div class="banner-content">
            <span class="banner-icon">⚠️</span>
            <span class="banner-message">${options.message}</span>
            ${options.learnMoreLink ? 
                `<a href="${options.learnMoreLink}" class="banner-learn-more">
                    Learn More
                </a>` : 
                ''
            }
            ${options.dismissible ? 
                '<button class="banner-dismiss" aria-label="Dismiss">×</button>' : 
                ''
            }
        </div>
    `;
    
    if (options.dismissible) {
        banner.querySelector('.banner-dismiss').onclick = () => {
            banner.style.display = 'none';
            if (options.level === 'warning') {
                localStorage.setItem('tls-warning-dismissed', 'true');
            }
        };
    }

    document.body.insertBefore(banner, document.body.firstChild);
    banner.style.display = 'block';
};

// Check TLS version when page loads
document.addEventListener('DOMContentLoaded', checkTLSVersion);

// Export functions for use in other modules
window.securityUtils = {
    checkTLSVersion,
    showSecurityBanner,
    validatePassword,
    updatePasswordStrengthUI
};
