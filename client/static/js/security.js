// security.js - TLS version checking and security notifications

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
    showSecurityBanner
};
