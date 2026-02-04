/**
 * Modal utilities for ArkFile UI
 */

import { ModalOptions, ConfirmModalOptions, ModalButton } from '../types/dom';

export class ModalManager {
  private static activeModals = new Set<HTMLElement>();

  public static createModal(options: ModalOptions): HTMLElement {
    const modal = document.createElement('div');
    modal.className = 'modal-overlay';
    modal.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background-color: rgba(0, 0, 0, 0.5);
      display: flex;
      justify-content: center;
      align-items: center;
      z-index: 1000;
    `;

    const modalContent = document.createElement('div');
    modalContent.className = 'modal-content';
    modalContent.style.cssText = `
      background: white;
      padding: 30px;
      border-radius: 8px;
      max-width: 80%;
      width: 90%;
      max-height: 85vh;
      overflow-y: auto;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
      ${options.className ? `additional-class: ${options.className};` : ''}
    `;

    // Add TOTP-specific styles for backup codes grid
    if (!document.getElementById('modal-totp-styles')) {
      const style = document.createElement('style');
      style.id = 'modal-totp-styles';
      style.textContent = `
        .backup-codes-grid {
          display: grid;
          grid-template-columns: repeat(2, 1fr);
          gap: 8px;
          padding: 12px;
          background: #fffbea;
          border-radius: 4px;
          border: 1px solid #ffc107;
        }
        .backup-code {
          font-family: 'Courier New', monospace;
          font-size: 14px;
          font-weight: bold;
          padding: 6px 10px;
          background: white;
          border-radius: 3px;
          text-align: center;
          letter-spacing: 1px;
        }
        @media (max-width: 480px) {
          .backup-codes-grid {
            grid-template-columns: 1fr;
          }
        }
      `;
      document.head.appendChild(style);
    }

    // Title
    const title = document.createElement('h3');
    title.style.cssText = `
      margin-top: 0;
      margin-bottom: 15px;
      color: #333;
      text-align: center;
    `;
    title.textContent = options.title;

    // Message
    const message = document.createElement('div');
    message.style.cssText = `
      margin-bottom: 20px;
      line-height: 1.5;
      color: #666;
      white-space: pre-line;
    `;
    message.textContent = options.message;

    // Buttons
    const buttonsContainer = document.createElement('div');
    buttonsContainer.style.cssText = `
      display: flex;
      flex-direction: column;
      gap: 10px;
    `;

    if (options.buttons && options.buttons.length > 0) {
      options.buttons.forEach((buttonOptions: ModalButton) => {
        const button = this.createModalButton(buttonOptions, modal);
        buttonsContainer.appendChild(button);
      });
    } else {
      // Default close button
      const closeButton = this.createModalButton({
        text: 'Close',
        action: () => this.closeModal(modal),
        variant: 'primary'
      }, modal);
      buttonsContainer.appendChild(closeButton);
    }

    modalContent.appendChild(title);
    modalContent.appendChild(message);
    modalContent.appendChild(buttonsContainer);
    modal.appendChild(modalContent);

    // Close modal when clicking outside (if allowed)
    if (options.allowClose !== false) {
      modal.onclick = (e) => {
        if (e.target === modal) {
          this.closeModal(modal);
        }
      };
    }

    document.body.appendChild(modal);
    this.activeModals.add(modal);
    
    return modal;
  }

  public static createConfirmModal(options: ConfirmModalOptions): HTMLElement {
    const modalOptions: ModalOptions = {
      title: options.title,
      message: options.message,
      buttons: [
        {
          text: options.confirmText || 'Confirm',
          action: async () => {
            try {
              await options.onConfirm();
            } catch (error) {
              console.error('Confirm action error:', error);
            }
          },
          variant: options.variant === 'danger' ? 'danger' : 'primary'
        },
        {
          text: options.cancelText || 'Cancel',
          action: () => {
            if (options.onCancel) {
              options.onCancel();
            }
          },
          variant: 'secondary'
        }
      ],
      allowClose: true
    };

    return this.createModal(modalOptions);
  }

  private static createModalButton(options: ModalButton, modal: HTMLElement): HTMLElement {
    const button = document.createElement('button');
    button.textContent = options.text;
    button.disabled = options.disabled || false;
    
    // Button styling based on variant
    const baseStyle = `
      width: 100%;
      padding: 10px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 16px;
      transition: background-color 0.2s;
    `;
    
    let variantStyle = '';
    switch (options.variant) {
      case 'danger':
        variantStyle = `
          background-color: #dc3545;
          color: white;
        `;
        break;
      case 'secondary':
        variantStyle = `
          background-color: #6c757d;
          color: white;
        `;
        break;
      case 'success':
        variantStyle = `
          background-color: #28a745;
          color: white;
        `;
        break;
      default:
        variantStyle = `
          background-color: #007bff;
          color: white;
        `;
    }

    if (options.disabled) {
      variantStyle += `
        opacity: 0.6;
        cursor: not-allowed;
      `;
    }

    button.style.cssText = baseStyle + variantStyle;

    button.onclick = async (e) => {
      e.preventDefault();
      e.stopPropagation();

      if (options.disabled) return;

      try {
        // Show loading state if this is an async action
        if (options.loading !== false) {
          button.disabled = true;
          const originalText = button.textContent;
          button.textContent = 'Loading...';
          
          await options.action();
          
          button.textContent = originalText;
          button.disabled = options.disabled || false;
        } else {
          await options.action();
        }
        
        // Close modal after successful action (unless it's a cancel button)
        if (options.variant !== 'secondary') {
          this.closeModal(modal);
        }
      } catch (error) {
        console.error('Button action error:', error);
        button.disabled = options.disabled || false;
        // Don't close modal on error
      }
    };

    return button;
  }

  public static closeModal(modal: HTMLElement): void {
    if (this.activeModals.has(modal)) {
      this.activeModals.delete(modal);
      modal.remove();
    }
  }

  public static closeAllModals(): void {
    this.activeModals.forEach(modal => {
      modal.remove();
    });
    this.activeModals.clear();
  }

  public static getActiveModalCount(): number {
    return this.activeModals.size;
  }
}

// TOTP Apps Recommendation Modal
export function showTOTPAppsModal(): HTMLElement {
  const modal = document.createElement('div');
  modal.className = 'modal-overlay';
  modal.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(0, 0, 0, 0.5);
    display: flex;
    justify-content: center;
    align-items: center;
    z-index: 1000;
  `;

  const modalContent = document.createElement('div');
  modalContent.className = 'modal-content totp-apps-modal';
  modalContent.style.cssText = `
    background: white;
    padding: 30px;
    border-radius: 8px;
    max-width: 550px;
    width: 90%;
    max-height: 80vh;
    overflow-y: auto;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
  `;

  const appsData = {
    mobile: [
      { name: "Aegis Authenticator", platform: "Android", desc: "Encrypted backups", url: "https://github.com/beemdevelopment/Aegis" },
      { name: "FreeOTP+", platform: "Android/iOS", desc: "Simple & reliable", url: "https://github.com/helloworld1/FreeOTP-Plus" },
      { name: "Tofu", platform: "iOS", desc: "Native iOS experience", url: "https://github.com/iKenndac/Tofu" }
    ],
    desktop: [
      { name: "KeePassXC", desc: "Password manager with TOTP", url: "https://keepassxc.org" },
      { name: "Authenticator", platform: "GNOME", desc: "Linux desktop app", url: "https://gitlab.gnome.org/World/Authenticator" }
    ],
    advanced: [
      { name: "oath-toolkit", desc: "Command-line tool", url: "https://gitlab.com/oath-toolkit/oath-toolkit" }
    ]
  };

  const createAppsList = (apps: any[], emoji: string, title: string) => {
    return `
      <div style="margin-bottom: 20px;">
        <h4 style="margin: 0 0 10px 0; color: #333; font-size: 16px;">
          ${emoji} ${title}
        </h4>
        ${apps.map(app => `
          <div style="margin-bottom: 8px; padding: 8px; background: #f8f9fa; border-radius: 4px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <div style="flex: 1;">
                <strong>${app.name}</strong>
                ${app.platform ? ` (${app.platform})` : ''}
                <div style="font-size: 12px; color: #666; margin-top: 2px;">
                  ${app.desc}
                </div>
              </div>
              <a href="${app.url}" target="_blank" rel="noopener" style="
                color: #007bff;
                text-decoration: none;
                font-size: 12px;
                padding: 4px 8px;
                border: 1px solid #007bff;
                border-radius: 3px;
                margin-left: 10px;
                white-space: nowrap;
              " onmouseover="this.style.backgroundColor='#007bff'; this.style.color='white';" 
                 onmouseout="this.style.backgroundColor='transparent'; this.style.color='#007bff';">
                View →
              </a>
            </div>
          </div>
        `).join('')}
      </div>
    `;
  };

  modalContent.innerHTML = `
    <h3 style="margin: 0 0 20px 0; color: #333; text-align: center;">Recommended TOTP Apps</h3>
    <div style="margin-bottom: 20px;">
      ${createAppsList(appsData.mobile, '', 'Mobile (Recommended)')}
      ${createAppsList(appsData.desktop, '', 'Desktop')}
      ${createAppsList(appsData.advanced, '️', 'Advanced')}
      <div style="margin-top: 20px; padding: 15px; background: #e7f3ff; border-radius: 4px; font-size: 14px; color: #0066cc;">
        <strong>Tip:</strong> All listed apps are fully open source and respect your privacy.
      </div>
    </div>
    <button onclick="this.closest('.modal-overlay').remove();" style="
      width: 100%;
      padding: 10px;
      background-color: #007bff;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 16px;
    ">Close</button>
  `;

  modal.appendChild(modalContent);

  // Close modal when clicking outside
  modal.onclick = (e) => {
    if (e.target === modal) {
      modal.remove();
    }
  };

  document.body.appendChild(modal);
  
  return modal;
}

// Export utility functions
export function showModal(options: ModalOptions): HTMLElement {
  return ModalManager.createModal(options);
}

export function showConfirmModal(options: ConfirmModalOptions): HTMLElement {
  return ModalManager.createConfirmModal(options);
}

export function closeModal(modal: HTMLElement): void {
  ModalManager.closeModal(modal);
}

export function closeAllModals(): void {
  ModalManager.closeAllModals();
}
