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
      background-color: color-mix(in srgb, var(--depth-1) 70%, transparent);
      display: flex;
      justify-content: center;
      align-items: center;
      z-index: 1000;
    `;

    const modalContent = document.createElement('div');
    modalContent.className = 'modal-content';
    modalContent.style.cssText = `
      background: var(--depth-3);
      color: var(--foam-1);
      border: 1px solid var(--depth-4);
      padding: 30px;
      border-radius: 8px;
      max-width: 80%;
      width: 90%;
      max-height: 85vh;
      overflow-y: auto;
      box-shadow: 0 4px 20px color-mix(in srgb, var(--depth-1) 80%, transparent);
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
          background: color-mix(in srgb, var(--phosphor) 15%, var(--depth-3));
          border-radius: 4px;
          border: 1px solid var(--phosphor);
        }
        .backup-code {
          font-family: 'Courier New', monospace;
          font-size: 14px;
          font-weight: bold;
          padding: 6px 10px;
          background: var(--salt);
          color: var(--depth-1);
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
      color: var(--salt);
      text-align: center;
    `;
    title.textContent = options.title;

    // Message
    const message = document.createElement('div');
    message.style.cssText = `
      margin-bottom: 20px;
      line-height: 1.5;
      color: var(--foam-2);
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
          background-color: var(--coral);
          color: var(--salt);
        `;
        break;
      case 'secondary':
        variantStyle = `
          background-color: var(--depth-4);
          color: var(--salt);
        `;
        break;
      case 'success':
        variantStyle = `
          background-color: var(--biolum);
          color: var(--depth-1);
        `;
        break;
      default:
        variantStyle = `
          background-color: var(--current-2);
          color: var(--salt);
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
    background-color: color-mix(in srgb, var(--depth-1) 70%, transparent);
    display: flex;
    justify-content: center;
    align-items: center;
    z-index: 1000;
  `;

  const modalContent = document.createElement('div');
  modalContent.className = 'modal-content totp-apps-modal';
  modalContent.style.cssText = `
    background: var(--depth-3);
    color: var(--foam-1);
    border: 1px solid var(--depth-4);
    padding: 30px;
    border-radius: 8px;
    max-width: 550px;
    width: 90%;
    max-height: 80vh;
    overflow-y: auto;
    box-shadow: 0 4px 20px color-mix(in srgb, var(--depth-1) 80%, transparent);
  `;

  const appsData = {
    mobile: [
      { name: "Aegis Authenticator", platform: "Android", desc: "Open source (GPL-3.0)", url: "https://github.com/beemdevelopment/Aegis" },
      { name: "Ente Auth", platform: "Android/iOS", desc: "Open source (AGPL-3.0)", url: "https://github.com/ente-io/ente" },
      { name: "Bitwarden Authenticator", platform: "Android/iOS", desc: "Open source (GPL-3.0)", url: "https://github.com/bitwarden/authenticator-android" },
      { name: "Tofu", platform: "iOS", desc: "Open source (Apache 2.0)", url: "https://github.com/iKenndac/Tofu" },
      { name: "FreeOTP+", platform: "Android", desc: "Open source (Apache 2.0)", url: "https://github.com/helloworld1/FreeOTP-Plus" }
    ],
    desktop: [
      { name: "KeePassXC", desc: "Open source (GPL-3.0)", url: "https://keepassxc.org" },
      { name: "Authenticator", platform: "Linux", desc: "Open source (GPL-3.0)", url: "https://gitlab.gnome.org/World/Authenticator" }
    ],
    advanced: [
      { name: "oath-toolkit", desc: "Open source (GPL-3.0+)", url: "https://gitlab.com/oath-toolkit/oath-toolkit" }
    ]
  };

  const createAppsList = (apps: any[], emoji: string, title: string) => {
    return `
      <div style="margin-bottom: 20px;">
        <h4 style="margin: 0 0 10px 0; color: var(--salt); font-size: 16px;">
          ${emoji} ${title}
        </h4>
        ${apps.map(app => `
          <div style="margin-bottom: 8px; padding: 8px; background: var(--depth-2); border-radius: 4px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <div style="flex: 1;">
                <strong>${app.name}</strong>
                ${app.platform ? ` (${app.platform})` : ''}
                <div style="font-size: 12px; color: var(--foam-2); margin-top: 2px;">
                  ${app.desc}
                </div>
              </div>
              <a href="${app.url}" target="_blank" rel="noopener" style="
                color: var(--current-2);
                text-decoration: none;
                font-size: 12px;
                padding: 4px 8px;
                border: 1px solid var(--current-2);
                border-radius: 3px;
                margin-left: 10px;
                white-space: nowrap;
              " onmouseover="this.style.backgroundColor='var(--current-2)'; this.style.color='var(--salt)';" 
                 onmouseout="this.style.backgroundColor='transparent'; this.style.color='var(--current-2)';">
                View →
              </a>
            </div>
          </div>
        `).join('')}
      </div>
    `;
  };

  modalContent.innerHTML = `
    <h3 style="margin: 0 0 20px 0; color: var(--salt); text-align: center;">Recommended TOTP Apps</h3>
    <div style="margin-bottom: 20px;">
      ${createAppsList(appsData.mobile, '', 'Mobile (Recommended)')}
      ${createAppsList(appsData.desktop, '', 'Desktop')}
      ${createAppsList(appsData.advanced, '', 'Advanced')}
      <div style="margin-top: 20px; padding: 15px; background: color-mix(in srgb, var(--current-2) 15%, var(--depth-3)); border-radius: 4px; font-size: 14px; color: var(--current-2);">
        <strong>Tip:</strong> All listed apps are fully open source and respect your privacy.
      </div>
    </div>
    <button onclick="this.closest('.modal-overlay').remove();" style="
      width: 100%;
      padding: 10px;
      background-color: var(--current-2);
      color: var(--salt);
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
