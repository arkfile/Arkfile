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
      max-width: 500px;
      width: 90%;
      max-height: 80vh;
      overflow-y: auto;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
      ${options.className ? `additional-class: ${options.className};` : ''}
    `;

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
