/**
 * Message utilities for error/success notifications
 */

import { ToastOptions } from '../types/dom';

export class MessageManager {
  private static activeMessages = new Set<HTMLElement>();
  private static messageContainer: HTMLElement | null = null;

  private static ensureMessageContainer(): HTMLElement {
    if (!this.messageContainer) {
      this.messageContainer = document.createElement('div');
      this.messageContainer.id = 'message-container';
      this.messageContainer.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 2000;
        display: flex;
        flex-direction: column;
        gap: 10px;
        max-width: 400px;
        pointer-events: none;
      `;
      document.body.appendChild(this.messageContainer);
    }
    return this.messageContainer;
  }

  public static showToast(options: ToastOptions): HTMLElement {
    const container = this.ensureMessageContainer();
    
    const toast = document.createElement('div');
    toast.className = `toast toast-${options.type || 'info'}`;
    toast.style.cssText = `
      padding: 16px 20px;
      border-radius: 8px;
      color: white;
      font-size: 14px;
      line-height: 1.4;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
      opacity: 0;
      transform: translateX(100%);
      transition: all 0.3s ease-out;
      pointer-events: auto;
      max-width: 100%;
      word-wrap: break-word;
    `;

    // Set background color based on type
    let backgroundColor = '#17a2b8'; // info
    switch (options.type) {
      case 'success':
        backgroundColor = '#28a745';
        break;
      case 'error':
        backgroundColor = '#dc3545';
        break;
      case 'warning':
        backgroundColor = '#ffc107';
        toast.style.color = '#212529'; // Dark text for warning
        break;
    }
    toast.style.backgroundColor = backgroundColor;

    // Create content
    const messageContent = document.createElement('div');
    messageContent.style.cssText = `
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 12px;
    `;

    const messageText = document.createElement('div');
    messageText.textContent = options.message;
    messageText.style.flex = '1';

    messageContent.appendChild(messageText);

    // Add action buttons if provided
    if (options.actions && options.actions.length > 0) {
      const actionsContainer = document.createElement('div');
      actionsContainer.style.cssText = `
        display: flex;
        gap: 8px;
        flex-shrink: 0;
      `;

      options.actions.forEach(actionOption => {
        const actionButton = document.createElement('button');
        actionButton.textContent = actionOption.text;
        actionButton.style.cssText = `
          background: rgba(255, 255, 255, 0.2);
          border: 1px solid rgba(255, 255, 255, 0.3);
          color: inherit;
          padding: 4px 8px;
          border-radius: 4px;
          font-size: 12px;
          cursor: pointer;
          transition: background-color 0.2s;
        `;
        
        actionButton.onclick = (e) => {
          e.stopPropagation();
          try {
            actionOption.action();
          } catch (error) {
            console.error('Toast action error:', error);
          }
          this.removeToast(toast);
        };

        actionsContainer.appendChild(actionButton);
      });

      messageContent.appendChild(actionsContainer);
    }

    // Add close button
    const closeButton = document.createElement('button');
    closeButton.innerHTML = '×';
    closeButton.style.cssText = `
      background: none;
      border: none;
      color: inherit;
      font-size: 20px;
      cursor: pointer;
      padding: 0;
      width: 24px;
      height: 24px;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
      opacity: 0.7;
      transition: opacity 0.2s;
    `;
    closeButton.onclick = () => this.removeToast(toast);
    closeButton.onmouseenter = () => { closeButton.style.opacity = '1'; };
    closeButton.onmouseleave = () => { closeButton.style.opacity = '0.7'; };

    messageContent.appendChild(closeButton);
    toast.appendChild(messageContent);
    container.appendChild(toast);
    
    this.activeMessages.add(toast);

    // Animate in
    requestAnimationFrame(() => {
      toast.style.opacity = '1';
      toast.style.transform = 'translateX(0)';
    });

    // Auto-remove after duration (unless duration is 0)
    const duration = options.duration ?? 5000;
    if (duration > 0) {
      setTimeout(() => {
        this.removeToast(toast);
      }, duration);
    }

    return toast;
  }

  private static removeToast(toast: HTMLElement): void {
    if (!this.activeMessages.has(toast)) return;

    // Animate out
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';

    setTimeout(() => {
      if (toast.parentNode) {
        toast.parentNode.removeChild(toast);
      }
      this.activeMessages.delete(toast);

      // Clean up container if no messages left
      if (this.activeMessages.size === 0 && this.messageContainer) {
        if (this.messageContainer.parentNode) {
          this.messageContainer.parentNode.removeChild(this.messageContainer);
        }
        this.messageContainer = null;
      }
    }, 300);
  }

  public static clearAllMessages(): void {
    this.activeMessages.forEach(toast => {
      this.removeToast(toast);
    });
  }

  public static getActiveMessageCount(): number {
    return this.activeMessages.size;
  }
}

// Utility functions for common message types
export function showError(message: string, duration?: number): HTMLElement {
  const options: ToastOptions = {
    message,
    type: 'error'
  };
  if (duration !== undefined) {
    options.duration = duration;
  }
  return MessageManager.showToast(options);
}

export function showSuccess(message: string, duration?: number): HTMLElement {
  const options: ToastOptions = {
    message,
    type: 'success'
  };
  if (duration !== undefined) {
    options.duration = duration;
  }
  return MessageManager.showToast(options);
}

export function showWarning(message: string, duration?: number): HTMLElement {
  const options: ToastOptions = {
    message,
    type: 'warning'
  };
  if (duration !== undefined) {
    options.duration = duration;
  }
  return MessageManager.showToast(options);
}

export function showInfo(message: string, duration?: number): HTMLElement {
  const options: ToastOptions = {
    message,
    type: 'info'
  };
  if (duration !== undefined) {
    options.duration = duration;
  }
  return MessageManager.showToast(options);
}

export function showToast(options: ToastOptions): HTMLElement {
  return MessageManager.showToast(options);
}

export function clearAllMessages(): void {
  MessageManager.clearAllMessages();
}
