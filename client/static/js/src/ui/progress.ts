/**
 * Progress indicator utilities - Optimized for performance and bundle size
 */

import { ProgressOptions, ProgressState } from '../types/dom';

// Optimized CSS constants to reduce inline styles and bundle size
const STYLES = {
  PROGRESS_MODAL: `position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:white;padding:30px;border-radius:8px;box-shadow:0 4px 20px rgba(0,0,0,0.3);z-index:1500;min-width:300px;text-align:center;border:1px solid #ddd`,
  TITLE: `margin:0 0 15px 0;color:#333;font-size:18px`,
  MESSAGE: `margin-bottom:20px;color:#666;font-size:14px;line-height:1.4`,
  PROGRESS_CONTAINER: `width:100%;height:8px;background-color:#f0f0f0;border-radius:4px;overflow:hidden;margin-bottom:15px`,
  PROGRESS_BAR: `height:100%;background-color:#007bff;border-radius:4px;transition:width 0.3s ease`,
  PROGRESS_INDETERMINATE: `background:linear-gradient(90deg,transparent 0%,#007bff 50%,transparent 100%);background-size:200% 100%;animation:indeterminate 1.5s infinite;width:100%`,
  PERCENTAGE: `font-size:12px;color:#888;margin-bottom:15px`,
  CANCEL_BUTTON: `background-color:#6c757d;color:white;border:none;padding:8px 16px;border-radius:4px;cursor:pointer;font-size:14px`,
  INFO: `font-size:11px;color:#999;margin-top:10px;line-height:1.3`,
  ERROR: `color:#dc3545;font-size:13px;margin-top:10px;padding:8px;background-color:#f8d7da;border-radius:4px;border:1px solid #f5c6cb`,
  BACKDROP: `position:fixed;top:0;left:0;width:100%;height:100%;background-color:rgba(0,0,0,0.3);z-index:1400`
} as const;

const KEYFRAMES_ID = 'progress-keyframes';

export class ProgressManager {
  private static activeProgress: HTMLElement | null = null;
  private static progressState: ProgressState | null = null;

  public static showProgress(options: ProgressOptions): HTMLElement {
    this.hideProgress();

    const progressDiv = document.createElement('div');
    progressDiv.id = 'progress-indicator';
    progressDiv.className = 'progress-message';
    progressDiv.style.cssText = STYLES.PROGRESS_MODAL;

    // Build UI components efficiently
    this.addTitle(progressDiv, options.title);
    if (options.message) this.addMessage(progressDiv, options.message);
    
    const progressBar = this.addProgressBar(progressDiv, options);
    if (options.percentage !== undefined) this.addPercentageText(progressDiv, options.percentage);
    if (options.allowCancel && options.onCancel) this.addCancelButton(progressDiv, options.onCancel);

    this.addBackdrop();
    document.body.appendChild(progressDiv);

    // Set internal state
    this.activeProgress = progressDiv;
    this.progressState = {
      title: options.title,
      percentage: options.percentage || 0,
      stage: 'processing',
      ...(options.message !== undefined && { message: options.message })
    };

    return progressDiv;
  }

  private static addTitle(container: HTMLElement, title: string): void {
    const titleEl = document.createElement('h4');
    titleEl.textContent = title;
    titleEl.style.cssText = STYLES.TITLE;
    container.appendChild(titleEl);
  }

  private static addMessage(container: HTMLElement, message: string): void {
    const messageEl = document.createElement('div');
    messageEl.className = 'progress-message-text';
    messageEl.textContent = message;
    messageEl.style.cssText = STYLES.MESSAGE;
    container.appendChild(messageEl);
  }

  private static addProgressBar(container: HTMLElement, options: ProgressOptions): HTMLElement {
    const progressContainer = document.createElement('div');
    progressContainer.style.cssText = STYLES.PROGRESS_CONTAINER;

    const progressBar = document.createElement('div');
    progressBar.className = 'progress-bar';
    progressBar.style.cssText = STYLES.PROGRESS_BAR;

    if (options.indeterminate || options.percentage === undefined) {
      progressBar.style.cssText += `;${STYLES.PROGRESS_INDETERMINATE}`;
      this.ensureKeyframes();
    } else {
      progressBar.style.width = `${Math.max(0, Math.min(100, options.percentage))}%`;
    }

    progressContainer.appendChild(progressBar);
    container.appendChild(progressContainer);
    return progressBar;
  }

  private static addPercentageText(container: HTMLElement, percentage: number): void {
    const percentageText = document.createElement('div');
    percentageText.className = 'progress-percentage';
    percentageText.textContent = `${Math.round(percentage)}%`;
    percentageText.style.cssText = STYLES.PERCENTAGE;
    container.appendChild(percentageText);
  }

  private static addCancelButton(container: HTMLElement, onCancel: () => void): void {
    const cancelButton = document.createElement('button');
    cancelButton.textContent = 'Cancel';
    cancelButton.style.cssText = STYLES.CANCEL_BUTTON;
    cancelButton.onclick = () => {
      onCancel();
      this.hideProgress();
    };
    container.appendChild(cancelButton);
  }

  private static addBackdrop(): void {
    const backdrop = document.createElement('div');
    backdrop.style.cssText = STYLES.BACKDROP;
    document.body.appendChild(backdrop);
  }

  private static ensureKeyframes(): void {
    if (!document.getElementById(KEYFRAMES_ID)) {
      const style = document.createElement('style');
      style.id = KEYFRAMES_ID;
      style.textContent = '@keyframes indeterminate{0%{background-position:-200% 0}100%{background-position:200% 0}}';
      document.head.appendChild(style);
    }
  }

  public static updateProgress(state: Partial<ProgressState>): void {
    if (!this.activeProgress) return;

    // Update internal state
    if (this.progressState) {
      this.progressState = { ...this.progressState, ...state };
    }

    // Update title
    if (state.title) {
      const titleElement = this.activeProgress.querySelector('h4');
      if (titleElement) {
        titleElement.textContent = state.title;
      }
    }

    // Update message
    if (state.message !== undefined) {
      const messageElement = this.activeProgress.querySelector('.progress-message-text');
      if (messageElement) {
        messageElement.textContent = state.message;
      }
    }

    // Update progress bar
    if (state.percentage !== undefined) {
      const progressBar = this.activeProgress.querySelector('.progress-bar') as HTMLElement;
      const percentageText = this.activeProgress.querySelector('.progress-percentage');
      
      if (progressBar) {
        progressBar.style.width = `${Math.max(0, Math.min(100, state.percentage))}%`;
        // Remove indeterminate animation
        progressBar.style.animation = '';
        progressBar.style.background = '#007bff';
      }

      if (percentageText) {
        percentageText.textContent = `${Math.round(state.percentage)}%`;
      }
    }

    // Update additional info (speed, remaining time)
    if (state.speed !== undefined || state.remainingTime !== undefined) {
      let infoElement = this.activeProgress.querySelector('.progress-info') as HTMLElement;
      if (!infoElement) {
        infoElement = document.createElement('div');
        infoElement.className = 'progress-info';
        infoElement.style.cssText = STYLES.INFO;
        this.activeProgress.appendChild(infoElement);
      }

      const infoParts: string[] = [];
      if (state.speed !== undefined) {
        infoParts.push(`${this.formatBytes(state.speed)}/s`);
      }
      if (state.remainingTime !== undefined) {
        infoParts.push(`${this.formatTime(state.remainingTime)} remaining`);
      }
      
      infoElement.textContent = infoParts.join(' • ');
    }

    // Handle error state
    if (state.error) {
      const progressDiv = this.activeProgress;
      progressDiv.style.borderColor = '#dc3545';
      
      const errorElement = document.createElement('div');
      errorElement.style.cssText = STYLES.ERROR;
      errorElement.textContent = state.error;
      progressDiv.appendChild(errorElement);
    }
  }

  public static hideProgress(): void {
    if (this.activeProgress) {
      // Remove backdrop
      const backdrop = document.querySelector('div[style*="z-index: 1400"]');
      if (backdrop) {
        backdrop.remove();
      }

      this.activeProgress.remove();
      this.activeProgress = null;
      this.progressState = null;
    }
  }

  public static getProgressState(): ProgressState | null {
    return this.progressState;
  }

  public static isProgressVisible(): boolean {
    return this.activeProgress !== null;
  }

  private static formatBytes(bytes: number): string {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  private static formatTime(seconds: number): string {
    if (seconds < 60) {
      return `${Math.round(seconds)}s`;
    } else if (seconds < 3600) {
      const minutes = Math.floor(seconds / 60);
      const remainingSeconds = Math.round(seconds % 60);
      return `${minutes}m ${remainingSeconds}s`;
    } else {
      const hours = Math.floor(seconds / 3600);
      const minutes = Math.floor((seconds % 3600) / 60);
      return `${hours}h ${minutes}m`;
    }
  }
}

// Export utility functions
export function showProgress(options: ProgressOptions): HTMLElement {
  return ProgressManager.showProgress(options);
}

export function updateProgress(state: Partial<ProgressState>): void {
  ProgressManager.updateProgress(state);
}

export function hideProgress(): void {
  ProgressManager.hideProgress();
}

export function getProgressState(): ProgressState | null {
  return ProgressManager.getProgressState();
}

export function isProgressVisible(): boolean {
  return ProgressManager.isProgressVisible();
}

// Legacy compatibility function for simple progress messages
export function showProgressMessage(message: string): HTMLElement {
  return ProgressManager.showProgress({
    title: 'Processing...',
    message,
    indeterminate: true
  });
}
