/**
 * Progress indicator utilities - Optimized for performance and bundle size
 * Now uses CSS classes instead of inline styles to comply with CSP
 */

import { ProgressOptions, ProgressState } from '../types/dom';

export class ProgressManager {
  private static activeProgress: HTMLElement | null = null;
  private static progressState: ProgressState | null = null;

  public static showProgress(options: ProgressOptions): HTMLElement {
    this.hideProgress();

    const progressDiv = document.createElement('div');
    progressDiv.id = 'progress-indicator';
    progressDiv.className = 'progress-modal';

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
    container.appendChild(titleEl);
  }

  private static addMessage(container: HTMLElement, message: string): void {
    const messageEl = document.createElement('div');
    messageEl.className = 'progress-message-text';
    messageEl.textContent = message;
    container.appendChild(messageEl);
  }

  private static addProgressBar(container: HTMLElement, options: ProgressOptions): HTMLElement {
    const progressContainer = document.createElement('div');
    progressContainer.className = 'progress-container';

    const progressBar = document.createElement('div');
    progressBar.className = 'progress-bar';

    if (options.indeterminate || options.percentage === undefined) {
      progressBar.classList.add('indeterminate');
    } else {
      // Use CSS custom property for width (CSP-compliant)
      progressBar.style.setProperty('--progress-width', `${Math.max(0, Math.min(100, options.percentage))}%`);
    }

    progressContainer.appendChild(progressBar);
    container.appendChild(progressContainer);
    return progressBar;
  }

  private static addPercentageText(container: HTMLElement, percentage: number): void {
    const percentageText = document.createElement('div');
    percentageText.className = 'progress-percentage';
    percentageText.textContent = `${Math.round(percentage)}%`;
    container.appendChild(percentageText);
  }

  private static addCancelButton(container: HTMLElement, onCancel: () => void): void {
    const cancelButton = document.createElement('button');
    cancelButton.className = 'cancel-button';
    cancelButton.textContent = 'Cancel';
    cancelButton.onclick = () => {
      onCancel();
      this.hideProgress();
    };
    container.appendChild(cancelButton);
  }

  private static addBackdrop(): void {
    const backdrop = document.createElement('div');
    backdrop.className = 'progress-backdrop';
    document.body.appendChild(backdrop);
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
        // Use CSS custom property for width (CSP-compliant)
        progressBar.style.setProperty('--progress-width', `${Math.max(0, Math.min(100, state.percentage))}%`);
        // Remove indeterminate class to stop animation
        progressBar.classList.remove('indeterminate');
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
        this.activeProgress.appendChild(infoElement);
      }

      const infoParts: string[] = [];
      if (state.speed !== undefined) {
        infoParts.push(`${this.formatBytes(state.speed)}/s`);
      }
      if (state.remainingTime !== undefined) {
        infoParts.push(`${this.formatTime(state.remainingTime)} remaining`);
      }
      
      infoElement.textContent = infoParts.join(' - ');
    }

    // Handle error state
    if (state.error) {
      const progressDiv = this.activeProgress;
      progressDiv.classList.add('error');
      
      const errorElement = document.createElement('div');
      errorElement.className = 'progress-error';
      errorElement.textContent = state.error;
      progressDiv.appendChild(errorElement);
    }
  }

  public static hideProgress(): void {
    if (this.activeProgress) {
      // Remove backdrop
      const backdrop = document.querySelector('.progress-backdrop');
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
