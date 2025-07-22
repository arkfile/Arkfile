/**
 * Progress indicator utilities
 */

import { ProgressOptions, ProgressState } from '../types/dom';

export class ProgressManager {
  private static activeProgress: HTMLElement | null = null;
  private static progressState: ProgressState | null = null;

  public static showProgress(options: ProgressOptions): HTMLElement {
    // Remove existing progress indicator
    this.hideProgress();

    const progressDiv = document.createElement('div');
    progressDiv.id = 'progress-indicator';
    progressDiv.className = 'progress-message';
    progressDiv.style.cssText = `
      position: fixed;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      background: white;
      padding: 30px;
      border-radius: 8px;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
      z-index: 1500;
      min-width: 300px;
      text-align: center;
      border: 1px solid #ddd;
    `;

    // Title
    const title = document.createElement('h4');
    title.textContent = options.title;
    title.style.cssText = `
      margin: 0 0 15px 0;
      color: #333;
      font-size: 18px;
    `;

    // Message
    const message = document.createElement('div');
    message.className = 'progress-message-text';
    if (options.message) {
      message.textContent = options.message;
    }
    message.style.cssText = `
      margin-bottom: 20px;
      color: #666;
      font-size: 14px;
      line-height: 1.4;
    `;

    // Progress bar container
    const progressContainer = document.createElement('div');
    progressContainer.style.cssText = `
      width: 100%;
      height: 8px;
      background-color: #f0f0f0;
      border-radius: 4px;
      overflow: hidden;
      margin-bottom: 15px;
    `;

    // Progress bar
    const progressBar = document.createElement('div');
    progressBar.className = 'progress-bar';
    progressBar.style.cssText = `
      height: 100%;
      background-color: #007bff;
      border-radius: 4px;
      transition: width 0.3s ease;
      width: ${options.percentage || 0}%;
    `;

    // Indeterminate animation if percentage not provided
    if (options.indeterminate || options.percentage === undefined) {
      progressBar.style.cssText += `
        background: linear-gradient(90deg, 
          transparent 0%, 
          #007bff 50%, 
          transparent 100%
        );
        background-size: 200% 100%;
        animation: indeterminate 1.5s infinite;
        width: 100%;
      `;

      // Add keyframes for indeterminate animation
      if (!document.getElementById('progress-keyframes')) {
        const style = document.createElement('style');
        style.id = 'progress-keyframes';
        style.textContent = `
          @keyframes indeterminate {
            0% { background-position: -200% 0; }
            100% { background-position: 200% 0; }
          }
        `;
        document.head.appendChild(style);
      }
    }

    progressContainer.appendChild(progressBar);

    // Percentage text
    const percentageText = document.createElement('div');
    percentageText.className = 'progress-percentage';
    if (options.percentage !== undefined) {
      percentageText.textContent = `${Math.round(options.percentage)}%`;
    }
    percentageText.style.cssText = `
      font-size: 12px;
      color: #888;
      margin-bottom: 15px;
    `;

    // Cancel button (if allowed)
    const buttonsContainer = document.createElement('div');
    if (options.allowCancel && options.onCancel) {
      const cancelButton = document.createElement('button');
      cancelButton.textContent = 'Cancel';
      cancelButton.style.cssText = `
        background-color: #6c757d;
        color: white;
        border: none;
        padding: 8px 16px;
        border-radius: 4px;
        cursor: pointer;
        font-size: 14px;
      `;
      cancelButton.onclick = () => {
        if (options.onCancel) {
          options.onCancel();
        }
        this.hideProgress();
      };
      buttonsContainer.appendChild(cancelButton);
    }

    // Assemble the progress indicator
    progressDiv.appendChild(title);
    if (options.message) {
      progressDiv.appendChild(message);
    }
    progressDiv.appendChild(progressContainer);
    if (options.percentage !== undefined) {
      progressDiv.appendChild(percentageText);
    }
    if (buttonsContainer.children.length > 0) {
      progressDiv.appendChild(buttonsContainer);
    }

    // Add backdrop
    const backdrop = document.createElement('div');
    backdrop.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background-color: rgba(0, 0, 0, 0.3);
      z-index: 1400;
    `;

    document.body.appendChild(backdrop);
    document.body.appendChild(progressDiv);

    this.activeProgress = progressDiv;
    const progressState: ProgressState = {
      title: options.title,
      percentage: options.percentage || 0,
      stage: 'processing'
    };
    if (options.message !== undefined) {
      progressState.message = options.message;
    }
    this.progressState = progressState;

    return progressDiv;
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
        infoElement.style.cssText = `
          font-size: 11px;
          color: #999;
          margin-top: 10px;
          line-height: 1.3;
        `;
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
      errorElement.style.cssText = `
        color: #dc3545;
        font-size: 13px;
        margin-top: 10px;
        padding: 8px;
        background-color: #f8d7da;
        border-radius: 4px;
        border: 1px solid #f5c6cb;
      `;
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
