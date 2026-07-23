/**
 * Thin application entry point: Trusted Types, shell construction,
 * DOMContentLoaded, and shared.html ShareAccessUI bridge.
 */

import { showError } from './ui/messages';
import { loadFiles } from './files/list';
import { registerTrustedTypesPolicy } from './app/trusted-types';
import { isHomePage as detectHomePage, showHome as revealHome, showApp as revealApp } from './app/navigation';
import { setupAppListenersOnce, type ListenerAttachState } from './app/app-listeners';
import { bootstrapApplication } from './app/bootstrap';
import type { AppShell } from './app/shell';

registerTrustedTypesPolicy();

class ArkFileApp implements AppShell {
  private initialized = false;
  private readonly listenerState: ListenerAttachState = { attached: false };

  public async initialize(): Promise<void> {
    if (this.initialized) return;
    const completed = await bootstrapApplication(this);
    if (completed) {
      this.initialized = true;
    }
  }

  public isHomePage(): boolean {
    return detectHomePage();
  }

  public showHome(): void {
    revealHome();
  }

  public showApp(): void {
    revealApp(() => this.setupAppListeners());
  }

  public setupAppListeners(): void {
    setupAppListenersOnce(this, this.listenerState);
  }

  public async loadUserFiles(): Promise<void> {
    try {
      await loadFiles();
      await this.loadUserShares();
    } catch (error) {
      console.error('Error loading user files:', error);
      showError('Failed to load your files. Please refresh the page.');
    }
  }

  private async loadUserShares(): Promise<void> {
    try {
      const { initializeShareList } = await import('./shares/share-list');
      await initializeShareList();
    } catch (error) {
      console.error('Error loading user shares:', error);
    }
  }

  public navigateToApp(): void {
    this.showApp();
  }

  public navigateToHome(): void {
    this.showHome();
  }
}

const app = new ArkFileApp();

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    void app.initialize();
  });
} else {
  void app.initialize();
}

if (typeof window !== 'undefined') {
  window.arkfile = window.arkfile || {};

  import('./shares/share-access').then((module) => {
    window.arkfile!.shares = {
      ...(window.arkfile!.shares || {}),
      ShareAccessUI: module.ShareAccessUI,
    };
  });
}
