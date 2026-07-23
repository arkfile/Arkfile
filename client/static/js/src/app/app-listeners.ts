import { setupAuthListeners } from './auth-listeners';
import { setupShellListeners } from './shell-listeners';
import { setupUploadListeners } from './upload-listeners';
import { setupTOTPListeners } from './totp-listeners';
import type { AppShell } from './shell';

export type ListenerAttachState = { attached: boolean };

/**
 * Register all authenticated-app DOM listeners exactly once.
 * showApp() may call this repeatedly; addEventListener stacks handlers.
 */
export function setupAppListenersOnce(
  shell: AppShell,
  state: ListenerAttachState
): void {
  if (state.attached) return;
  state.attached = true;

  setupAuthListeners(shell);
  setupShellListeners(shell);
  setupUploadListeners();
  setupTOTPListeners();
}
