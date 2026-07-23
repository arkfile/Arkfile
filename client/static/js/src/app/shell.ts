/**
 * Shared callbacks the app shell modules use to navigate and load data
 * without depending on the ArkFileApp class shape.
 */
export interface AppShell {
  showHome(): void;
  showApp(): void;
  loadUserFiles(): Promise<void>;
  setupAppListeners(): void;
  isHomePage(): boolean;
}
