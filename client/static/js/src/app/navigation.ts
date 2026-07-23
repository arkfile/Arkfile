/**
 * Home / app container visibility helpers.
 */

export function isHomePage(): boolean {
  const heroSection = document.querySelector('.hero-section');
  return heroSection !== null && !heroSection.classList.contains('hidden');
}

export function showHome(): void {
  const homeContainer = document.querySelector('.home-container');
  const appContainer = document.getElementById('app-container');

  if (homeContainer) {
    homeContainer.classList.remove('hidden');
  }
  if (appContainer) {
    appContainer.classList.add('hidden');
  }
}

export function showApp(onShow?: () => void): void {
  const homeContainer = document.querySelector('.home-container');
  const appContainer = document.getElementById('app-container');

  if (homeContainer) {
    homeContainer.classList.add('hidden');
  }
  if (appContainer) {
    appContainer.classList.remove('hidden');
  }

  onShow?.();
}
