/**
 * Test Setup — Bun Test Environment
 *
 * Provides browser-API mocks (sessionStorage, window) so that
 * crypto modules can be unit-tested outside a real browser.
 *
 * Usage: import './setup.js' at the top of each test file.
 */

// ============================================================================
// sessionStorage mock (Map-backed)
// ============================================================================

class MockStorage implements Storage {
  private store = new Map<string, string>();

  get length(): number {
    return this.store.size;
  }

  clear(): void {
    this.store.clear();
  }

  getItem(key: string): string | null {
    return this.store.get(key) ?? null;
  }

  key(index: number): string | null {
    const keys = Array.from(this.store.keys());
    return keys[index] ?? null;
  }

  removeItem(key: string): void {
    this.store.delete(key);
  }

  setItem(key: string, value: string): void {
    this.store.set(key, value);
  }
}

// Install sessionStorage globally if not present
if (typeof globalThis.sessionStorage === 'undefined') {
  (globalThis as any).sessionStorage = new MockStorage();
}

// ============================================================================
// window mock (minimal — just enough for addEventListener / setTimeout)
// ============================================================================

if (typeof globalThis.window === 'undefined') {
  const _listeners: Record<string, Function[]> = {};

  (globalThis as any).window = {
    addEventListener(event: string, handler: Function, _opts?: any): void {
      if (!_listeners[event]) _listeners[event] = [];
      _listeners[event].push(handler);
    },
    removeEventListener(event: string, handler: Function): void {
      if (_listeners[event]) {
        _listeners[event] = _listeners[event].filter((h) => h !== handler);
      }
    },
    setTimeout: globalThis.setTimeout.bind(globalThis),
    clearTimeout: globalThis.clearTimeout.bind(globalThis),
    setInterval: globalThis.setInterval.bind(globalThis),
    clearInterval: globalThis.clearInterval.bind(globalThis),
  };
}

// ============================================================================
// Reset helper — call in beforeEach to get a clean slate
// ============================================================================

export function resetMocks(): void {
  sessionStorage.clear();
}
