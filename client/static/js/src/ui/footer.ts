/**
 * Sitewide footer: admin contact (plain text), instance info.
 */

import { fetchAdminContacts } from '../utils/auth.js';

const DEFAULT_ADMIN_CONTACT = 'admin@example.com';

/**
 * Populate Contact Admin spans and instance info in all sitewide footers.
 */
export async function initSitewideFooters(): Promise<void> {
  void populateAdminContacts();
  void populateInstanceInfo();
}

async function populateAdminContacts(): Promise<void> {
  const elements = document.querySelectorAll<HTMLElement>('.footer-admin-contact');
  if (elements.length === 0) return;

  try {
    const { contact } = await fetchAdminContacts();
    const display =
      contact && contact !== DEFAULT_ADMIN_CONTACT ? contact : 'not configured';
    for (const el of elements) {
      el.textContent = display;
    }
  } catch {
    for (const el of elements) {
      el.textContent = 'not configured';
    }
  }
}

async function populateInstanceInfo(): Promise<void> {
  const elements = document.querySelectorAll<HTMLElement>('.footer-instance-info');
  if (elements.length === 0) return;

  try {
    const resp = await fetch('/api/version');
    if (!resp.ok) return;

    const data = await resp.json();
    const version = data?.version || 'unknown';
    const hostname = window.location.hostname;
    const text = `Arkfile Instance: ${hostname} (${version})`;
    for (const el of elements) {
      el.textContent = text;
    }
  } catch {
    // Cosmetic only
  }
}

/**
 * Best-effort admin contact for MFA recovery hints (plain text).
 */
export async function getAdminContactForDisplay(): Promise<string | null> {
  try {
    const { contact } = await fetchAdminContacts();
    if (contact && contact !== DEFAULT_ADMIN_CONTACT) {
      return contact;
    }
  } catch {
    // ignore
  }
  return null;
}
