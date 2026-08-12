/**
 * Sitewide footer: admin contact (plain text), server host and commit.
 */

import { fetchAdminContacts } from '../utils/auth.js';

/**
 * Populate Contact Admin spans and server/commit info in all sitewide footers.
 */
export async function initSitewideFooters(): Promise<void> {
  void populateAdminContacts();
  void populateInstanceInfo();
}

async function populateAdminContacts(): Promise<void> {
  const elements = document.querySelectorAll<HTMLElement>('.footer-admin-contact');
  if (elements.length === 0) return;

  try {
    const { contact, configured } = await fetchAdminContacts();
    const display = configured && contact ? contact : 'not configured';
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

  const host = window.location.hostname.trim();
  let commit = '';

  try {
    const resp = await fetch('/api/version');
    if (resp.ok) {
      const data = await resp.json();
      const raw = typeof data?.commit === 'string' ? data.commit.trim() : '';
      if (raw !== '' && raw !== 'unknown') {
        commit = raw;
      }
    }
  } catch {
    // Cosmetic only
  }

  const hasCommit = commit !== '';
  let text = '';
  if (host && hasCommit) {
    text = `Arkfile Server: ${host} -- Commit: ${commit}`;
  } else if (host) {
    text = `Arkfile Server: ${host}`;
  } else if (hasCommit) {
    text = `Commit: ${commit}`;
  } else {
    return;
  }

  for (const el of elements) {
    el.textContent = text;
  }
}

/**
 * Best-effort admin contact for MFA recovery hints (plain text).
 */
export async function getAdminContactForDisplay(): Promise<string | null> {
  try {
    const { contact, configured } = await fetchAdminContacts();
    if (configured && contact) {
      return contact;
    }
  } catch {
    // ignore
  }
  return null;
}
