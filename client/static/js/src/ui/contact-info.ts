/**
 * Contact information management UI
 * Allows users to set, view, and delete their contact details.
 * Contact info is encrypted server-side and readable only by the admin.
 */

import { authenticatedFetch, getUsernameFromToken } from '../utils/auth';
import { showError, showSuccess } from './messages';
import { closeNavInlinePanelsExcept } from './sections.js';

const VALID_CONTACT_TYPES = [
  'email', 'sms', 'signal', 'whatsapp', 'wechat', 'telegram', 'matrix', 'other'
];

interface ContactMethod {
  type: string;
  value: string;
  label?: string;
}

interface ContactInfo {
  display_name: string;
  contacts: ContactMethod[];
  notes: string;
}

/** Last successfully loaded/saved snapshot for the main Contact Info panel. */
let lastSavedMain: ContactInfo | null = null;
/** Last successfully loaded/saved snapshot for the pending-approval form. */
let lastSavedPending: ContactInfo | null = null;

function defaultDisplayName(): string {
  return getUsernameFromToken() || '';
}

function emptyBaseline(): ContactInfo {
  return {
    display_name: defaultDisplayName(),
    contacts: [],
    notes: '',
  };
}

function cloneInfo(info: ContactInfo): ContactInfo {
  return {
    display_name: info.display_name || '',
    contacts: (info.contacts || []).map((c) => ({
      type: c.type,
      value: c.value,
      ...(c.label ? { label: c.label } : {}),
    })),
    notes: info.notes || '',
  };
}

/** Stable compare key for no-op save detection. */
function normalizeInfoKey(info: ContactInfo): string {
  const contacts = (info.contacts || []).map((c) => ({
    type: c.type,
    value: c.value,
    label: c.type === 'other' ? (c.label || '') : '',
  }));
  return JSON.stringify({
    display_name: info.display_name || '',
    contacts,
    notes: info.notes || '',
  });
}

function hasChangesFromSaved(info: ContactInfo, lastSaved: ContactInfo | null): boolean {
  const baseline = lastSaved ? cloneInfo(lastSaved) : emptyBaseline();
  return normalizeInfoKey(info) !== normalizeInfoKey(baseline);
}

/** Toggle the contact info panel visibility and load data when opening */
export async function toggleContactInfoPanel(): Promise<void> {
  const panel = document.getElementById('contact-info-panel');
  if (!panel) return;

  const isHidden = panel.classList.contains('hidden');
  panel.classList.toggle('hidden');

  if (isHidden) {
    closeNavInlinePanelsExcept('contact-info-panel');
    await loadContactInfo();
  }
}

/** Load the user's current contact info from the server */
export async function loadContactInfo(): Promise<void> {
  try {
    const response = await authenticatedFetch('/api/user/contact-info', { method: 'GET' });

    if (!response.ok) {
      if (response.status === 401) return;
      throw new Error(`Server returned ${response.status}`);
    }

    const result = await response.json();
    if (result.data?.has_contact_info && result.data?.contact_info) {
      const info = result.data.contact_info as ContactInfo;
      lastSavedMain = cloneInfo(info);
      populateForm(info);
    } else {
      lastSavedMain = null;
      clearForm();
    }
  } catch (err) {
    console.error('Failed to load contact info:', err);
  }
}

/** Save the contact info form to the server */
export async function saveContactInfo(): Promise<void> {
  const info = collectFormData(lastSavedMain);
  if (!info) return; // Validation failed or no-op

  try {
    const response = await authenticatedFetch('/api/user/contact-info', {
      method: 'PUT',
      body: JSON.stringify(info),
    });

    if (!response.ok) {
      const result = await response.json().catch(() => ({}));
      throw new Error(result.message || `Server returned ${response.status}`);
    }

    lastSavedMain = cloneInfo(info);
    showSuccess('Contact information saved.');
  } catch (err) {
    showError(`Failed to save contact info: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/** Delete the user's contact info */
export async function deleteContactInfo(): Promise<void> {
  if (!confirm('Delete your contact information? This cannot be undone.')) return;

  try {
    const response = await authenticatedFetch('/api/user/contact-info', { method: 'DELETE' });

    if (!response.ok) {
      const result = await response.json().catch(() => ({}));
      throw new Error(result.message || `Server returned ${response.status}`);
    }

    lastSavedMain = null;
    clearForm();
    showSuccess('Contact information deleted.');
  } catch (err) {
    showError(`Failed to delete contact info: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/** Load contact info into the pending-approval section form */
export async function loadPendingContactInfo(): Promise<void> {
  try {
    const response = await authenticatedFetch('/api/user/contact-info', { method: 'GET' });

    if (!response.ok) {
      if (response.status === 401 || response.status === 403) return;
      throw new Error(`Server returned ${response.status}`);
    }

    const result = await response.json();
    if (result.data?.has_contact_info && result.data?.contact_info) {
      const info = result.data.contact_info as ContactInfo;
      lastSavedPending = cloneInfo(info);
      populatePendingForm(info);
    } else {
      lastSavedPending = null;
      clearPendingForm();
    }
  } catch (err) {
    console.error('Failed to load contact info (pending context):', err);
  }
}

/** Save the pending-section contact info form to the server */
export async function savePendingContactInfo(): Promise<void> {
  const info = collectPendingFormData(lastSavedPending);
  if (!info) return;

  try {
    const response = await authenticatedFetch('/api/user/contact-info', {
      method: 'PUT',
      body: JSON.stringify(info),
    });

    if (!response.ok) {
      const result = await response.json().catch(() => ({}));
      throw new Error(result.message || `Server returned ${response.status}`);
    }

    lastSavedPending = cloneInfo(info);
    showSuccess('Contact information saved.');
  } catch (err) {
    showError(`Failed to save contact info: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/** Delete contact info from the pending-section context */
export async function deletePendingContactInfo(): Promise<void> {
  if (!confirm('Delete your contact information? This cannot be undone.')) return;

  try {
    const response = await authenticatedFetch('/api/user/contact-info', { method: 'DELETE' });

    if (!response.ok) {
      const result = await response.json().catch(() => ({}));
      throw new Error(result.message || `Server returned ${response.status}`);
    }

    lastSavedPending = null;
    clearPendingForm();
    showSuccess('Contact information deleted.');
  } catch (err) {
    showError(`Failed to delete contact info: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/** Add a new empty contact method row to the pending-context form */
export function addPendingContactMethodRow(type = '', value = '', label = ''): void {
  addContactMethodRowToList('pending-ci-methods-list', type, value, label);
}

/** Add a new empty contact method row to the main contact-info panel */
export function addContactMethodRow(type = '', value = '', label = ''): void {
  addContactMethodRowToList('contact-methods-list', type, value, label);
}

/** Internal: add a contact method row to the specified list element */
function addContactMethodRowToList(listId: string, type = '', value = '', label = ''): void {
  const list = document.getElementById(listId);
  if (!list) return;

  const row = document.createElement('div');
  row.className = 'contact-method-row';
  row.innerHTML = `
    <select class="contact-type">
      ${VALID_CONTACT_TYPES.map(t =>
        `<option value="${t}"${t === type ? ' selected' : ''}>${typeLabel(t)}</option>`
      ).join('')}
    </select>
    <input type="text" class="contact-value" placeholder="Contact ID or number" value="${escapeAttr(value)}" maxlength="500">
    <input type="text" class="contact-label${type !== 'other' ? ' hidden' : ''}" placeholder="Label" value="${escapeAttr(label)}" maxlength="100">
    <button type="button" class="remove-contact-btn" title="Remove">[X]</button>
  `;

  // Toggle label field visibility on type change
  const select = row.querySelector('.contact-type') as HTMLSelectElement;
  const labelInput = row.querySelector('.contact-label') as HTMLInputElement;
  select?.addEventListener('change', () => {
    if (select.value === 'other') {
      labelInput?.classList.remove('hidden');
    } else {
      labelInput?.classList.add('hidden');
      if (labelInput) labelInput.value = '';
    }
  });

  // Remove button
  const removeBtn = row.querySelector('.remove-contact-btn');
  removeBtn?.addEventListener('click', () => row.remove());

  list.appendChild(row);
}

function collectContactsFromList(listId: string): ContactMethod[] | null {
  const contacts: ContactMethod[] = [];
  const list = document.getElementById(listId);
  const rows = list ? list.querySelectorAll('.contact-method-row') : [];
  for (const row of rows) {
    const typeSelect = row.querySelector('.contact-type') as HTMLSelectElement;
    const valueInput = row.querySelector('.contact-value') as HTMLInputElement;
    const labelInput = row.querySelector('.contact-label') as HTMLInputElement;

    const type = typeSelect?.value || '';
    const value = valueInput?.value.trim() || '';
    const label = labelInput?.value.trim() || '';

    if (!value) continue;

    const contact: ContactMethod = { type, value };
    if (type === 'other' && label) {
      contact.label = label;
    } else if (type === 'other' && !label) {
      showError('Label is required for "Other" contact type.');
      labelInput?.focus();
      return null;
    }
    contacts.push(contact);
  }
  return contacts;
}

/** Collect pending-section form data and validate */
function collectPendingFormData(lastSaved: ContactInfo | null): ContactInfo | null {
  const nameInput = document.getElementById('pending-ci-display-name') as HTMLInputElement;
  const notesInput = document.getElementById('pending-ci-notes') as HTMLTextAreaElement;

  let displayName = nameInput?.value.trim() || '';
  if (!displayName) {
    displayName = defaultDisplayName();
    if (nameInput) nameInput.value = displayName;
  }

  const contacts = collectContactsFromList('pending-ci-methods-list');
  if (contacts === null) return null;

  const info: ContactInfo = {
    display_name: displayName,
    contacts,
    notes: notesInput?.value.trim() || '',
  };

  if (!hasChangesFromSaved(info, lastSaved)) {
    showError('Nothing to save. Add or change contact details first.');
    return null;
  }

  return info;
}

/** Populate the pending-section form with existing contact info */
function populatePendingForm(info: ContactInfo): void {
  const nameInput = document.getElementById('pending-ci-display-name') as HTMLInputElement;
  const notesInput = document.getElementById('pending-ci-notes') as HTMLTextAreaElement;

  if (nameInput) nameInput.value = info.display_name || defaultDisplayName();
  if (notesInput) notesInput.value = info.notes || '';

  const list = document.getElementById('pending-ci-methods-list');
  if (list) list.innerHTML = '';

  if (info.contacts && info.contacts.length > 0) {
    for (const c of info.contacts) {
      addPendingContactMethodRow(c.type, c.value, c.label || '');
    }
  }
}

/** Clear the pending-section form to empty state (display name = username) */
function clearPendingForm(): void {
  const nameInput = document.getElementById('pending-ci-display-name') as HTMLInputElement;
  const notesInput = document.getElementById('pending-ci-notes') as HTMLTextAreaElement;
  const list = document.getElementById('pending-ci-methods-list');

  if (nameInput) nameInput.value = defaultDisplayName();
  if (notesInput) notesInput.value = '';
  if (list) list.innerHTML = '';
}

/** Collect form data and validate */
function collectFormData(lastSaved: ContactInfo | null): ContactInfo | null {
  const nameInput = document.getElementById('contact-display-name') as HTMLInputElement;
  const notesInput = document.getElementById('contact-notes') as HTMLTextAreaElement;

  let displayName = nameInput?.value.trim() || '';
  if (!displayName) {
    displayName = defaultDisplayName();
    if (nameInput) nameInput.value = displayName;
  }

  const contacts = collectContactsFromList('contact-methods-list');
  if (contacts === null) return null;

  const info: ContactInfo = {
    display_name: displayName,
    contacts,
    notes: notesInput?.value.trim() || '',
  };

  if (!hasChangesFromSaved(info, lastSaved)) {
    showError('Nothing to save. Add or change contact details first.');
    return null;
  }

  return info;
}

/** Populate the form with existing contact info */
function populateForm(info: ContactInfo): void {
  const nameInput = document.getElementById('contact-display-name') as HTMLInputElement;
  const notesInput = document.getElementById('contact-notes') as HTMLTextAreaElement;

  if (nameInput) nameInput.value = info.display_name || defaultDisplayName();
  if (notesInput) notesInput.value = info.notes || '';

  const list = document.getElementById('contact-methods-list');
  if (list) list.innerHTML = '';

  if (info.contacts && info.contacts.length > 0) {
    for (const c of info.contacts) {
      addContactMethodRow(c.type, c.value, c.label || '');
    }
  }
}

/** Clear the form to empty state (display name = username) */
function clearForm(): void {
  const nameInput = document.getElementById('contact-display-name') as HTMLInputElement;
  const notesInput = document.getElementById('contact-notes') as HTMLTextAreaElement;
  const list = document.getElementById('contact-methods-list');

  if (nameInput) nameInput.value = defaultDisplayName();
  if (notesInput) notesInput.value = '';
  if (list) list.innerHTML = '';
}

/** Human-readable label for a contact type */
function typeLabel(type: string): string {
  const labels: Record<string, string> = {
    email: 'Email',
    sms: 'SMS',
    signal: 'Signal',
    whatsapp: 'WhatsApp',
    wechat: 'WeChat',
    telegram: 'Telegram',
    matrix: 'Matrix',
    other: 'Other...'
  };
  return labels[type] || type;
}

/** Escape a string for use in an HTML attribute value */
function escapeAttr(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
