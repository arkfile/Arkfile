/**
 * Contact information management UI
 * Allows users to set, view, and delete their contact details.
 * Contact info is encrypted server-side and readable only by the admin.
 */

import { getToken } from '../utils/auth';
import { showError, showSuccess } from './messages';

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

/** Toggle the contact info panel visibility and load data when opening */
export async function toggleContactInfoPanel(): Promise<void> {
  const panel = document.getElementById('contact-info-panel');
  if (!panel) return;

  const isHidden = panel.classList.contains('hidden');
  panel.classList.toggle('hidden');

  // Close security settings if open
  const securityPanel = document.getElementById('security-settings');
  if (securityPanel && !securityPanel.classList.contains('hidden')) {
    securityPanel.classList.add('hidden');
  }

  // Load contact info when opening the panel
  if (isHidden) {
    await loadContactInfo();
  }
}

/** Load the user's current contact info from the server */
export async function loadContactInfo(): Promise<void> {
  const token = getToken();
  if (!token) return;

  try {
    const response = await fetch('/api/user/contact-info', {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${token}` }
    });

    if (!response.ok) {
      if (response.status === 401) return;
      throw new Error(`Server returned ${response.status}`);
    }

    const result = await response.json();
    if (result.data?.has_contact_info && result.data?.contact_info) {
      populateForm(result.data.contact_info as ContactInfo);
    } else {
      clearForm();
    }
  } catch (err) {
    console.error('Failed to load contact info:', err);
  }
}

/** Save the contact info form to the server */
export async function saveContactInfo(): Promise<void> {
  const token = getToken();
  if (!token) {
    showError('Not authenticated. Please log in.');
    return;
  }

  const info = collectFormData();
  if (!info) return; // Validation failed

  try {
    const response = await fetch('/api/user/contact-info', {
      method: 'PUT',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(info)
    });

    if (!response.ok) {
      const result = await response.json().catch(() => ({}));
      throw new Error(result.message || `Server returned ${response.status}`);
    }

    showSuccess('Contact information saved.');
  } catch (err) {
    showError(`Failed to save contact info: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/** Delete the user's contact info */
export async function deleteContactInfo(): Promise<void> {
  const token = getToken();
  if (!token) return;

  if (!confirm('Delete your contact information? This cannot be undone.')) return;

  try {
    const response = await fetch('/api/user/contact-info', {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${token}` }
    });

    if (!response.ok) {
      const result = await response.json().catch(() => ({}));
      throw new Error(result.message || `Server returned ${response.status}`);
    }

    clearForm();
    showSuccess('Contact information deleted.');
  } catch (err) {
    showError(`Failed to delete contact info: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/** Add a new empty contact method row to the form */
export function addContactMethodRow(type = '', value = '', label = ''): void {
  const list = document.getElementById('contact-methods-list');
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

/** Collect form data and validate */
function collectFormData(): ContactInfo | null {
  const nameInput = document.getElementById('contact-display-name') as HTMLInputElement;
  const notesInput = document.getElementById('contact-notes') as HTMLTextAreaElement;

  const displayName = nameInput?.value.trim() || '';
  if (!displayName) {
    showError('Display name is required.');
    nameInput?.focus();
    return null;
  }

  const contacts: ContactMethod[] = [];
  const rows = document.querySelectorAll('.contact-method-row');
  for (const row of rows) {
    const typeSelect = row.querySelector('.contact-type') as HTMLSelectElement;
    const valueInput = row.querySelector('.contact-value') as HTMLInputElement;
    const labelInput = row.querySelector('.contact-label') as HTMLInputElement;

    const type = typeSelect?.value || '';
    const value = valueInput?.value.trim() || '';
    const label = labelInput?.value.trim() || '';

    if (!value) continue; // Skip empty rows

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

  return {
    display_name: displayName,
    contacts,
    notes: notesInput?.value.trim() || ''
  };
}

/** Populate the form with existing contact info */
function populateForm(info: ContactInfo): void {
  const nameInput = document.getElementById('contact-display-name') as HTMLInputElement;
  const notesInput = document.getElementById('contact-notes') as HTMLTextAreaElement;

  if (nameInput) nameInput.value = info.display_name || '';
  if (notesInput) notesInput.value = info.notes || '';

  // Clear existing rows and add from data
  const list = document.getElementById('contact-methods-list');
  if (list) list.innerHTML = '';

  if (info.contacts && info.contacts.length > 0) {
    for (const c of info.contacts) {
      addContactMethodRow(c.type, c.value, c.label || '');
    }
  }
}

/** Clear the form to empty state */
function clearForm(): void {
  const nameInput = document.getElementById('contact-display-name') as HTMLInputElement;
  const notesInput = document.getElementById('contact-notes') as HTMLTextAreaElement;
  const list = document.getElementById('contact-methods-list');

  if (nameInput) nameInput.value = '';
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
