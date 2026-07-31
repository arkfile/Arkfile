/**
 * Post-upload single-tag mutation and Edit tags modal.
 */

import { authenticatedFetch, getUsernameFromToken } from '../utils/auth';
import { showError, showSuccess } from '../ui/messages';
import { getCachedAccountKey } from '../crypto/file-encryption';
import { decryptMetadataField } from '../crypto/metadata-helpers';
import { AAD_FIELD_TAGS, buildMetadataFieldAAD } from '../crypto/aad';
import { encryptAESGCM, toBase64, concatBytes } from '../crypto/primitives';
import {
  loadFileTagsParams,
  parseAndAddTags,
  parseTagList,
  removeTag,
  replaceTag,
  serializeTags,
  tagPresent,
  type FileTagsParams,
} from '../crypto/file-tags';

export interface TagMutationTarget {
  file_id: string;
  owner_username: string;
  filename: string;
  tags: string[];
  tags_available: boolean;
  tags_revision: number;
  encrypted_tags?: string;
  tags_nonce?: string;
}

type MutationKind = 'add' | 'remove' | 'replace';

async function encryptTagsPayload(
  tags: string[],
  accountKey: Uint8Array,
  fileID: string,
  ownerUsername: string,
): Promise<{ encrypted_tags: string; tags_nonce: string }> {
  if (tags.length === 0) {
    return { encrypted_tags: '', tags_nonce: '' };
  }
  const plaintext = new TextEncoder().encode(serializeTags(tags));
  const aad = buildMetadataFieldAAD(fileID, AAD_FIELD_TAGS, ownerUsername);
  const result = await encryptAESGCM({ data: plaintext, key: accountKey, aad });
  return {
    encrypted_tags: toBase64(concatBytes(result.ciphertext, result.tag)),
    tags_nonce: toBase64(result.iv),
  };
}

async function putTags(
  fileID: string,
  encrypted_tags: string,
  tags_nonce: string,
  expected_revision: number,
): Promise<number> {
  const response = await authenticatedFetch(`/api/files/${fileID}/tags`, {
    method: 'PUT',
    body: JSON.stringify({ encrypted_tags, tags_nonce, expected_revision }),
  });
  if (response.status === 409) {
    const body = await response.json().catch(() => ({}));
    const err = new Error((body as { message?: string }).message || 'tags revision conflict');
    (err as Error & { code?: string }).code = 'tags_revision_conflict';
    throw err;
  }
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error((body as { message?: string }).message || `Failed to update tags (HTTP ${response.status})`);
  }
  const data = (await response.json()) as { tags_revision: number };
  return data.tags_revision;
}

async function fetchCurrentTags(fileID: string, accountKey: Uint8Array, ownerUsername: string): Promise<{
  tags: string[];
  tags_available: boolean;
  tags_revision: number;
}> {
  const response = await authenticatedFetch(`/api/files/${fileID}/meta`);
  if (!response.ok) {
    throw new Error('Failed to reload file metadata');
  }
  const meta = (await response.json()) as {
    tags_revision?: number;
    encrypted_tags?: string;
    tags_nonce?: string;
    owner_username?: string;
  };
  const revision = meta.tags_revision ?? 0;
  const owner = meta.owner_username || ownerUsername;
  if (!meta.encrypted_tags || !meta.tags_nonce) {
    return { tags: [], tags_available: true, tags_revision: revision };
  }
  try {
    const plaintext = await decryptMetadataField(
      meta.encrypted_tags,
      meta.tags_nonce,
      accountKey,
      fileID,
      AAD_FIELD_TAGS,
      owner,
    );
    const tags = plaintext ? plaintext.split(',') : [];
    return { tags, tags_available: true, tags_revision: revision };
  } catch {
    return { tags: [], tags_available: false, tags_revision: revision };
  }
}

async function applyMutation(
  target: TagMutationTarget,
  kind: MutationKind,
  tagA: string,
  tagB: string,
  params: FileTagsParams,
  allowRetry: boolean,
): Promise<TagMutationTarget> {
  const username = getUsernameFromToken();
  if (!username) {
    throw new Error('Not logged in');
  }
  const accountKey = await getCachedAccountKey(username, undefined);
  if (!accountKey) {
    throw new Error('Unlock file metadata before editing tags');
  }

  let working = { ...target, tags: target.tags.slice() };
  if (!working.tags_available) {
    const refreshed = await fetchCurrentTags(working.file_id, accountKey, working.owner_username);
    if (!refreshed.tags_available) {
      throw new Error('Could not decrypt current tags');
    }
    working.tags = refreshed.tags;
    working.tags_revision = refreshed.tags_revision;
    working.tags_available = true;
  }

  let nextTags: string[];
  if (kind === 'add') {
    // tagA may be one tag or a comma-separated list (spaces around commas trimmed).
    nextTags = parseAndAddTags(working.tags, tagA, params);
    if (serializeTags(nextTags) === serializeTags(working.tags)) {
      return working;
    }
  } else if (kind === 'remove') {
    if (!tagPresent(working.tags, tagA)) {
      return working;
    }
    nextTags = removeTag(working.tags, tagA);
  } else {
    nextTags = replaceTag(working.tags, tagA, tagB, params);
  }

  const payload = await encryptTagsPayload(nextTags, accountKey, working.file_id, working.owner_username);
  try {
    const newRevision = await putTags(
      working.file_id,
      payload.encrypted_tags,
      payload.tags_nonce,
      working.tags_revision,
    );
    return {
      ...working,
      tags: nextTags,
      tags_revision: newRevision,
      tags_available: true,
    };
  } catch (err) {
    const code = (err as Error & { code?: string }).code;
    if (code !== 'tags_revision_conflict' || !allowRetry) {
      throw err;
    }
    const refreshed = await fetchCurrentTags(working.file_id, accountKey, working.owner_username);
    if (!refreshed.tags_available) {
      throw new Error('Tags changed and could not be reloaded');
    }
    if (kind === 'add') {
      const wanted = parseTagList(tagA);
      if (wanted.length > 0 && wanted.every((t) => tagPresent(refreshed.tags, t))) {
        return { ...working, tags: refreshed.tags, tags_revision: refreshed.tags_revision, tags_available: true };
      }
    }
    if (kind === 'remove' && !tagPresent(refreshed.tags, tagA)) {
      return { ...working, tags: refreshed.tags, tags_revision: refreshed.tags_revision, tags_available: true };
    }
    if (kind === 'replace' && !tagPresent(refreshed.tags, tagA)) {
      throw new Error('Tags changed; the original tag is no longer present');
    }
    const retried: TagMutationTarget = {
      ...working,
      tags: refreshed.tags,
      tags_revision: refreshed.tags_revision,
      tags_available: true,
    };
    return applyMutation(retried, kind, tagA, tagB, params, false);
  }
}

let activeTarget: TagMutationTarget | null = null;
let onUpdated: ((updated: TagMutationTarget) => void) | null = null;
let previouslyFocused: HTMLElement | null = null;
let editTagsModalWired = false;

function getEditTagsModal(): HTMLElement | null {
  return document.getElementById('editTagsModal');
}

function setModalOpenState(modal: HTMLElement, open: boolean): void {
  modal.classList.toggle('hidden', !open);
  modal.setAttribute('aria-hidden', open ? 'false' : 'true');
  if (open) {
    modal.removeAttribute('inert');
  } else {
    modal.setAttribute('inert', '');
  }
}

function closeEditTagsModal(): void {
  const modal = getEditTagsModal();
  if (modal) {
    setModalOpenState(modal, false);
  }
  activeTarget = null;
  onUpdated = null;
  const restore = previouslyFocused;
  previouslyFocused = null;
  if (restore && typeof restore.focus === 'function') {
    restore.focus();
  }
}

function renderEditChips(tags: string[]): void {
  const chips = document.getElementById('editTagsChips');
  if (!chips) return;
  chips.innerHTML = '';
  for (const tag of tags) {
    const chip = document.createElement('span');
    chip.className = 'tag-chip';
    chip.textContent = tag;
    const removeBtn = document.createElement('button');
    removeBtn.type = 'button';
    removeBtn.className = 'tag-chip-remove';
    removeBtn.setAttribute('aria-label', `Remove tag ${tag}`);
    removeBtn.textContent = 'x';
    removeBtn.addEventListener('click', () => {
      void runModalMutation('remove', tag, '');
    });
    chip.appendChild(removeBtn);
    chips.appendChild(chip);
  }
  if (tags.length === 0) {
    chips.textContent = 'No tags';
  }
}

async function runModalMutation(kind: MutationKind, tagA: string, tagB: string): Promise<void> {
  if (!activeTarget) return;
  const status = document.getElementById('editTagsStatus');
  try {
    const params = await loadFileTagsParams();
    const updated = await applyMutation(activeTarget, kind, tagA, tagB, params, true);
    activeTarget = updated;
    renderEditChips(updated.tags);
    if (status) status.textContent = '';
    onUpdated?.(updated);
    showSuccess(kind === 'remove' ? 'Tag removed' : kind === 'replace' ? 'Tag replaced' : 'Tags updated');
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Tag update failed';
    if (status) status.textContent = message;
    showError(message);
  }
}

export function openEditTagsModal(
  target: TagMutationTarget,
  onChange: (updated: TagMutationTarget) => void,
): void {
  activeTarget = { ...target, tags: target.tags.slice() };
  onUpdated = onChange;
  const modal = getEditTagsModal();
  const filenameEl = document.getElementById('editTagsFilename');
  const status = document.getElementById('editTagsStatus');
  if (filenameEl) filenameEl.textContent = target.filename;
  if (status) status.textContent = '';
  renderEditChips(activeTarget.tags);
  previouslyFocused = document.activeElement instanceof HTMLElement
    ? document.activeElement
    : null;
  if (modal) {
    setModalOpenState(modal, true);
  }
  const addInput = document.getElementById('editTagsAddInput') as HTMLInputElement | null;
  addInput?.focus();
}

export function wireEditTagsModal(): void {
  if (editTagsModalWired) return;
  editTagsModalWired = true;

  const modal = getEditTagsModal();
  if (modal) {
    // Ensure closed state matches markup even if CSS/JS load order differs.
    setModalOpenState(modal, false);
  }

  document.getElementById('editTagsCloseBtn')?.addEventListener('click', () => {
    closeEditTagsModal();
  });

  modal?.addEventListener('click', (ev) => {
    if (ev.target === modal) {
      closeEditTagsModal();
    }
  });

  document.addEventListener('keydown', (ev) => {
    if (ev.key !== 'Escape') return;
    const openModal = getEditTagsModal();
    if (!openModal || openModal.classList.contains('hidden')) return;
    ev.preventDefault();
    closeEditTagsModal();
  });

  document.getElementById('editTagsAddBtn')?.addEventListener('click', () => {
    const input = document.getElementById('editTagsAddInput') as HTMLInputElement | null;
    const value = input?.value.trim() || '';
    if (!value) return;
    void runModalMutation('add', value, '').then(() => {
      if (input) input.value = '';
    });
  });
  document.getElementById('editTagsAddInput')?.addEventListener('keydown', (ev) => {
    if (ev.key !== 'Enter') return;
    ev.preventDefault();
    document.getElementById('editTagsAddBtn')?.click();
  });

  document.getElementById('editTagsReplaceBtn')?.addEventListener('click', () => {
    const from = document.getElementById('editTagsReplaceFrom') as HTMLInputElement | null;
    const to = document.getElementById('editTagsReplaceTo') as HTMLInputElement | null;
    const a = from?.value.trim() || '';
    const b = to?.value.trim() || '';
    if (!a || !b) return;
    void runModalMutation('replace', a, b).then(() => {
      if (from) from.value = '';
      if (to) to.value = '';
    });
  });
}
