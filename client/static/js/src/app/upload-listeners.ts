/** Upload button, file/folder selection, and cancel wiring. */

type PendingUploadSelection = {
  files: File[];
  source: 'files' | 'folder';
};

let pendingSelection: PendingUploadSelection = { files: [], source: 'files' };
let activeUploadAbort: AbortController | null = null;

function basenameOnly(file: File): string {
  // Folder picks may expose webkitRelativePath; encrypted metadata uses base name only.
  const name = file.name || '';
  const slash = Math.max(name.lastIndexOf('/'), name.lastIndexOf('\\'));
  return slash >= 0 ? name.slice(slash + 1) : name;
}

function updateCustomPasswordLabel(count: number): void {
  const label = document.getElementById('customPasswordLabel');
  if (!label) return;
  label.textContent = count > 1
    ? 'Use a custom password for these files'
    : 'Use a custom password for this file';
}

function renderSelectedFilesList(files: File[]): void {
  const list = document.getElementById('selectedFilesList');
  const clearBtn = document.getElementById('clear-file-selection-btn');
  if (!list) return;

  if (files.length === 0) {
    list.classList.add('hidden');
    list.innerHTML = '';
    clearBtn?.classList.add('hidden');
    updateCustomPasswordLabel(0);
    return;
  }

  const names = files.map(basenameOnly);
  const preview = names.slice(0, 12);
  const extra = names.length > 12 ? `<li class="selected-files-more">…and ${names.length - 12} more</li>` : '';
  list.innerHTML = `<p class="selected-files-count">${names.length} file${names.length === 1 ? '' : 's'} selected</p><ul>${preview.map((n) => `<li>${escapeHtml(n)}</li>`).join('')}${extra}</ul>`;
  list.classList.remove('hidden');
  clearBtn?.classList.remove('hidden');
  updateCustomPasswordLabel(files.length);
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function setLabelState(
  labelId: string,
  nameId: string,
  text: string,
  hasFile: boolean,
): void {
  const label = document.getElementById(labelId);
  const nameEl = document.getElementById(nameId);
  if (nameEl) nameEl.textContent = text;
  if (label) {
    if (hasFile) label.classList.add('has-file');
    else label.classList.remove('has-file');
  }
}

function clearPendingSelection(): void {
  pendingSelection = { files: [], source: 'files' };
  const fileInput = document.getElementById('fileInput') as HTMLInputElement | null;
  const folderInput = document.getElementById('folderInput') as HTMLInputElement | null;
  if (fileInput) fileInput.value = '';
  if (folderInput) folderInput.value = '';
  setLabelState('fileInputLabel', 'fileInputName', '', false);
  setLabelState('folderInputLabel', 'folderInputName', '', false);
  renderSelectedFilesList([]);
}

/** Clear the queued file/folder selection in the upload UI. */
export function clearUploadSelection(): void {
  clearPendingSelection();
}

/** Snapshot of files currently queued for upload (base-name display only). */
export function getPendingUploadFiles(): File[] {
  return pendingSelection.files.slice();
}

/** AbortController for the in-flight batch, if any. */
export function getActiveUploadAbortController(): AbortController | null {
  return activeUploadAbort;
}

export function setActiveUploadAbortController(controller: AbortController | null): void {
  activeUploadAbort = controller;
  const cancelBtn = document.getElementById('cancel-upload-btn');
  if (!cancelBtn) return;
  if (controller) cancelBtn.classList.remove('hidden');
  else cancelBtn.classList.add('hidden');
}

export function setupUploadListeners(): void {
  const uploadFileBtn = document.getElementById('upload-file-btn');
  if (uploadFileBtn) {
    uploadFileBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      const { handleFileUpload } = await import('../files/upload');
      await handleFileUpload();
    });
  }

  const cancelBtn = document.getElementById('cancel-upload-btn');
  if (cancelBtn) {
    cancelBtn.addEventListener('click', (e) => {
      e.preventDefault();
      if (activeUploadAbort) {
        activeUploadAbort.abort();
      }
    });
  }

  const clearBtn = document.getElementById('clear-file-selection-btn');
  if (clearBtn) {
    clearBtn.addEventListener('click', (e) => {
      e.preventDefault();
      clearPendingSelection();
    });
  }

  const fileInput = document.getElementById('fileInput') as HTMLInputElement | null;
  if (fileInput) {
    fileInput.addEventListener('change', () => {
      const files = fileInput.files ? Array.from(fileInput.files) : [];
      pendingSelection = { files, source: 'files' };
      const folderInput = document.getElementById('folderInput') as HTMLInputElement | null;
      if (folderInput) folderInput.value = '';
      setLabelState('folderInputLabel', 'folderInputName', '', false);
      if (files.length === 1) {
        setLabelState('fileInputLabel', 'fileInputName', basenameOnly(files[0]), true);
      } else if (files.length > 1) {
        setLabelState('fileInputLabel', 'fileInputName', `${files.length} files selected`, true);
      } else {
        setLabelState('fileInputLabel', 'fileInputName', '', false);
      }
      renderSelectedFilesList(files);
    });
  }

  const folderInput = document.getElementById('folderInput') as HTMLInputElement | null;
  if (folderInput) {
    folderInput.addEventListener('change', () => {
      // Flatten directory pick into a File list; encrypt base names only.
      const files = folderInput.files
        ? Array.from(folderInput.files).filter((f) => f.size > 0)
        : [];
      pendingSelection = { files, source: 'folder' };
      const fileInputEl = document.getElementById('fileInput') as HTMLInputElement | null;
      if (fileInputEl) fileInputEl.value = '';
      setLabelState('fileInputLabel', 'fileInputName', '', false);
      if (files.length > 0) {
        setLabelState('folderInputLabel', 'folderInputName', `${files.length} files from folder`, true);
      } else {
        setLabelState('folderInputLabel', 'folderInputName', '', false);
      }
      renderSelectedFilesList(files);
    });
  }
}
