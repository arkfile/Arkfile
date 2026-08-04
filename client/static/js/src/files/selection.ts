/**
 * Client-side selection set for owner file multi-download.
 * Selection is a Set of file_id values. Changing the tag filter should prune
 * to IDs that remain in the loaded matching set.
 */

export type SelectionChangeListener = (selected: ReadonlySet<string>) => void;

const selectedIds = new Set<string>();
const listeners = new Set<SelectionChangeListener>();

function notify(): void {
  const snapshot = new Set(selectedIds);
  for (const listener of listeners) {
    listener(snapshot);
  }
}

export function getSelectedFileIds(): ReadonlySet<string> {
  return selectedIds;
}

export function getSelectedCount(): number {
  return selectedIds.size;
}

export function isFileSelected(fileId: string): boolean {
  return selectedIds.has(fileId);
}

export function toggleFileSelection(fileId: string): boolean {
  if (!fileId) {
    return false;
  }
  if (selectedIds.has(fileId)) {
    selectedIds.delete(fileId);
  } else {
    selectedIds.add(fileId);
  }
  notify();
  return selectedIds.has(fileId);
}

export function setFileSelected(fileId: string, selected: boolean): void {
  if (!fileId) {
    return;
  }
  if (selected) {
    selectedIds.add(fileId);
  } else {
    selectedIds.delete(fileId);
  }
  notify();
}

/** Select every ID in `visibleIds` (select-all shown). */
export function selectVisible(visibleIds: Iterable<string>): void {
  for (const id of visibleIds) {
    if (id) {
      selectedIds.add(id);
    }
  }
  notify();
}

/** Replace selection with exactly the provided IDs (select-all matching filter). */
export function replaceSelection(ids: Iterable<string>): void {
  selectedIds.clear();
  for (const id of ids) {
    if (id) {
      selectedIds.add(id);
    }
  }
  notify();
}

/** Drop selected IDs that are not in `allowedIds`. */
export function pruneSelectionTo(allowedIds: Iterable<string>): void {
  const allowed = new Set<string>();
  for (const id of allowedIds) {
    if (id) {
      allowed.add(id);
    }
  }
  let changed = false;
  for (const id of Array.from(selectedIds)) {
    if (!allowed.has(id)) {
      selectedIds.delete(id);
      changed = true;
    }
  }
  if (changed) {
    notify();
  }
}

export function clearSelection(): void {
  if (selectedIds.size === 0) {
    return;
  }
  selectedIds.clear();
  notify();
}

export function onSelectionChange(listener: SelectionChangeListener): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** Header checkbox state for the currently visible rows. */
export function visibleSelectionState(
  visibleIds: readonly string[],
): 'none' | 'some' | 'all' {
  if (visibleIds.length === 0) {
    return 'none';
  }
  let selectedVisible = 0;
  for (const id of visibleIds) {
    if (selectedIds.has(id)) {
      selectedVisible += 1;
    }
  }
  if (selectedVisible === 0) {
    return 'none';
  }
  if (selectedVisible === visibleIds.length) {
    return 'all';
  }
  return 'some';
}
