import { describe, test, expect, beforeEach } from 'bun:test';
import {
  clearSelection,
  getSelectedCount,
  isFileSelected,
  pruneSelectionTo,
  replaceSelection,
  selectVisible,
  setFileSelected,
  toggleFileSelection,
  visibleSelectionState,
} from '../files/selection.js';

beforeEach(() => {
  clearSelection();
});

describe('file selection set', () => {
  test('toggle and count', () => {
    expect(toggleFileSelection('a')).toBe(true);
    expect(isFileSelected('a')).toBe(true);
    expect(getSelectedCount()).toBe(1);
    expect(toggleFileSelection('a')).toBe(false);
    expect(getSelectedCount()).toBe(0);
  });

  test('selectVisible and prune', () => {
    selectVisible(['a', 'b', 'c']);
    expect(getSelectedCount()).toBe(3);
    pruneSelectionTo(['a', 'c']);
    expect(isFileSelected('a')).toBe(true);
    expect(isFileSelected('b')).toBe(false);
    expect(isFileSelected('c')).toBe(true);
  });

  test('replaceSelection for matching filter', () => {
    selectVisible(['a']);
    replaceSelection(['x', 'y']);
    expect(getSelectedCount()).toBe(2);
    expect(isFileSelected('a')).toBe(false);
    expect(isFileSelected('x')).toBe(true);
  });

  test('visibleSelectionState', () => {
    setFileSelected('a', true);
    expect(visibleSelectionState(['a', 'b'])).toBe('some');
    setFileSelected('b', true);
    expect(visibleSelectionState(['a', 'b'])).toBe('all');
    clearSelection();
    expect(visibleSelectionState(['a', 'b'])).toBe('none');
  });
});
