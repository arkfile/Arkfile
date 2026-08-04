import { describe, test, expect } from 'bun:test';
import {
  nextAvailableBasename,
  reserveBasenames,
  splitBasenameExtension,
} from '../files/output-basename.js';

describe('output basename helper', () => {
  test('splitBasenameExtension', () => {
    expect(splitBasenameExtension('photo.png')).toEqual({ stem: 'photo', ext: '.png' });
    expect(splitBasenameExtension('readme')).toEqual({ stem: 'readme', ext: '' });
    expect(splitBasenameExtension('/tmp/a.b.c')).toEqual({ stem: 'a.b', ext: '.c' });
  });

  test('nextAvailableBasename increments before extension', () => {
    const taken = new Set<string>(['photo.png', 'photo-1.png']);
    expect(nextAvailableBasename('photo.png', taken)).toBe('photo-2.png');
  });

  test('reserveBasenames is stable for a batch', () => {
    const reserved = reserveBasenames([
      { key: 'a', filename: 'photo.png' },
      { key: 'b', filename: 'photo.png' },
    ]);
    expect(reserved.get('a')).toBe('photo.png');
    expect(reserved.get('b')).toBe('photo-1.png');
  });
});
