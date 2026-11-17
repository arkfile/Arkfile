import { describe, test, expect } from 'bun:test';
import {
  BasenameReserver,
  nextAvailableBasename,
  reserveBasenames,
  safeDownloadBasename,
  safeOwnerBasename,
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

  test('collisions are case-insensitive and keep the requested case', () => {
    const reserved = reserveBasenames(
      [
        { key: 'a', filename: 'photo.png' },
        { key: 'b', filename: 'PHOTO.png' },
      ],
      ['Photo.png'],
    );
    expect(reserved.get('a')).toBe('photo-1.png');
    expect(reserved.get('b')).toBe('PHOTO-2.png');
  });

  test('suffix reservation keeps the original extension and counts existing bundles', () => {
    const reserved = reserveBasenames(
      [
        { key: 'a', filename: 'photo.png' },
        { key: 'b', filename: 'photo.png' },
        { key: 'c', filename: 'photo.jpg' },
      ],
      ['photo.png.arkbackup', 'photo.jpg'],
      '.arkbackup',
    );
    expect(reserved.get('a')).toBe('photo-1.png.arkbackup');
    expect(reserved.get('b')).toBe('photo-2.png.arkbackup');
    expect(reserved.get('c')).toBe('photo.jpg.arkbackup');
  });

  test('BasenameReserver hands out a fresh name after a late collision', () => {
    const reserver = new BasenameReserver([], '.arkbackup');
    expect(reserver.reserve('photo.png')).toBe('photo.png.arkbackup');
    expect(reserver.reserve('photo.png')).toBe('photo-1.png.arkbackup');
  });

  test('safeOwnerBasename keeps leading dots and strips paths and controls', () => {
    expect(safeOwnerBasename('.bashrc', 'id')).toBe('.bashrc');
    expect(safeOwnerBasename('../../etc/passwd', 'id')).toBe('passwd');
    expect(safeOwnerBasename('..', 'id')).toBe('id');
    expect(safeOwnerBasename('bad\u001b[31m\u202ename.txt', 'id')).toBe('bad[31mname.txt');
    expect(safeOwnerBasename('', '')).toBe('download');
  });

  test('safeDownloadBasename strips leading dots, dashes, paths, and bidi controls', () => {
    expect(safeDownloadBasename('.bashrc', 'share.bin')).toBe('bashrc');
    expect(safeDownloadBasename('--rf', 'share.bin')).toBe('rf');
    expect(safeDownloadBasename('../../etc/passwd', 'share.bin')).toBe('passwd');
    expect(safeDownloadBasename('invoice\u202Efdp.exe', 'share.bin')).toBe('invoicefdp.exe');
    expect(safeDownloadBasename('...', 'share.bin')).toBe('share.bin');
    expect(safeDownloadBasename('', '')).toBe('download');
  });

  test('safeDownloadBasename bounds length and keeps a short extension', () => {
    const long = `${'a'.repeat(300)}.pdf`;
    const safe = safeDownloadBasename(long, 'share.bin');
    expect(new TextEncoder().encode(safe).length).toBeLessThanOrEqual(200);
    expect(safe.endsWith('.pdf')).toBe(true);
    const multiByte = safeDownloadBasename(`${'\u00e9'.repeat(150)}.txt`, 'share.bin');
    expect(new TextEncoder().encode(multiByte).length).toBeLessThanOrEqual(200);
    expect(multiByte.endsWith('.txt')).toBe(true);
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
