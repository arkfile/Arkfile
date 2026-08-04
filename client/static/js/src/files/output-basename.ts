/**
 * Basename collision helper for multi-file download.
 * photo.png -> photo-1.png -> photo-2.png
 */

export function splitBasenameExtension(filename: string): { stem: string; ext: string } {
  const base = filename.replace(/^.*[/\\]/, '');
  const safe = base.length > 0 ? base : 'download';
  const lastDot = safe.lastIndexOf('.');
  if (lastDot <= 0) {
    return { stem: safe, ext: '' };
  }
  return {
    stem: safe.slice(0, lastDot),
    ext: safe.slice(lastDot),
  };
}

export function nextAvailableBasename(
  desiredName: string,
  taken: ReadonlySet<string>,
): string {
  const { stem, ext } = splitBasenameExtension(desiredName);
  let candidate = `${stem}${ext}`;
  if (!taken.has(candidate)) {
    return candidate;
  }
  let n = 1;
  while (taken.has(`${stem}-${n}${ext}`)) {
    n += 1;
  }
  return `${stem}-${n}${ext}`;
}

/**
 * Reserve unique basenames for a batch. Each target keeps its reserved name
 * across retries -- callers should reuse the returned map rather than
 * re-running reservation after a failed attempt.
 */
export function reserveBasenames(
  items: ReadonlyArray<{ key: string; filename: string }>,
  alreadyTaken: Iterable<string> = [],
): Map<string, string> {
  const taken = new Set<string>();
  for (const name of alreadyTaken) {
    if (name) {
      taken.add(name);
    }
  }
  const reserved = new Map<string, string>();
  for (const item of items) {
    const name = nextAvailableBasename(item.filename || item.key, taken);
    taken.add(name);
    reserved.set(item.key, name);
  }
  return reserved;
}
