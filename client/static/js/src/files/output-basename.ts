/**
 * Basename collision helper for multi-file download and export.
 * photo.png -> photo-1.png -> photo-2.png
 *
 * Collisions compare case-insensitively because backup and restore targets
 * are often case-insensitive (FAT or exFAT drives, macOS and Windows folders
 * reached through the directory picker). Returned names keep their case.
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

// C0/C1 controls, DEL, and Unicode bidirectional controls.
const UNSAFE_NAME_CHARS = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;

/**
 * Reduce an owner's decrypted filename to one safe path element, keeping
 * leading dots (dotfile backups are legitimate) but rejecting names made only
 * of dots. Mirrors safeOwnerBasename in the CLI.
 */
export function safeOwnerBasename(name: string, fallback: string): string {
  const reduce = (value: string): string => {
    const base = value.replace(/^.*[/\\]/, '').replace(UNSAFE_NAME_CHARS, '');
    const trimmed = base.replace(/^[-\s]+/, '').replace(/\s+$/, '');
    return /^\.*$/.test(trimmed) ? '' : trimmed;
  };
  return reduce(name) || reduce(fallback) || 'download';
}

/** `taken` holds lowercase names. */
export function nextAvailableBasename(
  desiredName: string,
  taken: ReadonlySet<string>,
): string {
  const { stem, ext } = splitBasenameExtension(desiredName);
  let candidate = `${stem}${ext}`;
  if (!taken.has(candidate.toLowerCase())) {
    return candidate;
  }
  let n = 1;
  while (taken.has(`${stem}-${n}${ext}`.toLowerCase())) {
    n += 1;
  }
  return `${stem}-${n}${ext}`;
}

/**
 * Hands out collision-free names inside one destination. With a suffix such
 * as ".arkbackup", reservation works on names without the suffix
 * (photo.png -> photo.png.arkbackup, photo-1.png.arkbackup) and only
 * existing entries ending in the suffix count as taken.
 */
export class BasenameReserver {
  private readonly taken = new Set<string>();

  constructor(
    alreadyTaken: Iterable<string> = [],
    private readonly suffix = '',
  ) {
    for (const name of alreadyTaken) {
      this.markTaken(name);
    }
  }

  markTaken(name: string): void {
    if (!name) return;
    const lower = name.toLowerCase();
    if (!this.suffix) {
      this.taken.add(lower);
      return;
    }
    const lowerSuffix = this.suffix.toLowerCase();
    if (lower.endsWith(lowerSuffix)) {
      this.taken.add(lower.slice(0, lower.length - lowerSuffix.length));
    }
  }

  /** Claims the first free name derived from desired, with the suffix appended. */
  reserve(desired: string): string {
    const name = nextAvailableBasename(desired, this.taken);
    this.taken.add(name.toLowerCase());
    return `${name}${this.suffix}`;
  }
}

/**
 * Reserve unique basenames for a batch. Each target keeps its reserved name
 * across retries -- callers should reuse the returned map rather than
 * re-running reservation after a failed attempt.
 */
export function reserveBasenames(
  items: ReadonlyArray<{ key: string; filename: string }>,
  alreadyTaken: Iterable<string> = [],
  suffix = '',
): Map<string, string> {
  const reserver = new BasenameReserver(alreadyTaken, suffix);
  const reserved = new Map<string, string>();
  for (const item of items) {
    reserved.set(item.key, reserver.reserve(item.filename || item.key));
  }
  return reserved;
}
