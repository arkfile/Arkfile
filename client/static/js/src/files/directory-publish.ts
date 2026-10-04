/**
 * Publishing files into a directory chosen with showDirectoryPicker.
 *
 * Writes go to a temporary entry that move() renames to the reserved name
 * after a fresh absence check. The File System Access API has no atomic
 * no-replace rename, so a destination created by another program between
 * that check and move() can still be replaced; that residual race is
 * documented, never widened. Where move() is unsupported, the reserved
 * entry is created only after a fresh absence check. Failure cleanup removes
 * only entries the attempt itself created.
 */

/** Late collisions tolerated before a publish gives up. */
const MAX_LATE_COLLISIONS = 32;

export function fileSystemFileHandleSupportsMove(): boolean {
  return (
    typeof FileSystemFileHandle !== 'undefined' &&
    typeof (FileSystemFileHandle.prototype as unknown as { move?: unknown }).move === 'function'
  );
}

/** Every entry name (files and directories) in the directory. */
export async function listDirectoryEntryNames(directory: FileSystemDirectoryHandle): Promise<string[]> {
  const names: string[] = [];
  const iterable = directory as FileSystemDirectoryHandle & {
    keys?: () => AsyncIterableIterator<string>;
  };
  if (typeof iterable.keys !== 'function') {
    return names;
  }
  for await (const name of iterable.keys()) {
    names.push(name);
  }
  return names;
}

function isNotFound(err: unknown): boolean {
  return err instanceof Error && (err.name === 'NotFoundError' || /not.?found/i.test(err.message));
}

/** True when an entry of any kind already uses name. */
export async function directoryEntryExists(directory: FileSystemDirectoryHandle, name: string): Promise<boolean> {
  try {
    await directory.getFileHandle(name);
    return true;
  } catch (err) {
    if (!isNotFound(err)) {
      // TypeMismatchError: a directory holds the name.
      return true;
    }
  }
  try {
    await directory.getDirectoryHandle(name);
    return true;
  } catch (err) {
    return !isNotFound(err);
  }
}

async function removeEntryBestEffort(directory: FileSystemDirectoryHandle, name: string): Promise<void> {
  try {
    await directory.removeEntry(name);
  } catch (err) {
    console.warn('[arkfile-directory-publish] Could not remove partial entry:', err instanceof Error ? err.message : err);
  }
}

async function firstAbsentName(
  directory: FileSystemDirectoryHandle,
  name: string,
  nextName: () => string,
): Promise<string> {
  let candidate = name;
  for (let i = 0; i <= MAX_LATE_COLLISIONS; i++) {
    if (!(await directoryEntryExists(directory, candidate))) {
      return candidate;
    }
    candidate = nextName();
  }
  throw new Error('destination_exists');
}

/**
 * Stream into the directory and publish under reservedName, or under a name
 * from nextName() if a late collision appears. Returns the published name.
 * write() receives the writable; it must close it on success (pipeTo does)
 * and may throw to fail the file.
 */
export async function writeToDirectoryEntry(
  directory: FileSystemDirectoryHandle,
  reservedName: string,
  nextName: () => string,
  write: (writable: FileSystemWritableFileStream) => Promise<void>,
): Promise<string> {
  const supportsMove = fileSystemFileHandleSupportsMove();
  let createdName: string | null = null;
  try {
    let name = reservedName;
    let writeName: string;
    if (supportsMove) {
      writeName = `.arkfile-output-${crypto.randomUUID()}.tmp`;
    } else {
      name = await firstAbsentName(directory, name, nextName);
      writeName = name;
    }
    const fileHandle = await directory.getFileHandle(writeName, { create: true });
    createdName = writeName;
    const writable = await fileHandle.createWritable();
    try {
      await write(writable);
    } catch (err) {
      try {
        await writable.abort();
      } catch {
        // Already closed or errored by pipeTo.
      }
      throw err;
    }

    if (supportsMove) {
      name = await firstAbsentName(directory, name, nextName);
      await (fileHandle as FileSystemFileHandle & { move: (newName: string) => Promise<void> }).move(name);
    }
    createdName = null;
    return name;
  } catch (err) {
    if (createdName) {
      await removeEntryBestEffort(directory, createdName);
    }
    throw err instanceof Error ? err : new Error(String(err));
  }
}
