/**
 * Owner file tag parse / validate / mutate helpers.
 * Limits come from crypto/file-tags-params.json via GET /api/config/file-tags.
 * No hardcoded browser fallback: callers must handle load failure.
 */

export interface FileTagsParams {
  maxTagsPerFile: number;
  maxTagLength: number;
  maxTagsPerFilterQuery: number;
}

const TAG_SYNTAX = /^[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*$/;

let cachedParams: FileTagsParams | null = null;
let loadPromise: Promise<FileTagsParams> | null = null;

export function clearFileTagsParamsCacheForTests(): void {
  cachedParams = null;
  loadPromise = null;
}

export async function loadFileTagsParams(): Promise<FileTagsParams> {
  if (cachedParams) {
    return cachedParams;
  }
  if (!loadPromise) {
    loadPromise = (async () => {
      const response = await fetch('/api/config/file-tags');
      if (!response.ok) {
        throw new Error(`Failed to load file-tags config: HTTP ${response.status}`);
      }
      const data = (await response.json()) as FileTagsParams;
      if (
        !data ||
        typeof data.maxTagsPerFile !== 'number' ||
        typeof data.maxTagLength !== 'number' ||
        typeof data.maxTagsPerFilterQuery !== 'number' ||
        data.maxTagsPerFile <= 0 ||
        data.maxTagLength <= 0 ||
        data.maxTagsPerFilterQuery <= 0
      ) {
        throw new Error('Invalid file-tags config payload');
      }
      cachedParams = data;
      return data;
    })().catch((err) => {
      loadPromise = null;
      throw err;
    });
  }
  return loadPromise;
}

export function getCachedFileTagsParams(): FileTagsParams | null {
  return cachedParams;
}

export function parseTagList(input: string): string[] {
  if (input.trim() === '') {
    return [];
  }
  const parts = input.split(',');
  const out: string[] = [];
  for (const part of parts) {
    const tag = part.trim();
    if (tag === '') {
      throw new Error('empty tag segment');
    }
    out.push(tag);
  }
  return out;
}

export function validateTagSyntax(tag: string, maxLen: number): void {
  if (!tag) {
    throw new Error('tag is empty');
  }
  if (tag.length > maxLen) {
    throw new Error(`tag exceeds max length ${maxLen}`);
  }
  if (/\s/.test(tag)) {
    throw new Error('tag contains whitespace');
  }
  if (!TAG_SYNTAX.test(tag)) {
    throw new Error('tag has invalid syntax');
  }
}

/** Canonical user-facing limit error for per-file tag count. */
export function maxTagsPerFileError(max: number): Error {
  return new Error(`${max} tags maximum`);
}

export function canonicalizeTags(tags: string[], params: FileTagsParams): string[] {
  if (tags.length > params.maxTagsPerFile) {
    throw maxTagsPerFileError(params.maxTagsPerFile);
  }
  const seen = new Set<string>();
  const out: string[] = [];
  for (const tag of tags) {
    validateTagSyntax(tag, params.maxTagLength);
    const key = tag.toLowerCase();
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    out.push(tag);
  }
  if (out.length > params.maxTagsPerFile) {
    throw maxTagsPerFileError(params.maxTagsPerFile);
  }
  return out;
}

export function parseAndCanonicalizeTags(input: string, params: FileTagsParams): string[] {
  return canonicalizeTags(parseTagList(input), params);
}

export function serializeTags(tags: string[]): string {
  return tags.join(',');
}

export function parseFilterTags(input: string, params: FileTagsParams): string[] {
  const parsed = parseTagList(input);
  const seen = new Set<string>();
  const out: string[] = [];
  for (const tag of parsed) {
    validateTagSyntax(tag, params.maxTagLength);
    const key = tag.toLowerCase();
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    out.push(tag);
  }
  if (out.length > params.maxTagsPerFilterQuery) {
    throw new Error(`too many filter tags: max ${params.maxTagsPerFilterQuery}`);
  }
  return out;
}

export function fileHasAllTags(fileTags: string[], queryTags: string[]): boolean {
  if (queryTags.length === 0) {
    return true;
  }
  const set = new Set(fileTags.map((t) => t.toLowerCase()));
  return queryTags.every((q) => set.has(q.toLowerCase()));
}

export function tagPresent(tags: string[], tag: string): boolean {
  const key = tag.toLowerCase();
  return tags.some((t) => t.toLowerCase() === key);
}

export function addTag(tags: string[], tag: string, params: FileTagsParams): string[] {
  return addTags(tags, [tag], params);
}

/**
 * Append each tag in toAdd if not already present (case-insensitive).
 * Preserves existing order; appends new tags in toAdd order.
 * Callers should parseTagList first so spaces around commas are trimmed.
 */
export function addTags(tags: string[], toAdd: string[], params: FileTagsParams): string[] {
  const out = tags.slice();
  for (const tag of toAdd) {
    validateTagSyntax(tag, params.maxTagLength);
    if (tagPresent(out, tag)) {
      continue;
    }
    if (out.length >= params.maxTagsPerFile) {
      throw maxTagsPerFileError(params.maxTagsPerFile);
    }
    out.push(tag);
  }
  return out;
}

/** Parse comma-separated input (trim around commas) and merge into existing tags. */
export function parseAndAddTags(existing: string[], input: string, params: FileTagsParams): string[] {
  const parsed = parseTagList(input);
  if (parsed.length === 0) {
    throw new Error('tag is empty');
  }
  return addTags(existing, parsed, params);
}

export function removeTag(tags: string[], tag: string): string[] {
  const key = tag.toLowerCase();
  let removed = false;
  return tags.filter((t) => {
    if (!removed && t.toLowerCase() === key) {
      removed = true;
      return false;
    }
    return true;
  });
}

export function replaceTag(
  tags: string[],
  oldTag: string,
  newTag: string,
  params: FileTagsParams,
): string[] {
  validateTagSyntax(newTag, params.maxTagLength);
  const oldKey = oldTag.toLowerCase();
  const newKey = newTag.toLowerCase();
  const idx = tags.findIndex((t) => t.toLowerCase() === oldKey);
  if (idx < 0) {
    throw new Error('tag not found');
  }
  if (oldKey !== newKey) {
    for (let i = 0; i < tags.length; i++) {
      if (i !== idx && tags[i].toLowerCase() === newKey) {
        throw new Error('replacement collides with existing tag');
      }
    }
  }
  const out = tags.slice();
  out[idx] = newTag;
  return out;
}

export interface TagVocabularyEntry {
  display: string;
  count: number;
}

/** Build case-insensitive vocabulary with display spelling and usage counts. */
export function buildTagVocabulary(fileTagLists: Array<string[] | null | undefined>): TagVocabularyEntry[] {
  const map = new Map<string, TagVocabularyEntry>();
  for (const list of fileTagLists) {
    if (!list) continue;
    for (const tag of list) {
      const key = tag.toLowerCase();
      const existing = map.get(key);
      if (existing) {
        existing.count += 1;
      } else {
        map.set(key, { display: tag, count: 1 });
      }
    }
  }
  return Array.from(map.values());
}

const DEFAULT_SUGGESTION_LIMIT = 8;

export function suggestTags(
  vocabulary: TagVocabularyEntry[],
  query: string,
  selected: string[],
  limit: number = DEFAULT_SUGGESTION_LIMIT,
): string[] {
  const q = query.trim().toLowerCase();
  const selectedSet = new Set(selected.map((t) => t.toLowerCase()));
  const candidates = vocabulary.filter((v) => !selectedSet.has(v.display.toLowerCase()));
  const scored = candidates
    .map((v) => {
      const displayLower = v.display.toLowerCase();
      let rank = 2;
      if (q && displayLower.startsWith(q)) {
        rank = 0;
      } else if (q && displayLower.includes(q)) {
        rank = 1;
      } else if (q) {
        return null;
      }
      return { display: v.display, rank, count: v.count };
    })
    .filter((x): x is { display: string; rank: number; count: number } => x !== null);
  scored.sort((a, b) => {
    if (a.rank !== b.rank) return a.rank - b.rank;
    if (b.count !== a.count) return b.count - a.count;
    return a.display.localeCompare(b.display);
  });
  return scored.slice(0, limit).map((s) => s.display);
}
