import './setup';
import { describe, test, expect, beforeEach } from 'bun:test';
import {
  addTag,
  buildTagVocabulary,
  canonicalizeTags,
  clearFileTagsParamsCacheForTests,
  fileHasAllTags,
  loadFileTagsParams,
  parseAndCanonicalizeTags,
  parseFilterTags,
  removeTag,
  replaceTag,
  serializeTags,
  suggestTags,
  validateTagSyntax,
  type FileTagsParams,
} from '../crypto/file-tags';

const params: FileTagsParams = {
  maxTagsPerFile: 5,
  maxTagLength: 32,
  maxTagsPerFilterQuery: 10,
};

describe('file-tags helpers', () => {
  beforeEach(() => {
    clearFileTagsParamsCacheForTests();
  });

  test('loads config from /api/config/file-tags', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      if (String(input).includes('/api/config/file-tags')) {
        return new Response(JSON.stringify(params), { status: 200 });
      }
      return new Response('not found', { status: 404 });
    }) as typeof fetch;
    try {
      const loaded = await loadFileTagsParams();
      expect(loaded.maxTagsPerFile).toBe(5);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('canonicalizes with first-seen casing and trims commas', () => {
    expect(serializeTags(parseAndCanonicalizeTags(' Food ,activity,FUN,food ', params)))
      .toBe('Food,activity,FUN');
  });

  test('rejects invalid syntax', () => {
    expect(() => validateTagSyntax('-abcd-', 32)).toThrow();
    expect(() => validateTagSyntax('ab--cd', 32)).toThrow();
    expect(() => validateTagSyntax('ab cd', 32)).toThrow();
    expect(() => validateTagSyntax('a_b', 32)).toThrow();
    expect(() => validateTagSyntax('ok-tag', 32)).not.toThrow();
  });

  test('add/remove/replace preserve order and position', () => {
    let tags = canonicalizeTags(['Food', 'activity'], params);
    tags = addTag(tags, 'FUN', params);
    expect(serializeTags(tags)).toBe('Food,activity,FUN');
    tags = removeTag(tags, 'activity');
    expect(serializeTags(tags)).toBe('Food,FUN');
    tags = replaceTag(tags, 'Food', 'FOOD', params);
    expect(serializeTags(tags)).toBe('FOOD,FUN');
    expect(() => replaceTag(tags, 'FOOD', 'FUN', params)).toThrow();
  });

  test('filter collapses duplicates and ANDs', () => {
    const query = parseFilterTags('Food, food,FUN', params);
    expect(query).toEqual(['Food', 'FUN']);
    expect(fileHasAllTags(['Food', 'activity', 'FUN'], query)).toBe(true);
    expect(fileHasAllTags(['Food'], query)).toBe(false);
  });

  test('suggestTags prefers prefix then frequency', () => {
    const vocab = buildTagVocabulary([
      ['Food', 'activity'],
      ['Food', 'FUN'],
      ['folder-A'],
    ]);
    expect(suggestTags(vocab, 'fo', [], 8)).toEqual(['Food', 'folder-A']);
  });
});
