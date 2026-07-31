import './setup';
import { describe, test, expect, beforeEach } from 'bun:test';
import {
  addTag,
  addTags,
  buildTagVocabulary,
  canonicalizeTags,
  clearFileTagsParamsCacheForTests,
  fileHasAllTags,
  loadFileTagsParams,
  parseAndAddTags,
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

  test('trims spaces around commas and reports 5 tags maximum', () => {
    expect(() => parseAndCanonicalizeTags('apple, banana, cherry, DOG, 123, noun', params))
      .toThrow('5 tags maximum');
    expect(serializeTags(parseAndCanonicalizeTags('apple, banana, cherry, DOG, 123', params)))
      .toBe('apple,banana,cherry,DOG,123');
  });

  test('rejects invalid syntax with named rules', () => {
    expect(() => validateTagSyntax('ok-tag', 32)).not.toThrow();
    expect(() => validateTagSyntax('a-b-c-d', 32)).not.toThrow();
    expect(() => validateTagSyntax('ab cd', 32)).toThrow('tag contains whitespace');
    expect(() => validateTagSyntax('-abc', 32)).toThrow('tag cannot start with a dash');
    expect(() => validateTagSyntax('a-b-c-d-', 32)).toThrow('tag cannot end with a dash');
    expect(() => validateTagSyntax('-abcd-', 32)).toThrow('tag cannot start with a dash');
    expect(() => validateTagSyntax('ab--cd', 32)).toThrow('tag cannot contain consecutive dashes');
    expect(() => validateTagSyntax('a_b', 32)).toThrow(
      'tag contains invalid characters (use A-Z, a-z, 0-9, and single dashes between segments)',
    );
    expect(() => validateTagSyntax('a'.repeat(33), 32)).toThrow('tag exceeds max length 32');
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

  test('parseAndAddTags accepts one or many comma-separated tags', () => {
    expect(serializeTags(parseAndAddTags(['Food'], ' activity , FUN ,food ', params)))
      .toBe('Food,activity,FUN');
    expect(serializeTags(addTags(['a'], ['b', 'c'], params))).toBe('a,b,c');
    expect(() => parseAndAddTags(['a', 'b', 'c', 'd', 'e'], 'f, g', params))
      .toThrow('5 tags maximum');
    expect(() => parseAndAddTags([], 'apple banana', params)).toThrow();
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
