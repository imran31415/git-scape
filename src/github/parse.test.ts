import { describe, expect, it } from 'vitest';
import { parseRepoInput } from './parse';

describe('parseRepoInput', () => {
  it.each([
    ['owner/repo', { owner: 'owner', repo: 'repo', ref: undefined }],
    ['https://github.com/owner/repo', { owner: 'owner', repo: 'repo', ref: undefined }],
    ['https://github.com/owner/repo.git', { owner: 'owner', repo: 'repo', ref: undefined }],
    ['http://www.github.com/owner/repo/', { owner: 'owner', repo: 'repo', ref: undefined }],
    ['github.com/juice-shop/juice-shop', { owner: 'juice-shop', repo: 'juice-shop', ref: undefined }],
    ['git@github.com:owner/repo.git', { owner: 'owner', repo: 'repo' }],
    [
      'https://github.com/owner/repo/tree/develop/src/utils',
      { owner: 'owner', repo: 'repo', ref: 'develop' },
    ],
    [
      'https://github.com/owner/repo/blob/v1.2.3/README.md',
      { owner: 'owner', repo: 'repo', ref: 'v1.2.3' },
    ],
    ['  owner/repo  ', { owner: 'owner', repo: 'repo', ref: undefined }],
    ['owner/repo.js', { owner: 'owner', repo: 'repo.js', ref: undefined }],
  ])('parses %s', (input, expected) => {
    expect(parseRepoInput(input)).toMatchObject(expected);
  });

  it.each(['', 'just-a-word', 'https://gitlab.com/x', '///', 'a/../b'])(
    'rejects %s',
    (input) => {
      expect(parseRepoInput(input)).toBeNull();
    },
  );
});
