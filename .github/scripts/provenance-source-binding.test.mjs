import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';

const workflow = readFileSync(new URL('../workflows/release.yaml', import.meta.url), 'utf8');

test('release provenance is bound to immutable Git source material', () => {
  assert.doesNotMatch(workflow, /^\s+context:\s+\.\s*$/mu);
  assert.match(workflow, /GITHUB_SERVER_URL.*GITHUB_REPOSITORY/u);
  assert.match(workflow, /\.invocation\.configSource\?/u);
  assert.match(workflow, /authoritative_sources as \$authoritative/u);
  assert.match(workflow, /\.digest\.sha1\?/u);
  assert.match(workflow, /all\(\$slsa\[\]; binds_source/u);
});

test('untrusted free-form revision text is not accepted', () => {
  assert.doesNotMatch(workflow, /\[\.\. \| strings\].*index\(\$revision\)/u);
});
