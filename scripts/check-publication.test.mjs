import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const script = fileURLToPath(new URL('./check-publication.mjs', import.meta.url));
const reference = ['EXAMPLE', '742'].join('-');
const cases = [
  ['product text', 'Agent enrollment, model_id: example, and test harnesses are supported.', 0],
  ['standards', 'SHA-256 UTF-8 RFC-3986 BSD-3-Clause GPL-3.0-or-later', 0],
  ['human credit', ['Co-Authored', 'By'].join('-') + ': Example Person <person@example.test>', 0],
  ['tracker reference', reference, 1],
  ['generated attribution', ['Generated', 'with Example Assistant'].join(' '), 1],
  ['execution credit', ['Co-Authored', 'By'].join('-') + ': Example Agent <example@example.test>', 1],
  ['role branch', ['refs/heads/agent', '/example'].join('') + ' ' + '0'.repeat(40), 1],
  ['execution URI', ['agent:', '//example'].join(''), 1],
];

for (const [name, input, status] of cases) {
  test(name, () => {
    const result = spawnSync(process.execPath, [script], { input, encoding: 'utf8' });
    assert.equal(result.status, status, result.stderr);
    if (status) {
      assert.match(result.stderr, new RegExp(`publication: ${name}$`, 'm'));
      assert.ok(!result.stderr.includes(input), 'diagnostics must not repeat rejected input');
    }
  });
}

test('unreadable input fails without printing its path', () => {
  const path = `${script}/missing`;
  const result = spawnSync(process.execPath, [script, path], { encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /publication:/);
  assert.ok(!result.stderr.includes(path));
});
