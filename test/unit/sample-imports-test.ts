// The README points consumers at test/sample/ as canonical usage, so every
// import in it must be one a consumer can write: a package specifier, never a
// relative path that climbs out of test/sample/ into the repo's src/.
import QUnit from 'qunit';
import { readdirSync, readFileSync } from 'fs';
import { join, relative, resolve, dirname } from 'path';

const { module, test } = QUnit;

const SAMPLE_ROOT = resolve('test/sample');

function sampleFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return sampleFiles(path);
    return /\.[cm]?[jt]s$/.test(entry.name) ? [path] : [];
  });
}

function specifiers(source: string): string[] {
  const found: string[] = [];
  const pattern = /(?:\bfrom\s*|\bimport\s*\(?\s*)['"]([^'"]+)['"]/g;
  for (const match of source.matchAll(pattern)) found.push(match[1]);
  return found;
}

module('[Unit] Sample imports', function() {
  test('every test/sample import is one a consumer can write', function(assert) {
    const files = sampleFiles(SAMPLE_ROOT);
    const all = files.flatMap(file => specifiers(readFileSync(file, 'utf8')).map(spec => ({ file, spec })));

    // Non-vacuity: the scan reaches the samples and recognises a package import.
    assert.ok(files.length > 0, 'the scan finds sample files');
    assert.ok(all.some(({ spec }) => spec.startsWith('@stonyx/oauth')), 'the scan sees @stonyx/oauth imports');

    const escaping = all
      .filter(({ file, spec }) => spec.startsWith('.') && relative(SAMPLE_ROOT, resolve(dirname(file), spec)).startsWith('..'))
      .map(({ file, spec }) => `${relative(process.cwd(), file)}: ${spec}`);

    assert.deepEqual(escaping, [], 'no sample import leaves test/sample/');
  });
});
