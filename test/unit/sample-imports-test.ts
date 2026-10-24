// The README points consumers at test/sample/ as canonical usage, so every
// import in it must be one a consumer can write: never a relative path that
// climbs out of test/sample/ into the repo's src/, and never a subpath of this
// package that package.json `exports` does not publish. A type-only import is
// erased at runtime, so neither mistake would fail the suite by itself.
import QUnit from 'qunit';
import { readdirSync, readFileSync } from 'fs';
import { join, relative, resolve, dirname } from 'path';

const { module, test } = QUnit;

const ROOT = resolve('.');
const SAMPLE_ROOT = resolve('test/sample');
const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as { name: string; exports: Record<string, unknown> };

function sampleFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry: { name: string; isDirectory(): boolean }) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return sampleFiles(path);
    return /\.[cm]?[jt]s$/.test(entry.name) ? [path] : [];
  });
}

function specifiers(source: string): string[] {
  const found: string[] = [];
  const pattern = /(?:\bfrom\s*|\bimport\s*\(?\s*)['"`]([^'"`]+)['"`]/g;
  for (const match of source.matchAll(pattern)) found.push(match[1]);
  return found;
}

// `@stonyx/oauth` -> `.`, `@stonyx/oauth/x` -> `./x`; null for any other package.
function exportKey(spec: string): string | null {
  if (spec === pkg.name) return '.';
  if (spec.startsWith(`${pkg.name}/`)) return `.${spec.slice(pkg.name.length)}`;
  return null;
}

module('[Unit] Sample imports', function() {
  test('every test/sample import is one a consumer can write', function(assert) {
    const files = sampleFiles(SAMPLE_ROOT);
    const all = files.flatMap(file => specifiers(readFileSync(file, 'utf8')).map(spec => ({ file, spec })));
    const label = ({ file, spec }: { file: string; spec: string }) => `${relative(ROOT, file)}: ${spec}`;

    // Non-vacuity: the scan reaches the samples and recognises a self-import.
    assert.ok(files.length > 0, 'the scan finds sample files');
    assert.ok(all.some(({ spec }) => exportKey(spec) !== null), `the scan sees ${pkg.name} imports`);

    const escaping = all
      .filter(({ file, spec }) => spec.startsWith('.') && relative(SAMPLE_ROOT, resolve(dirname(file), spec)).startsWith('..'))
      .map(label);
    assert.deepEqual(escaping, [], 'no sample import leaves test/sample/');

    const unexported = all
      .filter(({ spec }) => {
        const key = exportKey(spec);
        return key !== null && !Object.hasOwn(pkg.exports, key);
      })
      .map(label);
    assert.deepEqual(unexported, [], `every ${pkg.name} import names a package.json exports key`);
  });
});
