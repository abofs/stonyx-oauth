// Regression test for stonyx-oauth#26.
//
// The package must publish `config/environment.js` (plain JS) and must NOT
// publish `config/environment.ts`. Node refuses to type-strip inside
// `node_modules`, so if we ship a `.ts` here the stonyx module loader
// dynamic-import of this config will crash consumers at parse time.
//
// This test invokes `npm pack --dry-run --json` and asserts the tarball
// entry list contains `config/environment.js` and does not contain
// `config/environment.ts`.
import QUnit from 'qunit';
import { execFileSync } from 'child_process';

const { module, test } = QUnit;

module('[Unit] Publish surface', function () {
  test('config/environment.js is published and .ts is not', function (assert) {
    const stdout = execFileSync('npm', ['pack', '--dry-run', '--json'], {
      cwd: process.cwd(),
      encoding: 'utf8',
    });
    const report = JSON.parse(stdout);
    const entry = Array.isArray(report) ? report[0] : report;
    const files = (entry.files ?? []).map((f: { path: string }) => f.path);

    assert.ok(
      files.includes('config/environment.js'),
      'published tarball includes config/environment.js'
    );
    assert.notOk(
      files.includes('config/environment.ts'),
      'published tarball does NOT include config/environment.ts'
    );
  });
});
