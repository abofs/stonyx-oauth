// Custom test setup for stonyx-oauth.
//
// Works around a race in stonyx's cli/test-setup.js: that setup calls
// `new Stonyx(config, cwd)` but does NOT await `Stonyx.ready`, so qunit
// proceeds to load test files before the async `Stonyx.start()` has
// flipped `Stonyx.initialized = true`. Integration tests that touch
// stonyx internals at module load then hit the "Stonyx has not been
// initialized yet" getter guard.
//
// This custom setup mirrors stonyx's but awaits `Stonyx.ready` before
// returning. It runs as a `--import` loader, so its top-level-await
// keeps qunit's test-file loading blocked until Stonyx is fully
// initialized.
import { pathToFileURL } from 'url';

const cwd = process.cwd();

const { default: Stonyx } = await import('stonyx');
const { default: config } = await import(pathToFileURL(`${cwd}/config/environment.js`).href);

new Stonyx(config, cwd);
await Stonyx.ready;
