import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { scanInputs } from '../src/toolguard.js';

const root = path.resolve(import.meta.dirname, '..');
const fixtures = path.join(root, 'test', 'fixtures');
const cli = path.join(root, 'bin', 'toolguard.js');

test('clean input is deterministic and has no findings', async () => {
  const file = path.join(fixtures, 'clean.json');
  const first = await scanInputs([file], { root });
  const second = await scanInputs([file], { root });
  assert.deepEqual(first, second);
  assert.equal(first.summary.findings, 0);
  assert.equal(first.summary.errors, 0);
  assert.equal(first.summary.mcpServers, 2);
  assert.equal(first.summary.tools, 1);
});

test('risk rules detect the requested categories without exposing token values', async () => {
  const report = await scanInputs([path.join(fixtures, 'risky.json')], { root });
  const categories = new Set(report.findings.map((finding) => finding.category));
  for (const category of [
    'hidden-instruction',
    'hardcoded-secret',
    'unpinned-package',
    'over-broad-permission',
    'suspicious-url',
    'cross-tool-shadowing',
  ]) assert.ok(categories.has(category), `missing ${category}`);
  assert.ok(report.summary.maxScore >= 70);
  assert.ok(!JSON.stringify(report).includes('ghp_abcdefghijklmnopqrstuvwxyz1234567890'));
});

test('CLI emits JSON and returns input-error status for malformed JSON', () => {
  const result = spawnSync(process.execPath, [cli, 'scan', path.join(fixtures, 'invalid.json'), '--format', 'json'], {
    cwd: root,
    encoding: 'utf8',
  });
  assert.equal(result.status, 2);
  const report = JSON.parse(result.stdout);
  assert.equal(report.summary.errors, 1);
  assert.equal(report.errors[0].code, 'TG.JSON.INVALID');
});

test('HTML output is standalone and contains no external resources', () => {
  const html = execFileSync(process.execPath, [cli, 'scan', path.join(fixtures, 'clean.json'), '--format', 'html'], {
    cwd: root,
    encoding: 'utf8',
  });
  assert.match(html, /^<!doctype html>/i);
  assert.match(html, /MCP servers/);
  assert.doesNotMatch(html, /<(?:script|link|img|iframe)[^>]+(?:src|href)=/i);
});

test('stdin scans do not depend on network access', () => {
  const input = readFileSync(path.join(fixtures, 'clean.json'), 'utf8');
  const result = spawnSync(process.execPath, [cli, 'scan', '--stdin', '--stdin-name', 'piped.json', '--format', 'json'], {
    cwd: root,
    input,
    encoding: 'utf8',
  });
  assert.equal(result.status, 0);
  const report = JSON.parse(result.stdout);
  assert.equal(report.files[0].path, 'piped.json');
  assert.equal(report.summary.findings, 0);
});

test('package maps, images, nested permissions, and BOM stdin are covered', async () => {
  const input = String.fromCharCode(0xfeff) + JSON.stringify({
    dependencies: { lodash: '^4.17.0' },
    image: 'nginx:latest',
    permissions: { shell: true, filesystem: { read: ['/'] } },
  });
  const report = await scanInputs([], { stdin: input, stdinName: 'edge.json' });
  assert.equal(report.errors.length, 0);
  assert.equal(report.findings.filter((finding) => finding.category === 'unpinned-package').length, 2);
  assert.equal(report.findings.filter((finding) => finding.category === 'over-broad-permission').length, 2);
});

test('malformed JSON errors do not echo secret fragments and missing option values fail', async () => {
  const report = await scanInputs([], {
    stdin: '{"token": ghp_abcdefghijklmnopqrstuvwxyz1234567890',
    stdinName: 'malformed.json',
  });
  assert.equal(report.errors.length, 1);
  assert.doesNotMatch(report.errors[0].message, /ghp_/);
  const result = spawnSync(process.execPath, [cli, 'scan', path.join(fixtures, 'clean.json'), '--output'], {
    cwd: root,
    encoding: 'utf8',
  });
  assert.equal(result.status, 2);
});
