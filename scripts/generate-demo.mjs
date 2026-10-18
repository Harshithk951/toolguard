import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { render } from '../src/cli.js';
import { scanInputs } from '../src/toolguard.js';

const root = path.resolve(import.meta.dirname, '..');
const report = await scanInputs([path.join(root, 'examples', 'malicious')], { root });
const output = path.join(root, 'docs', 'index.html');

await mkdir(path.dirname(output), { recursive: true });
await writeFile(output, render(report, 'html'), 'utf8');
process.stdout.write(`Wrote ${path.relative(root, output)}\n`);
