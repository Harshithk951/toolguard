#!/usr/bin/env node

import { main } from '../src/cli.js';

main(process.argv.slice(2)).catch((error) => {
  process.stderr.write(`ToolGuard: ${error.message}\n`);
  process.exitCode = 3;
});
