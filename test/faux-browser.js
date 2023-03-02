#!/usr/bin/env node
require('fs').writeFileSync(
  require('path').join(__dirname, 'argv.json'),
  JSON.stringify(process.argv)
);
process.exitCode = 1;
