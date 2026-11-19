#!/usr/bin/env node
// Checks submitted flags against a cohort seed.
//   FLAG_SEED=cohort-seed node checker/check.js 'BB{...}' 'BB{...}'
//   FLAG_SEED=cohort-seed node checker/check.js --file submitted.txt
import fs from 'node:fs';
import { WEAKNESSES, flagFor } from '../src/config.js';

const seed = process.env.FLAG_SEED ?? 'local-practice';
const args = process.argv.slice(2);
let flags = args;
if (args[0] === '--file') flags = fs.readFileSync(args[1], 'utf8').match(/BB\{[^}]+\}/g) ?? [];
if (!flags.length) {
  console.log('Usage: FLAG_SEED=<seed> node checker/check.js <flag> [...]  or  --file <path>');
  process.exit(1);
}
const known = new Map(Object.entries(WEAKNESSES).map(([id, w]) => [flagFor(id, seed), { id, ...w }]));
let good = 0;
for (const f of new Set(flags.map((x) => x.trim()))) {
  const w = known.get(f);
  if (w) { good += 1; console.log(`VALID    level ${w.level}  ${w.top10.padEnd(5)}  ${w.id}  ${w.title}`); }
  else console.log(`INVALID  ${f}`);
}
console.log(`${good} valid of ${new Set(flags).size} submitted (seed "${seed}")`);
process.exit(good === new Set(flags).size ? 0 : 2);
