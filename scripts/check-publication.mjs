#!/usr/bin/env node
import { readFileSync } from 'node:fs';

const standards = /\b(?:SHA-(?:1|224|256|384|512)|UTF-(?:8|16|32)|RFC-\d{1,5}|BSD-[234]-Clause|(?:A?GPL|LGPL)-(?:2\.0|2\.1|3\.0)(?:-only|-or-later)?|CC0-[1]\.0|TEST-NET-[123]|LICENSE-[2]\.0)\b/gi;
const rules = [
  ['tracker reference', /(?<![\w-])[A-Z][A-Z0-9]{1,11}-\d+(?![\w-]|\.\d)/],
  ['generated attribution', /^\s*(?:[>*#-]\s*)?(?:generated|authored|implemented|written)\s+(?:with|by|using)\s+/im],
  ['execution credit', /\bco-authored-by\s*:.*(?:\bassistant\b|\bagent\b|\bAI\b|\bmodel\b)/i],
  ['role branch', /(?:^|refs\/heads\/)(?:agents?|assistants?|sessions?|runs?|harness|models?)\//im],
  ['execution URI', /\b(?:agent|history|session|artifact|proc):\/\//i],
];

try {
  if (process.argv.length > 3) throw new Error('expected stdin or one file');
  const text = readFileSync(process.argv[2] ?? 0, 'utf8').replace(standards, '');
  for (const [name, pattern] of rules) {
    if (pattern.test(text)) {
      console.error(`publication: ${name}`);
      process.exitCode = 1;
    }
  }
} catch {
  console.error('publication: unreadable input');
  process.exitCode = 1;
}
