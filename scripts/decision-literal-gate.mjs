import { readFileSync, readdirSync, realpathSync, statSync } from 'node:fs';
import { isAbsolute, relative, resolve, sep } from 'node:path';

const args = new Set(process.argv.slice(2));
const valueAfter = (flag, fallback) => {
  const index = process.argv.indexOf(flag);
  return index === -1 ? fallback : process.argv[index + 1];
};
const root = resolve(valueAfter('--root', process.cwd()));
const configPath = resolve(root, valueAfter('--config', 'decision-literal-allowlist.json'));
const blocking = args.has('--blocking');
let config;
try {
  config = JSON.parse(readFileSync(configPath, 'utf8'));
} catch {
  throw new Error('Invalid decision literal allowlist schema.');
}
const hasOnlyKeys = (value, keys) => (
  typeof value === 'object' && value !== null && !Array.isArray(value) &&
  Object.keys(value).every((key) => keys.has(key))
);
if (
  !hasOnlyKeys(config, new Set(['version', 'runtimePaths', 'allowedOccurrences'])) ||
  config.version !== 1 ||
  !Array.isArray(config.runtimePaths) ||
  config.runtimePaths.some((entry) => typeof entry !== 'string' || entry.length === 0) ||
  !Array.isArray(config.allowedOccurrences)
) {
  throw new Error('Invalid decision literal allowlist schema.');
}

const allowances = config.allowedOccurrences.map((entry) => {
  if (
    !hasOnlyKeys(entry, new Set(['path', 'literal', 'expression', 'expectedCount', 'reason'])) ||
    typeof entry.path !== 'string' ||
    (entry.literal !== 'APPROVED' && entry.literal !== 'ALLOWED') ||
    typeof entry.expression !== 'string' ||
    entry.expression.trim() !== entry.expression ||
    !Number.isSafeInteger(entry.expectedCount) ||
    entry.expectedCount < 1 ||
    typeof entry.reason !== 'string' ||
    entry.reason.length === 0
  ) {
    throw new Error('Invalid decision literal allowance entry.');
  }
  return { ...entry, actualCount: 0 };
});
const allowanceKeys = new Set();
for (const allowance of allowances) {
  const key = `${allowance.path}\0${allowance.literal}\0${allowance.expression}`;
  if (allowanceKeys.has(key)) throw new Error('Duplicate decision literal allowance.');
  allowanceKeys.add(key);
}

const quotedLiteral = /(['"`])(APPROVED|ALLOWED)\1/g;
const files = [];
const walk = (absolute) => {
  for (const entry of readdirSync(absolute, { withFileTypes: true })) {
    const child = resolve(absolute, entry.name);
    if (entry.isDirectory()) walk(child);
    else if (entry.isFile() && /\.(?:[cm]?[jt]sx?|json)$/.test(entry.name)) files.push(child);
  }
};
const realRoot = realpathSync(root);
for (const runtimePath of config.runtimePaths) {
  const absolute = realpathSync(resolve(root, runtimePath));
  const relativeRuntimePath = relative(realRoot, absolute);
  if (relativeRuntimePath === '..' || relativeRuntimePath.startsWith(`..${sep}`) || isAbsolute(relativeRuntimePath)) {
    throw new Error('Runtime path escapes repository root.');
  }
  if (statSync(absolute).isDirectory()) walk(absolute);
  else files.push(absolute);
}

const violations = [];
for (const file of files) {
  const repoPath = relative(realRoot, file).split('\\').join('/');
  const lines = readFileSync(file, 'utf8').split('\n');
  for (let index = 0; index < lines.length; index += 1) {
    const expression = lines[index].trim();
    quotedLiteral.lastIndex = 0;
    let match;
    while ((match = quotedLiteral.exec(lines[index])) !== null) {
      const allowance = allowances.find((entry) => (
        entry.path === repoPath && entry.literal === match[2] && entry.expression === expression
      ));
      if (allowance) allowance.actualCount += 1;
      else violations.push(`${repoPath}:${index + 1}:${expression}`);
    }
  }
}
for (const allowance of allowances) {
  if (allowance.actualCount !== allowance.expectedCount) {
    violations.push(
      `${allowance.path}: expected ${allowance.expectedCount} occurrence(s) of ${JSON.stringify(allowance.expression)}, found ${allowance.actualCount}`,
    );
  }
}

if (violations.length === 0) {
  console.log('decision-literal-gate: 0 violations');
  process.exit(0);
}
console.error(`decision-literal-gate: ${violations.length} violation(s)${blocking ? '' : ' (advisory)'}`);
for (const violation of violations) console.error(violation);
process.exit(blocking ? 1 : 0);
