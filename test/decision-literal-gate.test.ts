import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

describe('decision literal gate', () => {
  it('fails closed on a planted unclassified occurrence while advisory mode reports it', () => {
    const root = mkdtempSync(join(tmpdir(), 'decision-literal-gate-'));
    const success = ['ALLOW', 'ED'].join('');
    const quoted = (value: string) => `'${value}'`;
    const staticTemplate = (value: string) => `\`${value}\``;
    try {
      mkdirSync(resolve(root, 'src'));
      writeFileSync(
        resolve(root, 'decision-literal-allowlist.json'),
        `${JSON.stringify({
          version: 1,
          runtimePaths: ['src'],
          allowedOccurrences: [{
            path: 'src/fixture.ts',
            literal: success,
            expression: `export const canonical = ${quoted(success)};`,
            expectedCount: 1,
            reason: 'negative-control baseline',
          }],
        }, null, 2)}\n`,
      );
      writeFileSync(
        resolve(root, 'src/fixture.ts'),
        `export const canonical = ${quoted(success)};\nexport const planted = ${staticTemplate(`prefix-${success}-suffix`)};\n`,
      );

      const gate = resolve(process.cwd(), 'scripts/decision-literal-gate.mjs');
      const blocked = spawnSync(process.execPath, [gate, '--root', root, '--blocking'], { encoding: 'utf8' });
      expect(blocked.status).toBe(1);
      expect(blocked.stderr).toContain('planted');

      const advisory = spawnSync(process.execPath, [gate, '--root', root], { encoding: 'utf8' });
      expect(advisory.status).toBe(0);
      expect(advisory.stderr).toContain('(advisory)');
      expect(advisory.stderr).toContain('planted');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it.each([
    ['unknown field', JSON.stringify({
      version: 1,
      runtimePaths: ['src'],
      allowedOccurrences: [],
      unexpected: true,
    })],
    ['truncated JSON', '{"version":1'],
    ['unsupported version', JSON.stringify({
      version: 2,
      runtimePaths: ['src'],
      allowedOccurrences: [],
    })],
  ].flatMap(([description, config]) => [
    [description, config, false],
    [description, config, true],
  ]))('rejects %s in advisory and blocking modes', (_description, config, blocking) => {
    const root = mkdtempSync(join(tmpdir(), 'decision-literal-schema-'));
    try {
      mkdirSync(resolve(root, 'src'));
      writeFileSync(
        resolve(root, 'decision-literal-allowlist.json'),
        `${String(config)}\n`,
      );
      const result = spawnSync(
        process.execPath,
        [
          resolve(process.cwd(), 'scripts/decision-literal-gate.mjs'),
          '--root',
          root,
          ...(blocking ? ['--blocking'] : []),
        ],
        { encoding: 'utf8' },
      );
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain('Invalid decision literal allowlist schema.');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('rejects a runtime path symlink that escapes the repository', () => {
    const parent = mkdtempSync(join(tmpdir(), 'decision-literal-symlink-'));
    const root = resolve(parent, 'repo');
    const outside = resolve(parent, 'outside');
    try {
      mkdirSync(root);
      mkdirSync(outside);
      symlinkSync(
        outside,
        resolve(root, 'linked'),
        process.platform === 'win32' ? 'junction' : 'dir',
      );
      writeFileSync(
        resolve(root, 'decision-literal-allowlist.json'),
        `${JSON.stringify({ version: 1, runtimePaths: ['linked'], allowedOccurrences: [] })}\n`,
      );
      const result = spawnSync(
        process.execPath,
        [resolve(process.cwd(), 'scripts/decision-literal-gate.mjs'), '--root', root, '--blocking'],
        { encoding: 'utf8' },
      );
      expect(result.status).toBe(1);
      expect(result.stderr).toContain('Runtime path escapes repository root.');
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  });
});
