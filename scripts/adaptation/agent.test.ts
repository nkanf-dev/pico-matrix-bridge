import { describe, test, expect } from 'bun:test';
import { mkdtempSync, writeFileSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import register from './agent';

// Exercise trusted tool handlers without a provider, key or application binary.
function fixture() {
  const work = mkdtempSync(join(tmpdir(), 'vd-agent-test-'));
  process.env.VD_AGENT_EVIDENCE = join(work, 'evidence.json');
  process.env.VD_AGENT_OUTPUT = join(work, 'candidate.json');
  writeFileSync(process.env.VD_AGENT_EVIDENCE, JSON.stringify({ index: ['gate'], gate: { changed: true } }));
  const tools: Record<string, any> = {};
  const schema: any = new Proxy(() => schema, { get: () => schema, apply: () => schema });
  register({ zod: schema, on() {}, registerTool(tool: any) { tools[tool.name] = tool; } } as any);
  return { work, tools, output: process.env.VD_AGENT_OUTPUT };
}

describe('bounded evidence tools', () => {
  test('no path traversal or inherited object properties', async () => {
    const f = fixture();
    try {
      for (const id of ['../../state/models.yml', '__proto__', 'constructor']) {
        await expect(f.tools.read_evidence.execute('1', { id })).rejects.toThrow('Unknown evidence ID');
      }
      expect(await f.tools.read_evidence.execute('2', { id: 'gate' })).toMatchObject({ content: [{ type: 'text', text: '{"changed":true}' }] });
      expect(Object.keys(f.tools)).toEqual(['read_evidence', 'submit_candidate']);
    } finally { rmSync(f.work, { recursive: true }); }
  });
  test('one atomic submission, known evidence only', async () => {
    const f = fixture();
    try {
      const value = { disposition: 'review-required', rationale: 'changed gate', evidenceIds: ['missing'], anchors: [] };
      await expect(f.tools.submit_candidate.execute('1', value)).rejects.toThrow('Invalid submission');
      expect(existsSync(f.output)).toBe(false);
      value.evidenceIds = ['gate'];
      await f.tools.submit_candidate.execute('2', value);
      expect(JSON.parse(readFileSync(f.output, 'utf8')).disposition).toBe('review-required');
      expect(existsSync(f.output + '.pending')).toBe(false);
      await expect(f.tools.submit_candidate.execute('3', value)).rejects.toThrow('Invalid submission');
    } finally { rmSync(f.work, { recursive: true }); }
  });
  test('fixed tool budget', async () => {
    const f = fixture();
    try {
      for (let n = 0; n < 12; n++) await f.tools.read_evidence.execute('1', { id: 'gate' });
      await expect(f.tools.read_evidence.execute('1', { id: 'gate' })).rejects.toThrow('budget exhausted');
    } finally { rmSync(f.work, { recursive: true }); }
  });
});
