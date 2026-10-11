import { createHash } from 'node:crypto';

/** stable json stringify (sorted keys) for hashing */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value as Record<string, unknown>).sort()) {
      out[k] = sortValue((value as Record<string, unknown>)[k]);
    }
    return out;
  }
  return value;
}

export function sha256(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

/** safe json read: null on any failure, with error text for reporting */
export function readJsonFile(path: string): { data: unknown; error?: string } {
  let raw: string;
  try {
    raw = readFileSyncUtf8(path);
  } catch (e) {
    return { data: null, error: `unreadable: ${(e as Error).message}` };
  }
  try {
    return { data: JSON.parse(raw) };
  } catch (e) {
    return { data: null, error: `malformed JSON: ${(e as Error).message.split('\n')[0]}` };
  }
}

import { readFileSync } from 'node:fs';
function readFileSyncUtf8(path: string): string {
  return readFileSync(path, 'utf8');
}

export function truncate(text: string, max: number): string {
  if (text.length <= max) return text;
  return text.slice(0, max - 1) + '…';
}
