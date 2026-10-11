import type { Finding, Severity } from './models.js';

interface SecretRule {
  id: string;
  name: string;
  severity: Severity;
  pattern: RegExp;
  /** hint text for the kind of credential */
  hint: string;
}

const SECRET_RULES: SecretRule[] = [
  { id: 'FAM-SEC-01', name: 'AWS access key id', severity: 'critical', hint: 'aws access key', pattern: /\bAKIA[0-9A-Z]{16}\b/ },
  { id: 'FAM-SEC-02', name: 'AWS secret access key', severity: 'critical', hint: 'aws secret key', pattern: /\b(?<![A-Za-z0-9])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])\b/ },
  { id: 'FAM-SEC-03', name: 'GitHub fine-grained PAT', severity: 'critical', hint: 'github token', pattern: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/ },
  { id: 'FAM-SEC-04', name: 'GitHub classic PAT', severity: 'critical', hint: 'github token', pattern: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/ },
  { id: 'FAM-SEC-06', name: 'Anthropic key', severity: 'critical', hint: 'anthropic key', pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/ },
  { id: 'FAM-SEC-05', name: 'OpenAI key', severity: 'critical', hint: 'openai key', pattern: /\bsk-(proj-)?[A-Za-z0-9_-]{20,}\b/ },
  { id: 'FAM-SEC-07', name: 'Slack token', severity: 'high', hint: 'slack token', pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/ },
  { id: 'FAM-SEC-08', name: 'Google API key', severity: 'high', hint: 'google api key', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { id: 'FAM-SEC-09', name: 'Stripe live key', severity: 'critical', hint: 'stripe live key', pattern: /\b[srp]k_live_[A-Za-z0-9]{16,}\b/ },
  { id: 'FAM-SEC-10', name: 'Private key material', severity: 'critical', hint: 'private key', pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { id: 'FAM-SEC-11', name: 'JWT', severity: 'high', hint: 'jwt', pattern: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/ },
  { id: 'FAM-SEC-12', name: 'Connection string with password', severity: 'high', hint: 'connection string', pattern: /\b(postgres|postgresql|mysql|mongodb(\+srv)?|redis|amqp):\/\/[^\s:/]+:[^\s@/]+@[^\s]+/i },
];

// var names that scream "this is a credential" even when the value looks random-but-unmatched
const SECRET_NAME_HINTS: Array<{ re: RegExp; hint: string }> = [
  { re: /(aws)?_?secret_?access_?_?key/i, hint: 'aws secret key' },
  { re: /aws_?access_?key_?id/i, hint: 'aws access key' },
  { re: /(api|auth|access|secret|private|service)[_-]?key/i, hint: 'api key' },
  { re: /(api|auth|access|bearer|session|refresh)[_-]?token/i, hint: 'auth token' },
  { re: /pass(word|phrase)?/i, hint: 'password' },
  { re: /(client|webhook)[_-]?secret/i, hint: 'client secret' },
  { re: /github|gh_?pat|ghp/i, hint: 'github credential' },
];

const INTERPOLATION_RE = /^\$\{[^}]*\}$|^\{\{[^}]*\}\}$|^\$[A-Z0-9_]+$|^%[A-Z0-9_]+%$/;
const GENERIC_VALUE_RE = /^[A-Za-z0-9_/+=.-]{16,128}$/;

/** mask a detected secret: keep only type, prefix, and length */
export function maskSecret(value: string, hint: string): string {
  const head = value.slice(0, 4);
  return `${head}${'•'.repeat(8)} (${hint}, ${value.length} chars)`;
}

export function scanEnv(env: Record<string, string>, server: string): Finding[] {
  const findings: Finding[] = [];
  for (const [key, rawValue] of Object.entries(env)) {
    const value = String(rawValue ?? '');
    if (value === '') continue;

    let matched: SecretRule | undefined;
    for (const rule of SECRET_RULES) {
      if (rule.id === 'FAM-SEC-02') continue; // 40-char entropy rule: too noisy alone, handled below with name hints
      const m = value.match(rule.pattern);
      if (m) { matched = rule; break; }
    }

    if (matched) {
      findings.push({
        id: matched.id,
        severity: matched.severity,
        title: `plaintext credential in env: ${key}`,
        detail: `${matched.name} embedded in server env. anyone who reads this config file owns this credential. value masked: ${maskSecret(value, matched.hint)}`,
        server,
      });
      continue;
    }

    // interpolated references are fine
    if (INTERPOLATION_RE.test(value)) {
      findings.push({
        id: 'FAM-SEC-20',
        severity: 'info',
        title: `interpolated env reference: ${key}`,
        detail: `value looks like an environment/templating reference, not a literal secret. this is the right pattern.`,
        server,
      });
      continue;
    }

    // generic high-entropy value under a secret-sounding name
    const nameHint = SECRET_NAME_HINTS.find((h) => h.re.test(key));
    if (nameHint && GENERIC_VALUE_RE.test(value) && !/^(true|false|1|0|yes|no|none|null)$/i.test(value)) {
      findings.push({
        id: 'FAM-SEC-21',
        severity: 'high',
        title: `probable plaintext credential in env: ${key}`,
        detail: `env name suggests a ${nameHint.hint} and the value looks like a literal credential. masked: ${maskSecret(value, nameHint.hint)}`,
        server,
      });
    }
  }
  return findings;
}
