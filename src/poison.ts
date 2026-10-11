import type { Finding, ToolDef } from './models.js';

interface PoisonRule {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  detail: string;
  pattern: RegExp;
}

const RULES: PoisonRule[] = [
  {
    id: 'FAM-PSN-01',
    severity: 'critical',
    title: 'instruction override directive',
    detail: 'the description tells the model to ignore or replace its standing instructions. this is the canonical tool poisoning pattern.',
    pattern: /\bignore\b[^.]{0,40}\b(instructions?|rules?|guardrails?|constraints?|directives?)\b|\bdisregard\b[^.]{0,40}\b(all|any|previous|prior|above|your)\b|\bforget\b[^.]{0,40}\b(instructions?|context|previous)\b/i,
  },
  {
    id: 'FAM-PSN-02',
    severity: 'critical',
    title: 'concealment directive',
    detail: 'the tool instructs the model to hide its behavior from the human. legitimate tools have no reason to keep secrets from their operator.',
    pattern: /\b(do not|don'?t|never)\b[^.]{0,30}\b(tell|inform|notify|reveal|mention|disclose|show|alert)\b[^.]{0,30}\b(user|human|owner|operator|developer)\b|\b(keep|maintain)\b[^.]{0,20}\b(this|it)\b[^.]{0,20}\b(secret|hidden|covert)\b/i,
  },
  {
    id: 'FAM-PSN-03',
    severity: 'critical',
    title: 'filesystem harvesting directive',
    detail: 'the description directs the model toward credential stores, shell history, wallets, or browser profile data. no ordinary tool needs these paths.',
    pattern: /(?:read|open|cat|load|list|scan|search|access|collect|grab|harvest)[^.]{0,60}(\/etc\/(?:passwd|shadow)|\.ssh|\.aws|\.env\b|\.git-credentials|\.bash_history|\.zsh_history|\.kube\/config|\.docker\/config|keystore|seed\s*phrase|wallet|browser\s+(?:profile|cookies|passwords|logins)|keychain|credential)/i,
  },
  {
    id: 'FAM-PSN-04',
    severity: 'critical',
    title: 'exfiltration directive',
    detail: 'the description instructs sending data to an external endpoint. combined with any data-access tool, this is a full exfil channel.',
    pattern: /\b(send|post|upload|transmit|forward|exfiltrate|push|deliver)\b[^.]{0,60}\b(to|into|via)\b[^.]{0,60}\b(https?:\/\/|webhook|pastebin|\.onion|telegram|discord\.com\/api\/webhooks|requestbin|pipedream|hookbbin|interact\.sh)\b/i,
  },
  {
    id: 'FAM-PSN-05',
    severity: 'high',
    title: 'identity hijack',
    detail: 'the description attempts to redefine what the model is or claims authority over its system prompt.',
    pattern: /\byou are (now|actually)\b|\byour (new |real |actual )?(system prompt|instructions)\b|\bact as\b[^.]{0,30}\b(instead|different|new)\b|\bsystem prompt\b[^.]{0,30}\b(says|requires|demands|overrides)/i,
  },
  {
    id: 'FAM-PSN-06',
    severity: 'high',
    title: 'tool precedence claim',
    detail: 'the description argues that the model should prefer this tool over others — including built-ins. shadowing attempts live here.',
    pattern: /\b(instead of|rather than|prefer(able)? (this|the) |always use (this|these)|use this (instead|tool)|before (using|calling)\b[^.]{0,40}\b(other|built-?in|native|similar)|supersede)/i,
  },
  {
    id: 'FAM-PSN-07',
    severity: 'high',
    title: 'command execution bootstrap',
    detail: 'the description steers the model toward running shell commands, or conditions its use on executing something first.',
    pattern: /\b(before|first)\b[^.]{0,40}\b(call|invoke|execute|run)\b[^.]{0,40}\b(shell|command|script|bash|curl|wget|powershell)\b|\brun\b[^.]{0,30}\bthe following (command|script)\b/i,
  },
  {
    id: 'FAM-PSN-08',
    severity: 'medium',
    title: 'urgency and authority pressure',
    detail: 'the description uses compliance pressure (mandatory, critical, security, must comply). real tool descriptions state function, not authority.',
    pattern: /\b(mandatory|obligatory|strictly required|must comply|compliance required|security requirement|audit requirement|policy (?:requires|mandates)|it is important that you)\b/i,
  },
];

const INVISIBLE_RANGES: Array<{ name: string; test: (cp: number) => boolean }> = [
  { name: 'zero-width (U+200B-200F)', test: (cp) => cp >= 0x200b && cp <= 0x200f },
  { name: 'bidi control (U+202A-202E, U+2066-2069)', test: (cp) => (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069) },
  { name: 'tag block (U+E0000-E007F)', test: (cp) => cp >= 0xe0000 && cp <= 0xe007f },
  { name: 'variation selector (U+FE00-FE0F)', test: (cp) => cp >= 0xfe00 && cp <= 0xfe0f },
  { name: 'word joiner / invisible ops', test: (cp) => cp === 0x2060 || cp === 0x00ad || cp === 0xfeff },
];

// cyrillic / greek lookalikes commonly used to hide tokens in otherwise-ascii text
const HOMOGLYPH_RE = /[\u0400-\u04FF\u0370-\u03FF]/;

const URL_RE = /https?:\/\/[^\s"'<>)\]]+/g;
const CALLBACK_HOSTS = /webhook\.site|pipedream\.net|requestbin|interact\.sh|pastebin\.com|hastebin|discord\.com\/api\/webhooks|ngrok\.io|trycloudflare\.com|transfer\.sh|file\.io|0x0\.st/i;
const BASE64_RE = /\b[A-Za-z0-9+/]{60,}={0,2}\b/;

/** visible rendering of text with hidden characters escaped */
export function exposeInvisible(text: string): string {
  let out = '';
  for (const ch of text) {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp >= 0xe0000 && cp <= 0xe007f) {
      out += `<U+${cp.toString(16).toUpperCase().padStart(6, '0')}>`;
    } else if (cp >= 0x200b && cp <= 0x200f) {
      out += `<U+${cp.toString(16).toUpperCase().padStart(4, '0')}>`;
    } else if ((cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069) || cp === 0x2060 || cp === 0x00ad || cp === 0xfeff) {
      out += `<U+${cp.toString(16).toUpperCase().padStart(4, '0')}>`;
    } else {
      out += ch;
    }
  }
  return out;
}

export function auditTool(tool: ToolDef): Finding[] {
  const findings: Finding[] = [];
  const desc = tool.description ?? '';
  const where = { server: tool.server, tool: tool.name };

  for (const rule of RULES) {
    const m = desc.match(rule.pattern);
    if (m) {
      const fragment = exposeInvisible(desc.slice(Math.max(0, (m.index ?? 0) - 20), (m.index ?? 0) + m[0].length + 40));
      findings.push({
        id: rule.id,
        severity: rule.severity,
        title: rule.title,
        detail: `${rule.detail} matched: "…${fragment.replace(/\s+/g, ' ')}…"`,
        ...where,
      });
    }
  }

  // hidden characters: the channel humans cannot read but models can
  const found: string[] = [];
  const seen = new Set<number>();
  for (const ch of desc) {
    const cp = ch.codePointAt(0) ?? 0;
    if (seen.has(cp)) continue;
    for (const range of INVISIBLE_RANGES) {
      if (range.test(cp)) {
        found.push(`U+${cp.toString(16).toUpperCase().padStart(4, '0')} (${range.name})`);
        seen.add(cp);
        break;
      }
    }
  }
  if (found.length > 0) {
    findings.push({
      id: 'FAM-PSN-10',
      severity: 'critical',
      title: `invisible characters in description: ${found.length} kind(s)`,
      detail: `hidden unicode present: ${found.slice(0, 6).join('; ')}. invisible characters smuggle a second description to the model that humans never see. treat every such tool as hostile until proven otherwise.`,
      ...where,
    });
  }

  if (HOMOGLYPH_RE.test(desc) && /[a-z]/i.test(desc)) {
    findings.push({
      id: 'FAM-PSN-11',
      severity: 'medium',
      title: 'non-latin characters mixed into latin text',
      detail: `cyrillic/greek lookalike characters found inside an otherwise latin description. homoglyphs defeat human review and can poison name matching.`,
      ...where,
    });
  }

  // callback urls
  const urls = desc.match(URL_RE) ?? [];
  for (const u of urls.slice(0, 3)) {
    const isCallback = CALLBACK_HOSTS.test(u);
    findings.push({
      id: 'FAM-PSN-12',
      severity: isCallback ? 'critical' : 'low',
      title: isCallback ? `known callback host in description: ${u}` : `external URL in description: ${u}`,
      detail: isCallback
        ? `the description embeds a request-collection endpoint. these services exist to receive whatever the model is convinced to send.`
        : `the description references an external URL. model-visible text pointing off-machine deserves a second look.`,
      ...where,
    });
  }

  // encoded payload
  if (BASE64_RE.test(desc)) {
    findings.push({
      id: 'FAM-PSN-13',
      severity: 'high',
      title: 'large base64 blob in description',
      detail: `the description carries a long base64 run. encoded payloads bypass human review by construction.`,
      ...where,
    });
  }

  return findings;
}

/** audit a whole toolset for one server */
export function auditTools(tools: ToolDef[]): Finding[] {
  const out: Finding[] = [];
  for (const t of tools) out.push(...auditTool(t));
  return out;
}
