import { createHash } from 'node:crypto';
import { lstat, readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { isIP } from 'node:net';
import { TextDecoder } from 'node:util';
import { URL } from 'node:url';

export const VERSION = '0.1.0';
export const RULESET_VERSION = 1;

const SEVERITIES = [
  ['critical', 90],
  ['high', 70],
  ['medium', 40],
  ['low', 20],
  ['info', 0],
];

const SECRET_KEY = /(?:password|passwd|secret|token|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key|credential|authorization|cookie|session|webhook)/i;
const PERMISSION_KEY = /^(?:permissions?|scopes?|access|allow|allowlist|allowedpaths?|allowedhosts?|filesystem|network|shell|execute|admin)$/i;
const PACKAGE_KEY = /^(?:package|packagename|packages|image|dependency|dependencies)$/i;
const URL_PATTERN = /(?:https?|wss?|javascript|data|file|gopher|ftp):[^\s"'<>`]+/gi;
const INVISIBLE_PATTERN = /[\u00ad\u200b-\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]/u;
const PLACEHOLDER_PATTERN = /^(?:\$\{[^}]+\}|\$[A-Z_][A-Z0-9_]*|\{\{[^}]+\}\}|<[^>]*(?:token|secret|key|password)[^>]*>|change[-_ ]?me|replace[-_ ]?me|example|test|dummy|(?:x|0)+)$/i;

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function normalizeKey(value) {
  return String(value).normalize('NFKC').toLowerCase().trim();
}

function pointerPart(value) {
  return String(value).replaceAll('~', '~0').replaceAll('/', '~1');
}

export function pointer(parts) {
  return parts.length ? `/${parts.map(pointerPart).join('/')}` : '';
}

function canonicalToolName(value) {
  return normalizeKey(value).replace(/[._\s-]+/g, '-');
}

function stable(value) {
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
  if (isObject(value)) return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

function fingerprint(parts) {
  return `sha256:${createHash('sha256').update(stable(parts)).digest('hex').slice(0, 16)}`;
}

function severityFor(score) {
  for (const [name, minimum] of SEVERITIES) {
    if (score >= minimum) return name;
  }
  return 'info';
}

function relativeDisplay(file, root) {
  const relative = path.relative(root, file) || path.basename(file);
  return relative.split(path.sep).join('/');
}

function sortByPath(a, b) {
  return a.localeCompare(b, 'en', { numeric: false, sensitivity: 'variant' });
}

async function discoverOne(input, files, explicit = false) {
  const absolute = path.resolve(input);
  let stat;
  try {
    stat = await lstat(absolute);
  } catch (error) {
    throw new Error(`cannot read ${input}: ${error.message}`);
  }

  if (stat.isSymbolicLink()) {
    if (explicit) throw new Error(`symlink inputs are not supported: ${input}`);
    return;
  }
  if (stat.isFile()) {
    files.push(absolute);
    return;
  }
  if (!stat.isDirectory()) return;

  const entries = await readdir(absolute, { withFileTypes: true });
  entries.sort((a, b) => sortByPath(a.name, b.name));
  for (const entry of entries) {
    if (entry.name === '.git' || entry.name === 'node_modules') continue;
    const child = path.join(absolute, entry.name);
    if (entry.isSymbolicLink()) continue;
    if (entry.isDirectory()) {
      await discoverOne(child, files);
    } else if (entry.isFile() && entry.name.toLowerCase().endsWith('.json')) {
      files.push(child);
    }
  }
}

async function decodeJson(buffer, file) {
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(buffer);
  } catch {
    throw new Error(`invalid UTF-8 in ${file}`);
  }
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  try {
    return { text, value: JSON.parse(text) };
  } catch {
    throw new Error(`invalid JSON in ${file}`);
  }
}

function walk(value, parts, callback, parentKey = '') {
  callback(value, parts, parentKey);
  if (Array.isArray(value)) {
    value.forEach((child, index) => walk(child, [...parts, index], callback, String(index)));
  } else if (isObject(value)) {
    for (const [key, child] of Object.entries(value)) {
      walk(child, [...parts, key], callback, key);
    }
  }
}

function toolRecord(value, parts, serverKey = '', mapName = '') {
  const name = typeof value?.name === 'string' && value.name.trim() ? value.name : mapName;
  const namePointer = typeof value?.name === 'string' ? pointer([...parts, 'name']) : pointer(parts);
  const descriptions = ['description', 'instructions', 'prompt', 'system', 'developer', 'usage', 'help', 'readme', 'examples', 'annotations']
    .flatMap((key) => typeof value?.[key] === 'string' ? [value[key]] : []);
  return {
    name,
    rawName: name,
    canonicalName: name ? canonicalToolName(name) : '',
    description: descriptions.join('\n'),
    inputSchema: value?.inputSchema,
    permissions: value?.permissions,
    aliases: Array.isArray(value?.aliases) ? value.aliases.filter((item) => typeof item === 'string') : [],
    serverKey,
    sourcePointer: pointer(parts),
    namePointer,
    value,
  };
}

function extractTools(container, parts, serverKey, output) {
  if (Array.isArray(container)) {
    container.forEach((item, index) => {
      if (isObject(item)) output.push(toolRecord(item, [...parts, index], serverKey));
    });
  } else if (isObject(container)) {
    for (const [name, item] of Object.entries(container)) {
      if (isObject(item)) output.push(toolRecord(item, [...parts, name], serverKey, name));
    }
  }
}

function looksLikeServer(value) {
  return isObject(value) && (
    typeof value.command === 'string' ||
    typeof value.url === 'string' ||
    Array.isArray(value.args) ||
    isObject(value.env) ||
    isObject(value.headers) ||
    isObject(value.permissions)
  );
}

function extractServers(root, tools) {
  const servers = [];
  const addServer = (value, parts, key = '') => {
    if (!isObject(value)) return;
    const record = {
      key,
      command: typeof value.command === 'string' ? value.command : '',
      args: Array.isArray(value.args) ? value.args : [],
      env: value.env,
      url: typeof value.url === 'string' ? value.url : '',
      headers: value.headers,
      permissions: value.permissions,
      capabilities: value.capabilities,
      sourcePointer: pointer(parts),
      value,
    };
    servers.push(record);
    if (value.tools) extractTools(value.tools, [...parts, 'tools'], key, tools);
    if (value.functions) extractTools(value.functions, [...parts, 'functions'], key, tools);
  };

  if (isObject(root?.mcpServers)) {
    for (const [key, value] of Object.entries(root.mcpServers)) addServer(value, ['mcpServers', key], key);
  }
  if (Array.isArray(root?.servers)) {
    root.servers.forEach((value, index) => addServer(value, ['servers', index], String(index)));
  } else if (isObject(root?.servers)) {
    for (const [key, value] of Object.entries(root.servers)) {
      if (looksLikeServer(value)) addServer(value, ['servers', key], key);
    }
  }
  return servers;
}

function extractDocument(value, file, text) {
  const tools = [];
  const servers = extractServers(value, tools);
  if (value?.tools) extractTools(value.tools, ['tools'], '', tools);
  if (value?.functions) extractTools(value.functions, ['functions'], '', tools);
  return {
    file,
    text,
    value,
    servers,
    tools,
    kind: servers.length ? 'mcp-config' : tools.length ? 'tool-manifest' : 'unknown',
  };
}

function addError(state, file, code, message) {
  state.report.errors.push({ code, file, message });
}

function addFinding(state, {
  code,
  category,
  base,
  factors = [],
  confidence = 'medium',
  message,
  file,
  parts = [],
  evidence = {},
  remediation,
  related = [],
}) {
  const points = factors.reduce((total, factor) => total + factor.points, base);
  const score = Math.min(100, points);
  const source = { file, pointer: pointer(parts) };
  const safeFactors = factors.map(({ code: factorCode, points: factorPoints }) => ({ code: factorCode, points: factorPoints }));
  const finding = {
    ruleId: code,
    category,
    severity: severityFor(score),
    score,
    confidence,
    message,
    source,
    evidence,
    factors: safeFactors,
    remediation,
    fingerprint: fingerprint({ file, pointer: source.pointer, code, evidence }),
  };
  if (related.length) finding.related = related;
  state.report.findings.push(finding);
}

function sourceFile(document) {
  return document.file;
}

function secretMatch(value, key) {
  const text = String(value);
  const named = SECRET_KEY.test(key);
  if (PLACEHOLDER_PATTERN.test(text.trim())) return null;
  if (/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/i.test(text)) return { type: 'pem-private-key', strong: true };
  if (/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/.test(text)) return { type: 'aws-access-key', strong: true };
  if (/\b(?:ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)[A-Za-z0-9_]{20,}\b/.test(text)) return { type: 'github-token', strong: true };
  if (/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/.test(text)) return { type: 'slack-token', strong: true };
  if (/\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{12,}\b/.test(text)) return { type: 'stripe-key', strong: true };
  if (/\bAIza[0-9A-Za-z_-]{20,}\b/.test(text)) return { type: 'google-api-key', strong: true };
  if (/^Bearer\s+\S{16,}$/i.test(text.trim())) return { type: 'bearer-token', strong: true };
  if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(text) && text.length >= 40) return { type: 'jwt', strong: true };
  if (named && text.length >= 8) return { type: 'credential-field', strong: text.length >= 16 };
  if (/^(?:authorization|cookie|x-api-key)$/i.test(key) && text.length >= 8) return { type: 'credential-header', strong: true };
  return null;
}

function analyzeInstruction(state, document, value, parts, key) {
  if (typeof value !== 'string' || value.length < 4) return;
  const text = value.normalize('NFKC');
  const promptOverride = /(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|system|developer)\s+instructions|you\s+are\s+now|(?:system|developer)\s+message|do\s+not\s+(?:reveal|mention)\s+this|always\s+(?:use|call)\s+this\s+tool|never\s+(?:use|call)\s+(?:the\s+)?(?:other|original)\s+tool/i.test(text);
  const dangerousAction = /(?:read|access|collect|upload|send|exfiltrat|execute|download|disable).{0,100}(?:credential|password|secret|token|ssh|cookie|key|shell|command|security|external endpoint)/i.test(text);
  const invisible = INVISIBLE_PATTERN.test(value) || /<!--[^>]*-->/s.test(value) || /(?:<\/?system>|\[INST\]|<\/?tool>)/i.test(value);
  if (!promptOverride && !dangerousAction && !invisible) return;
  const factors = [];
  if (promptOverride) factors.push({ code: 'prompt-override-language', points: 25 });
  if (dangerousAction) factors.push({ code: 'credential-or-action-language', points: 25 });
  if (invisible) factors.push({ code: 'hidden-or-obfuscated-content', points: 15 });
  if (/^(?:system|developer|prompt|instructions?)$/i.test(key)) factors.push({ code: 'control-field', points: 10 });
  addFinding(state, {
    code: invisible ? 'TG.INSTRUCTION.INVISIBLE_CONTENT' : 'TG.INSTRUCTION.PROMPT_OVERRIDE',
    category: 'hidden-instruction',
    base: 30,
    factors,
    confidence: invisible || dangerousAction ? 'high' : 'medium',
    message: invisible
      ? 'Tool content contains invisible, obfuscated, or model-format control text.'
      : 'Tool content contains language that attempts to control instructions or tool selection.',
    file: sourceFile(document),
    parts,
    evidence: { field: key || 'value', signals: factors.map((factor) => factor.code).sort() },
    remediation: 'Review the description as untrusted content and remove instruction-like directives.',
  });
}

function isPrivateIpv4(host) {
  const parts = host.split('.').map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  return parts[0] === 10 || parts[0] === 127 || parts[0] === 0 ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168) ||
    (parts[0] === 169 && parts[1] === 254);
}

function isPrivateHost(host) {
  const clean = host.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
  if (clean === 'localhost' || clean === '::1' || clean === '0.0.0.0') return true;
  if (isIP(clean) === 4) return isPrivateIpv4(clean);
  if (clean.startsWith('::ffff:')) {
    const groups = clean.slice('::ffff:'.length).split(':');
    if (groups.length === 2 && groups.every((group) => /^[0-9a-f]{1,4}$/.test(group))) {
      const first = Number.parseInt(groups[0], 16);
      const second = Number.parseInt(groups[1], 16);
      return isPrivateIpv4(`${first >> 8}.${first & 255}.${second >> 8}.${second & 255}`);
    }
  }
  return clean.startsWith('fc') || clean.startsWith('fd') || clean.startsWith('fe80:');
}

function analyzeUrl(state, document, urlText, parts, key) {
  let parsed;
  try {
    parsed = new URL(urlText);
  } catch {
    return;
  }
  const factors = [];
  const scheme = parsed.protocol.toLowerCase();
  const dangerousScheme = ['javascript:', 'data:', 'file:', 'gopher:', 'ftp:'].includes(scheme);
  if (dangerousScheme) factors.push({ code: 'dangerous-url-scheme', points: 35 });
  if (scheme === 'http:' || scheme === 'ws:') factors.push({ code: 'cleartext-url', points: 10 });
  if (parsed.username || parsed.password) factors.push({ code: 'url-credentials', points: 20 });
  if (isPrivateHost(parsed.hostname)) factors.push({ code: 'private-or-loopback-target', points: 20 });
  if (parsed.hostname.includes('xn--')) factors.push({ code: 'punycode-host', points: 15 });
  if (parsed.port && !['80', '443'].includes(parsed.port)) factors.push({ code: 'nonstandard-port', points: 10 });
  if (/\/(?:webhook|collect|upload|exfil|capture)(?:\/|$)/i.test(parsed.pathname)) factors.push({ code: 'collection-path', points: 15 });
  let secretQuery = false;
  for (const [queryKey] of parsed.searchParams) {
    if (/(?:token|secret|key|password|auth|credential)/i.test(queryKey)) secretQuery = true;
  }
  if (secretQuery) factors.push({ code: 'secret-query-key', points: 20 });
  if (!factors.length) return;
  addFinding(state, {
    code: 'TG.URL.SUSPICIOUS',
    category: 'suspicious-url',
    base: 15,
    factors,
    confidence: dangerousScheme || secretQuery || isPrivateHost(parsed.hostname) ? 'high' : 'medium',
    message: 'A configured URL has characteristics that deserve security review.',
    file: sourceFile(document),
    parts,
    evidence: {
      scheme,
      host: parsed.hostname,
      field: key || 'value',
      secretQuery,
    },
    remediation: 'Verify the endpoint, use HTTPS where applicable, and avoid embedding credentials or secrets in URLs.',
  });
  if (parsed.username || parsed.password || secretQuery) {
    addFinding(state, {
      code: 'TG.SECRET.URL_CREDENTIAL',
      category: 'hardcoded-secret',
      base: 60,
      factors: [{ code: 'secret-in-url', points: 20 }],
      confidence: 'high',
      message: 'A URL contains embedded credentials or a secret-like query parameter.',
      file: sourceFile(document),
      parts,
      evidence: { host: parsed.hostname, credentialType: parsed.username || parsed.password ? 'userinfo' : 'query-key' },
      remediation: 'Move credentials to an environment reference or external secret store.',
    });
  }
}

function analyzeSecrets(state, document, value, parts, key) {
  if (typeof value !== 'string' || value.length < 8) return;
  const match = secretMatch(value, key);
  if (!match) return;
  const factors = [];
  if (match.strong) factors.push({ code: 'known-token-pattern', points: 20 });
  if (SECRET_KEY.test(key)) factors.push({ code: 'secret-named-field', points: 15 });
  addFinding(state, {
    code: 'TG.SECRET.LITERAL',
    category: 'hardcoded-secret',
    base: 60,
    factors,
    confidence: match.strong ? 'high' : 'medium',
    message: 'A likely hardcoded secret appears in a configuration value.',
    file: sourceFile(document),
    parts,
    evidence: { matchType: match.type, valueKind: key || 'string', length: value.length },
    remediation: 'Use an environment-variable reference or external secret store instead of a literal secret.',
  });
}

function analyzePermissions(state, document, value, parts, key, capability = key) {
  if (!PERMISSION_KEY.test(key) && !capability) return;
  if (Array.isArray(value)) {
    value.forEach((child, index) => analyzePermissions(state, document, child, [...parts, index], String(index), capability));
    return;
  }
  if (isObject(value)) {
    for (const [childKey, child] of Object.entries(value)) {
      const nextCapability = PERMISSION_KEY.test(childKey) ? childKey : capability;
      analyzePermissions(state, document, child, [...parts, childKey], childKey, nextCapability);
    }
    return;
  }
  const text = typeof value === 'string' ? value.trim() : '';
  const processCapability = /(?:shell|execute|exec|process|admin|root|sudo)/i.test(capability || '');
  const broadGrant = value === true ||
    /^(?:\*|\/|\/\*\*|~|[a-z]:[\\/]\*|\$\{?home\}?\/?\*?)$/i.test(text) ||
    /^(?:0\.0\.0\.0\/0|::\/0)$/.test(text);
  const factors = [];
  if (broadGrant) factors.push({ code: 'unrestricted-wildcard-or-root', points: 25 });
  if (processCapability && (value === true || text)) factors.push({ code: 'process-or-admin-access', points: 20 });
  if (!factors.length) return;
  const permissionFingerprint = `${sourceFile(document)}:${pointer(parts)}`;
  if (state.permissionFindings?.has(permissionFingerprint)) return;
  state.permissionFindings?.add(permissionFingerprint);
  addFinding(state, {
    code: 'TG.PERMISSION.BROAD_SCOPE',
    category: 'over-broad-permission',
    base: 30,
    factors,
    confidence: 'high',
    message: 'A permission value grants a broad filesystem, network, or process scope.',
    file: sourceFile(document),
    parts,
    evidence: { field: capability || key, valueKind: typeof value },
    remediation: 'Replace wildcard, root, shell, or administrator access with the narrowest required scope.',
  });
}

function packageIsPinned(value) {
  if (typeof value !== 'string') return true;
  if (/@sha256:[a-f0-9]{64}$/i.test(value)) return true;
  if (/(?:^|#)(?:[a-f0-9]{40})$/i.test(value)) return true;
  return /(?:^|@)v?\d+\.\d+\.\d+$/.test(value);
}

function packageCandidate(value) {
  if (typeof value !== 'string') return [];
  return value.split(/[\s,]+/).map((item) => item.trim()).filter(Boolean);
}

function analyzePackage(state, document, value, parts, key, runner = false) {
  if (isObject(value)) {
    for (const [packageName, specification] of Object.entries(value)) {
      if (typeof specification === 'string' && !packageIsPinned(specification)) {
        emitFloatingPackage(state, document, `${packageName}@${specification}`, [...parts, packageName], key, runner);
      } else if (isObject(specification) && typeof specification.version === 'string' && !packageIsPinned(specification.version)) {
        emitFloatingPackage(state, document, `${packageName}@${specification.version}`, [...parts, packageName, 'version'], key, runner);
      }
    }
    return;
  }
  const candidates = Array.isArray(value)
    ? value.flatMap((item) => packageCandidate(item))
    : packageCandidate(value);
  for (const candidate of candidates) {
    if (/^(?:-|--|node|npm|exec|dlx|run|install|npx|pnpm|yarn|bunx|-y|-p|--yes|--package)$/i.test(candidate)) continue;
    if (key === 'image' || /^(?:https?|git\+|git@|docker:)/i.test(candidate) || candidate.includes('/') || candidate.includes('@') || /^[A-Za-z0-9_.:-]+$/.test(candidate)) {
      if (packageIsPinned(candidate)) continue;
      emitFloatingPackage(state, document, candidate, parts, key, runner);
    }
  }
}

function emitFloatingPackage(state, document, candidate, parts, key, runner) {
  const factors = [];
  if (runner) factors.push({ code: 'executable-package-runner', points: 10 });
  if (/(?:latest|next|beta|alpha|\*|\^|~|>=|>|<|\b\d+(?:\.\d+)?$)/i.test(candidate)) factors.push({ code: 'floating-tag-or-range', points: 15 });
  addFinding(state, {
    code: 'TG.PACKAGE.FLOATING_VERSION',
    category: 'unpinned-package',
    base: 25,
    factors,
    confidence: 'high',
    message: 'A package or executable reference is not pinned to an immutable version.',
    file: sourceFile(document),
    parts,
    evidence: { referenceKind: key === 'image' ? 'container-image' : runner ? 'package-runner' : key || 'package-field', hasVersion: /@[^/]+$/.test(candidate) },
    remediation: 'Pin packages to an exact version, commit hash, or image digest.',
  });
}

function commandTokens(command) {
  if (typeof command !== 'string') return [];
  return command.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g)?.map((item) => item.replace(/^['"]|['"]$/g, '')) ?? [];
}

function analyzeServer(state, document, server) {
  if (!server.command && !server.url) {
    addFinding(state, {
      code: 'TG.CONFIG.SERVER_TRANSPORT',
      category: 'configuration',
      base: 20,
      confidence: 'high',
      message: 'An MCP server entry has neither a command nor a URL transport.',
      file: sourceFile(document),
      parts: server.sourcePointer ? server.sourcePointer.slice(1).split('/').map((part) => part.replaceAll('~1', '/').replaceAll('~0', '~')) : [],
      evidence: { server: server.key },
      remediation: 'Define the intended command or remote URL for this MCP server.',
    });
  }
  const serverParts = server.sourcePointer ? server.sourcePointer.slice(1).split('/').map((part) => part.replaceAll('~1', '/').replaceAll('~0', '~')) : [];
  const commandParts = [...serverParts, 'command'];
  const argsParts = [...serverParts, 'args'];
  const commandWords = commandTokens(server.command);
  const runner = commandWords.some((word) => /^(?:npx|pnpm|yarn|bunx|npm)$/i.test(path.basename(word)));
  if (runner) analyzePackage(state, document, server.args, argsParts, 'args', true);
  if (runner) analyzePackage(state, document, commandWords.slice(1), commandParts, 'command', true);
  if (typeof server.command === 'string') {
    for (const match of server.command.matchAll(URL_PATTERN)) analyzeUrl(state, document, match[0], commandParts, 'command');
  }
}

function analyzeDocument(state, document) {
  for (const server of document.servers) analyzeServer(state, document, server);
  for (const tool of document.tools) {
    if (!tool.name) {
      addFinding(state, {
        code: 'TG.TOOL.MISSING_NAME',
        category: 'configuration',
        base: 20,
        confidence: 'high',
        message: 'A tool entry does not define a non-empty name.',
        file: sourceFile(document),
        parts: tool.namePointer.slice(1).split('/').filter(Boolean).map((part) => part.replaceAll('~1', '/').replaceAll('~0', '~')),
        evidence: {},
        remediation: 'Give each tool a stable, non-empty name.',
      });
    }
    if (tool.inputSchema !== undefined && !isObject(tool.inputSchema)) {
      addFinding(state, {
        code: 'TG.TOOL.INVALID_SCHEMA',
        category: 'configuration',
        base: 20,
        confidence: 'high',
        message: 'A tool inputSchema is not an object.',
        file: sourceFile(document),
        parts: [...tool.sourcePointer.slice(1).split('/').filter(Boolean), 'inputSchema'],
        evidence: { type: Array.isArray(tool.inputSchema) ? 'array' : typeof tool.inputSchema },
        remediation: 'Provide an object-shaped JSON Schema for the tool input.',
      });
    }
    if (tool.inputSchema === undefined && tool.name) {
      addFinding(state, {
        code: 'TG.TOOL.MISSING_SCHEMA',
        category: 'configuration',
        base: 20,
        confidence: 'medium',
        message: 'A named tool does not define an inputSchema.',
        file: sourceFile(document),
        parts: tool.sourcePointer.slice(1).split('/').filter(Boolean),
        evidence: { tool: tool.name },
        remediation: 'Define the tool input schema explicitly so callers can validate inputs.',
      });
    }
  }
  walk(document.value, [], (value, parts, key) => {
    if (PERMISSION_KEY.test(key)) analyzePermissions(state, document, value, parts, key);
    if (PACKAGE_KEY.test(key)) analyzePackage(state, document, value, parts, key);
    if (typeof value !== 'string') return;
    analyzeInstruction(state, document, value, parts, key);
    analyzeSecrets(state, document, value, parts, key);
    for (const match of value.matchAll(URL_PATTERN)) analyzeUrl(state, document, match[0], parts, key);
  });
}

function relatedTool(tool) {
  return {
    file: tool.file,
    pointer: tool.sourcePointer,
    name: tool.name,
    server: tool.serverKey || undefined,
  };
}

function analyzeCrossTool(state, documents) {
  const tools = documents.flatMap((document) => document.tools.map((tool) => ({ ...tool, file: document.file })));
  const grouped = new Map();
  for (const tool of tools) {
    if (!tool.canonicalName) continue;
    if (!grouped.has(tool.canonicalName)) grouped.set(tool.canonicalName, []);
    grouped.get(tool.canonicalName).push(tool);
  }
  for (const group of grouped.values()) {
    if (group.length < 2) continue;
    group.sort((a, b) => `${a.file}:${a.sourcePointer}`.localeCompare(`${b.file}:${b.sourcePointer}`));
    const related = group.map(relatedTool);
    for (let index = 1; index < group.length; index += 1) {
      const tool = group[index];
      addFinding(state, {
        code: 'TG.TOOL.NAME_COLLISION',
        category: 'cross-tool-shadowing',
        base: 35,
        factors: [{ code: 'normalized-name-collision', points: 25 }],
        confidence: 'high',
        message: 'Tool names collide after Unicode, case, or separator normalization.',
        file: tool.file,
        parts: tool.sourcePointer.slice(1).split('/').filter(Boolean),
        evidence: { canonicalName: tool.canonicalName, names: group.map((item) => item.name) },
        remediation: 'Use unique tool names or explicit server namespaces to prevent ambiguous dispatch.',
        related,
      });
    }
  }
  for (const tool of tools) {
    if (!tool.description || !tool.canonicalName) continue;
    const directive = /(?:use\s+this\s+instead\s+of|never\s+(?:call|use)|ignore\s+(?:the\s+)?other\s+tool|this\s+is\s+the\s+real|always\s+(?:call|use)\s+this\s+tool)/i.test(tool.description);
    if (!directive) continue;
    for (const target of tools) {
      if (target === tool || !target.canonicalName || !tool.description.toLowerCase().includes(target.canonicalName)) continue;
      addFinding(state, {
        code: 'TG.TOOL.SHADOW_DIRECTIVE',
        category: 'cross-tool-shadowing',
        base: 35,
        factors: [{ code: 'shadowing-directive-names-tool', points: 25 }],
        confidence: 'high',
        message: 'A tool description directs callers to replace or avoid another tool.',
        file: tool.file,
        parts: tool.sourcePointer.slice(1).split('/').filter(Boolean),
        evidence: { tool: tool.name, referencedTool: target.name },
        remediation: 'Treat tool descriptions as untrusted metadata and remove dispatch-manipulating directives.',
        related: [relatedTool(target)],
      });
    }
  }
}

function emptyReport() {
  return {
    version: 1,
    scannerVersion: VERSION,
    ruleSetVersion: RULESET_VERSION,
    summary: {
      files: 0,
      documentsParsed: 0,
      mcpServers: 0,
      tools: 0,
      findings: 0,
      maxScore: 0,
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      errors: 0,
    },
    files: [],
    servers: [],
    tools: [],
    findings: [],
    errors: [],
  };
}

function finalizeReport(report) {
  report.findings.sort((a, b) => {
    return sortByPath(a.source.file, b.source.file) ||
      a.source.pointer.localeCompare(b.source.pointer) ||
      a.ruleId.localeCompare(b.ruleId) ||
      a.fingerprint.localeCompare(b.fingerprint);
  });
  report.errors.sort((a, b) => sortByPath(a.file, b.file) || a.code.localeCompare(b.code) || a.message.localeCompare(b.message));
  report.files.sort((a, b) => sortByPath(a.path, b.path));
  report.servers.sort((a, b) => sortByPath(a.file, b.file) || a.pointer.localeCompare(b.pointer));
  report.tools.sort((a, b) => sortByPath(a.file, b.file) || a.pointer.localeCompare(b.pointer));
  for (const finding of report.findings) {
    finding.factors.sort((a, b) => a.code.localeCompare(b.code));
    if (finding.related) finding.related.sort((a, b) => `${a.file}:${a.pointer}`.localeCompare(`${b.file}:${b.pointer}`));
  }
  report.summary.findings = report.findings.length;
  report.summary.errors = report.errors.length;
  report.summary.maxScore = report.findings.reduce((maximum, finding) => Math.max(maximum, finding.score), 0);
  for (const severity of Object.keys(report.summary.bySeverity)) report.summary.bySeverity[severity] = 0;
  for (const finding of report.findings) report.summary.bySeverity[finding.severity] += 1;
  return report;
}

function addDocumentRecords(report, document) {
  for (const server of document.servers) {
    report.servers.push({
      file: document.file,
      pointer: server.sourcePointer,
      name: server.key,
      transport: server.url ? 'url' : server.command ? 'command' : 'missing',
    });
  }
  for (const tool of document.tools) {
    report.tools.push({
      file: document.file,
      pointer: tool.sourcePointer,
      name: tool.name || null,
      server: tool.serverKey || null,
    });
  }
}

export async function scanInputs(inputs, options = {}) {
  const root = path.resolve(options.root || process.cwd());
  const report = emptyReport();
  const state = { report, permissionFindings: new Set() };
  const documents = [];
  const files = [];
  const stdin = options.stdin;
  if (stdin !== undefined) {
    files.push({ absolute: options.stdinName || 'stdin.json', text: stdin, virtual: true });
  } else {
    for (const input of inputs) await discoverOne(input, files, true);
    files.sort((a, b) => sortByPath(a, b));
  }
  const maxBytes = options.maxBytes || 5 * 1024 * 1024;
  for (const entry of files) {
    const absolute = typeof entry === 'string' ? entry : entry.absolute;
    const display = typeof entry === 'string' ? relativeDisplay(absolute, root) : String(entry.absolute);
    report.files.push({ path: display, parsed: false, kind: 'unknown' });
    report.summary.files += 1;
    let text;
    try {
      if (typeof entry === 'string') {
        const buffer = await readFile(entry);
        if (buffer.byteLength > maxBytes) throw new Error(`input exceeds ${maxBytes} bytes`);
        ({ text } = await decodeJson(buffer, display));
      } else {
        text = entry.text;
        if (Buffer.byteLength(text, 'utf8') > maxBytes) throw new Error(`input exceeds ${maxBytes} bytes`);
      }
      if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
      let value;
      try {
        value = JSON.parse(text);
      } catch {
        throw new Error(`invalid JSON in ${display}`);
      }
      const document = extractDocument(value, display, text);
      documents.push(document);
      report.summary.documentsParsed += 1;
      report.summary.mcpServers += document.servers.length;
      report.summary.tools += document.tools.length;
      const fileRecord = report.files.at(-1);
      fileRecord.parsed = true;
      fileRecord.kind = document.kind;
      addDocumentRecords(report, document);
      analyzeDocument(state, document);
    } catch (error) {
      addError(state, display, 'TG.JSON.INVALID', error.message);
    }
  }
  analyzeCrossTool(state, documents);
  return finalizeReport(report);
}

export function statusCode(report) {
  if (report.errors.length) return 2;
  if (report.findings.length) return 1;
  return 0;
}
