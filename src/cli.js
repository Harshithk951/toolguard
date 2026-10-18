import { writeFile } from 'node:fs/promises';
import { scanInputs, statusCode, VERSION } from './toolguard.js';

function help() {
  return `ToolGuard ${VERSION}

Usage:
  toolguard scan <path>... [options]
  toolguard scan --stdin --stdin-name <name> [options]

Options:
  --format terminal|json|html  Report format (default: terminal)
  --output <file>|-            Write the report to a file or stdout
  --root <directory>           Base directory for displayed file paths
  --stdin                      Read one JSON document from stdin
  --stdin-name <name>          Display name for stdin (default: stdin.json)
  --help                       Show this help
  --version                    Show the version
`;
}

function parseArgs(argv) {
  if (argv.includes('--help') || argv.length === 0) return { help: true };
  if (argv.includes('--version')) return { version: true };
  if (argv[0] !== 'scan') throw new Error('expected the scan command');
  const paths = [];
  const options = { format: 'terminal' };
  for (let index = 1; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--stdin') {
      options.stdin = true;
    } else if (arg === '--stdin-name') {
      const value = argv[++index];
      if (!value || value.startsWith('--')) throw new Error('--stdin-name requires a value');
      options.stdinName = value;
    } else if (arg === '--format') {
      const value = argv[++index];
      if (!value || value.startsWith('--')) throw new Error('--format requires a value');
      options.format = value;
      if (!['terminal', 'json', 'html'].includes(options.format)) throw new Error('format must be terminal, json, or html');
    } else if (arg === '--output') {
      const value = argv[++index];
      if (!value || value.startsWith('--')) throw new Error('--output requires a value');
      options.output = value;
    } else if (arg === '--root') {
      const value = argv[++index];
      if (!value || value.startsWith('--')) throw new Error('--root requires a value');
      options.root = value;
    } else if (arg.startsWith('-')) {
      throw new Error(`unknown option: ${arg}`);
    } else {
      paths.push(arg);
    }
  }
  if (options.stdin && paths.length) throw new Error('--stdin cannot be combined with paths');
  if (!options.stdin && !paths.length) throw new Error('scan requires a path or --stdin');
  if (options.output === undefined) options.output = '-';
  return { paths, options };
}

async function readStdin() {
  let text = '';
  for await (const chunk of process.stdin) text += chunk;
  return text;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function terminalReport(report) {
  const { summary } = report;
  const lines = [
    'ToolGuard scan',
    `Files: ${summary.files}`,
    `Documents parsed: ${summary.documentsParsed}`,
    `MCP servers: ${summary.mcpServers}`,
    `Tools: ${summary.tools}`,
    `Findings: ${summary.findings}`,
    `Maximum score: ${summary.maxScore}/100`,
    `Severity: critical ${summary.bySeverity.critical}, high ${summary.bySeverity.high}, medium ${summary.bySeverity.medium}, low ${summary.bySeverity.low}, info ${summary.bySeverity.info}`,
    `Errors: ${summary.errors}`,
    `Status: ${summary.errors ? 'ERROR' : summary.findings ? 'REVIEW' : 'PASS'}`,
  ];
  for (const error of report.errors) lines.push(`ERROR ${error.code} ${error.file}: ${error.message}`);
  for (const finding of report.findings) {
    lines.push(`${finding.severity.toUpperCase()} ${finding.ruleId} ${finding.source.file}${finding.source.pointer} (${finding.score}/100): ${finding.message}`);
  }
  return `${lines.join('\n')}\n`;
}

function htmlReport(report) {
  const summary = report.summary;
  const findingRows = report.findings.length
    ? report.findings.map((finding) => `<article class="finding ${escapeHtml(finding.severity)}"><h3>${escapeHtml(finding.severity.toUpperCase())} · ${escapeHtml(finding.ruleId)} · ${escapeHtml(finding.score)}/100</h3><p>${escapeHtml(finding.message)}</p><code>${escapeHtml(finding.source.file)}${escapeHtml(finding.source.pointer)}</code><p class="meta">${escapeHtml(finding.category)} · confidence ${escapeHtml(finding.confidence)}</p></article>`).join('\n')
    : '<p class="clean">No findings.</p>';
  const errors = report.errors.length
    ? `<section><h2>Input errors</h2>${report.errors.map((error) => `<p class="error"><strong>${escapeHtml(error.code)}</strong> ${escapeHtml(error.file)}: ${escapeHtml(error.message)}</p>`).join('')}</section>`
    : '';
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ToolGuard report</title>
<style>
:root{color-scheme:light dark;font-family:system-ui,-apple-system,sans-serif}body{max-width:960px;margin:2rem auto;padding:0 1rem;line-height:1.45}h1{margin-bottom:.25rem}.muted,.meta{opacity:.72}.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:.75rem;margin:1.5rem 0}.card{border:1px solid #8885;border-radius:.6rem;padding:.8rem}.number{font-size:1.6rem;font-weight:700;display:block}.finding{border-left:5px solid #888;padding:.7rem 1rem;margin:1rem 0;background:#8881}.finding.critical{border-color:#d22}.finding.high{border-color:#e65}.finding.medium{border-color:#d99b00}.finding.low{border-color:#3978c5}.finding.info{border-color:#777}.finding h3{margin:.1rem 0}.finding code{overflow-wrap:anywhere}.error{color:#d66}.clean{color:#39884a;font-weight:700}</style></head>
<body><h1>ToolGuard report</h1><p class="muted">Scanner ${escapeHtml(report.scannerVersion)} · rule set ${escapeHtml(report.ruleSetVersion)}</p>
<section class="summary"><div class="card"><span class="number">${summary.files}</span>files</div><div class="card"><span class="number">${summary.mcpServers}</span>MCP servers</div><div class="card"><span class="number">${summary.tools}</span>tools</div><div class="card"><span class="number">${summary.findings}</span>findings</div><div class="card"><span class="number">${summary.maxScore}/100</span>maximum score</div><div class="card"><span class="number">${summary.errors}</span>input errors</div></section>
<section><h2>Findings</h2>${findingRows}</section>${errors}
</body></html>
`;
}

function render(report, format) {
  if (format === 'json') return `${JSON.stringify(report, null, 2)}\n`;
  if (format === 'html') return htmlReport(report);
  return terminalReport(report);
}

export async function main(argv) {
  let parsed;
  try {
    parsed = parseArgs(argv);
    if (parsed.help) {
      process.stdout.write(help());
      return;
    }
    if (parsed.version) {
      process.stdout.write(`${VERSION}\n`);
      return;
    }
    if (parsed.options.stdin) parsed.options.stdin = await readStdin();
  } catch (error) {
    process.stderr.write(`ToolGuard: ${error.message}\n`);
    process.exitCode = 2;
    return;
  }
  let report;
  try {
    report = await scanInputs(parsed.paths, parsed.options);
  } catch (error) {
    process.stderr.write(`ToolGuard: ${error.message}\n`);
    process.exitCode = 2;
    return;
  }
  const output = render(report, parsed.options.format);
  if (parsed.options.output === '-' || parsed.options.output === undefined) process.stdout.write(output);
  else await writeFile(parsed.options.output, output, 'utf8');
  process.exitCode = statusCode(report);
}
