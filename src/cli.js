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

function findingTool(report, finding) {
  return report.tools
    .filter((tool) => tool.file === finding.source.file && (finding.source.pointer === tool.pointer || finding.source.pointer.startsWith(`${tool.pointer}/`)))
    .sort((a, b) => b.pointer.length - a.pointer.length)[0] ?? null;
}

function groupedFindings(report) {
  const files = new Map();
  for (const finding of report.findings) {
    if (!files.has(finding.source.file)) files.set(finding.source.file, new Map());
    const tools = files.get(finding.source.file);
    const tool = findingTool(report, finding);
    const label = tool?.name ? `Tool: ${tool.name}` : tool?.server ? `Server: ${tool.server}` : 'Server and configuration settings';
    if (!tools.has(label)) tools.set(label, []);
    tools.get(label).push(finding);
  }
  return files;
}

function findingCard(finding, tool) {
  const remediation = (finding.remediation || 'Review this finding.').replace(/\s+/g, ' ').trim();
  return `<article class="finding ${escapeHtml(finding.severity)}">
  <div class="finding-topline"><span class="badge ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span><span class="score">Score ${escapeHtml(finding.score)}/100</span></div>
  <h5>${escapeHtml(finding.ruleId)}</h5>
  <p>${escapeHtml(finding.message)}</p>
  <p class="remediation"><strong>Remediation:</strong> ${escapeHtml(remediation)}</p>
  <dl class="finding-meta"><div><dt>Location</dt><dd><code>${escapeHtml(finding.source.file)}${escapeHtml(finding.source.pointer)}</code></dd></div><div><dt>Category</dt><dd>${escapeHtml(finding.category)}</dd></div><div><dt>Confidence</dt><dd>${escapeHtml(finding.confidence)}</dd></div>${tool?.server ? `<div><dt>Server</dt><dd>${escapeHtml(tool.server)}</dd></div>` : ''}</dl>
</article>`;
}

function groupedFindingSections(report) {
  const groups = groupedFindings(report);
  if (!groups.size) return '<div class="empty-state"><strong>No findings.</strong><span>The scanned inputs passed the configured checks.</span></div>';
  return [...groups.entries()].map(([file, tools]) => {
    const anchor = `file-${String(file).replace(/[^a-z0-9]+/gi, '-') || 'unknown'}`;
    return `<section class="file-group" aria-labelledby="${anchor}" id="group-${anchor}">
  <h3 id="${anchor}"><span class="section-kicker">File</span><code>${escapeHtml(file)}</code></h3>
  ${[...tools.entries()].map(([label, findings]) => `<section class="tool-group"><h4>${escapeHtml(label)}</h4>${findings.map((finding) => findingCard(finding, findingTool(report, finding))).join('\n')}</section>`).join('\n')}
</section>`;
  }).join('\n');
}

function htmlReport(report) {
  const summary = report.summary;
  const status = summary.errors ? 'error' : summary.findings ? 'review' : 'pass';
  const statusLabel = summary.errors ? 'Input errors' : summary.findings ? 'Review required' : 'No findings';
  const severityCards = ['critical', 'high', 'medium', 'low', 'info'].map((severity) => `<div class="severity-count"><span class="badge ${severity}">${severity}</span><strong>${summary.bySeverity[severity]}</strong></div>`).join('');
  const errors = report.errors.length
    ? `<section class="input-errors" aria-labelledby="input-errors-heading"><h2 id="input-errors-heading">Input errors</h2>${report.errors.map((error) => `<p><strong>${escapeHtml(error.code)}</strong> <code>${escapeHtml(error.file)}</code>: ${escapeHtml(error.message)}</p>`).join('')}</section>`
    : '';
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>ToolGuard security report</title>
<style>
:root{color-scheme:light dark;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f5f7fb;color:#172033;line-height:1.5;--surface:#fff;--surface-muted:#eef2f8;--border:#d7deea;--muted:#58657a;--shadow:0 12px 36px #27324d14;--critical:#b42318;--high:#c4320a;--medium:#9a6700;--low:#175cd3;--info:#475467;--focus:#175cd3}
@media(prefers-color-scheme:dark){:root{background:#101522;color:#edf2fa;--surface:#171e2d;--surface-muted:#202a3b;--border:#354157;--muted:#aab6c9;--shadow:0 12px 36px #0006;--critical:#ff8178;--high:#ff9b70;--medium:#f5c451;--low:#84adff;--info:#b8c4d8;--focus:#9dbdff}}
*{box-sizing:border-box}body{margin:0}main{max-width:1120px;margin:0 auto;padding:clamp(1rem,4vw,3rem) clamp(1rem,4vw,2rem)}h1,h2,h3,h4,h5,p{margin-top:0}h1{font-size:clamp(1.8rem,4vw,3rem);letter-spacing:-.04em;margin-bottom:.35rem}h2{font-size:1.35rem;margin-bottom:1rem}h3{font-size:1rem;margin-bottom:1rem}h4{font-size:1rem;margin-bottom:.8rem}h5{font-size:1rem;margin:0 0 .45rem}.muted,.meta{color:var(--muted)}code{font-family:"SFMono-Regular",Consolas,"Liberation Mono",monospace;overflow-wrap:anywhere}.hero{display:flex;align-items:stretch;justify-content:space-between;gap:1.5rem;margin-bottom:1.5rem}.eyebrow,.section-kicker{color:var(--muted);font-size:.72rem;font-weight:800;letter-spacing:.12em;text-transform:uppercase}.eyebrow{margin-bottom:.4rem}.score-card{min-width:190px;padding:1rem 1.15rem;border:1px solid var(--border);border-radius:1rem;background:var(--surface);box-shadow:var(--shadow);text-align:right}.score-label{display:block;color:var(--muted);font-size:.78rem}.score-value{display:block;font-size:2.3rem;letter-spacing:-.05em;line-height:1.1}.score-value small{font-size:.95rem;color:var(--muted);letter-spacing:0}.status{display:inline-block;margin-top:.55rem;font-size:.78rem;font-weight:800}.status.pass{color:#087443}.status.review{color:var(--high)}.status.error{color:var(--critical)}.summary-panel{padding:1rem;border:1px solid var(--border);border-radius:1rem;background:var(--surface);box-shadow:var(--shadow);margin-bottom:2rem}.summary-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:.75rem}.summary-card{padding:.85rem;border:1px solid var(--border);border-radius:.7rem;background:var(--surface-muted)}.summary-card strong{display:block;font-size:1.55rem;line-height:1.15}.summary-card span{color:var(--muted);font-size:.82rem}.severity-row{display:flex;flex-wrap:wrap;gap:.6rem;margin-top:1rem;padding-top:1rem;border-top:1px solid var(--border)}.severity-count{display:flex;align-items:center;gap:.4rem}.severity-count strong{font-size:1rem}.badge{display:inline-flex;align-items:center;min-height:1.5rem;padding:.18rem .55rem;border-radius:999px;font-size:.72rem;font-weight:850;letter-spacing:.04em;text-transform:uppercase}.badge.critical{background:#fee4e2;color:var(--critical)}.badge.high{background:#ffeadf;color:var(--high)}.badge.medium{background:#fff4cc;color:var(--medium)}.badge.low{background:#e0ecff;color:var(--low)}.badge.info{background:#eaecf0;color:var(--info)}.file-group{margin:0 0 2rem}.file-group>h3{display:flex;flex-wrap:wrap;align-items:baseline;gap:.65rem;padding-bottom:.7rem;border-bottom:2px solid var(--border)}.section-kicker{font-size:.65rem}.tool-group{margin:1rem 0 1.25rem 1rem}.finding{padding:1rem 1.1rem;margin:.75rem 0;border:1px solid var(--border);border-left:.3rem solid var(--info);border-radius:.7rem;background:var(--surface);box-shadow:0 4px 14px #27324d0b}.finding.critical{border-left-color:var(--critical)}.finding.high{border-left-color:var(--high)}.finding.medium{border-left-color:var(--medium)}.finding.low{border-left-color:var(--low)}.finding.info{border-left-color:var(--info)}.finding-topline{display:flex;align-items:center;gap:.65rem;margin-bottom:.55rem}.score{color:var(--muted);font-size:.8rem;font-weight:700}.finding p{margin-bottom:.65rem}.remediation{padding:.65rem .75rem;border-radius:.5rem;background:var(--surface-muted);font-size:.9rem}.finding-meta{display:flex;flex-wrap:wrap;gap:.35rem 1rem;margin:0;color:var(--muted);font-size:.78rem}.finding-meta div{min-width:10rem}.finding-meta dt{font-weight:750}.finding-meta dd{margin:0}.input-errors{padding:1rem;border:1px solid var(--critical);border-radius:.7rem;margin-top:1.5rem}.input-errors p{margin-bottom:.35rem}.empty-state{display:flex;flex-direction:column;gap:.25rem;padding:2rem;border:1px dashed var(--border);border-radius:.8rem;color:var(--muted)}a:focus-visible,button:focus-visible{outline:3px solid var(--focus);outline-offset:3px}@media(max-width:700px){.hero{flex-direction:column}.score-card{text-align:left;min-width:0}.summary-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.summary-card:last-child{grid-column:span 2}.tool-group{margin-left:0}.finding-meta{display:grid;grid-template-columns:1fr}.finding-meta div{min-width:0}}
</style></head>
<body><main><header class="hero"><div><p class="eyebrow">Offline static analysis</p><h1>ToolGuard security report</h1><p class="muted">Scanner ${escapeHtml(report.scannerVersion)} · rule set ${escapeHtml(report.ruleSetVersion)} · no network access used</p></div><div class="score-card"><span class="score-label">Maximum severity score</span><strong class="score-value">${escapeHtml(summary.maxScore)}<small>/100</small></strong><span class="status ${status}" role="status">${escapeHtml(statusLabel)}</span></div></header>
<section class="summary-panel" aria-labelledby="summary-heading"><h2 id="summary-heading">Scan summary</h2><div class="summary-grid"><div class="summary-card"><strong>${summary.files}</strong><span>Files scanned</span></div><div class="summary-card"><strong>${summary.mcpServers}</strong><span>MCP servers</span></div><div class="summary-card"><strong>${summary.tools}</strong><span>Tools</span></div><div class="summary-card"><strong>${summary.findings}</strong><span>Findings</span></div><div class="summary-card"><strong>${summary.errors}</strong><span>Input errors</span></div></div><div class="severity-row" aria-label="Findings by severity">${severityCards}</div></section>
<section aria-labelledby="findings-heading"><h2 id="findings-heading">Findings by file and tool</h2>${groupedFindingSections(report)}</section>${errors}
</main></body></html>
`;
}

export function render(report, format) {
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
