import type { CallGraph } from '../data/analysis-data';
import type { SiteMetadata, SourceCorrelation } from './TargetManager';
import { Download, FileJson, Workflow } from 'lucide-react';
import { Button } from './ui/button';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';

interface ArchitectureGuideProps {
  graph: CallGraph;
  site: SiteMetadata | null;
  correlations: SourceCorrelation[];
}

const download = (filename: string, type: string, content: string) => {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
};

const ArchitectureGuide = ({ graph, site, correlations }: ArchitectureGuideProps) => {
  const exportMarkdown = () => {
    const sections = graph.nodes.flatMap((node) => (node.vulnerabilities ?? (node.vulnerability ? [node.vulnerability] : [])).map((finding) => [
      `## ${finding.evidence?.category ?? node.name}`,
      `**Function:** ${node.name}`,
      `**File:** ${node.filePath}:${finding.evidence?.line ?? node.startLine}`,
      `**CWE:** ${finding.pass1_hypothesis.cwe_guess ?? 'Unclassified'}`,
      `**OWASP:** ${finding.evidence?.owasp ?? 'Unclassified'}`,
      `**Confidence:** ${finding.pass1_hypothesis.confidence}`,
      `**Triage verdict:** ${finding.pass2_triage.verdict}`,
      '### Static hypothesis', finding.pass1_hypothesis.reasoning,
      '### Evidence', finding.evidence?.excerpt ?? 'No excerpt recorded.',
      '### Triage', finding.pass2_triage.explanation,
      '### Recommendation', finding.pass2_triage.recommendation,
    ].join('\n\n')));
    const passive = site?.crawl.findings.map((finding) => [`## ${finding.category}`, `**URL:** ${finding.url}`, `**CWE:** ${finding.cwe}`, `**OWASP:** ${finding.owasp}`, `**Severity:** ${finding.severity}`, finding.evidence, `**Recommendation:** ${finding.recommendation}`].join('\n\n')) ?? [];
    download('aegis-triage-report.md', 'text/markdown', ['# AegisTriage Discovery & Triage Report', ...sections, ...passive].join('\n\n---\n\n'));
  };

  return (
    <div className="grid gap-5 lg:grid-cols-[1fr_.72fr]">
      <Card className="rounded-3xl border-slate-700 bg-slate-900/80 text-slate-100"><CardHeader><CardTitle className="flex items-center gap-2 text-cyan-300"><Workflow className="h-5 w-5" /> Analysis architecture</CardTitle></CardHeader><CardContent><ol className="grid gap-3 text-sm text-slate-400 sm:grid-cols-2">{['Administrator authentication and server-approved targets', 'tree-sitter AST parsing with fallback coverage', 'Source, sink, sanitizer, and taint analysis', 'Pinned-IP passive page and form inventory', 'Route-to-page evidence correlation', 'Human verification and redacted report export'].map((step, index) => <li key={step} className="rounded-2xl border border-slate-800 bg-slate-950/60 p-4"><span className="mb-2 block font-mono text-xs text-emerald-400">0{index + 1}</span>{step}</li>)}</ol></CardContent></Card>
      <Card className="rounded-3xl border-slate-700 bg-slate-900/80 text-slate-100"><CardHeader><CardTitle className="flex items-center gap-2 text-emerald-300"><Download className="h-5 w-5" /> Export current run</CardTitle></CardHeader><CardContent className="space-y-3"><p className="text-sm text-slate-400">Exports include redacted finding excerpts, call edges, passive crawl evidence, route correlations, and triage recommendations.</p><Button onClick={() => download('aegis-triage-report.json', 'application/json', JSON.stringify({ graph, site, correlations }, null, 2))} className="w-full rounded-xl bg-emerald-500 text-slate-950 hover:bg-emerald-400"><FileJson className="mr-2 h-4 w-4" /> Export JSON</Button><Button onClick={exportMarkdown} variant="outline" className="w-full rounded-xl border-cyan-400/30 text-cyan-200 hover:bg-cyan-400/10">Export Markdown</Button></CardContent></Card>
    </div>
  );
};

export default ArchitectureGuide;
