import type { CallGraph } from '../data/analysis-data';
import { Download, FileJson, Workflow } from 'lucide-react';
import { Button } from './ui/button';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';

interface ArchitectureGuideProps {
  graph: CallGraph;
}

const download = (filename: string, type: string, content: string) => {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
};

const ArchitectureGuide = ({ graph }: ArchitectureGuideProps) => {
  const exportMarkdown = () => {
    const sections = graph.nodes.filter((node) => node.vulnerability).map((node) => {
      const finding = node.vulnerability!;
      return [
        `## ${node.name}`,
        `**File:** ${node.filePath}:${node.startLine}-${node.endLine}`,
        `**CWE:** ${finding.pass1_hypothesis.cwe_guess ?? 'Unclassified'}`,
        `**Confidence:** ${finding.pass1_hypothesis.confidence}`,
        `**Triage verdict:** ${finding.pass2_triage.verdict}`,
        `**Verification status:** ${finding.pass2_triage.status}`,
        '### Pass 1 hypothesis', finding.pass1_hypothesis.reasoning,
        '### Pass 2 triage', finding.pass2_triage.explanation,
        '### Recommendation', finding.pass2_triage.recommendation,
      ].join('\n\n');
    });
    download('aegis-triage-report.md', 'text/markdown', ['# AegisTriage Vulnerability Report', ...sections].join('\n\n---\n\n'));
  };

  return (
    <div className="grid gap-5 lg:grid-cols-[1fr_.72fr]">
      <Card className="rounded-3xl border-slate-700 bg-slate-900/80 text-slate-100"><CardHeader><CardTitle className="flex items-center gap-2 text-cyan-300"><Workflow className="h-5 w-5" /> Analysis architecture</CardTitle></CardHeader><CardContent><ol className="grid gap-3 text-sm text-slate-400 sm:grid-cols-2">{['Authorized source target and allowlist validation', 'tree-sitter JavaScript/TypeScript parsing', 'Call-graph construction with networkx', 'Heuristic candidate pre-filtering', 'Provider-agnostic two-pass LLM review', 'Human verification and report export'].map((step, index) => <li key={step} className="rounded-2xl border border-slate-800 bg-slate-950/60 p-4"><span className="mb-2 block font-mono text-xs text-emerald-400">0{index + 1}</span>{step}</li>)}</ol></CardContent></Card>
      <Card className="rounded-3xl border-slate-700 bg-slate-900/80 text-slate-100"><CardHeader><CardTitle className="flex items-center gap-2 text-emerald-300"><Download className="h-5 w-5" /> Export current run</CardTitle></CardHeader><CardContent className="space-y-3"><p className="text-sm text-slate-400">Exports always use the currently loaded target, including its source snippets, graph edges, triage explanations, and verification states.</p><Button onClick={() => download('aegis-triage-report.json', 'application/json', JSON.stringify(graph, null, 2))} className="w-full rounded-xl bg-emerald-500 text-slate-950 hover:bg-emerald-400"><FileJson className="mr-2 h-4 w-4" /> Export JSON</Button><Button onClick={exportMarkdown} variant="outline" className="w-full rounded-xl border-cyan-400/30 text-cyan-200 hover:bg-cyan-400/10">Export Markdown</Button></CardContent></Card>
    </div>
  );
};

export default ArchitectureGuide;
