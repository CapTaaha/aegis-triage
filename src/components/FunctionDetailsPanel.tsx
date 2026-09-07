import type { FunctionNode } from '../data/analysis-data';
import { Badge } from './ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';

interface FunctionDetailsPanelProps { node: FunctionNode | null }

const FunctionDetailsPanel = ({ node }: FunctionDetailsPanelProps) => {
  if (!node) return <Card className="h-full rounded-2xl border-slate-800 bg-slate-900/70 text-slate-100"><CardHeader><CardTitle className="text-emerald-300">Select a function</CardTitle></CardHeader><CardContent><p className="text-sm text-slate-500">Choose a graph node to inspect its source, routes, findings, and static-flow evidence.</p></CardContent></Card>;

  const findings = node.vulnerabilities ?? (node.vulnerability ? [node.vulnerability] : []);
  const excerpt = node.sourceExcerpt ?? node.sourceCode;
  return (
    <Card className="min-h-full rounded-2xl border-slate-800 bg-slate-900/70 text-slate-100">
      <CardHeader><CardTitle className="text-emerald-300">{node.name}</CardTitle><p className="text-xs text-slate-500">{node.filePath}:{node.startLine}-{node.endLine}</p>{node.routes?.length ? <div className="flex flex-wrap gap-2">{node.routes.map((route) => <Badge key={route} variant="outline" className="border-cyan-400/30 text-cyan-300">{route}</Badge>)}</div> : null}</CardHeader>
      <CardContent className="space-y-5">
        <div><h3 className="mb-2 text-sm font-semibold uppercase tracking-wider text-cyan-300">Redacted finding excerpt</h3>{excerpt ? <pre className="max-h-[220px] overflow-auto rounded-xl border border-slate-800 bg-slate-950 p-4 text-xs leading-5 text-slate-300"><code>{excerpt}</code></pre> : <p className="rounded-xl border border-slate-800 bg-slate-950/70 p-4 text-sm text-slate-500">No source excerpt is returned when this function has no finding.</p>}</div>
        <div><h3 className="mb-2 text-sm font-semibold uppercase tracking-wider text-cyan-300">Findings ({findings.length})</h3><div className="space-y-3">{findings.map((finding, index) => <div key={`${finding.evidence?.ruleId ?? index}`} className="rounded-xl border border-slate-800 bg-slate-950/70 p-4"><div className="flex flex-wrap items-center gap-2"><Badge variant={finding.pass1_hypothesis.confidence === 'critical' ? 'destructive' : 'secondary'}>{finding.pass1_hypothesis.confidence}</Badge><span className="font-semibold text-slate-100">{finding.evidence?.category ?? finding.pass1_hypothesis.cwe_guess}</span><span className="font-mono text-xs text-cyan-300">{finding.pass1_hypothesis.cwe_guess}</span></div>{finding.evidence?.owasp && <p className="mt-2 text-xs text-slate-500">{finding.evidence.owasp} · {finding.evidence.ruleId} · line {finding.evidence.line}</p>}<p className="mt-3 text-sm text-slate-300">{finding.pass1_hypothesis.reasoning}</p>{finding.evidence?.source && <p className="mt-2 text-xs"><span className="text-slate-500">Source: </span><span className="text-amber-200">{finding.evidence.source}</span></p>}{finding.evidence?.sink && <pre className="mt-2 overflow-auto rounded-lg bg-slate-900 p-2 text-xs text-rose-200"><code>{finding.evidence.sink}</code></pre>}<p className="mt-3 text-sm text-emerald-200">{finding.pass2_triage.explanation}</p><p className="mt-2 text-xs text-slate-400">{finding.pass2_triage.recommendation}</p></div>)}{findings.length === 0 && <p className="rounded-xl border border-emerald-400/20 bg-emerald-400/5 p-4 text-sm text-emerald-200">No OWASP-oriented source or sink finding was associated with this function.</p>}</div></div>
      </CardContent>
    </Card>
  );
};

export default FunctionDetailsPanel;
