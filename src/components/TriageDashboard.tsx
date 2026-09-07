import { useEffect, useMemo, useState } from 'react';
import { ClipboardCheck, Filter, Search } from 'lucide-react';
import type { CallGraph, Confidence, FunctionNode, TriageVerdict, VerificationStatus, VulnerabilityFinding } from '../data/analysis-data';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table';
import VerificationDialog from './VerificationDialog';

type FindingNode = FunctionNode & { vulnerability: VulnerabilityFinding };
const isFinding = (node: FunctionNode): node is FindingNode => Boolean(node.vulnerability);

interface TriageDashboardProps {
  graph: CallGraph;
}

const TriageDashboard = ({ graph }: TriageDashboardProps) => {
  const [findings, setFindings] = useState<FindingNode[]>(() => graph.nodes.filter(isFinding));
  const [verdictFilter, setVerdictFilter] = useState<TriageVerdict | 'all'>('all');
  const [confidenceFilter, setConfidenceFilter] = useState<Confidence | 'all'>('all');
  const [query, setQuery] = useState('');
  const [selectedFinding, setSelectedFinding] = useState<FindingNode | null>(null);

  useEffect(() => setFindings(graph.nodes.filter(isFinding)), [graph]);

  const filteredFindings = useMemo(() => findings.filter((node) => {
    const text = `${node.name} ${node.filePath} ${node.vulnerability.pass1_hypothesis.cwe_guess ?? ''}`.toLowerCase();
    return (verdictFilter === 'all' || node.vulnerability.pass2_triage.verdict === verdictFilter)
      && (confidenceFilter === 'all' || node.vulnerability.pass1_hypothesis.confidence === confidenceFilter)
      && text.includes(query.toLowerCase());
  }), [confidenceFilter, findings, query, verdictFilter]);

  const handleSaveStatus = (status: VerificationStatus) => {
    if (!selectedFinding) return;
    setFindings((current) => current.map((finding) => finding.id === selectedFinding.id
      ? { ...finding, vulnerability: { ...finding.vulnerability, pass2_triage: { ...finding.vulnerability.pass2_triage, status } } }
      : finding));
  };

  return (
    <div className="h-full overflow-auto bg-slate-950 p-4 text-slate-100 sm:p-6">
      <div className="mb-6 flex flex-col justify-between gap-3 sm:flex-row sm:items-end">
        <div><p className="mb-1 text-xs font-semibold uppercase tracking-[0.22em] text-emerald-400">Human review queue</p><h2 className="text-2xl font-bold">{filteredFindings.length} triaged findings</h2></div>
        <Badge className="w-fit rounded-full border border-cyan-400/30 bg-cyan-400/10 px-3 text-cyan-200"><ClipboardCheck className="mr-1.5 h-3.5 w-3.5" /> Manual verification required</Badge>
      </div>
      <div className="mb-5 grid gap-3 rounded-2xl border border-slate-800 bg-slate-900/70 p-4 md:grid-cols-[1fr_190px_190px]">
        <div className="relative"><Search className="absolute left-3 top-3 h-4 w-4 text-slate-500" /><Input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search function, path, or CWE" className="rounded-xl border-slate-700 bg-slate-950 pl-9" /></div>
        <Select value={verdictFilter} onValueChange={(value: TriageVerdict | 'all') => setVerdictFilter(value)}><SelectTrigger className="rounded-xl border-slate-700 bg-slate-950"><Filter className="mr-2 h-4 w-4" /><SelectValue /></SelectTrigger><SelectContent><SelectItem value="all">All verdicts</SelectItem><SelectItem value="likely_vulnerable">Likely vulnerable</SelectItem><SelectItem value="needs_review">Needs review</SelectItem><SelectItem value="likely_false_positive">Likely false positive</SelectItem></SelectContent></Select>
        <Select value={confidenceFilter} onValueChange={(value: Confidence | 'all') => setConfidenceFilter(value)}><SelectTrigger className="rounded-xl border-slate-700 bg-slate-950"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="all">All confidence</SelectItem><SelectItem value="critical">Critical</SelectItem><SelectItem value="high">High</SelectItem><SelectItem value="medium">Medium</SelectItem><SelectItem value="low">Low</SelectItem></SelectContent></Select>
      </div>
      <div className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/50">
        <Table><TableHeader><TableRow className="border-slate-800 hover:bg-transparent"><TableHead>Function</TableHead><TableHead>CWE</TableHead><TableHead>Confidence</TableHead><TableHead>Verdict</TableHead><TableHead>Status</TableHead><TableHead className="text-right">Review</TableHead></TableRow></TableHeader><TableBody>
          {filteredFindings.map((node) => <TableRow key={node.id} className="border-slate-800 hover:bg-slate-800/60"><TableCell><div className="font-semibold text-slate-100">{node.name}</div><div className="max-w-64 truncate text-xs text-slate-500">{node.filePath}:{node.startLine}</div></TableCell><TableCell className="font-mono text-cyan-300">{node.vulnerability.pass1_hypothesis.cwe_guess}</TableCell><TableCell><Badge variant={node.vulnerability.pass1_hypothesis.confidence === 'critical' ? 'destructive' : 'secondary'} className="rounded-full">{node.vulnerability.pass1_hypothesis.confidence}</Badge></TableCell><TableCell className="text-sm text-slate-300">{node.vulnerability.pass2_triage.verdict.replace(/_/g, ' ')}</TableCell><TableCell><Badge variant="outline" className="rounded-full border-slate-600 text-slate-300">{node.vulnerability.pass2_triage.status.replace(/_/g, ' ')}</Badge></TableCell><TableCell className="text-right"><Button variant="outline" size="sm" className="rounded-lg border-emerald-400/30 text-emerald-300 hover:bg-emerald-400/10" onClick={() => setSelectedFinding(node)}>Update</Button></TableCell></TableRow>)}
          {filteredFindings.length === 0 && <TableRow><TableCell colSpan={6} className="h-32 text-center text-slate-500">No findings match the current filters.</TableCell></TableRow>}
        </TableBody></Table>
      </div>
      {selectedFinding && <VerificationDialog isOpen onClose={() => setSelectedFinding(null)} currentStatus={selectedFinding.vulnerability.pass2_triage.status} onSave={handleSaveStatus} />}
    </div>
  );
};

export default TriageDashboard;
