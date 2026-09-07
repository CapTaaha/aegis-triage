import { useState } from 'react';
import { Activity, Braces, Network, Radar, Settings2, ShieldCheck, Workflow } from 'lucide-react';
import ArchitectureGuide from '../components/ArchitectureGuide';
import CallGraphExplorer from '../components/CallGraphExplorer';
import FunctionDetailsPanel from '../components/FunctionDetailsPanel';
import LLMConfigurator from '../components/LLMConfigurator';
import TargetManager, { AnalysisResponse, SiteMetadata } from '../components/TargetManager';
import TriageDashboard from '../components/TriageDashboard';
import { Alert, AlertDescription, AlertTitle } from '../components/ui/alert';
import { Badge } from '../components/ui/badge';
import { Card, CardContent } from '../components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs';
import { analysisData, CallGraph, FunctionNode } from '../data/analysis-data';

export default function Index() {
  const [graph, setGraph] = useState<CallGraph>(analysisData);
  const [selectedNode, setSelectedNode] = useState<FunctionNode | null>(null);
  const [site, setSite] = useState<SiteMetadata | null>(null);
  const [activeTarget, setActiveTarget] = useState('Bundled Juice Shop demonstration');
  const [analysisMode, setAnalysisMode] = useState('bundled demo');
  const [analysisWarning, setAnalysisWarning] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState('targets');

  const loadAnalysis = (result: AnalysisResponse) => {
    setGraph(result.analysis);
    setSite(result.site);
    setActiveTarget(result.target.source);
    setAnalysisMode(result.analysis.summary?.parserMode ?? 'local worker');
    setAnalysisWarning(result.analysis.summary?.warning ?? null);
    setSelectedNode(null);
    setActiveTab('graph');
  };

  const findingCount = graph.nodes.filter((node) => node.vulnerability).length;

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800 bg-slate-950/95 px-4 py-4 backdrop-blur sm:px-6">
        <div className="mx-auto flex max-w-[1600px] flex-col justify-between gap-4 lg:flex-row lg:items-center">
          <div className="flex items-center gap-3"><div className="grid h-11 w-11 place-items-center rounded-2xl border border-emerald-300/30 bg-emerald-400/10 shadow-lg shadow-emerald-950"><ShieldCheck className="h-6 w-6 text-emerald-300" /></div><div><h1 className="text-xl font-bold tracking-tight sm:text-2xl">Aegis<span className="text-emerald-400">Triage</span></h1><p className="text-xs text-slate-500">Source discovery · dual-pass triage · human verification</p></div></div>
          <div className="flex flex-wrap items-center gap-2 text-xs"><Badge className="rounded-full border border-emerald-400/30 bg-emerald-400/10 text-emerald-200"><Activity className="mr-1.5 h-3 w-3" /> Ready</Badge><Badge variant="outline" className="max-w-[420px] truncate rounded-full border-slate-700 text-slate-400">Target: {activeTarget}</Badge><Badge variant="outline" className="rounded-full border-cyan-400/30 text-cyan-300">Parser: {analysisMode}</Badge><Badge variant="outline" className="rounded-full border-slate-700 text-slate-400">{graph.nodes.length} functions</Badge><Badge variant="outline" className="rounded-full border-rose-400/30 text-rose-300">{findingCount} findings</Badge></div>
        </div>
        {analysisWarning && <Alert className="mx-auto mt-4 max-w-[1600px] border-amber-400/30 bg-amber-400/10 text-amber-100"><AlertTitle>Fallback parser active</AlertTitle><AlertDescription>{analysisWarning}</AlertDescription></Alert>}
      </header>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="mx-auto flex min-h-[calc(100vh-78px)] max-w-[1600px] flex-col">
        <div className="overflow-x-auto border-b border-slate-800 px-4 sm:px-6"><TabsList className="h-14 min-w-max justify-start gap-1 rounded-none bg-transparent p-0"><TabsTrigger value="targets" className="rounded-xl data-[state=active]:bg-emerald-400/10 data-[state=active]:text-emerald-300"><Radar className="mr-2 h-4 w-4" /> Targets</TabsTrigger><TabsTrigger value="graph" className="rounded-xl data-[state=active]:bg-cyan-400/10 data-[state=active]:text-cyan-300"><Network className="mr-2 h-4 w-4" /> Call graph</TabsTrigger><TabsTrigger value="triage" className="rounded-xl data-[state=active]:bg-rose-400/10 data-[state=active]:text-rose-300"><Braces className="mr-2 h-4 w-4" /> Triage</TabsTrigger><TabsTrigger value="architecture" className="rounded-xl data-[state=active]:bg-cyan-400/10 data-[state=active]:text-cyan-300"><Workflow className="mr-2 h-4 w-4" /> Architecture & export</TabsTrigger><TabsTrigger value="settings" className="rounded-xl data-[state=active]:bg-slate-800"><Settings2 className="mr-2 h-4 w-4" /> LLM settings</TabsTrigger></TabsList></div>

        <TabsContent value="targets" className="m-0 flex-1 p-4 sm:p-6"><TargetManager onAnalysisComplete={loadAnalysis} />{site && <Card className="mt-5 rounded-3xl border-slate-700 bg-slate-900/80 text-slate-100"><CardContent className="grid gap-4 p-5 md:grid-cols-4"><div><p className="text-xs uppercase tracking-wider text-slate-500">Passive site</p><p className="mt-1 truncate font-medium text-cyan-300">{site.url}</p></div><div><p className="text-xs uppercase tracking-wider text-slate-500">HTTP status</p><p className="mt-1 text-lg font-semibold">{site.status}</p></div><div><p className="text-xs uppercase tracking-wider text-slate-500">TLS</p><p className="mt-1 text-lg font-semibold text-emerald-300">{site.tls.replace('_', ' ')}</p></div><div><p className="text-xs uppercase tracking-wider text-slate-500">Security headers</p><p className="mt-1 text-lg font-semibold">{Object.keys(site.headers).length}</p></div></CardContent></Card>}</TabsContent>
        <TabsContent value="graph" className="m-0 flex-1 overflow-hidden"><div className="grid h-[calc(100vh-135px)] min-h-[620px] lg:grid-cols-[minmax(0,1.7fr)_minmax(340px,.8fr)]"><div className="border-b border-slate-800 lg:border-b-0 lg:border-r"><CallGraphExplorer graph={graph} onNodeClick={setSelectedNode} /></div><div className="overflow-y-auto bg-slate-950 p-4"><FunctionDetailsPanel node={selectedNode} /></div></div></TabsContent>
        <TabsContent value="triage" className="m-0 flex-1 overflow-hidden"><TriageDashboard graph={graph} /></TabsContent>
        <TabsContent value="architecture" className="m-0 flex-1 p-4 sm:p-6"><ArchitectureGuide graph={graph} /></TabsContent>
        <TabsContent value="settings" className="m-0 flex-1 p-4 sm:p-6"><LLMConfigurator /></TabsContent>
      </Tabs>
    </main>
  );
}
