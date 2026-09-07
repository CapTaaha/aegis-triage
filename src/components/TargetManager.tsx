import { useState } from 'react';
import { AlertCircle, CheckCircle2, FolderSearch, GitBranch, Globe2, Play, ShieldCheck } from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from './ui/alert';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Checkbox } from './ui/checkbox';
import { Input } from './ui/input';
import { Label } from './ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select';
import type { CallGraph } from '../data/analysis-data';

type TargetType = 'repository' | 'local' | 'website';

export type PassiveFinding = {
  id: string;
  category: string;
  cwe: string;
  owasp: string;
  severity: 'low' | 'medium' | 'high';
  url: string;
  evidence: string;
  recommendation: string;
};

export type SiteMetadata = {
  url: string;
  status: number;
  headers: Record<string, string>;
  tls: 'enabled' | 'not_enabled';
  redirectLocation: string | null;
  crawl: {
    pages: Array<{ url: string; status: number; title: string; contentType: string; forms: Array<{ action: string; method: string; inputs: Array<{ name: string; type: string }> }>; scripts: string[]; linksDiscovered: number }>;
    forms: Array<{ action: string; method: string; inputs: Array<{ name: string; type: string }> }>;
    scripts: string[];
    findings: PassiveFinding[];
    summary: { pagesVisited: number; formsFound: number; scriptsFound: number; findings: number; skippedByRobots: number; failedPages: number; maxPages: number; maxDepth: number };
  };
};

export type SourceCorrelation = {
  functionId: string;
  functionName: string;
  filePath: string;
  route: string;
  pages: string[];
  forms: Array<{ action: string; method: string; inputs: Array<{ name: string; type: string }> }>;
  findingCount: number;
};

export type AnalysisResponse = {
  analysis: CallGraph & { summary?: { files?: number; functions: number; findings: number; filesRoot: string; parserMode?: string; rulesEvaluated?: number; coverage?: string[]; warning?: string | null } };
  site: SiteMetadata | null;
  correlations: SourceCorrelation[];
  target: { type: TargetType; source: string; analyzedAt: string };
};

interface TargetManagerProps {
  onAnalysisComplete: (result: AnalysisResponse) => void;
}

const TargetManager = ({ onAnalysisComplete }: TargetManagerProps) => {
  const [targetType, setTargetType] = useState<TargetType>('repository');
  const [source, setSource] = useState('https://github.com/juice-shop/juice-shop.git');
  const [siteUrl, setSiteUrl] = useState('https://juice-shop.herokuapp.com');
  const [apiKey, setApiKey] = useState('');
  const [maxPages, setMaxPages] = useState(60);
  const [maxDepth, setMaxDepth] = useState(3);
  const [authorized, setAuthorized] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState('');

  const changeType = (value: TargetType) => {
    setTargetType(value);
    setAuthorized(false);
    if (value === 'local') {
      setSource('');
    } else if (value === 'website') {
      setSource('');
      setSiteUrl('');
    } else {
      setSource('https://github.com/juice-shop/juice-shop.git');
      setSiteUrl('https://juice-shop.herokuapp.com');
    }
  };

  const runAnalysis = async () => {
    setError('');
    setRunning(true);
    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
        body: JSON.stringify({
          targetType,
          source: targetType === 'website' ? undefined : source.trim(),
          siteUrl: siteUrl.trim() || undefined,
          maxPages,
          maxDepth,
          authorized,
        }),
      });
      const payload = await response.json().catch(() => null);
      if (!response.ok) throw new Error(payload?.statusMessage || payload?.message || 'Analysis failed.');
      onAnalysisComplete(payload as AnalysisResponse);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Analysis failed.');
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="grid gap-5 lg:grid-cols-[1.15fr_.85fr]">
      <Card className="rounded-3xl border-slate-700 bg-slate-900/80 text-slate-100 shadow-2xl shadow-emerald-950/20">
        <CardHeader className="space-y-2">
          <div className="flex items-center justify-between gap-3">
            <CardTitle className="flex items-center gap-2 text-xl text-emerald-300"><FolderSearch className="h-5 w-5" /> New analysis target</CardTitle>
            <Badge className="rounded-full border border-cyan-400/30 bg-cyan-400/10 text-cyan-200">Discovery only</Badge>
          </div>
          <p className="text-sm text-slate-400">Analyze an authorized source repository or local folder. A deployed URL is used only for passive headers and TLS metadata.</p>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label>Source type</Label>
              <Select value={targetType} onValueChange={(value: TargetType) => changeType(value)}>
                <SelectTrigger className="rounded-xl border-slate-700 bg-slate-950"><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="repository">Public Git repository + optional site</SelectItem><SelectItem value="local">Local source folder + optional site</SelectItem><SelectItem value="website">Website-only passive crawl</SelectItem></SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="source">{targetType === 'repository' ? 'Repository URL' : targetType === 'local' ? 'Absolute folder path' : 'Source analysis'}</Label>
              <div className="relative">
                {targetType === 'repository' ? <GitBranch className="absolute left-3 top-3 h-4 w-4 text-slate-500" /> : <FolderSearch className="absolute left-3 top-3 h-4 w-4 text-slate-500" />}
                <Input id="source" disabled={targetType === 'website'} value={targetType === 'website' ? 'Not required for website-only mode' : source} onChange={(event) => setSource(event.target.value)} className="rounded-xl border-slate-700 bg-slate-950 pl-9 disabled:text-slate-500" placeholder={targetType === 'repository' ? 'https://github.com/org/repo.git' : 'C:\\source\\project or /home/me/project'} />
              </div>
            </div>
          </div>
          <div className="space-y-2">
            <Label htmlFor="siteUrl">Deployed site URL <span className="text-slate-500">(optional, passive inspection only)</span></Label>
            <div className="relative"><Globe2 className="absolute left-3 top-3 h-4 w-4 text-slate-500" /><Input id="siteUrl" value={siteUrl} onChange={(event) => setSiteUrl(event.target.value)} className="rounded-xl border-slate-700 bg-slate-950 pl-9" placeholder="https://app.example.com" /></div>
          </div>
          <div className="space-y-2">
            <Label htmlFor="apiKey">Administrator analysis key</Label>
            <Input id="apiKey" type="password" autoComplete="off" value={apiKey} onChange={(event) => setApiKey(event.target.value)} className="rounded-xl border-slate-700 bg-slate-950 font-mono" placeholder="Required for every analysis request" />
            <p className="text-xs text-slate-500">Targets are approved by server configuration. This key is sent only with this request and is not stored.</p>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2"><Label htmlFor="maxPages">Maximum pages</Label><Input id="maxPages" type="number" min={1} max={200} value={maxPages} onChange={(event) => setMaxPages(Math.min(200, Math.max(1, Number(event.target.value) || 1)))} className="rounded-xl border-slate-700 bg-slate-950" /></div>
            <div className="space-y-2"><Label htmlFor="maxDepth">Maximum crawl depth</Label><Input id="maxDepth" type="number" min={0} max={5} value={maxDepth} onChange={(event) => setMaxDepth(Math.min(5, Math.max(0, Number(event.target.value) || 0)))} className="rounded-xl border-slate-700 bg-slate-950" /></div>
          </div>
          <div className="flex items-start gap-3 rounded-2xl border border-emerald-400/20 bg-emerald-400/5 p-4">
            <Checkbox id="authorization" checked={authorized} onCheckedChange={(checked) => setAuthorized(checked === true)} className="mt-0.5 border-emerald-400 data-[state=checked]:bg-emerald-500" />
            <Label htmlFor="authorization" className="cursor-pointer text-sm font-normal leading-5 text-slate-300">I confirm that I own this target or have explicit permission to assess it, and that this run is limited to static discovery, passive metadata, and human-led triage.</Label>
          </div>
          {error && <Alert className="border-rose-400/30 bg-rose-400/10 text-rose-100"><AlertCircle className="h-4 w-4" /><AlertTitle>Analysis could not start</AlertTitle><AlertDescription>{error}</AlertDescription></Alert>}
          <Button onClick={runAnalysis} disabled={running || !apiKey || !authorized || (targetType !== 'website' && !source.trim()) || (targetType === 'website' && !siteUrl.trim())} className="h-12 w-full rounded-xl bg-emerald-500 font-semibold text-slate-950 hover:bg-emerald-400 disabled:bg-slate-700 disabled:text-slate-400">
            <Play className="mr-2 h-4 w-4" /> {running ? (targetType === 'website' ? 'Crawling authorized pages…' : 'Cloning and analyzing…') : 'Run authorized analysis'}
          </Button>
        </CardContent>
      </Card>

      <div className="space-y-5">
        <Card className="rounded-3xl border-slate-700 bg-slate-900/70 text-slate-100">
          <CardHeader><CardTitle className="flex items-center gap-2 text-lg text-cyan-200"><ShieldCheck className="h-5 w-5" /> Safety boundary</CardTitle></CardHeader>
          <CardContent className="space-y-3 text-sm text-slate-400">
            {['Requires an administrator key and server-approved targets', 'Builds a function call graph without returning complete source files', 'Pins each website request to a validated public IP address', 'Never generates exploits, sends payloads, or confirms exploitability automatically'].map((item) => <div key={item} className="flex gap-2"><CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" /><span>{item}</span></div>)}
          </CardContent>
        </Card>
        <Alert className="rounded-3xl border-amber-400/20 bg-amber-400/5 text-amber-100"><AlertCircle className="h-4 w-4" /><AlertTitle>Local worker prerequisite</AlertTitle><AlertDescription className="text-amber-100/70">The machine running AegisTriage needs Python and Git. The optional packages in <code className="rounded bg-slate-950 px-1.5 py-0.5">pipeline/requirements.txt</code> enable full tree-sitter AST extraction; analysis still runs without them.</AlertDescription></Alert>
      </div>
    </div>
  );
};

export default TargetManager;
