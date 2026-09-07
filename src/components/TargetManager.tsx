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
import { Textarea } from './ui/textarea';
import type { CallGraph } from '../data/analysis-data';

type TargetType = 'repository' | 'local';

export type SiteMetadata = {
  url: string;
  status: number;
  headers: Record<string, string>;
  tls: 'enabled' | 'not_enabled';
  redirectLocation: string | null;
};

type AnalysisResponse = {
  analysis: CallGraph & { summary?: { functions: number; findings: number; filesRoot: string } };
  site: SiteMetadata | null;
  target: { type: TargetType; source: string; analyzedAt: string };
};

interface TargetManagerProps {
  onAnalysisComplete: (result: AnalysisResponse) => void;
}

const TargetManager = ({ onAnalysisComplete }: TargetManagerProps) => {
  const [targetType, setTargetType] = useState<TargetType>('repository');
  const [source, setSource] = useState('https://github.com/juice-shop/juice-shop.git');
  const [siteUrl, setSiteUrl] = useState('https://juice-shop.herokuapp.com');
  const [allowlist, setAllowlist] = useState('https://github.com/juice-shop/juice-shop\njuice-shop.herokuapp.com');
  const [authorized, setAuthorized] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState('');

  const changeType = (value: TargetType) => {
    setTargetType(value);
    setAuthorized(false);
    if (value === 'local') {
      setSource('');
      setAllowlist('');
    } else {
      setSource('https://github.com/juice-shop/juice-shop.git');
      setAllowlist('https://github.com/juice-shop/juice-shop\njuice-shop.herokuapp.com');
    }
  };

  const runAnalysis = async () => {
    setError('');
    setRunning(true);
    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetType,
          source: source.trim(),
          siteUrl: siteUrl.trim() || undefined,
          allowlist: allowlist.split('\n').map((item) => item.trim()).filter(Boolean),
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
                <SelectContent><SelectItem value="repository">Public Git repository</SelectItem><SelectItem value="local">Local source folder</SelectItem></SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="source">{targetType === 'repository' ? 'Repository URL' : 'Absolute folder path'}</Label>
              <div className="relative">
                {targetType === 'repository' ? <GitBranch className="absolute left-3 top-3 h-4 w-4 text-slate-500" /> : <FolderSearch className="absolute left-3 top-3 h-4 w-4 text-slate-500" />}
                <Input id="source" value={source} onChange={(event) => setSource(event.target.value)} className="rounded-xl border-slate-700 bg-slate-950 pl-9" placeholder={targetType === 'repository' ? 'https://github.com/org/repo.git' : 'C:\\source\\project or /home/me/project'} />
              </div>
            </div>
          </div>
          <div className="space-y-2">
            <Label htmlFor="siteUrl">Deployed site URL <span className="text-slate-500">(optional, passive inspection only)</span></Label>
            <div className="relative"><Globe2 className="absolute left-3 top-3 h-4 w-4 text-slate-500" /><Input id="siteUrl" value={siteUrl} onChange={(event) => setSiteUrl(event.target.value)} className="rounded-xl border-slate-700 bg-slate-950 pl-9" placeholder="https://app.example.com" /></div>
          </div>
          <div className="space-y-2">
            <Label htmlFor="allowlist">Explicit allowlist <span className="text-slate-500">(one repository prefix, hostname, or local root per line)</span></Label>
            <Textarea id="allowlist" value={allowlist} onChange={(event) => setAllowlist(event.target.value)} className="min-h-24 rounded-xl border-slate-700 bg-slate-950 font-mono text-xs" placeholder="github.com&#10;C:\\authorized-projects" />
          </div>
          <div className="flex items-start gap-3 rounded-2xl border border-emerald-400/20 bg-emerald-400/5 p-4">
            <Checkbox id="authorization" checked={authorized} onCheckedChange={(checked) => setAuthorized(checked === true)} className="mt-0.5 border-emerald-400 data-[state=checked]:bg-emerald-500" />
            <Label htmlFor="authorization" className="cursor-pointer text-sm font-normal leading-5 text-slate-300">I confirm that I own this target or have explicit permission to assess it, and that this run is limited to static discovery, passive metadata, and human-led triage.</Label>
          </div>
          {error && <Alert className="border-rose-400/30 bg-rose-400/10 text-rose-100"><AlertCircle className="h-4 w-4" /><AlertTitle>Analysis could not start</AlertTitle><AlertDescription>{error}</AlertDescription></Alert>}
          <Button onClick={runAnalysis} disabled={running || !authorized || !source.trim() || !allowlist.trim()} className="h-12 w-full rounded-xl bg-emerald-500 font-semibold text-slate-950 hover:bg-emerald-400 disabled:bg-slate-700 disabled:text-slate-400">
            <Play className="mr-2 h-4 w-4" /> {running ? 'Cloning and analyzing…' : 'Run authorized analysis'}
          </Button>
        </CardContent>
      </Card>

      <div className="space-y-5">
        <Card className="rounded-3xl border-slate-700 bg-slate-900/70 text-slate-100">
          <CardHeader><CardTitle className="flex items-center gap-2 text-lg text-cyan-200"><ShieldCheck className="h-5 w-5" /> Safety boundary</CardTitle></CardHeader>
          <CardContent className="space-y-3 text-sm text-slate-400">
            {['Parses JavaScript and TypeScript source with tree-sitter', 'Builds a function call graph and applies low-cost risk heuristics', 'Collects only response headers and TLS presence from the optional site URL', 'Never generates exploits, sends payloads, or confirms exploitability automatically'].map((item) => <div key={item} className="flex gap-2"><CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" /><span>{item}</span></div>)}
          </CardContent>
        </Card>
        <Alert className="rounded-3xl border-amber-400/20 bg-amber-400/5 text-amber-100"><AlertCircle className="h-4 w-4" /><AlertTitle>Local worker prerequisite</AlertTitle><AlertDescription className="text-amber-100/70">The machine running AegisTriage needs Python, Git, and the packages listed in <code className="rounded bg-slate-950 px-1.5 py-0.5">pipeline/requirements.txt</code>. API credentials stay in server environment variables.</AlertDescription></Alert>
      </div>
    </div>
  );
};

export default TargetManager;
