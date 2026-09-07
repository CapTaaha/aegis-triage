import { AlertTriangle, FileInput, FileSearch, Globe2, ScrollText } from 'lucide-react';
import type { SiteMetadata, SourceCorrelation } from './TargetManager';
import { Badge } from './ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table';

interface SiteInventoryProps {
  site: SiteMetadata | null;
  correlations: SourceCorrelation[];
}

const SiteInventory = ({ site, correlations }: SiteInventoryProps) => {
  if (!site) return <div className="grid min-h-[420px] place-items-center p-8 text-center"><div><Globe2 className="mx-auto mb-4 h-10 w-10 text-slate-600" /><h2 className="text-xl font-semibold text-slate-200">No deployed site was crawled</h2><p className="mt-2 max-w-md text-sm text-slate-500">Add an authorized deployed URL on the Targets tab to inventory same-origin pages, forms, scripts, headers, and passive security signals.</p></div></div>;

  const { crawl } = site;
  const metrics = [
    { label: 'Pages', value: crawl.summary.pagesVisited, Icon: FileSearch },
    { label: 'Forms', value: crawl.summary.formsFound, Icon: FileInput },
    { label: 'Scripts', value: crawl.summary.scriptsFound, Icon: ScrollText },
    { label: 'Passive findings', value: crawl.summary.findings, Icon: AlertTriangle },
    { label: 'Failed pages', value: crawl.summary.failedPages, Icon: Globe2 },
  ];
  return (
    <div className="h-full overflow-auto bg-slate-950 p-4 text-slate-100 sm:p-6">
      <div className="mb-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        {metrics.map(({ label, value, Icon }) => <Card key={label} className="rounded-2xl border-slate-800 bg-slate-900/70 text-slate-100"><CardContent className="flex items-center gap-3 p-4"><div className="rounded-xl bg-emerald-400/10 p-2"><Icon className="h-4 w-4 text-emerald-300" /></div><div><p className="text-xs text-slate-500">{label}</p><p className="text-xl font-bold">{value}</p></div></CardContent></Card>)}
      </div>
      <Tabs defaultValue="findings"><TabsList className="rounded-xl bg-slate-900"><TabsTrigger value="findings">Passive findings</TabsTrigger><TabsTrigger value="correlations">Source correlations</TabsTrigger><TabsTrigger value="pages">Page inventory</TabsTrigger><TabsTrigger value="forms">Forms</TabsTrigger><TabsTrigger value="scripts">Scripts</TabsTrigger></TabsList>
        <TabsContent value="findings"><div className="grid gap-3">{crawl.findings.map((finding) => <Card key={finding.id} className="rounded-2xl border-slate-800 bg-slate-900/70 text-slate-100"><CardContent className="p-5"><div className="flex flex-wrap items-center gap-2"><Badge className={finding.severity === 'high' ? 'bg-rose-500 text-white' : finding.severity === 'medium' ? 'bg-amber-400 text-slate-950' : 'bg-cyan-500 text-slate-950'}>{finding.severity}</Badge><span className="font-semibold">{finding.category}</span><span className="font-mono text-xs text-cyan-300">{finding.cwe}</span><span className="text-xs text-slate-500">{finding.owasp}</span></div><p className="mt-3 break-all text-xs text-slate-500">{finding.url}</p><p className="mt-2 text-sm text-slate-300">{finding.evidence}</p><p className="mt-2 text-sm text-emerald-200">{finding.recommendation}</p></CardContent></Card>)}{crawl.findings.length === 0 && <div className="rounded-2xl border border-emerald-400/20 bg-emerald-400/5 p-8 text-center text-emerald-200">The passive crawl completed without identifying header or form configuration findings.</div>}</div></TabsContent>
        <TabsContent value="correlations"><div className="grid gap-3">{correlations.map((item) => <Card key={`${item.functionId}-${item.route}`} className="rounded-2xl border-slate-800 bg-slate-900/70 text-slate-100"><CardContent className="p-5"><div className="flex flex-wrap items-center gap-2"><span className="font-semibold text-emerald-300">{item.functionName}</span><Badge variant="outline" className="border-cyan-400/30 text-cyan-300">{item.route}</Badge>{item.findingCount > 0 && <Badge className="bg-rose-500">{item.findingCount} source findings</Badge>}</div><p className="mt-2 text-xs text-slate-500">{item.filePath}</p><p className="mt-3 text-sm text-slate-300">Matched {item.pages.length} crawled pages and {item.forms.length} forms.</p></CardContent></Card>)}{correlations.length === 0 && <div className="rounded-2xl border border-slate-800 p-8 text-center text-slate-500">No route-to-page correlations were found. Client-side routing or dynamic route construction may require manual mapping.</div>}</div></TabsContent>
        <TabsContent value="pages"><div className="overflow-hidden rounded-2xl border border-slate-800"><Table><TableHeader><TableRow><TableHead>Page</TableHead><TableHead>Status</TableHead><TableHead>Forms</TableHead><TableHead>Links</TableHead></TableRow></TableHeader><TableBody>{crawl.pages.map((page) => <TableRow key={page.url} className="border-slate-800"><TableCell><p className="font-medium">{page.title || 'Untitled page'}</p><p className="max-w-[700px] truncate text-xs text-slate-500">{page.url}</p></TableCell><TableCell>{page.status}</TableCell><TableCell>{page.forms.length}</TableCell><TableCell>{page.linksDiscovered}</TableCell></TableRow>)}</TableBody></Table></div></TabsContent>
        <TabsContent value="forms"><div className="grid gap-3 md:grid-cols-2">{crawl.forms.map((form, index) => <Card key={`${form.action}-${index}`} className="rounded-2xl border-slate-800 bg-slate-900/70 text-slate-100"><CardHeader><CardTitle className="break-all text-sm text-cyan-300">{form.method} {form.action}</CardTitle></CardHeader><CardContent className="flex flex-wrap gap-2">{form.inputs.map((input, inputIndex) => <Badge key={`${input.name}-${inputIndex}`} variant="outline" className="border-slate-600 text-slate-300">{input.name}: {input.type}</Badge>)}</CardContent></Card>)}</div></TabsContent>
        <TabsContent value="scripts"><div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-4">{crawl.scripts.map((script) => <p key={script} className="border-b border-slate-800 py-2 font-mono text-xs text-cyan-300 last:border-0">{script}</p>)}</div></TabsContent>
      </Tabs>
    </div>
  );
};

export default SiteInventory;
