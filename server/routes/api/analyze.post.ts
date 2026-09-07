import { spawn } from "node:child_process";
import { resolve } from "node:path";
import { defineHandler } from "nitro";
import { createError, readBody } from "nitro/h3";
import { crawlSite } from "../../utils/passive-crawler";

type SourceTargetType = "repository" | "local";
type TargetType = SourceTargetType | "website";

type AnalyzeRequest = {
  targetType?: TargetType;
  source?: string;
  siteUrl?: string;
  allowlist?: string[];
  authorized?: boolean;
  maxPages?: number;
  maxDepth?: number;
};

const normalizedPath = (value: string) => resolve(value).toLowerCase();

const validateTarget = async (body: AnalyzeRequest) => {
  if (!body.authorized) {
    throw createError({ statusCode: 403, statusMessage: "Confirm that you own or are authorized to assess this target." });
  }
  if (!body.targetType || (body.targetType !== "website" && !body.source?.trim())) {
    throw createError({ statusCode: 400, statusMessage: "Target type and source are required." });
  }
  if (body.targetType === "website" && !body.siteUrl?.trim()) {
    throw createError({ statusCode: 400, statusMessage: "A parent website URL is required for website-only analysis." });
  }
  const allowlist = (body.allowlist ?? []).map((item) => item.trim()).filter(Boolean);
  if (allowlist.length === 0) {
    throw createError({ statusCode: 403, statusMessage: "Add the target to the allowlist before analysis." });
  }

  if (body.targetType === "repository") {
    let repository: URL;
    try {
      repository = new URL(body.source);
    } catch {
      throw createError({ statusCode: 400, statusMessage: "Repository target must be a valid HTTPS URL." });
    }
    if (repository.protocol !== "https:" || !repository.pathname.replace(/\.git$/, "").split("/").filter(Boolean).length) {
      throw createError({ statusCode: 400, statusMessage: "Only public HTTPS repository URLs are accepted." });
    }
    const allowed = allowlist.some((entry) => {
      try {
        const allowedUrl = new URL(entry);
        return allowedUrl.protocol === "https:" && allowedUrl.hostname === repository.hostname && repository.pathname.startsWith(allowedUrl.pathname.replace(/\/$/, ""));
      } catch {
        return entry.toLowerCase() === repository.hostname.toLowerCase();
      }
    });
    if (!allowed) {
      throw createError({ statusCode: 403, statusMessage: "Repository is not covered by the allowlist." });
    }
  } else if (body.targetType === "local") {
    const sourcePath = normalizedPath(body.source!);
    const allowed = allowlist.some((entry) => {
      if (/^https?:\/\//i.test(entry)) return false;
      const root = normalizedPath(entry);
      return sourcePath === root || sourcePath.startsWith(`${root}\\`) || sourcePath.startsWith(`${root}/`);
    });
    if (!allowed) {
      throw createError({ statusCode: 403, statusMessage: "Local folder is not covered by the allowlist." });
    }
  }

  if (body.siteUrl?.trim()) {
    let site: URL;
    try {
      site = new URL(body.siteUrl);
    } catch {
      throw createError({ statusCode: 400, statusMessage: "Deployed site URL is invalid." });
    }
    const siteAllowed = allowlist.some((entry) => {
      try {
        return new URL(entry).hostname.toLowerCase() === site.hostname.toLowerCase();
      } catch {
        return entry.toLowerCase() === site.hostname.toLowerCase();
      }
    });
    if (!siteAllowed) {
      throw createError({ statusCode: 403, statusMessage: "Deployed site hostname is not covered by the allowlist." });
    }
  }
};

const runWorker = (targetType: SourceTargetType, source: string) => new Promise<Record<string, unknown>>((resolveWorker, reject) => {
  const python = process.platform === "win32" ? "python" : "python3";
  const script = resolve(process.cwd(), "pipeline", "analyze.py");
  const child = spawn(python, [script, "--target-type", targetType, "--source", source], {
    cwd: process.cwd(),
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  const maxOutput = 50 * 1024 * 1024;
  const timer = setTimeout(() => child.kill(), 5 * 60_000);

  child.stdout.on("data", (chunk) => {
    stdout += chunk.toString();
    if (stdout.length > maxOutput) child.kill();
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString();
    if (stderr.length > 2_000_000) child.kill();
  });
  child.on("error", (error) => {
    clearTimeout(timer);
    reject(error);
  });
  child.on("close", (code) => {
    clearTimeout(timer);
    if (code !== 0) {
      reject(new Error(stderr || "Python analyzer exited without results."));
      return;
    }
    try {
      resolveWorker(JSON.parse(stdout));
    } catch {
      reject(new Error("Python analyzer returned invalid JSON."));
    }
  });
});

const correlateEvidence = (analysis: Record<string, unknown>, site: Awaited<ReturnType<typeof crawlSite>>) => {
  if (!site) return [];
  const nodes = Array.isArray(analysis.nodes) ? analysis.nodes as Array<{ id: string; name: string; filePath: string; routes?: string[]; vulnerabilities?: unknown[] }> : [];
  return nodes.flatMap((node) => (node.routes ?? []).flatMap((route) => {
    const comparableRoute = route.replace(/:[^/]+/g, '').replace(/\*$/, '');
    const pages = site.crawl.pages.filter((page) => {
      try { return new URL(page.url).pathname.startsWith(comparableRoute); } catch { return false; }
    });
    const forms = site.crawl.forms.filter((form) => {
      try { return new URL(form.action, site.url).pathname.startsWith(comparableRoute); } catch { return false; }
    });
    if (!pages.length && !forms.length) return [];
    return [{ functionId: node.id, functionName: node.name, filePath: node.filePath, route, pages: pages.map((page) => page.url), forms: forms.map((form) => ({ action: form.action, method: form.method, inputs: form.inputs })), findingCount: node.vulnerabilities?.length ?? 0 }];
  }));
};

export default defineHandler(async (event) => {
  const body = await readBody<AnalyzeRequest>(event);
  await validateTarget(body);
  try {
    const sourceAnalysis = body.targetType === "website"
      ? Promise.resolve<Record<string, unknown>>({ nodes: [], edges: [], summary: { filesRoot: "website-only", files: 0, functions: 0, findings: 0, parserMode: "not applicable", rulesEvaluated: 0, coverage: [], warning: "Website-only mode inventories public pages and passive signals. Add a repository or local source folder for source-level vulnerability discovery." } })
      : runWorker(body.targetType as SourceTargetType, body.source!.trim());
    const [analysis, site] = await Promise.all([
      sourceAnalysis,
      crawlSite(body.siteUrl, body.maxPages, body.maxDepth),
    ]);
    return { analysis, site, correlations: correlateEvidence(analysis, site), target: { type: body.targetType, source: body.targetType === "website" ? body.siteUrl : body.source, analyzedAt: new Date().toISOString() } };
  } catch (error) {
    const message = error instanceof Error ? error.message : "Analysis failed.";
    throw createError({ statusCode: 500, statusMessage: message.slice(0, 500) });
  }
});
