import { spawn } from "node:child_process";
import { timingSafeEqual } from "node:crypto";
import { basename, isAbsolute, relative, resolve } from "node:path";
import { defineHandler } from "nitro";
import { createError, getRequestHeaders, readBody } from "nitro/h3";
import { crawlSite } from "../../utils/passive-crawler";
import { resolvePublicAddress } from "../../utils/network-security";

type SourceTargetType = "repository" | "local";
type TargetType = SourceTargetType | "website";

type AnalyzeRequest = {
  targetType?: TargetType;
  source?: string;
  siteUrl?: string;
  authorized?: boolean;
  maxPages?: number;
  maxDepth?: number;
};

type AnalysisPolicy = {
  apiKey: string;
  workerSecret: string;
  repositories: string[];
  localRoots: string[];
  websiteHosts: string[];
};

const configuredList = (value: unknown) => typeof value === "string"
  ? value.split(/[\n,]/).map((item) => item.trim()).filter(Boolean)
  : [];

const policyFor = (event: Parameters<Parameters<typeof defineHandler>[0]>[0]): AnalysisPolicy => {
  const config = useRuntimeConfig(event) as Record<string, unknown>;
  return {
    apiKey: typeof config.analysisApiKey === "string" ? config.analysisApiKey : "",
    workerSecret: typeof config.analysisWorkerSecret === "string" ? config.analysisWorkerSecret : "",
    repositories: configuredList(config.analysisRepositories),
    localRoots: configuredList(config.analysisLocalRoots).map((root) => resolve(root)),
    websiteHosts: configuredList(config.analysisWebsiteHosts).map((host) => host.toLowerCase().replace(/\.$/, "")),
  };
};

const requireAnalysisAccess = (event: Parameters<Parameters<typeof defineHandler>[0]>[0], policy: AnalysisPolicy) => {
  if (policy.apiKey.length < 32) {
    throw createError({ statusCode: 503, statusMessage: "Analysis is disabled until an administrator configures a strong analysis API key." });
  }
  const authorization = getRequestHeaders(event).authorization ?? "";
  const supplied = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
  const expectedBuffer = Buffer.from(policy.apiKey);
  const suppliedBuffer = Buffer.from(supplied);
  if (suppliedBuffer.length !== expectedBuffer.length || !timingSafeEqual(suppliedBuffer, expectedBuffer)) {
    throw createError({ statusCode: 401, statusMessage: "Valid analysis administrator credentials are required." });
  }
};

const canonicalRepository = (value: string) => {
  const repository = new URL(value);
  if (repository.protocol !== "https:" || repository.username || repository.password || repository.search || repository.hash || (repository.port && repository.port !== "443")) {
    throw new Error("Repository target must be a credential-free HTTPS URL without query parameters or fragments.");
  }
  const segments = repository.pathname.replace(/\/+$/, "").replace(/\.git$/i, "").split("/").filter(Boolean);
  if (segments.length !== 2) throw new Error("Repository target must identify one exact organization and repository.");
  return `https://${repository.hostname.toLowerCase()}/${segments.join("/")}`;
};

const isWithinRoot = (target: string, root: string) => {
  const pathFromRoot = relative(root, target);
  return pathFromRoot === "" || (!pathFromRoot.startsWith("..") && !isAbsolute(pathFromRoot));
};

const validateTarget = async (body: AnalyzeRequest, policy: AnalysisPolicy) => {
  if (!body.authorized) {
    throw createError({ statusCode: 403, statusMessage: "Confirm that you own or are authorized to assess this target." });
  }
  if (!body.targetType || (body.targetType !== "website" && !body.source?.trim())) {
    throw createError({ statusCode: 400, statusMessage: "Target type and source are required." });
  }
  if (body.targetType === "website" && !body.siteUrl?.trim()) {
    throw createError({ statusCode: 400, statusMessage: "A parent website URL is required for website-only analysis." });
  }

  let allowedLocalRoot: string | undefined;
  if (body.targetType === "repository") {
    let requested: string;
    try {
      requested = canonicalRepository(body.source!);
    } catch (error) {
      throw createError({ statusCode: 400, statusMessage: error instanceof Error ? error.message : "Repository target is invalid." });
    }
    const approved = policy.repositories.some((entry) => {
      try { return canonicalRepository(entry) === requested; } catch { return false; }
    });
    if (!approved) throw createError({ statusCode: 403, statusMessage: "Repository is not approved by the server administrator." });
    await resolvePublicAddress(new URL(requested).hostname);
  } else if (body.targetType === "local") {
    const sourcePath = resolve(body.source!);
    allowedLocalRoot = policy.localRoots.find((root) => isWithinRoot(sourcePath, root));
    if (!allowedLocalRoot) throw createError({ statusCode: 403, statusMessage: "Local analysis is disabled for this folder." });
  }

  if (body.siteUrl?.trim()) {
    let site: URL;
    try {
      site = new URL(body.siteUrl);
    } catch {
      throw createError({ statusCode: 400, statusMessage: "Deployed site URL is invalid." });
    }
    const hostname = site.hostname.toLowerCase().replace(/\.$/, "");
    if (!policy.websiteHosts.includes(hostname)) {
      throw createError({ statusCode: 403, statusMessage: "Website hostname is not approved by the server administrator." });
    }
  }
  return { allowedLocalRoot };
};

const runLocalWorker = (targetType: SourceTargetType, source: string, allowedLocalRoot?: string) => new Promise<Record<string, unknown>>((resolveWorker, reject) => {
  const python = process.platform === "win32" ? "python" : "python3";
  const script = resolve(process.cwd(), "pipeline", "analyze.py");
  const args = [script, "--target-type", targetType, "--source", source];
  if (targetType === "local" && allowedLocalRoot) args.push("--allowed-root", allowedLocalRoot);
  const child = spawn(python, args, {
    cwd: process.cwd(),
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  const maxOutput = 10 * 1024 * 1024;
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

const runVercelWorker = async (source: string, workerSecret: string) => {
  const deploymentHost = process.env.VERCEL_URL;
  if (!deploymentHost || workerSecret.length < 32) {
    throw new Error("The Vercel analysis worker is not configured.");
  }
  const response = await fetch(`https://${deploymentHost}/api/analyzer`, {
    method: "POST",
    redirect: "error",
    signal: AbortSignal.timeout(240_000),
    headers: {
      "Content-Type": "application/json",
      "X-Analysis-Worker-Secret": workerSecret,
    },
    body: JSON.stringify({ targetType: "repository", source }),
  });
  const contentLength = Number(response.headers.get("content-length") ?? 0);
  if (contentLength > 10 * 1024 * 1024) throw new Error("Python analyzer returned too much data.");
  const payload = await response.json().catch(() => null) as Record<string, unknown> | null;
  if (!response.ok || !payload) {
    const workerError = typeof payload?.error === "string" ? payload.error : "Vercel Python analyzer failed.";
    throw new Error(workerError);
  }
  return payload;
};

const runWorker = (targetType: SourceTargetType, source: string, allowedLocalRoot: string | undefined, workerSecret: string) => {
  if (!process.env.VERCEL) return runLocalWorker(targetType, source, allowedLocalRoot);
  if (targetType === "local") throw new Error("Local-folder analysis is unavailable on Vercel. Use an approved repository target.");
  return runVercelWorker(source, workerSecret);
};

const correlateEvidence = (analysis: Record<string, unknown>, site: Awaited<ReturnType<typeof crawlSite>>) => {
  if (!site) return [];
  const nodes = Array.isArray(analysis.nodes) ? analysis.nodes as Array<{ id: string; name: string; filePath: string; routes?: string[]; vulnerabilities?: unknown[] }> : [];
  return nodes.flatMap((node) => (node.routes ?? []).flatMap((route) => {
    const comparableRoute = route.replace(/:[^/]+/g, "").replace(/\*$/, "");
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
  const policy = policyFor(event);
  requireAnalysisAccess(event, policy);
  const body = await readBody<AnalyzeRequest>(event);
  const { allowedLocalRoot } = await validateTarget(body, policy);
  try {
    const sourceAnalysis = body.targetType === "website"
      ? Promise.resolve<Record<string, unknown>>({ nodes: [], edges: [], summary: { filesRoot: "website-only", files: 0, functions: 0, findings: 0, parserMode: "not applicable", rulesEvaluated: 0, coverage: [], warning: "Website-only mode inventories approved public pages and passive signals." } })
      : runWorker(body.targetType as SourceTargetType, body.source!.trim(), allowedLocalRoot, policy.workerSecret);
    const [analysis, site] = await Promise.all([
      sourceAnalysis,
      crawlSite(body.siteUrl, body.maxPages, body.maxDepth),
    ]);
    const targetSource = body.targetType === "local" ? basename(resolve(body.source!)) : body.targetType === "website" ? body.siteUrl : body.source;
    return { analysis, site, correlations: correlateEvidence(analysis, site), target: { type: body.targetType, source: targetSource, analyzedAt: new Date().toISOString() } };
  } catch (error) {
    const message = error instanceof Error ? error.message : "Analysis failed.";
    throw createError({ statusCode: 500, statusMessage: message.slice(0, 500) });
  }
});
