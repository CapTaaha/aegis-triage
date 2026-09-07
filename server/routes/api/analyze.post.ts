import { spawn } from "node:child_process";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { lookup } from "node:dns/promises";
import { defineHandler } from "nitro";
import { createError, readBody } from "nitro/h3";

type TargetType = "repository" | "local";

type AnalyzeRequest = {
  targetType?: TargetType;
  source?: string;
  siteUrl?: string;
  allowlist?: string[];
  authorized?: boolean;
};

const isPrivateAddress = (address: string) => {
  if (isIP(address) === 4) {
    const [a, b] = address.split(".").map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
  }
  const normalized = address.toLowerCase();
  return normalized === "::1" || normalized.startsWith("fc") || normalized.startsWith("fd") || normalized.startsWith("fe80:");
};

const normalizedPath = (value: string) => resolve(value).toLowerCase();

const validateTarget = async (body: AnalyzeRequest) => {
  if (!body.authorized) {
    throw createError({ statusCode: 403, statusMessage: "Confirm that you own or are authorized to assess this target." });
  }
  if (!body.targetType || !body.source?.trim()) {
    throw createError({ statusCode: 400, statusMessage: "Target type and source are required." });
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
  } else {
    const sourcePath = normalizedPath(body.source);
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

const inspectSite = async (rawUrl?: string) => {
  if (!rawUrl?.trim()) return null;
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw createError({ statusCode: 400, statusMessage: "Deployed site URL is invalid." });
  }
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) {
    throw createError({ statusCode: 400, statusMessage: "Passive metadata supports only credential-free HTTP(S) URLs." });
  }
  const addresses = await lookup(url.hostname, { all: true });
  if (addresses.length === 0 || addresses.some(({ address }) => isPrivateAddress(address))) {
    throw createError({ statusCode: 400, statusMessage: "Private, local, and link-local deployed-site addresses are blocked." });
  }
  const response = await fetch(url, { method: "HEAD", redirect: "manual", signal: AbortSignal.timeout(8_000) });
  const selectedHeaders = ["server", "content-type", "content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options", "referrer-policy"];
  return {
    url: url.toString(),
    status: response.status,
    headers: Object.fromEntries(selectedHeaders.map((name) => [name, response.headers.get(name)]).filter(([, value]) => value)),
    tls: url.protocol === "https:" ? "enabled" : "not_enabled",
    redirectLocation: response.headers.get("location"),
  };
};

const runWorker = (targetType: TargetType, source: string) => new Promise<Record<string, unknown>>((resolveWorker, reject) => {
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

export default defineHandler(async (event) => {
  const body = await readBody<AnalyzeRequest>(event);
  await validateTarget(body);
  try {
    const [analysis, site] = await Promise.all([
      runWorker(body.targetType!, body.source!.trim()),
      inspectSite(body.siteUrl),
    ]);
    return { analysis, site, target: { type: body.targetType, source: body.source, analyzedAt: new Date().toISOString() } };
  } catch (error) {
    const message = error instanceof Error ? error.message : "Analysis failed.";
    throw createError({ statusCode: 500, statusMessage: message.slice(0, 500) });
  }
});
