import { load } from "cheerio";
import { Agent, fetch } from "undici";
import { resolvePublicAddress } from "./network-security";

export type CrawlPage = {
  url: string;
  status: number;
  title: string;
  contentType: string;
  forms: Array<{ action: string; method: string; inputs: Array<{ name: string; type: string }> }>;
  scripts: string[];
  linksDiscovered: number;
};

export type PassiveFinding = {
  id: string;
  category: string;
  cwe: string;
  owasp: string;
  severity: "low" | "medium" | "high";
  url: string;
  evidence: string;
  recommendation: string;
};

type PinnedResponse = { status: number; ok: boolean; headers: Headers; text: string };

const fetchPublicPage = async (url: URL, accept: string, timeout: number, maxBytes: number): Promise<PinnedResponse> => {
  const resolved = await resolvePublicAddress(url.hostname);
  const dispatcher = new Agent({
    connect: {
      lookup: (hostname, _options, callback) => {
        if (hostname.toLowerCase().replace(/\.$/, "") !== url.hostname.toLowerCase().replace(/\.$/, "")) {
          callback(new Error("Unexpected outbound hostname."), "", 4);
          return;
        }
        callback(null, resolved.address, resolved.family);
      },
    },
  });

  try {
    const response = await fetch(url, {
      dispatcher,
      redirect: "manual",
      signal: AbortSignal.timeout(timeout),
      headers: { "User-Agent": "AegisTriage-PassiveCrawler/1.0", Accept: accept },
    });
    const declaredLength = Number(response.headers.get("content-length") ?? 0);
    if (declaredLength > maxBytes) {
      await response.body?.cancel();
      return { status: response.status, ok: response.ok, headers: response.headers as unknown as Headers, text: "" };
    }

    const reader = response.body?.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    while (reader) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        return { status: response.status, ok: response.ok, headers: response.headers as unknown as Headers, text: "" };
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return { status: response.status, ok: response.ok, headers: response.headers as unknown as Headers, text: new TextDecoder().decode(bytes) };
  } finally {
    await dispatcher.close();
  }
};

const normalizePageUrl = (raw: string, base: URL) => {
  try {
    const candidate = new URL(raw, base);
    if (candidate.origin !== base.origin || !["http:", "https:"].includes(candidate.protocol)) return null;
    candidate.hash = "";
    for (const key of [...candidate.searchParams.keys()]) candidate.searchParams.set(key, "");
    return candidate.toString();
  } catch {
    return null;
  }
};

const passiveFinding = (category: string, cwe: string, owasp: string, severity: PassiveFinding["severity"], url: string, evidence: string, recommendation: string): PassiveFinding => ({
  id: `${category}:${url}:${evidence}`,
  category,
  cwe,
  owasp,
  severity,
  url,
  evidence,
  recommendation,
});

const inspectHeaders = (url: URL, headers: Headers) => {
  const findings: PassiveFinding[] = [];
  if (!headers.get("content-security-policy")) findings.push(passiveFinding("Missing Content Security Policy", "CWE-693", "A05:2021 Security Misconfiguration", "medium", url.toString(), "Content-Security-Policy header was not observed.", "Define a restrictive, application-specific CSP and verify it does not rely on unsafe-inline or unsafe-eval."));
  if (url.protocol === "https:" && !headers.get("strict-transport-security")) findings.push(passiveFinding("Missing HSTS", "CWE-319", "A02:2021 Cryptographic Failures", "medium", url.toString(), "Strict-Transport-Security header was not observed.", "Enable HSTS after confirming all application subresources are available over HTTPS."));
  if (!headers.get("x-content-type-options")) findings.push(passiveFinding("MIME sniffing protection absent", "CWE-16", "A05:2021 Security Misconfiguration", "low", url.toString(), "X-Content-Type-Options header was not observed.", "Set X-Content-Type-Options: nosniff."));
  if (!headers.get("x-frame-options") && !headers.get("content-security-policy")?.includes("frame-ancestors")) findings.push(passiveFinding("Clickjacking protection absent", "CWE-1021", "A05:2021 Security Misconfiguration", "low", url.toString(), "Neither X-Frame-Options nor CSP frame-ancestors was observed.", "Restrict framing with CSP frame-ancestors or X-Frame-Options."));
  const cors = headers.get("access-control-allow-origin");
  if (cors === "*") findings.push(passiveFinding("Permissive CORS", "CWE-942", "A05:2021 Security Misconfiguration", "medium", url.toString(), "Access-Control-Allow-Origin is wildcard.", "Use a narrow allowlist and avoid credentialed cross-origin access."));
  return findings;
};

const robotsDisallows = async (origin: URL) => {
  try {
    const response = await fetchPublicPage(new URL("/robots.txt", origin), "text/plain", 8_000, 512_000);
    if (!response.ok) return [];
    let applies = false;
    const disallowed: string[] = [];
    for (const rawLine of response.text.split(/\r?\n/)) {
      const line = rawLine.split("#")[0].trim();
      const [rawKey, ...rest] = line.split(":");
      const key = rawKey?.trim().toLowerCase();
      const value = rest.join(":").trim();
      if (key === "user-agent") applies = value === "*";
      if (applies && key === "disallow" && value) disallowed.push(value);
    }
    return disallowed;
  } catch {
    return [];
  }
};

export const crawlSite = async (rawUrl?: string, maxPages = 60, maxDepth = 3) => {
  if (!rawUrl?.trim()) return null;
  const root = new URL(rawUrl);
  if (!["http:", "https:"].includes(root.protocol) || root.username || root.password) throw new Error("Passive crawling supports only credential-free HTTP(S) URLs.");
  await resolvePublicAddress(root.hostname);

  const limit = Math.min(Math.max(maxPages, 1), 200);
  const depthLimit = Math.min(Math.max(maxDepth, 0), 5);
  const disallowed = await robotsDisallows(root);
  const queue: Array<{ url: string; depth: number }> = [{ url: root.toString(), depth: 0 }];
  const visited = new Set<string>();
  const pages: CrawlPage[] = [];
  const findings: PassiveFinding[] = [];
  const allForms: CrawlPage["forms"] = [];
  const allScripts = new Set<string>();
  let skippedByRobots = 0;
  let failedPages = 0;
  let rootHeaders: Record<string, string> = {};
  let rootStatus = 0;

  while (queue.length && visited.size < limit) {
    const current = queue.shift()!;
    const pageUrl = new URL(current.url);
    if (visited.has(pageUrl.toString())) continue;
    if (disallowed.some((path) => pageUrl.pathname.startsWith(path))) {
      skippedByRobots += 1;
      continue;
    }
    visited.add(pageUrl.toString());
    try {
      const response = await fetchPublicPage(pageUrl, "text/html,application/xhtml+xml", 12_000, 1_500_000);
      const location = response.headers.get("location");
      if (response.status >= 300 && response.status < 400 && location) {
        const redirect = normalizePageUrl(location, pageUrl);
        if (redirect && current.depth <= depthLimit) queue.push({ url: redirect, depth: current.depth });
        continue;
      }
      const contentType = response.headers.get("content-type") ?? "";
      if (pages.length === 0) {
        rootStatus = response.status;
        const names = ["server", "content-type", "content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options", "referrer-policy", "access-control-allow-origin"];
        rootHeaders = Object.fromEntries(names.map((name) => [name, response.headers.get(name)]).filter((entry): entry is [string, string] => Boolean(entry[1])));
      }
      findings.push(...inspectHeaders(pageUrl, response.headers));
      if (!contentType.toLowerCase().includes("text/html") || !response.text) continue;
      const $ = load(response.text);
      const links = new Set<string>();
      $("a[href]").each((_index, element) => {
        const normalized = normalizePageUrl($(element).attr("href") ?? "", root);
        if (normalized) links.add(normalized);
      });
      const forms = $("form").map((_index, element) => {
        const action = normalizePageUrl($(element).attr("action") || pageUrl.toString(), root) ?? ($(element).attr("action") || pageUrl.toString());
        const method = ($(element).attr("method") || "GET").toUpperCase();
        const inputs = $(element).find("input, textarea, select").map((_inputIndex, input) => ({ name: $(input).attr("name") || $(input).attr("id") || "unnamed", type: ($(input).attr("type") || input.tagName || "text").toLowerCase() })).get();
        if (method === "GET" && inputs.some((input) => ["password", "email", "tel"].includes(input.type) || /pass|token|secret|email/i.test(input.name))) findings.push(passiveFinding("Sensitive form uses GET", "CWE-598", "A02:2021 Cryptographic Failures", "high", pageUrl.toString(), `Form action ${action} sends sensitive-looking fields with GET.`, "Use POST over HTTPS and ensure sensitive values are not placed in URLs or logs."));
        if (pageUrl.protocol !== "https:" && inputs.some((input) => input.type === "password")) findings.push(passiveFinding("Password form over HTTP", "CWE-319", "A02:2021 Cryptographic Failures", "high", pageUrl.toString(), "A password input was observed on a non-HTTPS page.", "Serve the entire authentication flow over HTTPS and enable HSTS."));
        try { if (new URL(action, root).origin !== root.origin) findings.push(passiveFinding("Cross-origin form action", "CWE-601", "A01:2021 Broken Access Control", "medium", pageUrl.toString(), `Form submits to ${action}.`, "Confirm the external destination is intentional and strictly allowlisted.")); } catch { /* malformed action is reported through manual review */ }
        return { action, method, inputs };
      }).get();
      const scripts = $("script[src]").map((_index, element) => new URL($(element).attr("src")!, pageUrl).toString()).get();
      scripts.forEach((script) => allScripts.add(script));
      allForms.push(...forms);
      pages.push({ url: pageUrl.toString(), status: response.status, title: $("title").first().text().trim(), contentType, forms, scripts, linksDiscovered: links.size });
      if (current.depth < depthLimit) for (const link of links) if (!visited.has(link)) queue.push({ url: link, depth: current.depth + 1 });
    } catch {
      failedPages += 1;
    }
  }

  const deduplicatedFindings = [...new Map(findings.map((finding) => [`${finding.category}:${finding.url}`, finding])).values()];
  return {
    url: root.toString(), status: rootStatus, headers: rootHeaders, tls: root.protocol === "https:" ? "enabled" : "not_enabled", redirectLocation: null,
    crawl: { pages, forms: allForms, scripts: [...allScripts], findings: deduplicatedFindings, summary: { pagesVisited: pages.length, formsFound: allForms.length, scriptsFound: allScripts.size, findings: deduplicatedFindings.length, skippedByRobots, failedPages, maxPages: limit, maxDepth: depthLimit } },
  };
};
