import * as cheerio from "cheerio";
import { XMLParser } from "fast-xml-parser";

export interface CrawledTarget {
  url: string;
  isApi: boolean;
  fields?: string[];
}

/**
 * Detects if an HTTP response is an SPA HTML shell fallback (200 OK index.html on arbitrary paths).
 */
export function isSpaHtmlFallback(resp: Response | null, bodyText: string): boolean {
  if (!resp) return false;
  const contentType = (resp.headers.get("content-type") || "").toLowerCase();
  const trimmed = (bodyText || "").trim().toLowerCase();
  if (contentType.includes("text/html") || trimmed.startsWith("<!doctype html") || trimmed.includes("<html") || trimmed.includes("<head>")) {
    return true;
  }
  return false;
}

/**
 * Extracts same-origin links and forms from HTML using Cheerio.
 * Supports React Router, Angular Router, Vue Router, Next.js links, and standard HTML forms.
 */
export function extractHtmlLinksAndForms(html: string, baseUrl: string): { links: string[]; forms: { actionUrl: string; method: "GET" | "POST"; fields: string[] }[] } {
  const base = new URL(baseUrl);
  const links = new Set<string>();
  const forms: { actionUrl: string; method: "GET" | "POST"; fields: string[] }[] = [];

  try {
    const $ = cheerio.load(html);

    // Extract links from standard HTML elements and SPA router directives
    $("a[href], [action], [routerlink], [to], [data-href], [ng-reflect-router-link]").each((_, el) => {
      const href = $(el).attr("href") || $(el).attr("action") || $(el).attr("routerlink") || $(el).attr("to") || $(el).attr("data-href") || $(el).attr("ng-reflect-router-link");
      if (!href) return;
      try {
        const u = new URL(href, baseUrl);
        if (u.hostname === base.hostname && !/\.(css|js|png|jpg|gif|ico|woff|woff2|svg|pdf|map)$/i.test(u.pathname)) {
          links.add(u.href);
        }
      } catch {}
    });

    // Extract paths embedded in inline script blocks (React Router, Angular, Vue, Next.js, SvelteKit)
    const scriptText = $("script:not([src])").map((_, el) => $(el).text()).get().join("\n");
    if (scriptText) {
      const routePatterns = [
        /["'`](\/(?:[a-zA-Z0-9_-]+\/)*[a-zA-Z0-9_-]+)["'`]/g,
        /path\s*:\s*["'`](\/[^"'`\s]+)["'`]/g,
        /<Route[^>]+path=["'`](\/[^"'`\s]+)["'`]/g,
        /routerLink=["'`](\/[^"'`\s]+)["'`]/g,
      ];
      for (const pattern of routePatterns) {
        for (const m of scriptText.matchAll(pattern)) {
          const routePath = m[1];
          if (!/\.(css|js|png|jpg|gif|ico|woff|woff2|svg|pdf|map)$/i.test(routePath) && routePath.length > 1) {
            try {
              const u = new URL(routePath, baseUrl);
              if (u.hostname === base.hostname) links.add(u.href);
            } catch {}
          }
        }
      }
    }

    // Extract forms (including React, Angular, Vue forms without explicit action)
    $("form").each((_, formEl) => {
      try {
        const rawAction = $(formEl).attr("action") || baseUrl;
        const actionUrl = new URL(rawAction, baseUrl);
        if (actionUrl.hostname !== base.hostname) return;

        const methodRaw = ($(formEl).attr("method") || "POST").toUpperCase();
        const method: "GET" | "POST" = methodRaw === "GET" ? "GET" : "POST";
        const fields: string[] = [];

        $(formEl).find("input, textarea, select").each((_, el) => {
          const name = $(el).attr("name") || $(el).attr("id") || $(el).attr("data-testid") || $(el).attr("ng-reflect-name") || $(el).attr("v-model");
          if (name && !["_csrf", "csrfmiddlewaretoken", "__VIEWSTATE", "_token"].includes(name)) {
            fields.push(name);
          }
        });

        if (fields.length > 0) {
          forms.push({ actionUrl: actionUrl.toString(), method, fields });
        }
      } catch {}
    });
  } catch {}

  return { links: [...links], forms };
}

/**
 * Parses sitemap XML using fast-xml-parser.
 */
export function parseSitemap(xml: string, baseUrl: string): string[] {
  const base = new URL(baseUrl);
  const urls: string[] = [];
  try {
    const parser = new XMLParser({ ignoreAttributes: false, cdataPropName: "__cdata" });
    const result = parser.parse(xml);
    const urlset = result?.urlset?.url || result?.sitemapindex?.sitemap || [];
    const items = Array.isArray(urlset) ? urlset : [urlset];
    for (const item of items) {
      const loc = item?.loc || item?.__cdata || "";
      if (typeof loc === "string") {
        try {
          const u = new URL(loc.trim());
          if (u.hostname === base.hostname) urls.push(u.href);
        } catch {}
      }
    }
  } catch {
    for (const m of xml.matchAll(/<loc>(https?:\/\/[^<]+)<\/loc>/gi)) {
      try {
        const u = new URL(m[1].trim());
        if (u.hostname === base.hostname) urls.push(u.href);
      } catch {}
    }
  }
  return urls.slice(0, 25);
}
