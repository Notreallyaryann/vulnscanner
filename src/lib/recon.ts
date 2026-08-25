import dns from "dns";

export interface WhoisIntel {
  registrar?: string;
  registeredAt?: string;
  expiresAt?: string;
  lastChanged?: string;
  daysUntilExpiration?: number;
  isExpired?: boolean;
  status?: string[];
  nameServers?: string[];
}

export interface ReconData {
  domain: string;
  apexDomain: string;
  whois?: WhoisIntel;
  subdomains: string[];
  techStack: Array<{ name: string; category: string; version?: string }>;
  apiEndpoints: Array<{ url: string; method?: string; origin?: string }>;
  discoveredLinks: string[];
  serverInfo?: {
    serverHeader?: string;
    poweredBy?: string;
    cdnName?: string;
    ipAddresses?: string[];
    openPorts?: number[];
  };
}

/** Extract apex/root domain (e.g. "sub.example.com" -> "example.com") */
export function extractApexDomain(hostname: string): string {
  const clean = hostname.toLowerCase().trim().replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
  const parts = clean.split(".");
  if (parts.length <= 2) return clean;
  // Handle 2-part TLDs like .co.uk, .com.au, .org.in
  const doubleTlds = ["co.uk", "com.au", "net.au", "org.uk", "co.in", "net.in", "org.in", "gov.in", "co.jp"];
  const lastTwo = parts.slice(-2).join(".");
  if (doubleTlds.includes(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }
  return parts.slice(-2).join(".");
}

/** Fetch WHOIS/RDAP Intel including registrar and expiration details */
export async function fetchWhoisIntel(apexDomain: string): Promise<WhoisIntel | undefined> {
  try {
    const res = await fetch(`https://rdap.org/domain/${apexDomain}`, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(7000),
    });

    if (!res.ok) return undefined;
    const data = (await res.json()) as any;

    const events: Array<{ eventAction: string; eventDate: string }> = data.events || [];
    const regEvent = events.find((e) => e.eventAction === "registration");
    const expEvent = events.find((e) => e.eventAction === "expiration");
    const lastChgEvent = events.find((e) => e.eventAction === "last changed");

    let registrar: string | undefined = undefined;
    if (data.entities && Array.isArray(data.entities)) {
      for (const ent of data.entities) {
        if (ent.roles && ent.roles.includes("registrar")) {
          if (ent.vcardArray && Array.isArray(ent.vcardArray[1])) {
            const fn = ent.vcardArray[1].find((item: any) => item[0] === "fn");
            if (fn && fn[3]) {
              registrar = String(fn[3]);
              break;
            }
          }
          if (!registrar && ent.handle) {
            registrar = String(ent.handle);
          }
        }
      }
    }

    const expiresAt = expEvent?.eventDate;
    let daysUntilExpiration: number | undefined = undefined;
    let isExpired: boolean | undefined = undefined;

    if (expiresAt) {
      const expDate = new Date(expiresAt);
      const diffMs = expDate.getTime() - Date.now();
      daysUntilExpiration = Math.ceil(diffMs / (1000 * 60 * 60 * 24));
      isExpired = daysUntilExpiration <= 0;
    }

    const nameServers: string[] = [];
    if (data.nameservers && Array.isArray(data.nameservers)) {
      for (const ns of data.nameservers) {
        if (ns.ldhName) nameServers.push(ns.ldhName);
      }
    }

    return {
      registrar,
      registeredAt: regEvent?.eventDate,
      expiresAt,
      lastChanged: lastChgEvent?.eventDate,
      daysUntilExpiration,
      isExpired,
      status: Array.isArray(data.status) ? data.status : undefined,
      nameServers: nameServers.length > 0 ? nameServers : undefined,
    };
  } catch {
    return undefined;
  }
}

/** Fetch subdomains using crt.sh & crt.name CT logs search API */
export async function fetchCrtSubdomains(apexDomain: string): Promise<string[]> {
  const subdomains = new Set<string>();

  // 1. Primary: crt.sh JSON endpoint
  try {
    const res = await fetch(`https://crt.sh/?q=${encodeURIComponent(apexDomain)}&output=json`, {
      signal: AbortSignal.timeout(8000),
    });
    if (res.ok) {
      const data = (await res.json()) as Array<{ common_name?: string; name_value?: string }>;
      for (const item of data) {
        if (item.name_value) {
          item.name_value.split("\n").forEach((s) => {
            const clean = s.trim().toLowerCase().replace(/^\*\./, "");
            if (clean && clean.endsWith(apexDomain)) subdomains.add(clean);
          });
        }
        if (item.common_name) {
          const clean = item.common_name.trim().toLowerCase().replace(/^\*\./, "");
          if (clean && clean.endsWith(apexDomain)) subdomains.add(clean);
        }
      }
    }
  } catch {
    // crt.sh timeout/error
  }

  // 2. Secondary fallback: crt.name endpoint
  if (subdomains.size === 0) {
    try {
      const res = await fetch(`https://crt.name/v1/search?apex=${encodeURIComponent(apexDomain)}`, {
        signal: AbortSignal.timeout(8000),
      });
      if (res.ok) {
        const text = await res.text();
        try {
          const data = JSON.parse(text);
          if (Array.isArray(data)) {
            for (const item of data) {
              const name = typeof item === "string" ? item : item.name || item.domain || item.subdomain;
              if (name && typeof name === "string") {
                const clean = name.trim().toLowerCase().replace(/^\*\./, "");
                if (clean.endsWith(apexDomain)) subdomains.add(clean);
              }
            }
          }
        } catch {
          // If non-JSON text output
          const matches = text.match(new RegExp(`[a-zA-Z0-9._-]+\\.${apexDomain.replace(".", "\\.")}`, "g"));
          if (matches) {
            matches.forEach((m) => subdomains.add(m.toLowerCase()));
          }
        }
      }
    } catch {
      // crt.name error
    }
  }

  return Array.from(subdomains).sort();
}

/** Gather IP addresses via DNS A record resolution */
export async function resolveHostIps(hostname: string): Promise<string[]> {
  try {
    const ips = await dns.promises.resolve4(hostname);
    return ips || [];
  } catch {
    return [];
  }
}
