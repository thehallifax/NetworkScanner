import { setTimeout as delay } from "timers/promises";

type FetchFn = (input: RequestInfo, init?: RequestInit) => Promise<Response>;

const API_BASE = "https://api.meraki.com/api/v1";

function getApiKey(override?: string) {
  const key = override || process.env.MERAKI_DASHBOARD_API_KEY;
  if (!key) {
    throw new Error("Missing MERAKI_DASHBOARD_API_KEY");
  }
  return key;
}

function normalizeLinkHeader(linkHeader: string | null) {
  if (!linkHeader) return {};
  const links: Record<string, string> = {};
  const parts = linkHeader.split(",");
  for (const part of parts) {
    const match = /<([^>]+)>;\s*rel="([^"]+)"/.exec(part.trim());
    if (match) {
      links[match[2]] = match[1];
    }
  }
  return links;
}

async function requestMeraki(
  fetchFn: FetchFn,
  path: string,
  attempts = 5,
  apiKeyOverride?: string
): Promise<{ json: any; next?: string }> {
  const apiKey = getApiKey(apiKeyOverride);
  let lastError: Error | undefined;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const response = await fetchFn(`${API_BASE}${path}`, {
      headers: {
        "X-Cisco-Meraki-API-Key": apiKey,
        "Content-Type": "application/json",
        "Accept": "application/json"
      }
    });
    if (response.status === 429) {
      const retryAfter = Number(response.headers.get("Retry-After"));
      const waitMs = Number.isFinite(retryAfter) ? retryAfter * 1000 : 1000 * (attempt + 1);
      await delay(waitMs);
      continue;
    }
    if (!response.ok) {
      lastError = new Error(`Meraki API error ${response.status}`);
      if (response.status >= 500 && attempt < attempts - 1) {
        await delay(500 * (attempt + 1));
        continue;
      }
      throw lastError;
    }
    const json = await response.json();
    const links = normalizeLinkHeader(response.headers.get("Link"));
    return { json, next: links.next };
  }
  throw lastError ?? new Error("Meraki API request failed");
}

export async function fetchAllPages(fetchFn: FetchFn, path: string, apiKeyOverride?: string) {
  const all: any[] = [];
  let next: string | undefined;
  let current = path;
  do {
    const { json, next: nextLink } = await requestMeraki(fetchFn, current, 5, apiKeyOverride);
    if (Array.isArray(json)) {
      all.push(...json);
    } else {
      all.push(json);
    }
    if (nextLink) {
      const url = new URL(nextLink);
      current = url.pathname + url.search;
      next = nextLink;
    } else {
      next = undefined;
    }
  } while (next);
  return all;
}

export async function merakiGetOrganizations(fetchFn: FetchFn, apiKeyOverride?: string) {
  return fetchAllPages(fetchFn, "/organizations", apiKeyOverride);
}

export async function merakiGetNetworks(fetchFn: FetchFn, orgId: string, apiKeyOverride?: string) {
  return fetchAllPages(fetchFn, `/organizations/${orgId}/networks`, apiKeyOverride);
}

export async function merakiGetDevices(fetchFn: FetchFn, networkId: string, apiKeyOverride?: string) {
  return fetchAllPages(fetchFn, `/networks/${networkId}/devices`, apiKeyOverride);
}

export async function merakiGetLldpCdp(fetchFn: FetchFn, serial: string, apiKeyOverride?: string) {
  const { json } = await requestMeraki(fetchFn, `/devices/${serial}/lldpCdp`, 5, apiKeyOverride);
  return json;
}

export async function merakiGetPortStatuses(fetchFn: FetchFn, serial: string, apiKeyOverride?: string) {
  const { json } = await requestMeraki(fetchFn, `/devices/${serial}/switch/ports/statuses`, 5, apiKeyOverride);
  return json;
}
