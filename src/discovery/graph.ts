import { Link } from "../types.js";

export function dedupeLinks(links: Link[]) {
  const seen = new Set<string>();
  const deduped: Link[] = [];

  for (const link of links) {
    const a = `${link.localHostname}:${link.localPort}`;
    const b = `${link.remoteSystemName}:${link.remotePort}`;
    const key = [a, b].sort().join("<->");
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(link);
  }

  return deduped;
}
