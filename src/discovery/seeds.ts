function ipToInt(ip: string) {
  return ip.split(".").reduce((acc, oct) => (acc << 8) + Number(oct), 0) >>> 0;
}

function intToIp(int: number) {
  return [
    (int >>> 24) & 255,
    (int >>> 16) & 255,
    (int >>> 8) & 255,
    int & 255
  ].join(".");
}

export function expandSeeds(seeds: string[], maxHosts = 1024) {
  const expanded: string[] = [];

  for (const seed of seeds) {
    if (!seed.includes("/")) {
      expanded.push(seed);
      continue;
    }

    const [ip, prefixStr] = seed.split("/");
    const prefix = Number(prefixStr);
    if (!Number.isFinite(prefix) || prefix < 0 || prefix > 32) {
      expanded.push(seed);
      continue;
    }

    const hostCount = Math.pow(2, 32 - prefix);
    if (hostCount > maxHosts) {
      expanded.push(ip);
      continue;
    }

    const base = ipToInt(ip);
    for (let i = 0; i < hostCount; i += 1) {
      expanded.push(intToIp(base + i));
    }
  }

  return expanded;
}
