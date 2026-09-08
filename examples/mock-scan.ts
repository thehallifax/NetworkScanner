import { MemoryStore } from "../src/storage/memory.js";
import { runDiscovery } from "../src/discovery/crawler.js";
import { dedupeLinks } from "../src/discovery/graph.js";
import { ScanConfig } from "../src/types.js";

async function main() {
  const config: ScanConfig = {
    seeds: ["10.10.0.1"],
    vendor: "mock",
    credentials: [{ id: "demo", username: "demo" }],
    concurrency: 3,
    retries: 0,
    timeoutMs: 2000
  };

  const metadata = {
    id: "mock-scan",
    startedAt: new Date().toISOString(),
    seeds: config.seeds,
    vendor: config.vendor,
    neighborsSeen: 0,
    neighborsResolvedToIp: 0,
    neighborsEnqueued: 0,
    concurrency: config.concurrency ?? 3,
    retries: config.retries ?? 0,
    timeoutMs: config.timeoutMs ?? 2000
  };

  const store = new MemoryStore(metadata);
  await runDiscovery(config, store);

  const results = {
    metadata: store.getMetadata(),
    devices: store.getDevices(),
    links: dedupeLinks(store.getLinks())
  };

  console.log(JSON.stringify(results, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
