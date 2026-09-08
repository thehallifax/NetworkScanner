import crypto from "crypto";
import { MemoryStore } from "../storage/memory.js";
import { runDiscovery } from "../discovery/crawler.js";
import { dedupeLinks } from "../discovery/graph.js";
import { collectMerakiTopology } from "../meraki/collector.js";
import { writeScanArtifacts, type ArtifactPaths } from "./artifacts.js";
import { Logger, ScanConfig, ScanMetadata, ScanResults } from "../types.js";

type FetchFn = (input: RequestInfo, init?: RequestInit) => Promise<Response>;

export type ScanSource = "discovery" | "meraki";

export type ScanRunOptions = {
  source: ScanSource;
  config?: ScanConfig;
  emitRaw?: boolean;
  fetchFn?: FetchFn;
  meraki?: {
    apiKey?: string;
    orgId?: string;
    orgName?: string;
    networkId?: string;
  };
  outputDir?: string;
  logger?: Logger;
  scanId?: string;
  now?: () => Date;
};

export type ScanSummary = {
  metadata: ScanMetadata;
  deviceCount: number;
  linkCount: number;
};

export type ScanRunResult = {
  results: ScanResults;
  summary: ScanSummary;
  artifacts: ArtifactPaths;
};

function buildMetadata(config: ScanConfig, now: () => Date, scanId?: string): ScanMetadata {
  return {
    id: scanId ?? crypto.randomUUID(),
    startedAt: now().toISOString(),
    finishedAt: undefined,
    seeds: config.seeds,
    vendor: config.vendor,
    neighborsSeen: 0,
    neighborsResolvedToIp: 0,
    neighborsEnqueued: 0,
    concurrency: config.concurrency ?? 5,
    retries: config.retries ?? 1,
    timeoutMs: config.timeoutMs ?? 8000
  };
}

export async function runScan(options: ScanRunOptions): Promise<ScanRunResult> {
  const now = options.now ?? (() => new Date());
  if (options.source === "meraki") {
    const config: ScanConfig = {
      seeds: [],
      vendor: "meraki",
      credentials: []
    };
    const metadata = buildMetadata(config, now, options.scanId);
    const { devices, links, raw } = await collectMerakiTopology({
      fetchFn: options.fetchFn,
      apiKey: options.meraki?.apiKey,
      orgId: options.meraki?.orgId,
      orgName: options.meraki?.orgName,
      networkId: options.meraki?.networkId
    });
    const results: ScanResults = {
      metadata: { ...metadata, finishedAt: now().toISOString() },
      devices,
      links: dedupeLinks(links)
    };
    const artifacts = writeScanArtifacts(results, { outputDir: options.outputDir, raw: options.emitRaw ? raw : undefined });
    const summary: ScanSummary = {
      metadata: results.metadata,
      deviceCount: results.devices.length,
      linkCount: results.links.length
    };
    return { results, summary, artifacts };
  }

  if (!options.config) {
    throw new Error("Discovery scans require config");
  }
  const metadata = buildMetadata(options.config, now, options.scanId);
  const store = new MemoryStore(metadata);
  await runDiscovery(options.config, store, options.logger);
  store.setMetadata({ finishedAt: now().toISOString() });
  const results: ScanResults = {
    metadata: store.getMetadata(),
    devices: store.getDevices(),
    links: dedupeLinks(store.getLinks())
  };
  const artifacts = writeScanArtifacts(results, { outputDir: options.outputDir });
  const summary: ScanSummary = {
    metadata: results.metadata,
    deviceCount: results.devices.length,
    linkCount: results.links.length
  };
  return { results, summary, artifacts };
}
