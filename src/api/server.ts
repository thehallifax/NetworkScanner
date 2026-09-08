import express from "express";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import Ajv from "ajv";
import { MemoryStore } from "../storage/memory.js";
import { runDiscovery } from "../discovery/crawler.js";
import { dedupeLinks } from "../discovery/graph.js";
import { collectMerakiTopology } from "../meraki/collector.js";
import { writeScanArtifacts } from "../scan/artifacts.js";
import { redactCredentials } from "../utils/redact.js";
import { LogEntry, Logger, ScanConfig, ScanMetadata } from "../types.js";

const app = express();
app.use(express.json());

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicDir = path.resolve(process.cwd(), "public");
app.use(express.static(publicDir));
const indexPath = path.resolve(publicDir, "index.html");
app.get(["/devices", "/links", "/topology"], (_req, res) => {
  res.sendFile(indexPath);
});

const schemaPath = path.resolve(process.cwd(), "schemas", "scan-request.schema.json");
const scanRequestSchema = JSON.parse(fs.readFileSync(schemaPath, "utf8"));
const ajv = new Ajv({ allErrors: true });
const validateScanRequest = ajv.compile(scanRequestSchema);

const scans = new Map<string, MemoryStore>();
const scanConfigs = new Map<string, ScanConfig>();
const scanLogs = new Map<string, LogEntry[]>();

function redactLogMessage(message: string) {
  return message
    .replace(/password\s*[:=]\s*[^\s,]+/gi, "password=***")
    .replace(/privateKey\s*[:=]\s*[^\s,]+/gi, "privateKey=***")
    .replace(/passphrase\s*[:=]\s*[^\s,]+/gi, "passphrase=***")
    .replace(/sshKeyPath\s*[:=]\s*[^\s,]+/gi, "sshKeyPath=***")
    .replace(/username\s*[:=]\s*[^\s,]+/gi, "username=***")
    .replace(/apiKey\s*[:=]\s*[^\s,]+/gi, "apiKey=***");
}

function createLogger(scanId: string, enabled: boolean): Logger {
  return (entry) => {
    if (!enabled) return;
    const buffer = scanLogs.get(scanId) || [];
    const sanitized: LogEntry = {
      ...entry,
      message: redactLogMessage(entry.message)
    };
    buffer.push(sanitized);
    if (buffer.length > 2000) {
      buffer.splice(0, buffer.length - 2000);
    }
    scanLogs.set(scanId, buffer);
  };
}

function createMetadata(config: ScanConfig, scanId?: string): ScanMetadata {
  return {
    id: scanId ?? crypto.randomUUID(),
    startedAt: new Date().toISOString(),
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

function toCsv<T extends Record<string, string | number | undefined>>(rows: T[]) {
  if (rows.length === 0) return "";
  const headers = Object.keys(rows[0]);
  const body = rows
    .map((row) => headers.map((h) => JSON.stringify(row[h] ?? "")).join(","))
    .join("\n");
  return `${headers.join(",")}\n${body}`;
}

function resolveSshConfig(payload: any): ScanConfig {
  const options = payload.options ?? {};
  const seeds = Array.isArray(payload.seedDevices)
    ? payload.seedDevices
    : Array.isArray(payload.seeds)
      ? payload.seeds
      : [];
  const credentials = Array.isArray(payload.credentials) ? payload.credentials : [];
  return {
    seeds,
    vendor: payload.vendor,
    credentials,
    vendorsAllowList: options.vendorsAllowList ?? payload.vendorsAllowList,
    resolveNeighbors: options.resolveNeighbors ?? payload.resolveNeighbors ?? "dns",
    sshMode: options.sshMode ?? payload.sshMode ?? "auto",
    debugSsh: options.debugSsh ?? payload.debugSsh ?? options.debug ?? payload.debug ?? false,
    debug: options.debug ?? payload.debug ?? false,
    hostmap: options.hostmap ?? payload.hostmap,
    includeEndpoints: options.includeEndpoints ?? payload.includeEndpoints ?? false,
    maxAttemptsPerHost: options.maxAttemptsPerHost ?? payload.maxAttemptsPerHost ?? 1,
    connectTimeoutMs: options.connectTimeoutMs ?? payload.connectTimeoutMs ?? 1000,
    tcpProbeTimeoutMs: options.tcpProbeTimeoutMs ?? payload.tcpProbeTimeoutMs ?? 400,
    timeoutMs: options.timeoutMs ?? payload.timeoutMs,
    concurrency: options.concurrency ?? payload.concurrency,
    retries: options.retries ?? payload.retries
  };
}

function startSshScan(scanId: string, payload: any) {
  const resolvedConfig = resolveSshConfig(payload);
  const metadata = createMetadata(resolvedConfig, scanId);
  const store = new MemoryStore(metadata);
  scans.set(metadata.id, store);
  scanConfigs.set(metadata.id, resolvedConfig);
  scanLogs.set(metadata.id, []);
  const logger = createLogger(metadata.id, resolvedConfig.debug ?? false);
  logger({
    ts: new Date().toISOString(),
    level: "info",
    scope: "api",
    message: "Scan request accepted",
    meta: { scanId: metadata.id }
  });

  runDiscovery(resolvedConfig, store, logger).catch((err) => {
    store.setMetadata({ finishedAt: new Date().toISOString() });
    logger({
      ts: new Date().toISOString(),
      level: "error",
      scope: "scan",
      message: err instanceof Error ? err.message : String(err)
    });
    const devices = store.getDevices();
    if (devices.length === 0) {
      store.upsertDevice({
        id: "scan-error",
        hostname: "scan-error",
        state: "failed",
        lastError: err instanceof Error ? err.message : String(err)
      });
    }
  });

  return { metadata, resolvedConfig };
}

function startMerakiScan(scanId: string, payload: any) {
  const config: ScanConfig = {
    seeds: [],
    vendor: "meraki",
    credentials: []
  };
  const metadata = createMetadata(config, scanId);
  const store = new MemoryStore(metadata);
  scans.set(metadata.id, store);
  scanConfigs.set(metadata.id, config);
  scanLogs.set(metadata.id, []);
  const loggerEnabled = payload?.options?.debug ?? payload?.debug ?? true;
  const logger = createLogger(metadata.id, Boolean(loggerEnabled));
  const log = (level: LogEntry["level"], message: string, meta?: LogEntry["meta"]) => {
    logger({
      ts: new Date().toISOString(),
      level,
      scope: "scan",
      message,
      meta
    });
  };
  logger({
    ts: new Date().toISOString(),
    level: "info",
    scope: "api",
    message: "Meraki scan request accepted",
    meta: { scanId: metadata.id }
  });

  const meraki = payload?.meraki || {};
  const emitRaw = Boolean(payload?.emitRaw);
  const merakiOptions = {
    apiKey: String(meraki.apiKey),
    orgId: meraki.orgId ? String(meraki.orgId) : undefined,
    orgName: meraki.orgName ? String(meraki.orgName) : undefined,
    networkId: meraki.networkId ? String(meraki.networkId) : undefined
  };

  collectMerakiTopology({
    ...merakiOptions,
    onLog: log
  })
    .then(({ devices, links, raw }) => {
      devices.forEach((device) => store.upsertDevice(device));
      links.forEach((link) => store.addLink(link));
      store.setMetadata({ finishedAt: new Date().toISOString() });
      if (emitRaw) {
        writeScanArtifacts(
          {
            metadata: store.getMetadata(),
            devices: store.getDevices(),
            links: dedupeLinks(store.getLinks())
          },
          { raw }
        );
      }
    })
    .catch((err) => {
      store.setMetadata({ finishedAt: new Date().toISOString() });
      logger({
        ts: new Date().toISOString(),
        level: "error",
        scope: "scan",
        message: err instanceof Error ? err.message : String(err)
      });
      const devices = store.getDevices();
      if (devices.length === 0) {
        store.upsertDevice({
          id: "scan-error",
          hostname: "scan-error",
          state: "failed",
          lastError: err instanceof Error ? err.message : String(err)
        });
      }
    });

  return { metadata, emitRaw, merakiOptions };
}

app.post("/scans", (req, res) => {
  const valid = validateScanRequest(req.body);
  if (!valid) {
    res.status(400).json({ error: "Invalid scan request", details: validateScanRequest.errors });
    return;
  }

  const scanId = crypto.randomUUID();
  if (req.body?.source === "meraki") {
    const meraki = req.body?.meraki || {};
    if (!meraki.apiKey) {
      res.status(400).json({ error: "Missing Meraki API key" });
      return;
    }
    const { metadata, emitRaw, merakiOptions } = startMerakiScan(scanId, req.body);
    res.status(202).json({
      scanId: metadata.id,
      metadata,
      config: {
        source: "meraki",
        vendor: "meraki",
        emitRaw,
        meraki: {
          apiKey: "***",
          orgId: merakiOptions.orgId,
          orgName: merakiOptions.orgName,
          networkId: merakiOptions.networkId
        }
      }
    });
    return;
  }

  const resolvedConfig = resolveSshConfig(req.body);
  if (!resolvedConfig?.seeds?.length || !Array.isArray(resolvedConfig.credentials) || !resolvedConfig.credentials.length || !resolvedConfig.vendor) {
    res.status(400).json({ error: "Missing seed devices, vendor, or credentials" });
    return;
  }
  const invalidCred = resolvedConfig.credentials.find((cred) => !cred.id || !cred.username);
  if (invalidCred) {
    res.status(400).json({ error: "Each credential requires id and username" });
    return;
  }

  const { metadata } = startSshScan(scanId, req.body);
  res.status(202).json({
    scanId: metadata.id,
    metadata,
    config: {
      ...resolvedConfig,
      credentials: redactCredentials(resolvedConfig.credentials)
    }
  });
});

app.post("/scan", (req, res) => {
  req.url = "/scans";
  app(req, res);
});

app.get("/scan/:id", (req, res) => {
  const store = scans.get(req.params.id);
  if (!store) {
    res.status(404).json({ error: "Scan not found" });
    return;
  }
  res.json({
    metadata: store.getMetadata(),
    deviceCount: store.getDevices().length,
    linkCount: store.getLinks().length
  });
});

app.get("/scans", (req, res) => {
  const list = Array.from(scans.values()).map((store) => store.getMetadata());
  res.json(list);
});

app.get("/scans/:id", (req, res) => {
  req.url = `/scan/${req.params.id}`;
  app(req, res);
});

app.get("/scan/:id/devices", (req, res) => {
  const store = scans.get(req.params.id);
  if (!store) {
    res.status(404).json({ error: "Scan not found" });
    return;
  }
  res.json(store.getDevices());
});

app.get("/scan/:id/devices/:deviceId", (req, res) => {
  const store = scans.get(req.params.id);
  if (!store) {
    res.status(404).json({ error: "Scan not found" });
    return;
  }
  const device = store.getDevices().find((item) => item.id === req.params.deviceId);
  if (!device) {
    res.status(404).json({ error: "Device not found" });
    return;
  }
  res.json(device);
});

app.get("/scans/:id/devices", (req, res) => {
  req.url = `/scan/${req.params.id}/devices`;
  app(req, res);
});

app.get("/scans/:id/devices/:deviceId", (req, res) => {
  req.url = `/scan/${req.params.id}/devices/${req.params.deviceId}`;
  app(req, res);
});

app.get("/scan/:id/links", (req, res) => {
  const store = scans.get(req.params.id);
  if (!store) {
    res.status(404).json({ error: "Scan not found" });
    return;
  }
  res.json(dedupeLinks(store.getLinks()));
});

app.get("/scans/:id/links", (req, res) => {
  req.url = `/scan/${req.params.id}/links`;
  app(req, res);
});

app.get("/scan/:id/topology", (req, res) => {
  const store = scans.get(req.params.id);
  if (!store) {
    res.status(404).json({ error: "Scan not found" });
    return;
  }
  res.json({
    nodes: store.getDevices(),
    links: dedupeLinks(store.getLinks())
  });
});

app.get("/scans/:id/topology", (req, res) => {
  req.url = `/scan/${req.params.id}/topology`;
  app(req, res);
});

app.get("/scan/:id/export/json", (req, res) => {
  const store = scans.get(req.params.id);
  if (!store) {
    res.status(404).json({ error: "Scan not found" });
    return;
  }
  res.json({
    metadata: store.getMetadata(),
    devices: store.getDevices(),
    links: dedupeLinks(store.getLinks())
  });
});

app.get("/scans/:id/export/json", (req, res) => {
  req.url = `/scan/${req.params.id}/export/json`;
  app(req, res);
});

app.get("/scan/:id/export/csv", (req, res) => {
  const store = scans.get(req.params.id);
  if (!store) {
    res.status(404).json({ error: "Scan not found" });
    return;
  }
  const type = String(req.query.type || "devices");
  if (type === "links") {
    const csv = toCsv(
      dedupeLinks(store.getLinks()).map((link) => ({
        ...link,
        capabilities: link.capabilities?.join("|")
      }))
    );
    res.type("text/csv").send(csv);
    return;
  }
  const csv = toCsv(
    store.getDevices().map((device) => ({
      ...device,
      capabilities: device.capabilities?.join("|"),
      power: device.power ? JSON.stringify(device.power) : undefined
    }))
  );
  res.type("text/csv").send(csv);
});

app.get("/scans/:id/export/csv", (req, res) => {
  req.url = `/scan/${req.params.id}/export/csv`;
  app(req, res);
});

app.get("/scans/:id/export/csv-links", (req, res) => {
  req.url = `/scan/${req.params.id}/export/csv?type=links`;
  app(req, res);
});

app.get("/scans/:id/logs", (req, res) => {
  const buffer = scanLogs.get(req.params.id) || [];
  const since = Number(req.query.since || 0);
  const limit = Math.min(Number(req.query.limit || 200), 1000);
  const filtered = buffer.filter((entry) => Date.parse(entry.ts) > since).slice(0, limit);
  const nextSince = filtered.length ? Date.parse(filtered[filtered.length - 1].ts) : since;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.status(200).json({ logs: filtered, nextSince });
});

app.post("/scans/:id/logs/clear", (req, res) => {
  if (!scanLogs.has(req.params.id)) {
    res.status(404).json({ error: "Scan not found" });
    return;
  }
  scanLogs.set(req.params.id, []);
  res.json({ ok: true });
});

app.post("/scan/:id/devices/:deviceId/config", async (req, res) => {
  const store = scans.get(req.params.id);
  const config = scanConfigs.get(req.params.id);
  if (!store) {
    res.status(404).json({ error: "Scan not found" });
    return;
  }
  if (!config) {
    res.status(404).json({ error: "Scan config not found" });
    return;
  }
  if (config.vendor === "meraki") {
    res.status(400).json({ error: "Config retrieval is only supported for SSH scans" });
    return;
  }
  const device = store.getDevices().find((item) => item.id === req.params.deviceId);
  if (!device) {
    res.status(404).json({ error: "Device not found" });
    return;
  }

  const mode = String(req.body?.mode || "running");
  const redact = req.body?.redact !== false;
  const platform = device.platform;
  const useShell = platform === "arubaos-s";
  const command = mode === "startup"
    ? useShell
      ? "no page\nshow startup-config"
      : "show startup-config"
    : useShell
      ? "no page\nshow running-config"
      : "show running-config";
  const host = device.managementIp || device.hostname;
  if (!host) {
    res.status(400).json({ error: "Device has no management address" });
    return;
  }

  const { connectWithFallback } = await import("../drivers/ssh.js");
  const { redactConfig } = await import("../utils/redactConfig.js");
  const credentials = config.credentials;
  const timeoutMs = config.timeoutMs ?? 8000;
  const sshMode = config.sshMode ?? "auto";
  const debugSsh = config.debugSsh ?? config.debug ?? false;
  const tcpProbeTimeoutMs = config.tcpProbeTimeoutMs ?? 400;
  const connectTimeoutMs = config.connectTimeoutMs ?? 1000;

  try {
    const result = await connectWithFallback(
      host,
      [command],
      credentials,
      timeoutMs,
      sshMode,
      debugSsh,
      undefined,
      tcpProbeTimeoutMs,
      connectTimeoutMs,
      useShell
    );
    const output = redact ? redactConfig(result.outputs[0]) : result.outputs[0];
    res.json({ output, redact, mode });
  } catch (err) {
    res.status(500).json({ error: err instanceof Error ? err.message : String(err) });
  }
});

app.post("/scans/:id/devices/:deviceId/config", (req, res) => {
  req.url = `/scan/${req.params.id}/devices/${req.params.deviceId}/config`;
  app(req, res);
});

const port = Number(process.env.PORT || 3000);
const host = process.env.HOST || "127.0.0.1";
app.listen(port, host, () => {
  console.log(`LLDP mapper API listening on http://${host}:${port}`);
});
