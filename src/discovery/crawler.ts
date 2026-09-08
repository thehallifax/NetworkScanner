import pLimit from "p-limit";
import { promises as dns } from "dns";
import { MemoryStore } from "../storage/memory.js";
import { CredentialSet, Credentials, Device, DeviceId, DeviceKind, DeviceVendor, DriverResult, DriverVendor, LLDPCapability, Logger, ScanConfig } from "../types.js";
import type { SshMode } from "../drivers/ssh.js";
import { getArubaOsSDriver, getDriver } from "../drivers/index.js";
import { expandSeeds } from "./seeds.js";
import { detectVendor } from "../drivers/detect.js";

function nowISO() {
  return new Date().toISOString();
}

function deviceIdFor(facts: { chassisId?: string; hostname: string }) {
  return facts.chassisId || facts.hostname;
}

function isSwitch(capabilities?: LLDPCapability[]) {
  return capabilities?.includes("bridge") ?? false;
}

function dedupeKeyFromFacts(facts: { chassisId?: string; hostname: string }) {
  return facts.chassisId ? `chassis:${facts.chassisId}` : `host:${facts.hostname}`;
}

function linkKey(local: string, localPort: string, remote: string, remotePort: string) {
  return [local, localPort, remote, remotePort].join("|");
}

function toDeviceVendor(vendor: ScanConfig["vendor"]): DeviceVendor {
  if (vendor === "aruba") return "Aruba";
  if (vendor === "cisco") return "Cisco";
  if (vendor === "meraki") return "Meraki";
  if (vendor === "mock") return "Mock";
  return "Unknown";
}

function classifyKind(name: string, capabilities?: LLDPCapability[], platform?: Device["platform"]): DeviceKind {
  if (capabilities?.includes("bridge") || capabilities?.includes("router")) return "switch";
  if (capabilities?.includes("wlan-ap")) return "ap";
  if (capabilities?.includes("telephone")) return "phone";
  if (platform === "aruba-cx" || platform === "arubaos-s" || platform === "aruba-s" || platform === "cisco" || platform === "meraki") return "switch";

  if (/^axis-/i.test(name)) return "camera";
  if (/^poly/i.test(name) || /poly/i.test(name)) return "phone";
  if (/WAP/i.test(name) || /-AP-/i.test(name) || /-WAP-/i.test(name)) return "ap";
  if (/^SW-/i.test(name)) return "switch";
  return "unknown";
}

async function fetchDevice(
  target: string,
  credentials: Credentials,
  timeoutMs: number,
  vendor: ScanConfig["vendor"],
  vendorsAllowList?: ScanConfig["vendorsAllowList"],
  vendorCache?: Map<string, DriverVendor>,
  sshMode?: SshMode,
  debugSsh?: boolean,
  logger?: Logger,
  tcpProbeTimeoutMs?: number,
  connectTimeoutMs?: number
): Promise<DriverResult> {
  if (vendor !== "auto") {
    if (vendor === "meraki") {
      throw new Error("Meraki scans are not supported via discovery");
    }
    const driver = getDriver(vendor as DriverVendor);
    return driver.getFactsAndNeighbors(
      target,
      credentials,
      timeoutMs,
      sshMode,
      debugSsh,
      logger,
      tcpProbeTimeoutMs,
      connectTimeoutMs
    );
  }

  const cached = vendorCache?.get(target);
  if (cached) {
    const driver = getDriver(cached);
    return driver.getFactsAndNeighbors(
      target,
      credentials,
      timeoutMs,
      sshMode,
      debugSsh,
      logger,
      tcpProbeTimeoutMs,
      connectTimeoutMs
    );
  }

  const detect = await detectVendor(
    target,
    credentials as CredentialSet[],
    timeoutMs,
    vendorsAllowList,
    sshMode,
    debugSsh,
    logger,
    tcpProbeTimeoutMs,
    connectTimeoutMs
  );

  if (detect.vendor === "Unknown") {
    return {
      facts: {
        hostname: detect.facts?.hostname ?? target,
        model: detect.facts?.model,
        productName: detect.facts?.productName,
        serial: detect.facts?.serial,
        osVersion: detect.facts?.osVersion,
        uptime: detect.facts?.uptime,
        chassisId: detect.facts?.chassisId,
        macAddress: detect.facts?.macAddress,
        managementIp: detect.facts?.managementIp ?? target
      },
      neighbors: detect.neighbors ?? [],
      credentialUsed: detect.credential.id,
      vendor: "Unknown",
      platform: detect.platform ?? "unknown"
    };
  }

  const driverVendor =
    detect.platform?.startsWith("aruba") ? "aruba" : detect.platform === "cisco" ? "cisco" : undefined;
  if (!driverVendor) {
    return {
      facts: {
        hostname: detect.facts?.hostname ?? target,
        model: detect.facts?.model,
        productName: detect.facts?.productName,
        serial: detect.facts?.serial,
        osVersion: detect.facts?.osVersion,
        uptime: detect.facts?.uptime,
        chassisId: detect.facts?.chassisId,
        macAddress: detect.facts?.macAddress,
        managementIp: detect.facts?.managementIp ?? target
      },
      neighbors: detect.neighbors ?? [],
      credentialUsed: detect.credential.id,
      vendor: detect.vendor as DeviceVendor,
      platform: detect.platform ?? "unknown"
    };
  }

  const driver =
    detect.platform === "arubaos-s" || detect.platform === "aruba-s"
      ? getArubaOsSDriver()
      : getDriver(driverVendor);
  const result = await driver.getFactsAndNeighbors(
    target,
    [detect.credential],
    timeoutMs,
    sshMode,
    debugSsh,
    logger,
    tcpProbeTimeoutMs,
    connectTimeoutMs
  );
  return {
    ...result,
    credentialUsed: result.credentialUsed ?? detect.credential.id,
    vendor: (result.vendor ?? detect.vendor) as DeviceVendor,
    platform: result.platform ?? detect.platform
  };
}

async function resolveNeighborTarget(
  neighborName: string,
  strategy: ScanConfig["resolveNeighbors"],
  hostmap: Record<string, string> | undefined,
  logger?: Logger
) {
  if (!neighborName || !strategy || strategy === "none") return undefined;

  if (strategy === "dns+hostmap" && hostmap?.[neighborName]) {
    logger?.({
      ts: new Date().toISOString(),
      level: "debug",
      scope: "crawler",
      message: "Resolved neighbor via hostmap",
      meta: { neighborName, address: hostmap[neighborName] }
    });
    return hostmap[neighborName];
  }

  if (strategy.includes("dns") && neighborName.includes(".")) {
    try {
      const result = await dns.lookup(neighborName);
      logger?.({
        ts: new Date().toISOString(),
        level: "debug",
        scope: "crawler",
        message: "Resolved neighbor via DNS",
        meta: { neighborName, address: result.address }
      });
      return result.address;
    } catch {
      logger?.({
        ts: new Date().toISOString(),
        level: "debug",
        scope: "crawler",
        message: "DNS resolution failed",
        meta: { neighborName }
      });
    }
  }

  if (strategy === "dns+hostmap" && hostmap) {
    logger?.({
      ts: new Date().toISOString(),
      level: "debug",
      scope: "crawler",
      message: "Hostmap had no match",
      meta: { neighborName }
    });
  }

  return undefined;
}

export async function runDiscovery(config: ScanConfig, store: MemoryStore, logger?: Logger) {
  const concurrency = config.concurrency ?? 5;
  const retries = config.retries ?? 1;
  const timeoutMs = config.timeoutMs ?? 8000;
  const maxAttempts = config.maxAttemptsPerHost ?? 1;
  const connectTimeoutMs = config.connectTimeoutMs ?? 1000;
  const tcpProbeTimeoutMs = config.tcpProbeTimeoutMs ?? 400;
  const limit = pLimit(concurrency);
  const queue: string[] = [];
  const queued = new Set<string>();
  const visited = new Set<string>();
  const linkKeys = new Set<string>();
  const dedupe = new Map<string, DeviceId>();
  const vendorCache = new Map<string, DriverVendor>();
  const neighborStats = {
    seen: 0,
    resolved: 0,
    enqueued: 0
  };

  for (const seed of expandSeeds(config.seeds)) {
    if (queued.has(seed)) continue;
    queue.push(seed);
    queued.add(seed);
  }

  logger?.({
    ts: nowISO(),
    level: "info",
    scope: "scan",
    message: "Scan started",
    meta: { seedCount: queue.length }
  });

  const schedule = () =>
    queue.splice(0).map((target) =>
      limit(async () => {
        if (visited.has(target)) return;
        visited.add(target);
        logger?.({
          ts: nowISO(),
          level: "debug",
          scope: "crawler",
          message: "Starting device probe",
          meta: { host: target }
        });

        let result: DriverResult | null = null;
        let lastError: string | undefined;

        for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
          try {
            const allowList =
              config.vendor === "auto" && config.vendorsAllowList?.length
                ? config.vendorsAllowList
                : undefined;
            result = await fetchDevice(
              target,
              config.credentials,
              timeoutMs,
              config.vendor,
              allowList,
              vendorCache,
              config.sshMode,
              config.debugSsh,
              logger,
              tcpProbeTimeoutMs,
              connectTimeoutMs
            );
            break;
          } catch (err) {
            lastError = err instanceof Error ? err.message : String(err);
          }
        }

        if (!result) {
          const failedDevice: Device = {
            id: target,
            hostname: target,
            managementIp: target,
            state: "failed",
            lastError
          };
          store.upsertDevice(failedDevice);
          return;
        }

        const dedupeKey = dedupeKeyFromFacts(result.facts);
        const existingId = dedupe.get(dedupeKey);
        const id = existingId || deviceIdFor(result.facts);
        dedupe.set(dedupeKey, id);

        const device: Device = {
          id,
          hostname: result.facts.hostname,
          managementIp: result.facts.managementIp ?? target,
          chassisId: result.facts.chassisId,
          macAddress: result.facts.macAddress,
          model: result.facts.model,
          productName: result.facts.productName,
          serial: result.facts.serial,
          osVersion: result.facts.osVersion,
          uptime: result.facts.uptime,
          vendor: result.vendor ?? toDeviceVendor(config.vendor),
          platform: result.platform ?? (result.vendor === "Cisco" ? "cisco" : "unknown"),
          kind: classifyKind(result.facts.hostname, undefined, result.platform),
          power: result.power,
          credentialUsed: result.credentialUsed,
          state: "success",
          discoveredAt: nowISO()
        };
        store.upsertDevice(device);

        logger?.({
          ts: nowISO(),
          level: "info",
          scope: "crawler",
          message: "Device discovered",
          meta: { host: target, vendor: device.vendor, platform: device.platform, neighbors: result.neighbors.length }
        });

        if (device.platform) {
          if (device.platform.startsWith("aruba")) vendorCache.set(target, "aruba");
          if (device.platform === "cisco") vendorCache.set(target, "cisco");
        }

        for (const neighbor of result.neighbors) {
          neighborStats.seen += 1;
          const linkId = linkKey(
            device.hostname,
            neighbor.localPort,
            neighbor.remoteSystemName,
            neighbor.remotePort
          );
          if (!linkKeys.has(linkId)) {
            linkKeys.add(linkId);
            store.addLink({
              localHostname: device.hostname,
              localPort: neighbor.localPort,
              remoteSystemName: neighbor.remoteSystemName,
              remotePort: neighbor.remotePort,
              remotePortDescription: neighbor.remotePortDescription,
              remoteChassisId: neighbor.remoteChassisId,
              remoteManagementIp: neighbor.remoteManagementIp,
              protocol: neighbor.protocol,
              capabilities: neighbor.capabilities
            });
          }

          logger?.({
            ts: nowISO(),
            level: "debug",
            scope: "crawler",
            message: "Neighbor seen",
            meta: { sysName: neighbor.remoteSystemName, chassisId: neighbor.remoteChassisId }
          });

          const resolvedTarget =
            neighbor.remoteManagementIp ||
            (await resolveNeighborTarget(
              neighbor.remoteSystemName,
              config.resolveNeighbors,
              config.hostmap,
              logger
            ));
          if (resolvedTarget) {
            neighborStats.resolved += 1;
          }
          const neighborState: Device["state"] = resolvedTarget ? "pending" : "unresolved";

          const neighborId = neighbor.remoteChassisId || neighbor.remoteSystemName;
          if (!neighborId) continue;
          const neighborDevice: Device = {
            id: neighborId,
            hostname: neighbor.remoteSystemName,
            managementIp: neighbor.remoteManagementIp || resolvedTarget,
            chassisId: neighbor.remoteChassisId,
            macAddress: neighbor.remoteChassisId,
            vendor: "Unknown",
            kind: classifyKind(neighbor.remoteSystemName, neighbor.capabilities),
            state: neighborState,
            capabilities: neighbor.capabilities
          };
          store.upsertDevice(neighborDevice);

          const isEndpoint = classifyKind(neighbor.remoteSystemName, neighbor.capabilities) !== "switch";
          if (isEndpoint && !config.includeEndpoints) {
            continue;
          }
          if (isSwitch(neighbor.capabilities) && resolvedTarget) {
            if (!queued.has(resolvedTarget)) {
              queue.push(resolvedTarget);
              queued.add(resolvedTarget);
              neighborStats.enqueued += 1;
              logger?.({
                ts: nowISO(),
                level: "debug",
                scope: "crawler",
                message: "Neighbor enqueued",
                meta: { target: resolvedTarget, sysName: neighbor.remoteSystemName }
              });
            }
          }
        }
      })
    );

  while (queue.length > 0) {
    await Promise.all(schedule());
  }

  store.setMetadata({
    finishedAt: nowISO(),
    neighborsSeen: neighborStats.seen,
    neighborsResolvedToIp: neighborStats.resolved,
    neighborsEnqueued: neighborStats.enqueued
  });
}
