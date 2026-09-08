import { CredentialSet, DeviceDriver, DriverResult, LLDPCapability, Logger } from "../types.js";
import { connectWithFallback, type SshMode } from "./ssh.js";

export function parseCiscoFacts(output: string) {
  const hostname =
    /(.+)\s+uptime is/i.exec(output)?.[1]?.trim()
    || /System Name\s*:\s*(.+)/i.exec(output)?.[1]?.trim();
  const uptime = /uptime is\s+(.+)/i.exec(output)?.[1]?.trim();
  const model = /[Mm]odel [Nn]umber\s*:\s*(.+)/.exec(output)?.[1]?.trim()
    || /[Mm]odel number\s*:\s*(.+)/.exec(output)?.[1]?.trim()
    || /cisco\s+(\S+)\s+\(/i.exec(output)?.[1]?.trim();
  const serial =
    /Processor board ID\s+(\S+)/i.exec(output)?.[1]?.trim()
    || /System serial number\s*:\s*(.+)/i.exec(output)?.[1]?.trim();
  const chassisMacRaw = /[Bb]ase [Ee]thernet [Mm]AC [Aa]ddress\s*:\s*([0-9A-Fa-f:.]+)/.exec(output)?.[1]?.trim();
  const chassisMac = normalizeMac(chassisMacRaw);
  const osVersion = /Version\s+([0-9.()A-Za-z]+)/.exec(output)?.[1]?.trim();

  return {
    hostname: hostname || "unknown",
    model,
    productName: model,
    serial,
    osVersion,
    uptime,
    chassisId: chassisMac || serial,
    macAddress: chassisMac
  };
}

function parseCapabilities(raw: string): LLDPCapability[] {
  const caps: LLDPCapability[] = [];
  if (/bridge/i.test(raw)) caps.push("bridge");
  if (/router/i.test(raw)) caps.push("router");
  if (/wlan/i.test(raw)) caps.push("wlan-ap");
  if (/telephone/i.test(raw)) caps.push("telephone");
  if (caps.length === 0) caps.push("other");
  return caps;
}

export function parseCiscoLLDP(output: string) {
  const neighbors: DriverResult["neighbors"] = [];
  if (isCliError(output)) return neighbors;
  const blocks = output.split(/\n\s*-------------------------\s*\n/);
  for (const block of blocks) {
    const localPort = /Local Intf\s*:\s*(.+)/i.exec(block)?.[1]?.trim();
    const remoteSystemName = /System Name\s*:\s*(.+)/i.exec(block)?.[1]?.trim();
    const remotePort = /Port id\s*:\s*(.+)/i.exec(block)?.[1]?.trim();
    const chassis = /Chassis id\s*:\s*(.+)/i.exec(block)?.[1]?.trim();
    const chassisId = normalizeMac(chassis);
    let mgmt = /Management Addresses\s*:\s*([\s\S]+)/i.exec(block)?.[1]?.split(/\s+/)?.[0]?.trim();
    if (mgmt) {
      mgmt = mgmt.replace(/^IP:\s*/i, "");
    }
    const capsRaw = /System Capabilities\s*:\s*(.+)/i.exec(block)?.[1]?.trim() || "";

    if (!localPort || !remoteSystemName || !remotePort) continue;
    neighbors.push({
      localPort,
      remoteSystemName,
      remotePort,
      remoteChassisId: chassisId,
      remoteManagementIp: mgmt,
      capabilities: parseCapabilities(capsRaw),
      protocol: "lldp"
    });
  }
  return neighbors;
}

function normalizeMac(value?: string) {
  if (!value) return undefined;
  const trimmed = value.trim();
  const hex = trimmed.replace(/[^a-fA-F0-9]/g, "");
  if (hex.length !== 12) return trimmed;
  return hex.match(/.{1,2}/g)?.join(":").toLowerCase();
}

function parseCiscoArp(output: string) {
  const table: Record<string, string> = {};
  const lines = output.split("\n");
  for (const line of lines) {
    const match = /(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9A-Fa-f.:-]{11,})/i.exec(line);
    if (!match) continue;
    const ip = match[1];
    const mac = normalizeMac(match[2]);
    if (mac) table[mac] = ip;
  }
  return Object.keys(table).length ? table : undefined;
}

function parseCapabilityLetters(raw: string) {
  const caps: LLDPCapability[] = [];
  if (/[Bb]/.test(raw)) caps.push("bridge");
  if (/[Rr]/.test(raw)) caps.push("router");
  if (/[Ww]/.test(raw)) caps.push("wlan-ap");
  if (/[Tt]/.test(raw)) caps.push("telephone");
  if (caps.length === 0) caps.push("other");
  return caps;
}

export function parseCiscoLLDPSummary(output: string) {
  const neighbors: DriverResult["neighbors"] = [];
  if (isCliError(output)) return neighbors;
  const lines = output.split("\n");
  for (const line of lines) {
    if (!line.trim() || /Device ID/i.test(line) || /----/.test(line)) continue;
    const match = /^(.+?)\s+([A-Za-z]+[0-9\/.]+)\s+(\d+)\s+([A-Za-z]+)\s+(.+)$/.exec(line);
    if (!match) continue;
    const [, deviceId, localPort, _hold, capsRaw, portId] = match;
    const chassisId = normalizeMac(deviceId);
    neighbors.push({
      localPort: localPort.trim(),
      remoteSystemName: deviceId.trim(),
      remotePort: portId.trim(),
      remoteChassisId: chassisId,
      capabilities: parseCapabilityLetters(capsRaw),
      protocol: "lldp"
    });
  }
  return neighbors;
}

export function parseCiscoCDP(output: string) {
  const neighbors: DriverResult["neighbors"] = [];
  if (isCliError(output)) return neighbors;
  const lines = output.split("\n");
  for (const line of lines) {
    if (!line.trim() || /Device ID/i.test(line) || /----/.test(line)) continue;
    const match = /^(.+?)\s+([A-Za-z]+[0-9\/.]+)\s+(\d+)\s+([A-Za-z]+)\s+(\S+)\s+(.+)$/.exec(line);
    if (!match) continue;
    const [, deviceId, localPort, _hold, capsRaw, _platform, portId] = match;
    neighbors.push({
      localPort: localPort.trim(),
      remoteSystemName: deviceId.trim(),
      remotePort: portId.trim(),
      capabilities: parseCapabilityLetters(capsRaw),
      protocol: "cdp"
    });
  }
  return neighbors;
}

export const ciscoDriver: DeviceDriver = {
  name: "cisco",
  async getFactsAndNeighbors(
    target,
    credentials,
    timeoutMs,
    sshMode: SshMode | undefined,
    debugSsh,
    logger,
    tcpProbeTimeoutMs,
    connectTimeoutMs
  ) {
    const { outputs, credentialId } = await connectWithFallback(
      target,
      ["show version", "show lldp neighbors"],
      credentials,
      timeoutMs,
      sshMode,
      debugSsh,
      logger,
      tcpProbeTimeoutMs,
      connectTimeoutMs
    );
    const [sysOutput, lldpOutput] = outputs;
    const facts = parseCiscoFacts(sysOutput);
    if (isCliError(lldpOutput)) {
      throw new Error(`LLDP command failed: ${lldpOutput.trim()}`);
    }
    let neighbors = parseCiscoLLDPSummary(lldpOutput);
    let cmdUsed = "show lldp neighbors";

    if (neighbors.length === 0) {
      const lldpAlt = await connectWithFallback(
        target,
        ["show lldp nei"],
        credentials,
        timeoutMs,
        sshMode,
        debugSsh,
        logger,
        tcpProbeTimeoutMs,
        connectTimeoutMs
      );
      if (isCliError(lldpAlt.outputs[0])) {
        throw new Error(`LLDP command failed: ${lldpAlt.outputs[0].trim()}`);
      }
      neighbors = parseCiscoLLDPSummary(lldpAlt.outputs[0]);
      cmdUsed = "show lldp nei";
    }

    if (neighbors.length === 0) {
      const lldpDetail = await connectWithFallback(
        target,
        ["show lldp neighbors detail"],
        credentials,
        timeoutMs,
        sshMode,
        debugSsh,
        logger,
        tcpProbeTimeoutMs,
        connectTimeoutMs
      );
      if (isCliError(lldpDetail.outputs[0])) {
        throw new Error(`LLDP command failed: ${lldpDetail.outputs[0].trim()}`);
      }
      neighbors = parseCiscoLLDP(lldpDetail.outputs[0]);
      cmdUsed = "show lldp neighbors detail";
    }

    if (neighbors.length === 0) {
      const cdp = await connectWithFallback(
        target,
        ["show cdp neighbors"],
        credentials,
        timeoutMs,
        sshMode,
        debugSsh,
        logger,
        tcpProbeTimeoutMs,
        connectTimeoutMs
      );
      if (isCliError(cdp.outputs[0])) {
        throw new Error(`CDP command failed: ${cdp.outputs[0].trim()}`);
      }
      neighbors = parseCiscoCDP(cdp.outputs[0]);
      cmdUsed = "show cdp neighbors";
    }

    let arpTable: Record<string, string> | undefined;
    try {
      const arp = await connectWithFallback(
        target,
        ["show ip arp"],
        credentials,
        timeoutMs,
        sshMode,
        debugSsh,
        logger,
        tcpProbeTimeoutMs,
        connectTimeoutMs
      );
      arpTable = parseCiscoArp(arp.outputs[0]);
    } catch {
      // ignore
    }

    const power = await fetchCiscoPower(
      target,
      credentials,
      timeoutMs,
      sshMode,
      debugSsh,
      logger,
      tcpProbeTimeoutMs,
      connectTimeoutMs
    );

    logger?.({
      ts: new Date().toISOString(),
      level: "debug",
      scope: "cisco",
      message: "Neighbor discovery complete",
      meta: { host: target, lldpCount: neighbors.length, cmdUsed }
    });
    return {
      facts,
      neighbors,
      credentialUsed: credentialId,
      vendor: "Cisco",
      platform: "cisco",
      power,
      arpTable
    };
  }
};

async function fetchCiscoPower(
  target: string,
  credentials: CredentialSet[],
  timeoutMs: number,
  sshMode: SshMode | undefined,
  debugSsh?: boolean,
  logger?: Logger,
  tcpProbeTimeoutMs?: number,
  connectTimeoutMs?: number
) {
  let poeOutput = "";
  try {
    const poe = await connectWithFallback(
      target,
      ["show power inline"],
      credentials,
      timeoutMs,
      sshMode,
      debugSsh,
      logger,
      tcpProbeTimeoutMs,
      connectTimeoutMs
    );
    poeOutput = poe.outputs[0];
  } catch {
    // ignore
  }

  const psuCommands = ["show environment power", "show power"];
  let psuOutput = "";
  for (const cmd of psuCommands) {
    try {
      const result = await connectWithFallback(
        target,
        [cmd],
        credentials,
        timeoutMs,
        sshMode,
        debugSsh,
        logger,
        tcpProbeTimeoutMs,
        connectTimeoutMs
      );
      psuOutput = result.outputs[0];
      if (psuOutput.trim()) break;
    } catch {
      continue;
    }
  }

  const poe = parsePoeSummary(poeOutput);
  const psu = parsePsuSummary(psuOutput);
  if (!poe && !psu) return undefined;
  return { poe, psu };
}

function parsePoeSummary(output: string) {
  if (!output) return undefined;
  const totals = /(?:^|\n)\s*Module\s+Available.*\n[-\s]*\n\s*(\d+)\s+(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)/m.exec(
    output
  );
  let used: string | undefined;
  let avail: string | undefined;
  let remaining: string | undefined;
  if (totals) {
    avail = totals[2];
    used = totals[3];
    remaining = totals[4];
  }
  if (!used && !avail && !remaining) {
    used = /([0-9.]+)\s*W\s*used/i.exec(output)?.[1];
    avail = /([0-9.]+)\s*W\s*available/i.exec(output)?.[1];
    remaining = /([0-9.]+)\s*W\s*remaining/i.exec(output)?.[1];
  }
  if (!used && !avail && !remaining) {
    return { details: output.trim() };
  }
  return {
    usedW: used ? Number(used) : undefined,
    availableW: avail ? Number(avail) : undefined,
    remainingW: remaining ? Number(remaining) : undefined,
    details: output.trim()
  };
}

function parsePsuSummary(output: string) {
  if (!output) return undefined;
  const count = /Power supplies\s*:\s*(\d+)/i.exec(output)?.[1];
  const capacity = /(\d+)\s*W/i.exec(output)?.[1];
  const status = /Status\s*:\s*(.+)/i.exec(output)?.[1]?.trim();
  if (!count && !capacity && !status) {
    return { details: output.trim() };
  }
  return {
    count: count ? Number(count) : undefined,
    capacityW: capacity ? Number(capacity) : undefined,
    status,
    details: output.trim()
  };
}

function isCliError(output: string) {
  return /invalid input|unknown command|unrecognized command|ambiguous command|not supported|^%/i.test(output);
}
