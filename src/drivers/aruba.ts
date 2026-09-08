import { CredentialSet, DeviceDriver, DriverResult, LLDPCapability, Logger } from "../types.js";
import { connectWithFallback, type SshMode } from "./ssh.js";

function normalizeMac(value?: string) {
  if (!value) return undefined;
  const trimmed = value.trim();
  const hex = trimmed.replace(/[^a-fA-F0-9]/g, "");
  if (hex.length !== 12) return trimmed;
  return hex.match(/.{1,2}/g)?.join(":").toLowerCase();
}

export function detectArubaPlatform(output: string) {
  if (
    /ArubaOS-CX Version/i.test(output)
    || /\\bFL\\./i.test(output)
    || (/Product Name/i.test(output) && /Chassis Serial Nbr/i.test(output))
  ) {
    return "aruba-cx" as const;
  }
  if (/Software revision/i.test(output) && /WC\\./i.test(output)) {
    return "arubaos-s" as const;
  }
  if (/Software revision/i.test(output) && /Base MAC Addr/i.test(output)) {
    return "arubaos-s" as const;
  }
  return "unknown" as const;
}

export function parseArubaSystemCx(output: string) {
  const hostname = /Hostname\s*:\s*(.+)/i.exec(output)?.[1]?.trim();
  const productName = /Product Name\s*:\s*(.+)/i.exec(output)?.[1]?.trim();
  const model = productName?.split(/\s+/)[0];
  const serial = /Chassis Serial Nbr\s*:\s*(.+)/i.exec(output)?.[1]?.trim();
  const baseMacRaw = /Base MAC Address\s*:\s*([0-9A-Fa-f:.-]+)/i.exec(output)?.[1]?.trim();
  const baseMac = normalizeMac(baseMacRaw);
  const osVersion = /ArubaOS-CX Version\s*:\s*(.+)/i.exec(output)?.[1]?.trim();
  const uptime = /Up Time\s*:\s*(.+)/i.exec(output)?.[1]?.trim();
  return {
    hostname: hostname || "unknown",
    productName,
    model,
    serial,
    osVersion,
    uptime,
    macAddress: baseMac,
    chassisId: baseMac
  };
}

export function parseArubaSystemS(output: string) {
  const modelMatch = /Aruba\s+(\S+)\s+(.+?)\s+Switch/i.exec(output);
  const model = modelMatch?.[1];
  const productName = modelMatch?.[2]?.trim();
  const hostname = extractField(output, "System Name");
  const serial = extractField(output, "Serial Number");
  const baseMacRaw = extractField(output, "Base MAC Addr");
  const baseMac = normalizeMac(baseMacRaw);
  const osVersion = extractField(output, "Software revision");
  const uptime = extractField(output, "Up Time");
  return {
    hostname: hostname || "unknown",
    model,
    productName,
    serial,
    osVersion,
    uptime,
    macAddress: baseMac,
    chassisId: baseMac
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

function normalizeChassisId(value?: string) {
  return normalizeMac(value) ?? value;
}

function parseArubaArp(output: string) {
  const table: Record<string, string> = {};
  const lines = output.split("\n");
  for (const line of lines) {
    const match = /(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9A-Fa-f:. -]{11,})/i.exec(line);
    if (!match) continue;
    const ip = match[1];
    const mac = normalizeMac(match[2]);
    if (mac) table[mac] = ip;
  }
  return Object.keys(table).length ? table : undefined;
}

function extractField(output: string, label: string) {
  const pattern = new RegExp(`${label}\\s*:\\s*([^\\n\\r]+)`, "i");
  const match = pattern.exec(output);
  if (!match) return undefined;
  let value = match[1].trim();
  // Trim trailing chained fields on the same line.
  value = value.split(/\s{2,}[A-Za-z].+?:/)[0].trim();
  return value;
}

export function parseArubaLLDPCx(output: string) {
  const neighbors: DriverResult["neighbors"] = [];
  if (isInvalidCommand(output)) return neighbors;
  const lines = output.split("\n");
  for (const line of lines) {
    if (/LOCAL-PORT/i.test(line) || /^-+\s*$/.test(line)) continue;
    const match = /^(\S+)\s+(\S+)\s+(\S+)\s+(.+?)\s+(\d+)\s+(\S+)\s*$/.exec(line);
    if (!match) continue;
    const [, localPort, chassisId, portId, portDesc, _ttl, sysName] = match;
    neighbors.push({
      localPort,
      remoteSystemName: sysName,
      remotePort: portId,
      remotePortDescription: portDesc.trim() === "-" ? undefined : portDesc.trim(),
      remoteChassisId: normalizeChassisId(chassisId),
      remoteManagementIp: undefined,
      capabilities: undefined
    });
  }
  return neighbors;
}

export function parseArubaLLDPS(output: string) {
  const neighbors: DriverResult["neighbors"] = [];
  if (isInvalidCommand(output)) return neighbors;
  const lines = output.split("\n");
  for (const line of lines) {
    if (/LocalPort/i.test(line) || /^-+\s*$/.test(line)) continue;
    const match = /^(\S+)\s+(\S+)\s+(\S+)\s+(.+?)\s+(\S+)\s*$/.exec(line);
    if (!match) continue;
    const [, localPort, chassisId, portId, portDesc, sysName] = match;
    neighbors.push({
      localPort,
      remoteSystemName: sysName,
      remotePort: portId,
      remotePortDescription: portDesc.trim() === "-" ? undefined : portDesc.trim(),
      remoteChassisId: normalizeChassisId(chassisId),
      remoteManagementIp: undefined,
      capabilities: undefined
    });
  }
  return neighbors;
}

export const arubaDriver: DeviceDriver = {
  name: "aruba",
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
    let { outputs, credentialId } = await connectWithFallback(
      target,
      ["show system"],
      credentials,
      timeoutMs,
      sshMode,
      debugSsh,
      logger,
      tcpProbeTimeoutMs,
      connectTimeoutMs
    );
    let [sysOutput] = outputs;
    if (!sysOutput.trim() || isInvalidCommand(sysOutput)) {
      const retry = await connectWithFallback(
        target,
        ["sh system"],
        credentials,
        timeoutMs,
        sshMode,
        debugSsh,
        logger,
        tcpProbeTimeoutMs,
        connectTimeoutMs
      );
      sysOutput = retry.outputs[0];
    }
    if (!sysOutput.trim() || isInvalidCommand(sysOutput)) {
      const shellRetry = await connectWithFallback(
        target,
        ["no page\nshow system"],
        credentials,
        timeoutMs,
        sshMode,
        debugSsh,
        logger,
        tcpProbeTimeoutMs,
        connectTimeoutMs,
        true
      );
      sysOutput = shellRetry.outputs[0];
    }
    const platform = detectArubaPlatform(sysOutput);
    let facts = platform === "aruba-cx" ? parseArubaSystemCx(sysOutput) : parseArubaSystemS(sysOutput);

    let lldpOutput = "";
    if (platform === "aruba-cx") {
      const lldp = await connectWithFallback(
        target,
        ["show lldp neighbor-info"],
        credentials,
        timeoutMs,
        sshMode,
        debugSsh,
        logger,
        tcpProbeTimeoutMs,
        connectTimeoutMs
      );
      lldpOutput = lldp.outputs[0];
      if (isInvalidCommand(lldpOutput)) {
        throw new Error(`LLDP command failed: ${lldpOutput.trim()}`);
      }
    } else {
      const lldp = await connectWithFallback(
        target,
        ["show lldp info remote-device"],
        credentials,
        timeoutMs,
        sshMode,
        debugSsh,
        logger,
        tcpProbeTimeoutMs,
        connectTimeoutMs
      );
      lldpOutput = lldp.outputs[0];
      if (isInvalidCommand(lldpOutput)) {
        throw new Error(`LLDP command failed: ${lldpOutput.trim()}`);
      }
    }

    const neighbors = platform === "aruba-cx" ? parseArubaLLDPCx(lldpOutput) : parseArubaLLDPS(lldpOutput);
    let arpTable: Record<string, string> | undefined;
    try {
      const arp = await connectWithFallback(
        target,
        ["show arp"],
        credentials,
        timeoutMs,
        sshMode,
        debugSsh,
        logger,
        tcpProbeTimeoutMs,
        connectTimeoutMs
      );
      arpTable = parseArubaArp(arp.outputs[0]);
    } catch {
      // ignore
    }
    const power = await fetchArubaPower(
      target,
      credentials,
      timeoutMs,
      sshMode,
      debugSsh,
      logger,
      tcpProbeTimeoutMs,
      connectTimeoutMs
    );
    return {
      facts,
      neighbors,
      credentialUsed: credentialId,
      vendor: "Aruba",
      platform,
      power,
      arpTable
    };
  }
};

async function fetchArubaPower(
  target: string,
  credentials: CredentialSet[],
  timeoutMs: number,
  sshMode: SshMode | undefined,
  debugSsh?: boolean,
  logger?: Logger,
  tcpProbeTimeoutMs?: number,
  connectTimeoutMs?: number
) {
  const poeCommands = ["show poe status", "show poe brief"];
  let poeOutput = "";
  let poeError = "";
  for (const cmd of poeCommands) {
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
      poeOutput = result.outputs[0];
      if (poeOutput.trim() && !isInvalidCommand(poeOutput)) break;
      if (isInvalidCommand(poeOutput)) {
        poeError = poeOutput;
      }
    } catch {
      poeError = "not supported";
      continue;
    }
  }

  const psuCommands = [
    "show environment power",
    "show system power-supply",
    "show environment power-supply"
  ];
  let psuOutput = "";
  let psuError = "";
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
      if (psuOutput.trim() && !isInvalidCommand(psuOutput)) break;
      if (isInvalidCommand(psuOutput)) {
        psuError = psuOutput;
      }
    } catch {
      psuError = "not supported";
      continue;
    }
  }

  const poe = parsePoeSummary(poeOutput)
    || (poeError ? { status: "not_supported", details: poeError } : undefined);
  const psu = parsePsuSummary(psuOutput)
    || (psuError ? { status: "not_supported", details: psuError } : undefined);
  if (!poe && !psu) return undefined;
  return { poe, psu };
}

function parsePoeSummary(output: string) {
  if (!output) return undefined;
  if (isInvalidCommand(output)) return { details: output.trim(), status: "not_supported" };
  const totalLine = /Total\s+([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)/i.exec(output);
  const used =
    totalLine?.[2]
    || /Used\s*[:=]\s*([0-9.]+)/i.exec(output)?.[1]
    || /([0-9.]+)\s*W\s*used/i.exec(output)?.[1];
  const avail =
    totalLine?.[1]
    || /Available\s*[:=]\s*([0-9.]+)/i.exec(output)?.[1]
    || /([0-9.]+)\s*W\s*available/i.exec(output)?.[1];
  const remaining =
    totalLine?.[3]
    || /Remaining\s*[:=]\s*([0-9.]+)/i.exec(output)?.[1]
    || /([0-9.]+)\s*W\s*remaining/i.exec(output)?.[1];
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
  if (isInvalidCommand(output)) return { details: output.trim(), status: "not_supported" };
  const lines = output.split("\n");
  const psuRows = lines.filter((line) => /^\s*\d+\/\d+/.test(line));
  const count = psuRows.length ? String(psuRows.length) : /Power supplies\s*:\s*(\d+)/i.exec(output)?.[1];
  let capacity = /Wattage Maximum\s+(\d+)/i.exec(output)?.[1];
  let status = /Status\s*:\s*(.+)/i.exec(output)?.[1]?.trim();
  if (psuRows.length) {
    const rows = psuRows.map((line) => {
      const statusMatch = /(OK|Present|Not Present|Absent|Fault|Fail|Unknown)/i.exec(line)?.[1];
      const wattMatch = /(\d+)\s*$/.exec(line)?.[1];
      return {
        status: statusMatch?.toLowerCase(),
        watt: wattMatch ? Number(wattMatch) : 0
      };
    });
    const presentRows = rows.filter((row) => row.status && row.status !== "absent" && row.watt > 0);
    const absentRows = rows.filter((row) => row.status === "absent" || row.watt === 0);
    const totalCapacity = presentRows.reduce((sum, row) => sum + row.watt, 0);
    const degraded = presentRows.some((row) => row.status && row.status !== "ok" && row.status !== "present");
    status = presentRows.length === 0 ? "not_supported" : degraded ? "degraded" : "ok";
    capacity = totalCapacity ? String(totalCapacity) : capacity;
    return {
      count: presentRows.length,
      absentCount: absentRows.length,
      capacityW: capacity ? Number(capacity) : undefined,
      status,
      details: output.trim()
    };
  }
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

function isInvalidCommand(output: string) {
  return /invalid input|unknown command|unrecognized command|ambiguous command|not supported/i.test(output);
}
