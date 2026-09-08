import { CredentialSet, DeviceDriver, Logger } from "../types.js";
import { connectWithFallback, type SshMode } from "./ssh.js";
import { parseArubaLLDPS, parseArubaSystemS } from "./aruba.js";

function isCliError(output: string) {
  return /invalid input|unknown command|unrecognized command|ambiguous command|not supported|^%/i.test(output);
}

function normalizeMac(value?: string) {
  if (!value) return undefined;
  const trimmed = value.trim();
  const hex = trimmed.replace(/[^a-fA-F0-9]/g, "");
  if (hex.length !== 12) return trimmed;
  return hex.match(/.{1,2}/g)?.join(":").toLowerCase();
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

export const arubaOsSDriver: DeviceDriver = {
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
      connectTimeoutMs,
      true
    );
    const sysOutput = outputs[0];
    if (!sysOutput.trim() || isCliError(sysOutput)) {
      const retry = await connectWithFallback(
        target,
        ["sh system"],
        credentials,
        timeoutMs,
        sshMode,
        debugSsh,
        logger,
        tcpProbeTimeoutMs,
        connectTimeoutMs,
        true
      );
      outputs = retry.outputs;
      credentialId = retry.credentialId;
    }
    let finalSysOutput = outputs[0];
    if (!finalSysOutput.trim() || isCliError(finalSysOutput)) {
      const shellRetry = await connectWithFallback(
        target,
        ["show system"],
        credentials,
        timeoutMs,
        sshMode,
        debugSsh,
        logger,
        tcpProbeTimeoutMs,
        connectTimeoutMs,
        true
      );
      finalSysOutput = shellRetry.outputs[0];
      credentialId = shellRetry.credentialId;
    }
    const facts = parseArubaSystemS(finalSysOutput);

    const lldp = await connectWithFallback(
      target,
      ["show lldp info remote-device"],
      credentials,
      timeoutMs,
      sshMode,
      debugSsh,
      logger,
      tcpProbeTimeoutMs,
      connectTimeoutMs,
      true
    );
    const lldpOutput = lldp.outputs[0];
    let finalLldpOutput = lldpOutput;
    if (!finalLldpOutput.trim() || isCliError(finalLldpOutput)) {
      const shellLldp = await connectWithFallback(
        target,
        ["show lldp info remote-device"],
        credentials,
        timeoutMs,
        sshMode,
        debugSsh,
        logger,
        tcpProbeTimeoutMs,
        connectTimeoutMs,
        true
      );
      finalLldpOutput = shellLldp.outputs[0];
    }
    if (isCliError(finalLldpOutput)) {
      throw new Error(`LLDP command failed: ${lldpOutput.trim()}`);
    }

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
        connectTimeoutMs,
        true
      );
      arpTable = parseArubaArp(arp.outputs[0]);
    } catch {
      // ignore
    }

    const power = await fetchArubaOsSPower(
      target,
      credentials,
      timeoutMs,
      sshMode,
      debugSsh,
      logger,
      tcpProbeTimeoutMs,
      connectTimeoutMs
    );
    if ((!facts.model || !facts.productName) && power?.poe?.details) {
      const banner = parseAosSBanner(power.poe.details);
      if (banner.model && !facts.model) facts.model = banner.model;
      if (banner.productName && !facts.productName) facts.productName = banner.productName;
    }

    return {
      facts,
      neighbors: parseArubaLLDPS(finalLldpOutput),
      credentialUsed: credentialId,
      vendor: "Aruba",
      platform: "arubaos-s",
      power,
      arpTable
    };
  }
};

async function fetchArubaOsSPower(
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
  const poeCommands = [
    "no page\nshow power-over-ethernet brief",
    "show power-over-ethernet brief",
    "page off\nshow power-over-ethernet brief"
  ];
  for (const cmd of poeCommands) {
    try {
      const poe = await connectWithFallback(
        target,
        [cmd],
        credentials,
        timeoutMs,
        sshMode,
        debugSsh,
        logger,
        tcpProbeTimeoutMs,
        connectTimeoutMs,
        true
      );
      poeOutput = poe.outputs[0];
      if (poeOutput.trim() && !isCliError(poeOutput)) break;
    } catch {
      continue;
    }
  }

  let psuOutput = "";
  try {
    const psu = await connectWithFallback(
      target,
      ["show system power-supply", "sh system power-supply"],
      credentials,
      timeoutMs,
      sshMode,
      debugSsh,
      logger,
      tcpProbeTimeoutMs,
      connectTimeoutMs,
      true
    );
    psuOutput = psu.outputs[0];
  } catch {
    // ignore
  }

  const poe = poeOutput && !isCliError(poeOutput) ? parseAosSPoe(poeOutput) : undefined;
  const psu = psuOutput && !isCliError(psuOutput) ? parseAosSPsu(psuOutput) : undefined;
  if (!poe && !psu) return undefined;
  return { poe, psu };
}

function parseAosSBanner(output: string) {
  const match = /Aruba\s+(\S+)\s+(.+?)\s+Switch/i.exec(output);
  return {
    model: match?.[1],
    productName: match?.[2]?.trim()
  };
}

function parseAosSPoe(output: string) {
  const summary = /Available:\s*([0-9.]+)\s*W\s+Used:\s*([0-9.]+)\s*W\s+Remaining:\s*([0-9.]+)\s*W/i.exec(
    output
  );
  const available =
    summary?.[1]
    || /Total\s+Power\s+Available\s*:\s*([0-9.]+)/i.exec(output)?.[1]
    || /Power\s+Available\s*:\s*([0-9.]+)/i.exec(output)?.[1];
  const used =
    summary?.[2]
    || /Total\s+Power\s+Used\s*:\s*([0-9.]+)/i.exec(output)?.[1]
    || /Power\s+Used\s*:\s*([0-9.]+)/i.exec(output)?.[1];
  const remaining =
    summary?.[3]
    || /Total\s+Power\s+Remaining\s*:\s*([0-9.]+)/i.exec(output)?.[1]
    || /Power\s+Remaining\s*:\s*([0-9.]+)/i.exec(output)?.[1];
  if (!available && !used && !remaining) {
    return { details: output.trim() };
  }
  return {
    availableW: available ? Number(available) : undefined,
    usedW: used ? Number(used) : undefined,
    remainingW: remaining ? Number(remaining) : undefined,
    details: output.trim()
  };
}

function parseAosSPsu(output: string) {
  const total = /Total\s+power:\s*([0-9.]+)\s*W/i.exec(output)?.[1];
  const supplyMatch = /(\d+)\s*\/\s*(\d+)\s*supply bays delivering power/i.exec(output);
  const supplyPresent = supplyMatch ? Number(supplyMatch[1]) : undefined;
  const supplyTotal = supplyMatch ? Number(supplyMatch[2]) : undefined;

  const lines = output.split("\n");
  const rows = lines
    .map((line) => line.trim())
    .filter((line) => /^\d+\s+/.test(line))
    .map((line) => line.split(/\s{2,}/))
    .filter((parts) => parts.length >= 5)
    .map((parts) => {
      const status = parts[3]?.trim();
      const max = Number(parts[parts.length - 1]);
      return {
        status,
        max: Number.isNaN(max) ? 0 : max
      };
    });

  const presentRows = rows.filter((row) => row.status && !/not avail|absent/i.test(row.status) && row.max > 0);
  const absentRows = rows.filter((row) => !row.status || /not avail|absent/i.test(row.status) || row.max === 0);
  const totalCapacity = presentRows.reduce((sum, row) => sum + row.max, 0);
  const degraded = presentRows.some((row) => row.status && !/ok|powered/i.test(row.status));

  if (!total && !supplyPresent && !supplyTotal && rows.length === 0) {
    return { details: output.trim() };
  }
  return {
    count: supplyPresent ?? (presentRows.length || undefined),
    absentCount: supplyTotal
      ? Math.max(supplyTotal - (supplyPresent ?? presentRows.length), 0)
      : (absentRows.length || undefined),
    capacityW: total ? Number(total) : (totalCapacity || undefined),
    status: degraded ? "degraded" : "ok",
    details: output.trim()
  };
}
