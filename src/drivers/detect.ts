import { CredentialSet, Device, DeviceFacts, DeviceVendor, LLDPNeighbor, Logger, Vendor } from "../types.js";
import type { SshMode } from "./ssh.js";
import { execSSHWithProfileFallback, execShellWithProfileFallback } from "./ssh.js";
import {
  detectArubaPlatform,
  parseArubaLLDPCx,
  parseArubaLLDPS,
  parseArubaSystemCx,
  parseArubaSystemS
} from "./aruba.js";
import { parseCiscoFacts, parseCiscoLLDP } from "./cisco.js";

const ciscoMarkers = [/Cisco IOS/i, /IOS XE/i];
const arubaMarkers = [/ArubaOS-Switch/i, /ProCurve/i, /HPE/i, /HP/i, /ArubaOS-CX/i];

function matchesAny(output: string, patterns: RegExp[]) {
  return patterns.some((pattern) => pattern.test(output));
}

function isCliError(output: string) {
  return /invalid input|unknown command|unrecognized command|incomplete command|ambiguous command|not supported|^%/i.test(
    output
  );
}

function hasOutput(output: string) {
  return Boolean(output && output.trim().length > 0);
}

function logProbe(
  logger: Logger | undefined,
  enabled: boolean | undefined,
  host: string,
  command: string,
  output: string,
  ok: boolean,
  viaShell = false
) {
  if (!enabled || !logger) return;
  const sample = output
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 80);
  logger({
    ts: new Date().toISOString(),
    level: "debug",
    scope: "detect",
    message: "Probe output",
    meta: {
      host,
      command,
      viaShell,
      ok,
      length: output.length,
      cliError: isCliError(output),
      sample
    }
  });
}

async function tryCommand(
  host: string,
  credential: CredentialSet,
  timeoutMs: number,
  command: string,
  sshMode?: SshMode,
  debugSsh?: boolean,
  logger?: Logger,
  tcpProbeTimeoutMs?: number,
  connectTimeoutMs?: number,
  useShell?: boolean
) {
  try {
    const output = useShell
      ? await execShellWithProfileFallback(
          host,
          command,
          credential,
          timeoutMs,
          sshMode,
          debugSsh,
          logger,
          tcpProbeTimeoutMs,
          connectTimeoutMs
        )
      : await execSSHWithProfileFallback(
          host,
          command,
          credential,
          timeoutMs,
          sshMode,
          debugSsh,
          logger,
          tcpProbeTimeoutMs,
          connectTimeoutMs
        );
    return { ok: true, output } as const;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, output: "", error: message } as const;
  }
}

export interface DetectResult {
  vendor: Vendor | DeviceVendor;
  credential: CredentialSet;
  facts?: DeviceFacts;
  neighbors?: LLDPNeighbor[];
  platform?: "aruba-cx" | "arubaos-s" | "aruba-s" | "cisco" | "unknown";
  power?: Device["power"];
}

export async function detectVendor(
  host: string,
  credentials: CredentialSet[],
  timeoutMs: number,
  allowList?: Array<"aruba" | "cisco">,
  sshMode?: SshMode,
  debugSsh?: boolean,
  logger?: Logger,
  tcpProbeTimeoutMs?: number,
  connectTimeoutMs?: number
): Promise<DetectResult> {
  const failures = new Map<string, string>();

  for (const credential of credentials) {
    let showVersion = await tryCommand(
      host,
      credential,
      timeoutMs,
      "show version",
      sshMode,
      debugSsh,
      logger,
      tcpProbeTimeoutMs,
      connectTimeoutMs
    );
    logProbe(logger, debugSsh, host, "show version", showVersion.output, showVersion.ok);
    let showSystem = await tryCommand(
      host,
      credential,
      timeoutMs,
      "show system",
      sshMode,
      debugSsh,
      logger,
      tcpProbeTimeoutMs,
      connectTimeoutMs
    );
    logProbe(logger, debugSsh, host, "show system", showSystem.output, showSystem.ok);

    if (showVersion.ok && (!hasOutput(showVersion.output) || isCliError(showVersion.output))) {
      showVersion = await tryCommand(
        host,
        credential,
        timeoutMs,
        "sh version",
        sshMode,
        debugSsh,
        logger,
        tcpProbeTimeoutMs,
        connectTimeoutMs
      );
      logProbe(logger, debugSsh, host, "sh version", showVersion.output, showVersion.ok);
    }

    if (showSystem.ok && (!hasOutput(showSystem.output) || isCliError(showSystem.output))) {
      showSystem = await tryCommand(
        host,
        credential,
        timeoutMs,
        "sh system",
        sshMode,
        debugSsh,
        logger,
        tcpProbeTimeoutMs,
        connectTimeoutMs
      );
      logProbe(logger, debugSsh, host, "sh system", showSystem.output, showSystem.ok);
    }

    if (showSystem.ok && (!hasOutput(showSystem.output) || isCliError(showSystem.output))) {
      showSystem = await tryCommand(
        host,
        credential,
        timeoutMs,
        "show system",
        sshMode,
        debugSsh,
        logger,
        tcpProbeTimeoutMs,
        connectTimeoutMs,
        true
      );
      logProbe(logger, debugSsh, host, "show system", showSystem.output, showSystem.ok, true);
    }

    if (showVersion.ok && hasOutput(showVersion.output) && !isCliError(showVersion.output) && matchesAny(showVersion.output, ciscoMarkers)) {
      if (!allowList || allowList.includes("cisco")) {
        logger?.({
          ts: new Date().toISOString(),
          level: "debug",
          scope: "detect",
          message: "Detected Cisco from show version",
          meta: { host }
        });
        return {
          vendor: "Cisco" as DeviceVendor,
          credential,
          facts: parseCiscoFacts(showVersion.output),
          platform: "cisco"
        };
      }
    }

    if (
      showSystem.ok
      && hasOutput(showSystem.output)
      && !isCliError(showSystem.output)
      && /Software revision/i.test(showSystem.output)
      && /WC\./i.test(showSystem.output)
    ) {
      if (!allowList || allowList.includes("aruba")) {
        logger?.({
          ts: new Date().toISOString(),
          level: "debug",
          scope: "detect",
          message: "Detected Aruba AOS-S from show system",
          meta: { host }
        });
        return {
          vendor: "Aruba" as DeviceVendor,
          credential,
          facts: parseArubaSystemS(showSystem.output),
          platform: "arubaos-s"
        };
      }
    }

    if (showSystem.ok && hasOutput(showSystem.output) && !isCliError(showSystem.output) && matchesAny(showSystem.output, arubaMarkers)) {
      const platform = detectArubaPlatform(showSystem.output);
      if (!allowList || allowList.includes("aruba")) {
        logger?.({
          ts: new Date().toISOString(),
          level: "debug",
          scope: "detect",
          message: `Detected Aruba ${platform} from show system`,
          meta: { host }
        });
        return {
          vendor: "Aruba" as DeviceVendor,
          credential,
          facts: platform === "aruba-cx" ? parseArubaSystemCx(showSystem.output) : parseArubaSystemS(showSystem.output),
          platform
        };
      }
    }

    if (showVersion.ok && hasOutput(showVersion.output) && !isCliError(showVersion.output) && matchesAny(showVersion.output, arubaMarkers)) {
      if (!allowList || allowList.includes("aruba")) {
        logger?.({
          ts: new Date().toISOString(),
          level: "debug",
          scope: "detect",
          message: "Detected Aruba from show version",
          meta: { host }
        });
        return {
          vendor: "Aruba" as DeviceVendor,
          credential,
          facts: parseArubaSystemS(showVersion.output),
          platform: "arubaos-s"
        };
      }
    }

    const arubaLldp = await tryCommand(
      host,
      credential,
      timeoutMs,
      "show lldp info remote-device",
      sshMode,
      debugSsh,
      logger,
      tcpProbeTimeoutMs,
      connectTimeoutMs
    );
    if (arubaLldp.ok && hasOutput(arubaLldp.output) && !isCliError(arubaLldp.output)) {
      if (!allowList || allowList.includes("aruba")) {
        const platform = showSystem.ok ? detectArubaPlatform(showSystem.output) : "arubaos-s";
        logger?.({
          ts: new Date().toISOString(),
          level: "debug",
          scope: "detect",
          message: `Detected Aruba ${platform} from LLDP`,
          meta: { host }
        });
        return {
          vendor: "Aruba" as DeviceVendor,
          credential,
          facts: showSystem.ok
            ? platform === "aruba-cx"
              ? parseArubaSystemCx(showSystem.output)
              : parseArubaSystemS(showSystem.output)
            : parseArubaSystemS(arubaLldp.output),
          neighbors: platform === "aruba-cx" ? parseArubaLLDPCx(arubaLldp.output) : parseArubaLLDPS(arubaLldp.output),
          platform
        };
      }
    }

    const ciscoLldp = await tryCommand(
      host,
      credential,
      timeoutMs,
      "show lldp neighbors detail",
      sshMode,
      debugSsh,
      logger,
      tcpProbeTimeoutMs,
      connectTimeoutMs
    );
    if (ciscoLldp.ok && hasOutput(ciscoLldp.output) && !isCliError(ciscoLldp.output)) {
      if (!allowList || allowList.includes("cisco")) {
        logger?.({
          ts: new Date().toISOString(),
          level: "debug",
          scope: "detect",
          message: "Detected Cisco from LLDP",
          meta: { host }
        });
        return {
          vendor: "Cisco" as DeviceVendor,
          credential,
          facts: showVersion.ok ? parseCiscoFacts(showVersion.output) : parseCiscoFacts(ciscoLldp.output),
          neighbors: parseCiscoLLDP(ciscoLldp.output),
          platform: "cisco"
        };
      }
    }

    const showSystemOk = showSystem.ok && hasOutput(showSystem.output) && !isCliError(showSystem.output);
    const showVersionOk = showVersion.ok && hasOutput(showVersion.output) && !isCliError(showVersion.output);
    if (showSystemOk || showVersionOk) {
      const platform = showSystemOk ? detectArubaPlatform(showSystem.output) : "arubaos-s";
      const arubaFacts = showSystemOk
        ? platform === "aruba-cx"
          ? parseArubaSystemCx(showSystem.output)
          : parseArubaSystemS(showSystem.output)
        : parseArubaSystemS(showVersion.output);
      const ciscoFacts = showVersionOk ? parseCiscoFacts(showVersion.output) : parseCiscoFacts(showSystem.output);
      const facts = arubaFacts.hostname !== "unknown" ? arubaFacts : ciscoFacts;
      logger?.({
        ts: new Date().toISOString(),
        level: "debug",
        scope: "detect",
        message: "Vendor unknown after probes",
        meta: { host }
      });
      return {
        vendor: "Unknown" as DeviceVendor,
        credential,
        facts,
        platform
      };
    }

    const firstError = showVersion.ok
      ? undefined
      : showVersion.error || showSystem.error || arubaLldp.error || ciscoLldp.error;
    if (firstError) {
      failures.set(credential.id, firstError);
    }
  }

  if (failures.size > 0) {
    const summary = Array.from(failures.entries())
      .map(([id, message]) => `${id}: '${message}'`)
      .join(", ");
    throw new Error(`All credentials failed: {${summary}}`);
  }

  return {
    vendor: "Unknown" as DeviceVendor,
    credential: credentials[0],
    facts: { hostname: host, model: undefined, chassisId: undefined, macAddress: undefined }
  };
}
