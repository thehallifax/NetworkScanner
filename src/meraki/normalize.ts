import { Link } from "../types.js";
import { MerakiDevice, MerakiLldpCdp, MerakiPortStatus } from "./types.js";

function isMerakiSwitch(device: MerakiDevice) {
  if (device.productType && device.productType.toLowerCase() === "switch") return true;
  if (device.model && device.model.toUpperCase().startsWith("MS")) return true;
  return false;
}

function normalizeMac(value?: string) {
  if (!value) return undefined;
  const cleaned = value.replace(/[^a-fA-F0-9]/g, "").toLowerCase();
  if (cleaned.length !== 12) return value;
  return cleaned.match(/.{1,2}/g)?.join(":");
}

function pickNeighborId(
  neighborMac: string | undefined,
  fallbackId: string | undefined,
  macToSerial: Map<string, string>
) {
  if (neighborMac) {
    const normalized = normalizeMac(neighborMac);
    if (normalized && macToSerial.has(normalized)) {
      return macToSerial.get(normalized);
    }
  }
  return fallbackId;
}

type NormalizeInput = {
  devices: MerakiDevice[];
  lldpCdpBySerial: Record<string, MerakiLldpCdp>;
  portStatusesBySerial: Record<string, MerakiPortStatus[]>;
};

export function normalizeMerakiTopology(input: NormalizeInput): Link[] {
  const macToSerial = new Map<string, string>();
  const edges: Link[] = [];
  const edgeMap = new Map<string, Link>();

  for (const device of input.devices) {
    if (!device.mac || !device.serial) continue;
    const normalized = normalizeMac(device.mac);
    if (normalized) macToSerial.set(normalized, device.serial);
  }

  for (const device of input.devices) {
    if (!isMerakiSwitch(device)) continue;
    const lldpCdp = input.lldpCdpBySerial[device.serial];
    if (!lldpCdp?.ports) continue;
    const portStatuses = input.portStatusesBySerial[device.serial] ?? [];
    const validPorts = new Set(portStatuses.map((status) => String(status.portId)));

    for (const [portId, entry] of Object.entries(lldpCdp.ports)) {
      const localPort = validPorts.has(portId) ? portId : portId;

      if (entry.lldp) {
        const neighborId = pickNeighborId(entry.lldp.chassisId, entry.lldp.systemName, macToSerial);
        edges.push({
          localHostname: device.name ?? device.serial,
          localPort: localPort,
          remoteSystemName: entry.lldp.systemName ?? "unknown",
          remotePort: entry.lldp.portId ?? "unknown",
          remotePortDescription: undefined,
          remoteChassisId: neighborId,
          remoteManagementIp: entry.lldp.managementAddress,
          protocol: "lldp"
        });
      }

      if (entry.cdp) {
        const neighborId = pickNeighborId(entry.cdp.address, entry.cdp.deviceId, macToSerial);
        const edge: Link = {
          localHostname: device.name ?? device.serial,
          localPort: localPort,
          remoteSystemName: entry.cdp.deviceId ?? "unknown",
          remotePort: entry.cdp.portId ?? "unknown",
          remotePortDescription: entry.cdp.platform,
          remoteChassisId: neighborId,
          remoteManagementIp: entry.cdp.address,
          protocol: "cdp"
        };
        edges.push(edge);
      }
    }
  }

  for (const edge of edges) {
    const key = [edge.localHostname, edge.localPort, edge.remoteSystemName].join("|");
    const existing = edgeMap.get(key);
    if (!existing || (existing.protocol === "cdp" && edge.protocol === "lldp")) {
      edgeMap.set(key, edge);
    }
  }

  const output = Array.from(edgeMap.values());
  output.sort((a, b) => {
    const aKey = `${a.localHostname}|${a.localPort}|${a.remoteSystemName}`;
    const bKey = `${b.localHostname}|${b.localPort}|${b.remoteSystemName}`;
    return aKey.localeCompare(bKey);
  });
  return output;
}
