import { merakiGetDevices, merakiGetLldpCdp, merakiGetNetworks, merakiGetOrganizations, merakiGetPortStatuses } from "./api.js";
import { normalizeMerakiTopology } from "./normalize.js";
import { Device } from "../types.js";
import { MerakiDevice, MerakiLldpCdp, MerakiPortStatus } from "./types.js";

type FetchFn = (input: RequestInfo, init?: RequestInit) => Promise<Response>;
type LogLevel = "debug" | "info" | "warn" | "error";
type LogFn = (level: LogLevel, message: string, meta?: Record<string, string | number | boolean | undefined>) => void;

type CollectOptions = {
  fetchFn?: FetchFn;
  apiKey?: string;
  orgId?: string;
  orgName?: string;
  networkId?: string;
  onLog?: LogFn;
};

type RawPayload = {
  orgs: any[];
  networks: any[];
  devices: MerakiDevice[];
  lldpCdpBySerial: Record<string, MerakiLldpCdp>;
  portStatusesBySerial: Record<string, MerakiPortStatus[]>;
};

function isMerakiSwitch(device: MerakiDevice) {
  if (device.productType && device.productType.toLowerCase() === "switch") return true;
  if (device.model && device.model.toUpperCase().startsWith("MS")) return true;
  return false;
}

function selectOrg(orgs: any[], options: CollectOptions) {
  const orgId = options.orgId ?? process.env.MERAKI_ORG_ID;
  if (orgId) {
    const match = orgs.find((org) => org.id === orgId);
    if (!match) throw new Error(`MERAKI_ORG_ID ${orgId} not found`);
    return match;
  }
  const orgName = options.orgName ?? process.env.MERAKI_ORG_NAME;
  if (orgName) {
    const match = orgs.find((org) => org.name === orgName);
    if (!match) throw new Error(`MERAKI_ORG_NAME ${orgName} not found`);
    return match;
  }
  if (!orgs.length) throw new Error("No Meraki organizations available");
  console.warn("MERAKI_ORG_ID not set; using first organization");
  return orgs[0];
}

function selectNetworks(networks: any[], options: CollectOptions) {
  const networkId = options.networkId ?? process.env.MERAKI_NETWORK_ID;
  if (networkId) {
    const match = networks.find((net) => net.id === networkId);
    if (!match) throw new Error(`MERAKI_NETWORK_ID ${networkId} not found`);
    return [match];
  }
  return networks;
}

export type MerakiCollectorResult = {
  devices: Device[];
  links: ReturnType<typeof normalizeMerakiTopology>;
  raw: RawPayload;
};

export async function collectMerakiTopology(options: CollectOptions = {}): Promise<MerakiCollectorResult> {
  const fetchFn = options.fetchFn ?? fetch;
  const apiKey = options.apiKey;
  options.onLog?.("info", "Meraki scan started");
  const orgs = await merakiGetOrganizations(fetchFn, apiKey);
  options.onLog?.("info", "Meraki organizations loaded", { count: orgs.length });
  const org = selectOrg(orgs, options);
  options.onLog?.("info", "Meraki organization selected", { orgId: org.id, orgName: org.name });
  const networks = await merakiGetNetworks(fetchFn, org.id, apiKey);
  const selectedNetworks = selectNetworks(networks, options);
  options.onLog?.("info", "Meraki networks loaded", { count: networks.length, selected: selectedNetworks.length });

  const inventoryDevices: MerakiDevice[] = [];
  for (const network of selectedNetworks) {
    const networkDevices = await merakiGetDevices(fetchFn, network.id, apiKey);
    inventoryDevices.push(...networkDevices);
  }
  options.onLog?.("info", "Meraki devices loaded", { count: inventoryDevices.length });
  const deviceSample = inventoryDevices.slice(0, 5).map((device) => ({
    name: device.name ?? device.hostname,
    model: device.model,
    productType: device.productType,
    serial: device.serial,
    mac: device.mac,
    lanIp: device.lanIp,
    firmware: device.firmware
  }));
  options.onLog?.("debug", "Meraki device sample", {
    sample: JSON.stringify(deviceSample)
  });
  const countsByProductType = inventoryDevices.reduce<Record<string, number>>((acc, device) => {
    const key = (device.productType || "undefined").toLowerCase();
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
  options.onLog?.("info", "Meraki devices by productType", countsByProductType);

  const switchDevices = inventoryDevices.filter(isMerakiSwitch);
  options.onLog?.("info", "Meraki switches detected", { count: switchDevices.length });
  const lldpCdpBySerial: Record<string, MerakiLldpCdp> = {};
  const portStatusesBySerial: Record<string, MerakiPortStatus[]> = {};

  for (const device of switchDevices) {
    if (!device.serial) continue;
    options.onLog?.("debug", "Fetching Meraki LLDP/CDP", { serial: device.serial });
    lldpCdpBySerial[device.serial] = await merakiGetLldpCdp(fetchFn, device.serial, apiKey);
    options.onLog?.("debug", "Fetching Meraki port status", { serial: device.serial });
    portStatusesBySerial[device.serial] = await merakiGetPortStatuses(fetchFn, device.serial, apiKey);
  }

  const raw: RawPayload = {
    orgs,
    networks: selectedNetworks,
    devices: switchDevices,
    lldpCdpBySerial,
    portStatusesBySerial
  };

  const links = normalizeMerakiTopology({
    devices: switchDevices,
    lldpCdpBySerial,
    portStatusesBySerial
  });
  options.onLog?.("info", "Meraki links built", { count: links.length });
  const devices: Device[] = switchDevices.map((device, index) => {
    const id = device.serial || device.mac || device.name || `meraki-${index}`;
    return {
      id,
      hostname: device.name ?? device.hostname ?? "unknown",
      managementIp: device.lanIp ?? device.wiredIp ?? device.wan1Ip ?? device.wan2Ip,
      macAddress: device.mac,
      chassisId: device.mac,
      vendor: "Cisco",
      platform: "meraki",
      kind: "switch",
      state: "success",
      model: device.model,
      productName: device.model,
      serial: device.serial,
      osVersion: device.firmware,
      discoveredAt: new Date().toISOString()
    };
  });

  options.onLog?.("info", "Meraki scan finished", { devices: devices.length, links: links.length });
  return { devices, links, raw };
}
