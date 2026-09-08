export type DeviceId = string;

export type DeviceState = "pending" | "success" | "failed" | "unresolved" | "unreachable";
export type DeviceKind = "switch" | "ap" | "phone" | "camera" | "printer" | "unknown";
export type LogLevel = "debug" | "info" | "warn" | "error";
export type LogScope = "scan" | "ssh" | "detect" | "aruba" | "cisco" | "crawler" | "api";

export interface LogEntry {
  ts: string;
  level: LogLevel;
  scope: LogScope;
  message: string;
  meta?: Record<string, string | number | boolean | undefined>;
}

export type Logger = (entry: LogEntry) => void;

export type Vendor = "aruba" | "cisco" | "mock" | "auto" | "meraki" | "unknown";
export type DeviceVendor = "Aruba" | "Cisco" | "Meraki" | "Mock" | "Unknown";
export type ScanVendor = Exclude<Vendor, "unknown">;
export type DriverVendor = Exclude<Vendor, "auto" | "unknown" | "meraki">;

export type LLDPCapability =
  | "bridge"
  | "router"
  | "wlan-ap"
  | "telephone"
  | "other";

export interface Device {
  id: DeviceId;
  hostname: string;
  managementIp?: string;
  chassisId?: string;
  macAddress?: string;
  model?: string;
  productName?: string;
  serial?: string;
  osVersion?: string;
  uptime?: string;
  vendor?: DeviceVendor;
  platform?: "aruba-cx" | "arubaos-s" | "aruba-s" | "cisco" | "meraki" | "unknown";
  kind?: DeviceKind;
  power?: {
    psu?: {
      count?: number;
      absentCount?: number;
      capacityW?: number;
      availableW?: number;
      status?: string;
      details?: string;
    };
    poe?: {
      availableW?: number;
      usedW?: number;
      remainingW?: number;
      status?: string;
      details?: string;
    };
  };
  capabilities?: LLDPCapability[];
  credentialUsed?: string;
  state: DeviceState;
  lastError?: string;
  discoveredAt?: string;
}

export interface Link {
  localHostname: string;
  localPort: string;
  remoteSystemName: string;
  remotePort: string;
  remotePortDescription?: string;
  remoteChassisId?: string;
  remoteManagementIp?: string;
  protocol?: "lldp" | "cdp";
  capabilities?: LLDPCapability[];
}

export interface ScanMetadata {
  id: string;
  startedAt: string;
  finishedAt?: string;
  seeds: string[];
  vendor: ScanVendor;
  neighborsSeen: number;
  neighborsResolvedToIp: number;
  neighborsEnqueued: number;
  concurrency: number;
  retries: number;
  timeoutMs: number;
}

export interface ScanResults {
  metadata: ScanMetadata;
  devices: Device[];
  links: Link[];
}

export interface CredentialSet {
  id: string;
  username: string;
  password?: string;
  sshKeyPath?: string;
  privateKey?: string;
  passphrase?: string;
  useAgent?: boolean;
  description?: string;
}

export interface ScanConfig {
  seeds: string[];
  vendor: ScanVendor;
  vendorsAllowList?: Array<Exclude<DriverVendor, "mock">>;
  credentials: CredentialSet[];
  sshMode?: "auto" | "force-modern" | "force-legacy" | "force-legacy-cisco";
  debug?: boolean;
  debugSsh?: boolean;
  resolveNeighbors?: "none" | "dns" | "dns+hostmap" | "arp" | "dns+arp" | "dns+hostmap+arp";
  hostmap?: Record<string, string>;
  includeEndpoints?: boolean;
  maxAttemptsPerHost?: number;
  connectTimeoutMs?: number;
  tcpProbeTimeoutMs?: number;
  concurrency?: number;
  retries?: number;
  timeoutMs?: number;
}

export interface DeviceFacts {
  hostname: string;
  model?: string;
  productName?: string;
  serial?: string;
  osVersion?: string;
  uptime?: string;
  chassisId?: string;
  macAddress?: string;
  managementIp?: string;
}

export interface LLDPNeighbor {
  localPort: string;
  remoteSystemName: string;
  remotePort: string;
  remotePortDescription?: string;
  remoteChassisId?: string;
  remoteManagementIp?: string;
  protocol?: "lldp" | "cdp";
  capabilities?: LLDPCapability[];
}

export interface DriverResult {
  facts: DeviceFacts;
  neighbors: LLDPNeighbor[];
  credentialUsed?: string;
  vendor?: DeviceVendor;
  platform?: "aruba-cx" | "arubaos-s" | "aruba-s" | "cisco" | "unknown";
  power?: Device["power"];
  arpTable?: Record<string, string>;
}

export type Credentials = CredentialSet[];

export interface DeviceDriver {
  name: DriverVendor;
  getFactsAndNeighbors(
    target: string,
    credentials: Credentials,
    timeoutMs: number,
    sshMode?: "auto" | "force-modern" | "force-legacy" | "force-legacy-cisco",
    debugSsh?: boolean,
    logger?: Logger,
    tcpProbeTimeoutMs?: number,
    connectTimeoutMs?: number
  ): Promise<DriverResult>;
}
