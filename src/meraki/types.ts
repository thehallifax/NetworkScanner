export type MerakiDevice = {
  serial: string;
  name?: string;
  hostname?: string;
  mac?: string;
  lanIp?: string;
  wan1Ip?: string;
  wan2Ip?: string;
  wiredIp?: string;
  productType?: string;
  model?: string;
  firmware?: string;
  lastReportedAt?: string;
};

export type MerakiLldpCdpPort = {
  lldp?: {
    systemName?: string;
    portId?: string;
    chassisId?: string;
    managementAddress?: string;
  };
  cdp?: {
    deviceId?: string;
    portId?: string;
    address?: string;
    platform?: string;
    capabilities?: string;
  };
};

export type MerakiLldpCdp = {
  ports: Record<string, MerakiLldpCdpPort>;
};

export type MerakiPortStatus = {
  portId: string;
  enabled?: boolean;
  status?: string;
  speed?: string;
};
