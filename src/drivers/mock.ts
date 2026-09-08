import fs from "fs";
import path from "path";
import { DeviceDriver, DriverResult } from "../types.js";

const mockPath = path.resolve("mocks/topology.json");

function loadMock() {
  const raw = fs.readFileSync(mockPath, "utf8");
  return JSON.parse(raw) as {
    devices: Array<{
      hostname: string;
      managementIp?: string;
      chassisId?: string;
      model?: string;
      neighbors: DriverResult["neighbors"];
    }>;
  };
}

export const mockDriver: DeviceDriver = {
  name: "mock",
  async getFactsAndNeighbors(
    target,
    credentials,
    _timeoutMs,
    _sshMode,
    _debugSsh,
    _logger,
    _tcpProbeTimeoutMs,
    _connectTimeoutMs
  ) {
    const mock = loadMock();
    const device = mock.devices.find(
      (item) => item.managementIp === target || item.hostname === target
    );

    if (!device) {
      return {
        facts: {
          hostname: target
        },
        neighbors: []
      };
    }

    return {
      facts: {
        hostname: device.hostname,
        managementIp: device.managementIp,
        chassisId: device.chassisId,
        model: device.model,
        macAddress: device.chassisId
      },
      neighbors: device.neighbors,
      credentialUsed: credentials[0]?.id,
      vendor: "Mock",
      platform: "unknown"
    };
  }
};
