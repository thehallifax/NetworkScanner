import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { normalizeMerakiTopology } from "../src/meraki/normalize.js";
import { MerakiDevice, MerakiLldpCdp, MerakiPortStatus } from "../src/meraki/types.js";

function readJson<T>(relativePath: string): T {
  const filePath = path.resolve(process.cwd(), relativePath);
  return JSON.parse(fs.readFileSync(filePath, "utf8")) as T;
}

test("normalizeMerakiTopology builds edges and dedupes LLDP/CDP", () => {
  const devices = readJson<MerakiDevice[]>("tests/fixtures/meraki/devices.json");
  const lldpCdpBySerial: Record<string, MerakiLldpCdp> = {
    "Q2SW-AAAA-0001": readJson<MerakiLldpCdp>("tests/fixtures/meraki/lldpCdp_Q2SW-AAAA-0001.json"),
    "Q2SW-BBBB-0002": readJson<MerakiLldpCdp>("tests/fixtures/meraki/lldpCdp_Q2SW-BBBB-0002.json")
  };
  const portStatusesBySerial: Record<string, MerakiPortStatus[]> = {
    "Q2SW-AAAA-0001": readJson<MerakiPortStatus[]>("tests/fixtures/meraki/portStatuses_Q2SW-AAAA-0001.json"),
    "Q2SW-BBBB-0002": readJson<MerakiPortStatus[]>("tests/fixtures/meraki/portStatuses_Q2SW-BBBB-0002.json")
  };

  const edges = normalizeMerakiTopology({
    devices,
    lldpCdpBySerial,
    portStatusesBySerial
  });

  assert.ok(edges.length > 0, "edges should not be empty");

  const required = [
    "localHostname",
    "localPort",
    "remoteSystemName",
    "remotePort",
    "protocol"
  ];
  for (const edge of edges) {
    for (const key of required) {
      assert.ok(edge[key as keyof typeof edge], `edge missing ${key}`);
    }
  }

  const deduped = edges.filter((edge) => edge.localHostname === "Core-SW-01" && edge.localPort === "1");
  assert.equal(deduped.length, 1);
  assert.equal(deduped[0].protocol, "lldp");

  const resolved = edges.find((edge) => edge.remoteSystemName === "Edge-SW-02");
  assert.equal(resolved?.remoteChassisId, "Q2SW-BBBB-0002");

  const sorted = [...edges].sort((a, b) => {
    const aKey = `${a.localHostname}|${a.localPort}|${a.remoteSystemName}`;
    const bKey = `${b.localHostname}|${b.localPort}|${b.remoteSystemName}`;
    return aKey.localeCompare(bKey);
  });
  assert.deepEqual(edges, sorted);
});
