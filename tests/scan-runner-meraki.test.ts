import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { runScan } from "../src/scan/runScan.js";

function makeResponse(payload: any, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => null },
    json: async () => payload
  } as unknown as Response;
}

function readFixture(relativePath: string) {
  const filePath = path.resolve(process.cwd(), relativePath);
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function mockFetch(url: RequestInfo): Promise<Response> {
  const value = typeof url === "string" ? url : url.toString();
  const parsed = new URL(value);
  const pathName = parsed.pathname.replace("/api/v1", "");

  let payload: any = null;
  if (pathName === "/organizations") {
    payload = readFixture("tests/fixtures/meraki/organizations.json");
  } else if (pathName === "/organizations/org1/networks") {
    payload = readFixture("tests/fixtures/meraki/networks.json");
  } else if (pathName === "/networks/net1/devices") {
    payload = readFixture("tests/fixtures/meraki/devices.json");
  } else if (pathName === "/devices/Q2SW-AAAA-0001/lldpCdp") {
    payload = readFixture("tests/fixtures/meraki/lldpCdp_Q2SW-AAAA-0001.json");
  } else if (pathName === "/devices/Q2SW-BBBB-0002/lldpCdp") {
    payload = readFixture("tests/fixtures/meraki/lldpCdp_Q2SW-BBBB-0002.json");
  } else if (pathName === "/devices/Q2SW-AAAA-0001/switch/ports/statuses") {
    payload = readFixture("tests/fixtures/meraki/portStatuses_Q2SW-AAAA-0001.json");
  } else if (pathName === "/devices/Q2SW-BBBB-0002/switch/ports/statuses") {
    payload = readFixture("tests/fixtures/meraki/portStatuses_Q2SW-BBBB-0002.json");
  } else {
    return Promise.resolve(makeResponse({}, 404));
  }

  return Promise.resolve(makeResponse(payload, 200));
}

test("runScan integrates Meraki collector and writes artifacts", async () => {
  process.env.MERAKI_DASHBOARD_API_KEY = "test-key";
  process.env.MERAKI_ORG_ID = "org1";
  const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), "meraki-scan-"));
  const now = () => new Date("2026-01-01T00:00:00.000Z");

  const result = await runScan({
    source: "meraki",
    emitRaw: false,
    fetchFn: mockFetch,
    outputDir,
    scanId: "meraki-test",
    now
  });

  assert.ok(result.summary.metadata.id);
  assert.equal(result.summary.metadata.vendor, "meraki");
  assert.ok(result.summary.deviceCount > 0);
  assert.ok(result.summary.linkCount > 0);

  const resultsPath = path.join(outputDir, "scan-meraki-test", "results.json");
  assert.ok(fs.existsSync(resultsPath));
  const rawPath = path.join(outputDir, "scan-meraki-test", "raw.json");
  assert.ok(!fs.existsSync(rawPath));

  const saved = JSON.parse(fs.readFileSync(resultsPath, "utf8"));
  assert.equal(saved.metadata.id, "meraki-test");
  assert.equal(saved.devices.length, result.summary.deviceCount);
  assert.equal(saved.links.length, result.summary.linkCount);

  const edges = saved.links as Array<{ localHostname: string; localPort: string; remoteSystemName: string; protocol: string }>;
  const sorted = [...edges].sort((a, b) => {
    const aKey = `${a.localHostname}|${a.localPort}|${a.remoteSystemName}`;
    const bKey = `${b.localHostname}|${b.localPort}|${b.remoteSystemName}`;
    return aKey.localeCompare(bKey);
  });
  assert.deepEqual(edges, sorted);
});

test("runScan writes raw artifacts when emitRaw is true", async () => {
  process.env.MERAKI_DASHBOARD_API_KEY = "test-key";
  process.env.MERAKI_ORG_ID = "org1";
  const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), "meraki-raw-"));
  const now = () => new Date("2026-01-02T00:00:00.000Z");

  await runScan({
    source: "meraki",
    emitRaw: true,
    fetchFn: mockFetch,
    outputDir,
    scanId: "meraki-raw",
    now
  });

  const rawPath = path.join(outputDir, "scan-meraki-raw", "raw.json");
  assert.ok(fs.existsSync(rawPath));
  const raw = JSON.parse(fs.readFileSync(rawPath, "utf8"));
  assert.ok(raw.devices);
  assert.ok(raw.lldpCdpBySerial);
});
