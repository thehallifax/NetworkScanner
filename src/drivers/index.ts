import { DeviceDriver, DriverVendor } from "../types.js";
import { arubaDriver } from "./aruba.js";
import { arubaOsSDriver } from "./arubaos-s.js";
import { ciscoDriver } from "./cisco.js";
import { mockDriver } from "./mock.js";

const drivers: Record<DriverVendor, DeviceDriver> = {
  aruba: arubaDriver,
  cisco: ciscoDriver,
  mock: mockDriver
};

export function getDriver(vendor: DriverVendor): DeviceDriver {
  return drivers[vendor];
}

export function getArubaOsSDriver() {
  return arubaOsSDriver;
}
