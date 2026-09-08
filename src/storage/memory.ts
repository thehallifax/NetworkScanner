import { Device, DeviceId, Link, ScanMetadata } from "../types.js";

export class MemoryStore {
  private devices = new Map<DeviceId, Device>();
  private links: Link[] = [];
  private metadata: ScanMetadata;

  constructor(metadata: ScanMetadata) {
    this.metadata = metadata;
  }

  getMetadata() {
    return this.metadata;
  }

  setMetadata(update: Partial<ScanMetadata>) {
    this.metadata = { ...this.metadata, ...update };
  }

  upsertDevice(device: Device) {
    this.devices.set(device.id, device);
  }

  updateDevice(id: DeviceId, update: Partial<Device>) {
    const current = this.devices.get(id);
    if (!current) return;
    this.devices.set(id, { ...current, ...update });
  }

  getDevices() {
    return Array.from(this.devices.values());
  }

  addLink(link: Link) {
    this.links.push(link);
  }

  getLinks() {
    return this.links.slice();
  }
}
