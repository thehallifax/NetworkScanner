const credsContainer = document.getElementById("credentials");
const addCredentialButton = document.getElementById("add-credential");
const startScanButton = document.getElementById("start-scan");
const scanForm = document.getElementById("scan-form");
const formMessage = document.getElementById("form-message");
const statusPill = document.getElementById("scan-status");
const metadataEl = document.getElementById("metadata");
const devicesEl = document.getElementById("devices");
const linksEl = document.getElementById("links");
const topologyEl = document.getElementById("topology");
const scanSourceSelect = document.getElementById("scanSource");
const emitRawToggle = document.getElementById("emitRaw");
const exportJsonButton = document.getElementById("export-json");
const exportDevicesButton = document.getElementById("export-devices");
const exportLinksButton = document.getElementById("export-links");
const showEndpointsToggle = document.getElementById("show-endpoints");
const linksSwitchOnlyToggle = document.getElementById("links-switch-only");
const topologySwitchOnlyToggle = document.getElementById("topology-switch-only");
const tabButtons = document.querySelectorAll(".tab-button");
const tabPanels = {
  devices: document.getElementById("tab-devices"),
  links: document.getElementById("tab-links"),
  topology: document.getElementById("tab-topology"),
  debug: document.getElementById("tab-debug")
};
const deviceDetailsPanel = document.getElementById("device-details");
const deviceDetailsTabs = document.querySelectorAll(".details-tab");
const deviceDetailsContent = document.getElementById("details-content");
const configOutput = document.getElementById("config-output");
const fetchConfigButton = document.getElementById("fetch-config");
const downloadConfigButton = document.getElementById("download-config");
const redactToggle = document.getElementById("config-redact");
const configMode = document.getElementById("config-mode");
const wrapToggle = document.getElementById("config-wrap-toggle");
const copyConfigButton = document.getElementById("copy-config");
const logView = document.getElementById("log-view");
const logLevelSelect = document.getElementById("log-level");
const logSearchInput = document.getElementById("log-search");
const logPauseToggle = document.getElementById("log-pause");
const copyLogsButton = document.getElementById("copy-logs");
const clearLogsButton = document.getElementById("clear-logs");
const merakiSection = document.getElementById("merakiSection");
const discoveryTargets = document.getElementById("discovery-targets");
const credentialsSection = document.getElementById("credentials-section");
const sshSection = document.getElementById("sshSection");
const merakiApiKeyInput = document.getElementById("merakiApiKey");
const merakiOrgIdInput = document.getElementById("merakiOrgId");
const merakiOrgNameInput = document.getElementById("merakiOrgName");
const merakiNetworkIdInput = document.getElementById("merakiNetworkId");

let currentScanId = null;
let pollTimer = null;
let lastDevices = [];
let lastLinks = [];
let logTimer = null;
let logs = [];
let lastLogSince = 0;
let activeTab = "devices";
let userScrolledLog = false;
let activeScan = null;
let scanFinished = false;
let selectedDeviceId = null;
let configCache = "";
let logPolling = false;
let logPollAbort = null;

const draftScanConfig = {
  vendor: "auto",
  allowAruba: true,
  allowCisco: true,
  seeds: "",
  credentials: [],
  timeoutMs: 8000,
  concurrency: 5,
  resolveNeighbors: "dns+arp",
  hostmap: "",
  sshMode: "auto",
  debug: true,
  includeEndpoints: false,
  maxAttemptsPerHost: 1,
  connectTimeoutMs: 15000,
  tcpProbeTimeoutMs: 400
};

function createKey() {
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function createInput(labelText, type = "text", placeholder = "") {
  const wrapper = document.createElement("div");
  const label = document.createElement("label");
  label.textContent = labelText;
  const input = document.createElement("input");
  input.type = type;
  input.placeholder = placeholder;
  wrapper.appendChild(label);
  wrapper.appendChild(input);
  return { wrapper, input };
}

function createCredentialRow(credential) {
  const row = document.createElement("div");
  row.className = "cred-row";

  const idField = createInput("ID", "text", "core");
  const userField = createInput("Username", "text", "admin");
  const passField = createInput("Password", "password", "secret");
  const keyField = createInput("SSH Key Path", "text", "/home/user/.ssh/id_rsa");
  const passphraseField = createInput("Key Passphrase", "password", "optional");
  const descField = createInput("Description", "text", "optional");
  const agentWrapper = document.createElement("div");
  const agentLabel = document.createElement("label");
  agentLabel.textContent = "Use SSH Agent";
  const agentInput = document.createElement("input");
  agentInput.type = "checkbox";
  agentWrapper.appendChild(agentLabel);
  agentWrapper.appendChild(agentInput);

  const privateKeyWrapper = document.createElement("div");
  const privateKeyLabel = document.createElement("label");
  privateKeyLabel.textContent = "Private Key (paste)";
  const privateKeyInput = document.createElement("textarea");
  privateKeyInput.placeholder = "-----BEGIN PRIVATE KEY-----";
  privateKeyInput.className = "masked mono";
  privateKeyWrapper.appendChild(privateKeyLabel);
  privateKeyWrapper.appendChild(privateKeyInput);

  idField.input.value = credential.id || "";
  userField.input.value = credential.username || "";
  passField.input.value = credential.password || "";
  keyField.input.value = credential.sshKeyPath || "";
  passphraseField.input.value = credential.passphrase || "";
  descField.input.value = credential.description || "";
  privateKeyInput.value = credential.privateKey || "";
  agentInput.checked = Boolean(credential.useAgent);

  row.appendChild(idField.wrapper);
  row.appendChild(userField.wrapper);
  row.appendChild(passField.wrapper);
  row.appendChild(keyField.wrapper);
  row.appendChild(privateKeyWrapper);
  row.appendChild(passphraseField.wrapper);
  row.appendChild(agentWrapper);
  row.appendChild(descField.wrapper);

  const actions = document.createElement("div");
  actions.className = "cred-actions";

  const moveUp = document.createElement("button");
  moveUp.className = "ghost";
  moveUp.type = "button";
  moveUp.textContent = "Move up";
  moveUp.onclick = () => {
    const prev = row.previousElementSibling;
    if (prev) credsContainer.insertBefore(row, prev);
  };

  const moveDown = document.createElement("button");
  moveDown.className = "ghost";
  moveDown.type = "button";
  moveDown.textContent = "Move down";
  moveDown.onclick = () => {
    const next = row.nextElementSibling;
    if (next) credsContainer.insertBefore(next, row);
  };

  const remove = document.createElement("button");
  remove.className = "secondary";
  remove.type = "button";
  remove.textContent = "Remove";
  remove.onclick = () => {
    row.remove();
  };

  actions.appendChild(moveUp);
  actions.appendChild(moveDown);
  actions.appendChild(remove);
  row.appendChild(actions);

  const toggleAgent = () => {
    const disabled = agentInput.checked;
    passField.input.disabled = disabled;
    keyField.input.disabled = disabled;
    privateKeyInput.disabled = disabled;
    passphraseField.input.disabled = disabled;
  };
  agentInput.addEventListener("change", toggleAgent);
  toggleAgent();

  const updateCredential = () => {
    credential.id = idField.input.value.trim();
    credential.username = userField.input.value.trim();
    credential.password = passField.input.value;
    credential.sshKeyPath = keyField.input.value.trim();
    credential.privateKey = privateKeyInput.value;
    credential.passphrase = passphraseField.input.value;
    credential.useAgent = agentInput.checked;
    credential.description = descField.input.value.trim();
  };

  [
    idField.input,
    userField.input,
    passField.input,
    keyField.input,
    passphraseField.input,
    descField.input,
    privateKeyInput,
    agentInput
  ].forEach((input) => {
    input.addEventListener("input", updateCredential);
    input.addEventListener("change", updateCredential);
  });

  return row;
}

function setMessage(message, isError = false) {
  formMessage.textContent = message;
  formMessage.style.color = isError ? "#a33" : "#6c6a66";
}

function clearSensitiveInputs() {
  document.querySelectorAll(".cred-row input[type='password']").forEach((input) => {
    input.value = "";
  });
  document.querySelectorAll(".cred-row textarea").forEach((input) => {
    input.value = "";
  });
  document.querySelectorAll(".cred-row input[type='text']").forEach((input) => {
    if (input.placeholder && input.placeholder.includes(".ssh/")) {
      input.value = "";
    }
  });
  if (merakiApiKeyInput) {
    merakiApiKeyInput.value = "";
  }
}

function renderCredentials() {
  credsContainer.innerHTML = "";
  draftScanConfig.credentials.forEach((credential) => {
    const row = createCredentialRow(credential);
    row.dataset.key = credential._key;
    const buttons = row.querySelectorAll("button");
    const moveUp = buttons[0];
    const moveDown = buttons[1];
    const remove = buttons[2];
    moveUp.onclick = () => {
      const idx = draftScanConfig.credentials.indexOf(credential);
      if (idx > 0) {
        draftScanConfig.credentials.splice(idx - 1, 0, draftScanConfig.credentials.splice(idx, 1)[0]);
        renderCredentials();
      }
    };
    moveDown.onclick = () => {
      const idx = draftScanConfig.credentials.indexOf(credential);
      if (idx < draftScanConfig.credentials.length - 1) {
        draftScanConfig.credentials.splice(idx + 1, 0, draftScanConfig.credentials.splice(idx, 1)[0]);
        renderCredentials();
      }
    };
    remove.onclick = () => {
      draftScanConfig.credentials = draftScanConfig.credentials.filter((item) => item !== credential);
      renderCredentials();
    };
    credsContainer.appendChild(row);
  });
}

function parseHostmap(input) {
  const map = {};
  input
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"))
    .forEach((line) => {
      const [key, value] = line.split("=").map((part) => part.trim());
      if (key && value) {
        map[key] = value;
      }
    });
  return map;
}

function renderTable(target, rows, columns) {
  if (!rows.length) {
    target.innerHTML = "<div class='subtitle'>No data yet.</div>";
    return;
  }
  const table = document.createElement("table");
  const thead = document.createElement("thead");
  const headerRow = document.createElement("tr");
  columns.forEach((col) => {
    const th = document.createElement("th");
    th.textContent = col.label;
    headerRow.appendChild(th);
  });
  thead.appendChild(headerRow);
  table.appendChild(thead);

  const tbody = document.createElement("tbody");
  rows.forEach((row) => {
    const tr = document.createElement("tr");
    columns.forEach((col) => {
      const td = document.createElement("td");
      const value = row[col.key] ?? "";
      td.textContent = String(value);
      if (col.mono) td.classList.add("mono");
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  target.innerHTML = "";
  target.appendChild(table);
}

async function refreshScan() {
  if (!currentScanId) return;
  try {
    if (document.hidden) return;
    const needsInventory = ["devices", "links", "topology"].includes(activeTab);
    const statusRes = await fetch(`/scans/${currentScanId}`, { cache: "no-store" });
    const [devicesRes, linksRes] = await Promise.all([
      needsInventory ? fetch(`/scans/${currentScanId}/devices`, { cache: "no-store" }) : null,
      needsInventory ? fetch(`/scans/${currentScanId}/links`, { cache: "no-store" }) : null
    ]);

    if (!statusRes.ok) throw new Error("Failed to load scan status");

    const status = await statusRes.json();
    const devices = devicesRes && devicesRes.ok ? await devicesRes.json() : lastDevices;
    const links = linksRes && linksRes.ok ? await linksRes.json() : lastLinks;
    lastDevices = devices;
    lastLinks = links;

    scanFinished = Boolean(status.metadata?.finishedAt);
    statusPill.textContent = scanFinished ? "Completed" : "Running";
    metadataEl.innerHTML = `
      <div><strong>Scan ID:</strong> <span class="mono">${status.metadata.id}</span></div>
      <div><strong>Started:</strong> ${status.metadata.startedAt}</div>
      <div><strong>Finished:</strong> ${status.metadata.finishedAt || "-"}</div>
      <div><strong>Devices:</strong> ${status.deviceCount} &nbsp; <strong>Links:</strong> ${status.linkCount}</div>
      <div><strong>Neighbors seen:</strong> ${status.metadata.neighborsSeen ?? 0}</div>
      <div><strong>Neighbors resolved:</strong> ${status.metadata.neighborsResolvedToIp ?? 0}</div>
      <div><strong>Neighbors enqueued:</strong> ${status.metadata.neighborsEnqueued ?? 0}</div>
    `;

    if (needsInventory) {
      renderDevices();

      renderLinks();

      renderTopology();

      if (selectedDeviceId) {
        renderDeviceDetails();
      }
    }
    if (scanFinished) {
      stopPolling();
      stopLogPolling();
    }
  } catch (err) {
    statusPill.textContent = "Error";
    setMessage(err instanceof Error ? err.message : "Scan error", true);
  }
}

function renderDevices() {
  const showEndpoints = showEndpointsToggle?.checked;
  const devices = showEndpoints
    ? lastDevices
    : lastDevices.filter((device) => device.kind === "switch");
  renderTable(devicesEl, devices, [
    { key: "hostname", label: "Hostname" },
    { key: "managementIp", label: "Mgmt IP" },
    { key: "model", label: "Model" },
    { key: "productName", label: "Product" },
    { key: "serial", label: "Serial" },
    { key: "chassisId", label: "Chassis ID", mono: true },
    { key: "osVersion", label: "OS Version" },
    { key: "uptime", label: "Uptime" },
    { key: "vendor", label: "Vendor" },
    { key: "platform", label: "Platform" },
    { key: "kind", label: "Kind" },
    { key: "state", label: "State" },
    { key: "credentialUsed", label: "Credential Used" },
    { key: "lastError", label: "Error" }
  ]);
  Array.from(devicesEl.querySelectorAll("tbody tr")).forEach((row, idx) => {
    row.style.cursor = "pointer";
    row.addEventListener("click", () => {
      selectedDeviceId = devices[idx]?.id || devices[idx]?.chassisId || devices[idx]?.managementIp || null;
      renderDeviceDetails();
    });
  });
}

function buildDeviceMap() {
  const map = new Map();
  lastDevices.forEach((device) => {
    map.set(device.hostname, device);
    if (device.chassisId) {
      map.set(device.chassisId, device);
    }
  });
  return map;
}

function renderLinks() {
  const deviceMap = buildDeviceMap();
  const switchOnly = linksSwitchOnlyToggle?.checked;
  const links = switchOnly
    ? lastLinks.filter(
        (link) =>
          deviceMap.get(link.localHostname)?.kind === "switch"
          && deviceMap.get(link.remoteSystemName)?.kind === "switch"
      )
    : lastLinks;

  const rows = links.map((link) => {
    const remoteDevice =
      deviceMap.get(link.remoteSystemName) || (link.remoteChassisId ? deviceMap.get(link.remoteChassisId) : undefined);
    return {
      ...link,
      remoteManagementIp: remoteDevice?.managementIp || ""
    };
  });

  renderTable(linksEl, rows, [
    { key: "localHostname", label: "Local" },
    { key: "localPort", label: "Local Port", mono: true },
    { key: "remoteSystemName", label: "Remote" },
    { key: "remotePort", label: "Remote Port", mono: true },
    { key: "remotePortDescription", label: "Remote Port Desc" },
    { key: "remoteManagementIp", label: "Mgmt IP" }
  ]);
}

function renderTopology() {
  const deviceMap = buildDeviceMap();
  const switchOnly = topologySwitchOnlyToggle?.checked;
  const links = switchOnly
    ? lastLinks.filter(
        (link) =>
          deviceMap.get(link.localHostname)?.kind === "switch"
          && deviceMap.get(link.remoteSystemName)?.kind === "switch"
      )
    : lastLinks;

  if (links.length) {
    topologyEl.innerHTML = links
      .map(
        (link) =>
          `<div>${link.localHostname} ${link.localPort} → ${link.remoteSystemName} ${link.remotePort}</div>`
      )
      .join("");
  } else {
    topologyEl.textContent = "No links yet.";
  }
}

function renderDeviceDetails() {
  const selectedDevice =
    lastDevices.find((device) => device.id === selectedDeviceId)
    || lastDevices.find((device) => device.chassisId === selectedDeviceId)
    || lastDevices.find((device) => device.managementIp === selectedDeviceId);
  if (!selectedDevice) {
    deviceDetailsPanel.classList.add("hidden");
    return;
  }
  deviceDetailsPanel.classList.remove("hidden");
  configCache = "";
  renderDetailsTab("summary", selectedDevice);
}

function renderDetailsTab(tab, selectedDevice) {
  if (!selectedDevice) return;
  deviceDetailsTabs.forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.tab === tab);
  });
  const isMeraki = selectedDevice.platform === "meraki";
  const showConfig = tab === "config" && !isMeraki;
  document.getElementById("config-controls").style.display = showConfig ? "block" : "none";
  configOutput.style.display = showConfig ? "block" : "none";
  if (tab === "summary") {
    deviceDetailsContent.innerHTML = `
      <div><strong>Hostname:</strong> ${selectedDevice.hostname || "-"}</div>
      <div><strong>Mgmt IP:</strong> ${selectedDevice.managementIp || "-"}</div>
      <div><strong>Vendor/Platform:</strong> ${selectedDevice.vendor || "-"} / ${selectedDevice.platform || "-"}</div>
      <div><strong>Model/Product:</strong> ${selectedDevice.model || "-"} / ${selectedDevice.productName || "-"}</div>
      <div><strong>Serial:</strong> ${selectedDevice.serial || "-"}</div>
      <div><strong>Chassis ID:</strong> ${selectedDevice.chassisId || "-"}</div>
      <div><strong>OS Version:</strong> ${selectedDevice.osVersion || "-"}</div>
      <div><strong>Uptime:</strong> ${selectedDevice.uptime || "-"}</div>
      <div><strong>Credential Used:</strong> ${selectedDevice.credentialUsed || "-"}</div>
      <div><strong>State:</strong> ${selectedDevice.state || "-"}</div>
      <div><strong>Error:</strong> ${selectedDevice.lastError || "-"}</div>
    `;
  }
  if (tab === "power") {
    const poe = selectedDevice.power?.poe;
    const psu = selectedDevice.power?.psu;
    const formatW = (value) => (value === undefined || value === null ? "N/A" : `${value} W`);
    const poeHasNumbers = poe?.usedW !== undefined || poe?.availableW !== undefined || poe?.remainingW !== undefined;
    const psuHasNumbers = psu?.count !== undefined || psu?.capacityW !== undefined;
    const poeStatus = poe?.status === "not_supported" && !poeHasNumbers
      ? " (not supported)"
      : poe?.status
        ? ` (${poe.status})`
        : "";
    const psuStatus = psu?.status === "not_supported" && !psuHasNumbers
      ? " (not supported)"
      : psu?.status
        ? ` (${psu.status})`
        : "";
    deviceDetailsContent.innerHTML = `
      <div><strong>PoE Used:</strong> ${formatW(poe?.usedW)}${poeStatus}</div>
      <div><strong>PoE Available:</strong> ${formatW(poe?.availableW)}</div>
      <div><strong>PoE Remaining:</strong> ${formatW(poe?.remainingW)}</div>
      <div><strong>PSU:</strong> ${
        psu?.status === "not_supported" && !psuHasNumbers
          ? "Not supported by platform"
          : `${psu?.count ?? "N/A"} present (${psu?.absentCount ?? 0} absent)`
      }${psuStatus}</div>
      <div><strong>Total Capacity:</strong> ${formatW(psu?.capacityW)}</div>
      <details>
        <summary>PoE raw output</summary>
        <pre>${poe?.details || ""}</pre>
      </details>
      <details>
        <summary>PSU raw output</summary>
        <pre>${psu?.details || ""}</pre>
      </details>
    `;
  }
  if (tab === "config") {
    if (isMeraki) {
      deviceDetailsContent.innerHTML = "<div>Running config is not supported for Meraki Dashboard devices.</div>";
      return;
    }
    deviceDetailsContent.innerHTML = "";
    configOutput.textContent = configCache || "";
  }
}

function startPolling() {
  if (!currentScanId || scanFinished) return;
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(refreshScan, 2000);
  refreshScan();
}

function stopPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = null;
}

function resetLogs() {
  logs = [];
  lastLogSince = 0;
  userScrolledLog = false;
  renderLogs();
}

addCredentialButton.addEventListener("click", () => {
  draftScanConfig.credentials.push({ _key: createKey() });
  renderCredentials();
});

function getSeedDevices() {
  return draftScanConfig.seeds
    .split("\n")
    .map((seed) => seed.trim())
    .filter(Boolean);
}

function getCredentials() {
  return draftScanConfig.credentials
    .map((cred) => ({ ...cred }))
    .filter((cred) => cred.id || cred.username);
}

function getScanOptions() {
  const vendor = draftScanConfig.vendor;
  const allowAruba = draftScanConfig.allowAruba;
  const allowCisco = draftScanConfig.allowCisco;
  return {
    vendorsAllowList:
      vendor === "auto" ? [allowAruba ? "aruba" : null, allowCisco ? "cisco" : null].filter(Boolean) : undefined,
    resolveNeighbors: draftScanConfig.resolveNeighbors,
    sshMode: draftScanConfig.sshMode,
    debug: draftScanConfig.debug,
    hostmap: parseHostmap(draftScanConfig.hostmap),
    includeEndpoints: draftScanConfig.includeEndpoints,
    maxAttemptsPerHost: draftScanConfig.maxAttemptsPerHost,
    connectTimeoutMs: draftScanConfig.connectTimeoutMs,
    tcpProbeTimeoutMs: draftScanConfig.tcpProbeTimeoutMs,
    timeoutMs: draftScanConfig.timeoutMs,
    concurrency: draftScanConfig.concurrency
  };
}

function buildScanPayload() {
  const source = scanSourceSelect?.value || "ssh";
  const emitRaw = emitRawToggle?.checked ?? false;

  if (source === "meraki") {
    return {
      source: "meraki",
      emitRaw,
      meraki: {
        apiKey: merakiApiKeyInput?.value.trim() || "",
        orgId: merakiOrgIdInput?.value.trim() || undefined,
        orgName: merakiOrgNameInput?.value.trim() || undefined,
        networkId: merakiNetworkIdInput?.value.trim() || undefined
      }
    };
  }

  return {
    source: "ssh",
    vendor: document.getElementById("vendor")?.value || "auto",
    seedDevices: getSeedDevices(),
    credentials: getCredentials(),
    options: getScanOptions(),
    emitRaw
  };
}

startScanButton.addEventListener("click", async () => {
  console.log("startScan clicked");
  setMessage("");
  const payload = buildScanPayload();
  if (payload.source === "meraki") {
    if (!payload.meraki.apiKey) {
      setMessage("Provide a Meraki Dashboard API key.", true);
      return;
    }
  } else {
    if (!payload.seedDevices.length) {
      setMessage("Provide at least one seed device.", true);
      return;
    }
    if (!payload.credentials.length) {
      setMessage("Provide at least one credential.", true);
      return;
    }
    if (payload.credentials.some((cred) => !cred.id || !cred.username)) {
      setMessage("Every credential requires an id and username.", true);
      return;
    }
  }

  try {
    const response = await fetch("/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      let errorBody = "";
      try {
        errorBody = await response.text();
      } catch {
        errorBody = "";
      }
      console.error("Start scan failed", response.status, errorBody);
      let message = "Failed to start scan";
      try {
        const parsed = errorBody ? JSON.parse(errorBody) : null;
        if (parsed?.error) message = parsed.error;
      } catch {
        // Ignore invalid JSON in error body.
      }
      throw new Error(message);
    }

    const result = await response.json();
    currentScanId = result.scanId;
    activeScan = result.metadata;
    scanFinished = false;
    statusPill.textContent = "Running";
    setMessage(`Scan started: ${currentScanId}`);
    clearSensitiveInputs();
    startPolling();
    switchTab("devices");
    resetLogs();
    if (activeTab === "debug") startLogPolling();
  } catch (err) {
    setMessage(err instanceof Error ? err.message : "Failed to start scan", true);
  }
});

scanForm?.addEventListener("submit", (event) => {
  event.preventDefault();
});

function bindExport(button, endpoint) {
  button.addEventListener("click", () => {
    if (!currentScanId) return;
    window.open(endpoint(currentScanId), "_blank");
  });
}

bindExport(exportJsonButton, (id) => `/scans/${id}/export/json`);
bindExport(exportDevicesButton, (id) => `/scans/${id}/export/csv`);
bindExport(exportLinksButton, (id) => `/scans/${id}/export/csv-links`);

setMessage("Ready to scan.");
// Start polling only after a scan starts.

function bindDraftInputs() {
  document.getElementById("vendor").addEventListener("change", (event) => {
    draftScanConfig.vendor = event.target.value;
  });
  document.getElementById("allow-aruba").addEventListener("change", (event) => {
    draftScanConfig.allowAruba = event.target.checked;
  });
  document.getElementById("allow-cisco").addEventListener("change", (event) => {
    draftScanConfig.allowCisco = event.target.checked;
  });
  document.getElementById("seeds").addEventListener("input", (event) => {
    draftScanConfig.seeds = event.target.value;
  });
  document.getElementById("timeout").addEventListener("input", (event) => {
    draftScanConfig.timeoutMs = Number(event.target.value || 8000);
  });
  document.getElementById("concurrency").addEventListener("input", (event) => {
    draftScanConfig.concurrency = Number(event.target.value || 5);
  });
  document.getElementById("resolve-neighbors").addEventListener("change", (event) => {
    draftScanConfig.resolveNeighbors = event.target.value;
  });
  document.getElementById("hostmap").addEventListener("input", (event) => {
    draftScanConfig.hostmap = event.target.value;
  });
  document.getElementById("ssh-mode").addEventListener("change", (event) => {
    draftScanConfig.sshMode = event.target.value;
  });
  document.getElementById("debug-toggle").addEventListener("change", (event) => {
    draftScanConfig.debug = event.target.checked;
  });
  document.getElementById("include-endpoints").addEventListener("change", (event) => {
    draftScanConfig.includeEndpoints = event.target.checked;
  });
  document.getElementById("max-attempts").addEventListener("input", (event) => {
    draftScanConfig.maxAttemptsPerHost = Number(event.target.value || 1);
  });
  document.getElementById("connect-timeout").addEventListener("input", (event) => {
    draftScanConfig.connectTimeoutMs = Number(event.target.value || 15000);
  });
  document.getElementById("tcp-probe-timeout").addEventListener("input", (event) => {
    draftScanConfig.tcpProbeTimeoutMs = Number(event.target.value || 400);
  });
}

draftScanConfig.credentials = [{ _key: createKey(), id: "core", username: "admin" }];
renderCredentials();
bindDraftInputs();

const vendorSelect = document.getElementById("vendor");
vendorSelect.addEventListener("change", (event) => {
  const value = event.target.value;
  const allowlistField = document.getElementById("allowlist-field");
  allowlistField.classList.toggle("hidden", value !== "auto");
});
vendorSelect.dispatchEvent(new Event("change"));

function updateSourceVisibility() {
  const source = scanSourceSelect?.value || "ssh";
  const isMeraki = source === "meraki";
  discoveryTargets.classList.toggle("hidden", isMeraki);
  credentialsSection.classList.toggle("hidden", isMeraki);
  sshSection.classList.toggle("hidden", isMeraki);
  merakiSection.classList.toggle("hidden", !isMeraki);
}

scanSourceSelect?.addEventListener("change", updateSourceVisibility);
updateSourceVisibility();

showEndpointsToggle?.addEventListener("change", renderDevices);
linksSwitchOnlyToggle?.addEventListener("change", renderLinks);
topologySwitchOnlyToggle?.addEventListener("change", renderTopology);

tabButtons.forEach((button) => {
  button.addEventListener("click", () => {
    switchTab(button.dataset.tab);
  });
});

function switchTab(tab) {
  if (!tabPanels[tab]) return;
  activeTab = tab;
  Object.entries(tabPanels).forEach(([key, el]) => {
    if (!el) return;
    el.classList.toggle("hidden", key !== tab);
  });
  tabButtons.forEach((button) => {
    button.classList.toggle("active", button.dataset.tab === tab);
  });
  if (tab === "debug") {
    startLogPolling();
  } else {
    stopLogPolling();
  }
  if (["devices", "links", "topology"].includes(tab)) {
    refreshScan();
  }
}

deviceDetailsTabs.forEach((button) => {
  button.addEventListener("click", () => {
    const selectedDevice =
      lastDevices.find((device) => device.id === selectedDeviceId)
      || lastDevices.find((device) => device.chassisId === selectedDeviceId)
      || lastDevices.find((device) => device.managementIp === selectedDeviceId);
    renderDetailsTab(button.dataset.tab, selectedDevice);
  });
});

fetchConfigButton.addEventListener("click", async () => {
  const selectedDevice =
    lastDevices.find((device) => device.id === selectedDeviceId)
    || lastDevices.find((device) => device.chassisId === selectedDeviceId)
    || lastDevices.find((device) => device.managementIp === selectedDeviceId);
  if (!selectedDevice || !currentScanId) return;
  if (selectedDevice.platform === "meraki") {
    configOutput.textContent = "Running config is not supported for Meraki Dashboard devices.";
    return;
  }
  const mode = configMode.value;
  const redact = redactToggle.checked;
  if (!redact) {
    const confirmUnsafe = window.confirm("Show unredacted config? This may expose secrets.");
    if (!confirmUnsafe) return;
  }
  const response = await fetch(`/scans/${currentScanId}/devices/${selectedDevice.id}/config`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mode, redact })
  });
  if (!response.ok) {
    configOutput.textContent = "Failed to fetch config.";
    return;
  }
  const result = await response.json();
  configCache = result.output || "";
  configOutput.textContent = configCache;
});

downloadConfigButton.addEventListener("click", () => {
  if (!configCache) return;
  const selectedDevice =
    lastDevices.find((device) => device.id === selectedDeviceId)
    || lastDevices.find((device) => device.chassisId === selectedDeviceId)
    || lastDevices.find((device) => device.managementIp === selectedDeviceId);
  const blob = new Blob([configCache], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `${selectedDevice?.hostname || "config"}.txt`;
  anchor.click();
  URL.revokeObjectURL(url);
});

copyConfigButton.addEventListener("click", () => {
  if (!configCache) return;
  navigator.clipboard.writeText(configCache);
});

wrapToggle.addEventListener("change", () => {
  configOutput.style.whiteSpace = wrapToggle.checked ? "pre-wrap" : "pre";
});

function renderLogs() {
  const levelFilter = logLevelSelect.value;
  const search = logSearchInput.value.toLowerCase();
  const filtered = logs.filter((entry) => {
    const levelOk = levelFilter === "all" || entry.level === levelFilter;
    const meta = entry.meta ? ` ${JSON.stringify(entry.meta)}` : "";
    const line = `[${entry.ts}] ${entry.level.toUpperCase()} ${entry.scope}: ${entry.message}${meta}`.toLowerCase();
    const searchOk = !search || line.includes(search);
    return levelOk && searchOk;
  });
  if (logs.length === 0) {
    logView.textContent = "No logs yet.";
    return;
  }
  if (filtered.length === 0) {
    logView.textContent = "No logs match the current filters.";
    return;
  }
  const lines = filtered.map((entry) => {
    const meta = entry.meta ? ` ${JSON.stringify(entry.meta)}` : "";
    return `[${entry.ts}] ${entry.level.toUpperCase()} ${entry.scope}: ${entry.message}${meta}`;
  });
  logView.textContent = lines.join("\n");
  if (!userScrolledLog) {
    logView.scrollTop = logView.scrollHeight;
  }
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 10000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function pollLogs() {
  if (!currentScanId || logPauseToggle.checked || activeTab !== "debug") return;
  if (logPolling) return;
  logPolling = true;
  if (logPollAbort) {
    logPollAbort.abort();
  }
  logPollAbort = new AbortController();
  try {
    const response = await fetchWithTimeout(
      `/scans/${currentScanId}/logs?since=${lastLogSince}&limit=200`,
      { cache: "no-store", signal: logPollAbort.signal },
      10000
    );
    if (!response.ok) return;
    const payload = await response.json();
    const newEntries = Array.isArray(payload?.logs) ? payload.logs : [];
    const nextSince = typeof payload?.nextSince === "number" ? payload.nextSince : lastLogSince;
    if (newEntries.length) {
      logs = logs.concat(newEntries);
      lastLogSince = nextSince;
      renderLogs();
    }
  } catch (err) {
    if (err?.name !== "AbortError") {
      // Ignore log polling errors.
    }
  } finally {
    logPolling = false;
  }
}

function startLogPolling() {
  if (!currentScanId || scanFinished) {
    pollLogs();
    return;
  }
  if (logTimer) clearInterval(logTimer);
  logTimer = setInterval(pollLogs, 1500);
  pollLogs();
}

function stopLogPolling() {
  if (logTimer) clearInterval(logTimer);
  logTimer = null;
  if (logPollAbort) {
    logPollAbort.abort();
    logPollAbort = null;
  }
  logPolling = false;
}

logLevelSelect.addEventListener("change", renderLogs);
logSearchInput.addEventListener("input", renderLogs);
logPauseToggle.addEventListener("change", () => {
  if (!logPauseToggle.checked) pollLogs();
});
copyLogsButton.addEventListener("click", () => {
  navigator.clipboard.writeText(logView.textContent || "");
});
clearLogsButton.addEventListener("click", async () => {
  if (!currentScanId) return;
  await fetch(`/scans/${currentScanId}/logs/clear`, { method: "POST" });
  logs = [];
  lastLogSince = 0;
  renderLogs();
});
logView.addEventListener("scroll", () => {
  const nearBottom = logView.scrollHeight - logView.scrollTop - logView.clientHeight < 24;
  userScrolledLog = !nearBottom;
});

document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    stopPolling();
    stopLogPolling();
    return;
  }
  if (currentScanId && !scanFinished) {
    startPolling();
    if (activeTab === "debug") startLogPolling();
  }
});

switchTab("devices");
