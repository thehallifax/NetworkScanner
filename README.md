# LLDP Topology Mapper

LLDP-based network mapping and topology discovery tool for site audits. Starts from seed switches, pulls LLDP neighbors, and builds a deduplicated topology graph.

## Features
- Seed-based crawler with switch-first discovery
- Aruba AOS-S and Cisco IOS/IOS-XE drivers (SSH + structured parsing)
- Meraki Dashboard API collector (LLDP/CDP via API)
- In-memory storage (swappable later)
- API for starting scans, viewing results, and exporting JSON/CSV
- Mock data example for demos

## Project layout
- `src/drivers/`: vendor SSH commands + parsers
- `src/discovery/`: crawler + graph dedupe
- `src/storage/`: in-memory store
- `src/api/`: API endpoints
- `schemas/`: JSON schema
- `mocks/`: mock topology dataset
- `examples/`: demo scan script

## Install
```
npm install
```

## Run API
```
npm run dev
```

Bind host/port via env vars:
```
HOST=0.0.0.0 PORT=3000 npm run dev
PORT=4000 npm run dev
```

## Web UI
Open `http://localhost:3000` to launch the UI. The scan form stays visible on the left, with Devices/Links/Topology/Debug tabs on the right. The UI does not store credentials and only submits them in the POST body.

Meraki scans are available in the UI via the "Scan Source" selector. Choose "Meraki Dashboard API", paste the API key, optional org/network filters, and start the scan.

### Start a scan
```
curl -s -X POST http://localhost:3000/scans \
  -H 'Content-Type: application/json' \
  -d '{
    "source": "ssh",
    "vendor": "aruba",
    "seedDevices": ["10.10.0.1"],
    "credentials": [
      {"id": "core", "username": "admin", "password": "secret"},
      {"id": "edge-legacy", "username": "manager", "password": "secret"}
    ],
    "options": {
      "concurrency": 5,
      "retries": 1,
      "timeoutMs": 8000
    }
  }'
```

### Auto vendor scan (mixed Aruba + Cisco)
```
curl -s -X POST http://localhost:3000/scans \
  -H 'Content-Type: application/json' \
  -d '{
    "source": "ssh",
    "vendor": "auto",
    "seedDevices": ["10.10.0.1", "10.10.0.2"],
    "credentials": [
      {"id": "primary", "username": "admin", "password": "secret"}
    ],
    "options": {
      "vendorsAllowList": ["aruba", "cisco"],
      "resolveNeighbors": "dns",
      "sshMode": "auto",
      "debug": true,
      "timeoutMs": 8000,
      "concurrency": 5
    }
  }'
```

### SSH auth options
- `password`: password auth
- `sshKeyPath`: load key from disk
- `privateKey`: paste key text directly (in-memory only)
- `useAgent`: use SSH agent (`SSH_AUTH_SOCK`)

Example with private key and agent:
```
curl -s -X POST http://localhost:3000/scans \
  -H 'Content-Type: application/json' \
  -d '{
    "source": "ssh",
    "vendor": "cisco",
    "seedDevices": ["10.10.0.1"],
    "credentials": [
      {"id": "agent", "username": "admin", "useAgent": true},
      {"id": "key", "username": "admin", "privateKey": "-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----"}
    ]
  }'
```

### View results
```
curl -s http://localhost:3000/scans/{scanId}
curl -s http://localhost:3000/scans/{scanId}/devices
curl -s http://localhost:3000/scans/{scanId}/links
curl -s http://localhost:3000/scans/{scanId}/topology
```

### Export
```
curl -s http://localhost:3000/scans/{scanId}/export/json
curl -s http://localhost:3000/scans/{scanId}/export/csv
curl -s http://localhost:3000/scans/{scanId}/export/csv-links
```

### Debug logs
```
curl -s http://localhost:3000/scans/{scanId}/logs
curl -s -X POST http://localhost:3000/scans/{scanId}/logs/clear
```

## Example scan with mock data
```
npm run example:mock
```
This uses `mocks/topology.json` and prints a JSON result that matches `schemas/scan-result.schema.json`.

## Meraki topology collection
Meraki collection uses the Dashboard API instead of SSH/CLI. It runs through the same scan runner and artifact writer as other sources.

```
export MERAKI_DASHBOARD_API_KEY=...
export MERAKI_ORG_ID=...        # optional
export MERAKI_ORG_NAME=...      # optional, exact match
export MERAKI_NETWORK_ID=...    # optional

npm run scan -- --source meraki
```

Optional raw payload export:
```
npm run scan -- --source meraki --emit-raw
```
Artifacts are written to `artifacts/scan-<scanId>/results.json`, with raw payloads in `artifacts/scan-<scanId>/raw.json`.
Normalized links follow the canonical link schema in `schemas/scan-result.schema.json`.

### Meraki scan via API
```
curl -s -X POST http://localhost:3000/scans \
  -H 'Content-Type: application/json' \
  -d '{
    "source": "meraki",
    "emitRaw": true,
    "meraki": {
      "apiKey": "MERAKI_DASHBOARD_API_KEY",
      "orgId": "123456",
      "orgName": "My Org",
      "networkId": "N_1234567890"
    }
  }'
```
The API key is provided in the request body and is not stored in memory after the scan starts.
When `emitRaw` is true, artifacts are written to `artifacts/scan-<scanId>/results.json` and `artifacts/scan-<scanId>/raw.json`.

## Vendor command sets
- Aruba AOS-S
  - `show system`
  - `show lldp info remote-device detail`
- Cisco IOS/IOS-XE
  - `show version`
  - `show lldp neighbors detail`

## Data model
- Devices are deduplicated by chassis ID, then hostname.
- Links are deduplicated as undirected pairs of ports for topology output.
- Device state is tracked as `pending`, `success`, or `failed`.

## Security
- Credentials are held in memory only.
- API responses redact secrets.

## Notes
- CIDR seeds are expanded up to 1024 hosts; larger ranges collapse to the base IP.
- Auto vendor detection is a stub and currently defaults to Cisco, so specify vendor explicitly for accuracy.
