# Virtual IIoT Security Testbed

A reproducible, Docker-based Industrial IoT (Industry 4.0) testbed for **identifying and
prioritizing vulnerabilities** in the interfaces and network services of industrial
systems. Built for a research internship (BSUIR, Dept. of Infocommunications Technologies).

The testbed runs a simulated industrial process that produces realistic **Modbus TCP** and
**MQTT** traffic. That traffic is later captured and used to train and evaluate a machine
-learning method for vulnerability detection and impact scoring. Own-testbed traffic is used
for training; the public **CIC Modbus 2023** dataset is used for independent validation, so
feature extraction is kept consistent across both.

> ⚠️ **This testbed is intentionally insecure** (see `SECURITY.md`). Run it only on an
> isolated network. All host ports bind to `127.0.0.1`.

## Architecture

```
Industrial            Edge                       Monitoring
-----------           ------------------         ---------------------
OpenPLC (PLC) --502--> Node-RED (gateway) ------> InfluxDB (historian)
   |  Modbus            |  Modbus->MQTT            |          |
   |                    v                          |          v
   +-------------> FUXA (SCADA/HMI)      Mosquitto (MQTT)   Grafana (dashboards)
```

Simulated field sensors (temperature, pressure, flow, level) plus a digital coil run inside
the OpenPLC program and are exposed as Modbus registers.

## Components & ports

| Service    | Image                    | Port (localhost) | Role                                   |
|------------|--------------------------|------------------|----------------------------------------|
| OpenPLC    | `openplc:v3` (built)     | 8080, 502        | PLC simulator + Modbus TCP server      |
| FUXA       | `frangoteam/fuxa`        | 1881             | SCADA / HMI (Modbus master)            |
| Node-RED   | `nodered/node-red`       | 1880             | Edge gateway (Modbus->MQTT, ->InfluxDB)|
| Mosquitto  | `eclipse-mosquitto:2`    | 1883             | MQTT broker                            |
| InfluxDB   | `influxdb:2`             | 8086             | Time-series historian                  |
| Grafana    | `grafana/grafana`        | 3000             | Dashboards                             |

All containers share the `iiot-net` Docker bridge and address each other by name
(`openplc:502`, `mosquitto:1883`, `influxdb:8086`). Images are pinned by digest in
`docker-compose.yml` for reproducibility.

## Prerequisites

- Docker (tested with Docker 29.x under WSL2 / Ubuntu 24.04)
- The OpenPLC image, built once from the upstream repository:

```bash
git clone https://github.com/thiagoralves/OpenPLC_v3.git
cd OpenPLC_v3 && docker build -t openplc:v3 . && cd ..
```

## Run

```bash
cp .env.example .env       # then edit .env with your own values (stays local, gitignored)
docker compose up -d
docker compose ps
```

Post-start configuration (until the exported artifacts below are added):

1. **OpenPLC** — http://localhost:8080. Programs -> upload `plc/sensors.st` -> Launch ->
   Dashboard -> Start PLC.
2. **Node-RED** — http://localhost:1880. Install palettes `node-red-contrib-modbus` and
   `node-red-contrib-influxdb`, build the Modbus->MQTT / ->InfluxDB flow, Deploy.
3. **FUXA** — http://localhost:1881. Add a Modbus TCP device at `openplc:502` with the
   sensor tags (holding registers 1-4, coil 1).
4. **Grafana** — http://localhost:3000 (credentials from your `.env`). Add the InfluxDB
   data source (`http://influxdb:8086`, org/bucket/token from `.env`).

## Repository layout

```
docker-compose.yml        # the whole stack (images pinned by digest, secrets via .env)
.env.example              # configuration template (copy to .env)
.gitignore                # excludes secrets, keys, captures, runtime data
.pre-commit-config.yaml   # gitleaks + hygiene hooks
.github/workflows/security.yml  # CI: gitleaks + pre-commit on every push/PR
SECURITY.md               # intentional-vulnerability & reporting policy
LICENSE                   # MIT
mosquitto/mosquitto.conf  # broker config
plc/blink.st              # digital coil blink (link test)
plc/sensors.st            # temp/pressure/flow/level on Modbus holding registers
# --- added as each is completed & verified: ---
# nodered/flows.json       (export from Node-RED; inspect for secrets; never commit flows_cred.json)
# fuxa/project.json        (export from FUXA)
# grafana/dashboard.json   (export from Grafana)
```

## Security

See `SECURITY.md`. Credentials are injected at runtime from a gitignored `.env`; no real
secrets are committed. Weak settings (anonymous MQTT, default OpenPLC login, open FUXA
editor) are **intentional research conditions**, each mapped to a studied vulnerability
category. Do not expose this stack to an untrusted network.

## Standards & references

Framed against: **NIST SP 800-82r3** (OT security), **ISA/IEC 62443** (IACS security,
zones/conduits, security levels), the **OWASP IoT Top 10**, and **ENISA — Good Practices for
Security of IoT in Smart Manufacturing**. Detection/validation use **Zeek / CICFlowMeter**
feature extraction against the **CIC Modbus 2023** dataset.

## Status

- [x] PLC (OpenPLC) + Modbus server
- [x] SCADA/HMI (FUXA) reading Modbus
- [x] MQTT broker (Mosquitto)
- [x] Edge gateway (Node-RED): Modbus -> MQTT
- [x] Simulated sensors (temp/pressure/flow/level)
- [ ] Historian (InfluxDB) + Grafana dashboards (in progress)
- [ ] Traffic capture + feature extraction (Zeek / CICFlowMeter)
- [ ] Attack simulation (Kali, pymodbus, Ettercap/Bettercap)
- [ ] ML detection + impact scoring

## License

MIT — see `LICENSE`.
