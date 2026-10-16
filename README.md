# Suricata (DPI and Lua Scripting)

A programmable Intrusion Detection System built on **Suricata 6.0.20**, extended with **Lua scripts** to go beyond static signatures. The lab runs in **GNS3** and is validated by launching attacks from a Kali Linux machine against a segmented enterprise network.

> University project for the *Security* course (Computer Engineering, ISEC), 2025/26. The report and slides in `docs/` are written in Portuguese.

## Why this project

Signature-based detection struggles with traffic that is obfuscated or that changes shape. This lab uses Suricata as a **Deep Packet Inspection** engine and adds custom Lua logic for the cases plain rules can't express, such as keeping state across packets or applying conditional checks to payloads.

## Lab architecture

![Network topology](gns3/topology.png)

Built in GNS3 with Cisco IOU routers, split into three zones:

- **External zone:** Kali Linux attacker, behind two routers.
- **Inspection core:** Ubuntu server running Suricata, connected through an Ethernet **hub** on the backbone.
- **Internal zone:** two client subnets (`192.168.1.0/24` and `192.168.2.0/24`) and a web service on port 80 as the attack target.

### Design decisions

- **Hub instead of SPAN/port mirroring.** A hub replicates every packet to the IDS interface at the physical level, with no processing overhead on the routers and no dependence on mirroring configuration.
- **IP address on the monitoring interface.** The sensor was meant to run in stealth mode (no IP on the capture interface). In practice the HTTP transactions never completed, because the TCP stack had no address to answer from, so the interface got a static IP (`10.0.0.3/24`). This made the full request/response flow available to DPI.
- **Suricata 6.0.20 instead of 8.0.3.** The latest version was tried first, but the Lua API had very little documented community material. Version 6.0.20 had far more documentation and examples, which made the detection modules faster to build and test.

## Detection modules

Four Lua modules, each called from a Suricata rule (`rules/suricata.rules`):

| Module | SID | What it detects | Logic | Alert classification |
|---|---|---|---|---|
| `dlp_cartao.lua` | 100001 | Credit card data leaving the network (DLP) | Matches the `XXXX-XXXX-XXXX-XXXX` pattern in `http.request_body` | Potential Corporate Privacy Violation (P1) |
| `forca_bruta_contador.lua` | 100002 | Brute-force login attempts | Stateful counter; alerts after 3 failed attempts | Attempted Administrator Privilege Gain (P1) |
| `detecao_agente.lua` | 100003 | Offensive tools and scanners (`sqlmap`, `nmap`, `nikto`) | Searches the request payload for tool signatures | Web Application Attack (P1) |
| `bloq_exec.lua` | 100004 | Downloads of executables (`.exe`, `.sh`, `.bat`) | Searches the request for executable extensions | Potential Corporate Privacy Violation (P1) |

## Results

Every module fired the expected alert in `fast.log` during validation. Demos are in `demos/`.

| Test | Expected alert | Result |
|---|---|---|
| POST with card number | `[1:100001:1] ... Fuga de Cartao de Credito Detetada` | Detected |
| 3 failed logins | `[1:100002:1] ... Ataque de Forca Bruta Detetado` | Detected |
| Tool signature in request | `[1:100003:1] ... Tool de Ataque Detetada` | Detected |
| Request for `.exe` | `[1:100004:1] ... Download Executavel Detetado` | Detected |

## Repository structure

```
├── demos/        Demos of the lab
├── docs/         Report and presentation (Portuguese)
├── gns3/         Topology and diagram
├── lua/          Detection scripts
└── rules/        Suricata rules that call the scripts
```

## Authors

- Artur Falcão
- Gabriel Rodrigues
- Rodrigo Prazeres

## Disclaimer

For educational use in an isolated lab. Do not run the attack traffic against systems you do not own or have permission to test.
