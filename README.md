# Hybrid TCP-UDP Network Simulation Project

[![OMNeT++](https://img.shields.io/badge/OMNeT%2B%2B-6.x-blue.svg)](https://omnetpp.org/)
[![License](https://img.shields.io/badge/license-LGPL-green.svg)](LICENSE)
[![Language](https://img.shields.io/badge/language-C%2B%2B-orange.svg)](https://isocpp.org/)

A comprehensive network simulation system that implements hybrid TCP/UDP protocols with advanced routing, security, and traffic engineering features using OMNeT++.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Network Architecture](#network-architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Modules](#modules)
- [Configuration](#configuration)
- [Technical Specifications](#technical-specifications)
- [License](#license)

## 🎯 Overview

A realistic enterprise network simulation combining TCP and UDP protocols with dynamic routing (OSPF-TE, RIP), ECDH/AES security, SYN flood protection, and multiple application services (HTTP, Mail, DNS, Database) on a three-subnet topology.

## ✨ Features

- ✅ **Hybrid TCP/UDP**: Full TCP handshake, connectionless UDP, or AUTO adaptive mode
- 🔄 **Dynamic Routing**: OSPF-TE, RIP, and static routing
- � **Security**: ECDH key exchange, AES encryption, SYN flood protection
- 🌐 **Services**: DNS, HTTP, Mail, and Database servers
- 📊 **Traffic Management**: Priority queues, congestion control, bandwidth monitoring

## 🏗️ Network Architecture

The network consists of 3 subnets connected via a core router:

```
                        ┌──────────────┐
                        │ Core Router  │
                        │   (Addr: 100)│
                        └──────┬───────┘
                ┌──────────────┼──────────────┐
                │              │              │
        ┌───────▼──────┐ ┌────▼──────┐ ┌────▼──────┐
        │Subnet 1      │ │Subnet 2   │ │Subnet 3   │
        │Router (200)  │ │Router(300)│ │Router(400)│
        └───────┬──────┘ └────┬──────┘ └────┬──────┘
                │              │              │
        ┌───────┴─────────┐    │        ┌────┴──────┐
        │                 │    │        │           │
    ┌───▼──┐  ┌───▼──┐  ┌▼──┐ │   ┌───▼──┐   ┌───▼──┐
    │ PC1  │  │ PC2  │  │DNS│ │   │ Mail │   │  DB  │
    │(201) │  │(202) │  │301│ │   │ (501)│   │ (601)│
    └──────┘  └──────┘  └───┘ │   └──────┘   └──────┘
          ┌───▼──┐             │
          │ PC3  │         ┌───▼──┐  ┌──────┐
          │(203) │         │HTTP1 │  │HTTP2 │
          └──────┘         │(401) │  │(402) │
                           └──────┘  └──────┘
```

### Subnet Details

- **Subnet 1 (200-299)**: Router 200, 3 Clients (201-203), DNS 301
- **Subnet 2 (300-499)**: Router 300, 2 HTTP Servers (401-402)
- **Subnet 3 (400-699)**: Router 400, Mail 501, Database 601
- **Channels**: FastEthernet (100 Mbps), GigabitEthernet (1 Gbps)

## 🔧 Prerequisites

- OMNeT++ 6.x or later
- C++ Compiler (GCC 7+/Clang 6+)
- GNU Make

## 📦 Installation

```bash
git clone https://github.com/Sajib1472/HYBRID-TCP-UDP-NETWORK-PROJECT.git
cd HYBRID-TCP-UDP-NETWORK-PROJECT/src
source ~/omnetpp/setenv
opp_makemake -f --deep
make
```

## 🚀 Usage

```bash
# GUI mode
./hybrid_tcp_udp -u Qtenv -c General

# Command line mode
./hybrid_tcp_udp -u Cmdenv -c General
```

## 📁 Project Structure

```
src/
├── omnetpp.ini              # Simulation configuration
├── package.ned              # Package definition
├── SimpleNet.ned            # Network topology definition
├── PROJECT_REPORT.txt       # Detailed project documentation
├── Modules/                 # Module implementations
│   ├── router.cc            # Router with dynamic routing
│   ├── pc.cc                # Client PC with hybrid protocol
│   ├── dns.cc               # DNS server
│   ├── http.cc              # HTTP server
│   ├── mail.cc              # Mail server
│   ├── database.cc          # Database server
│   └── helpers.h            # Helper functions and utilities
└── results/                 # Simulation output files (generated)
```

## 🔌 Modules

| Module | File | Key Features |
|--------|------|--------------|
| **Router** | `router.cc` | OSPF-TE/RIP/Static routing, SYN flood protection, LSDB management |
| **PC (Client)** | `pc.cc` | TCP/UDP/AUTO modes, ECDH/AES encryption, congestion control |
| **DNS** | `dns.cc` | Domain resolution, caching, rate limiting |
| **HTTP** | `http.cc` | GET/POST handling, load balancing |
| **Mail** | `mail.cc` | SMTP functionality, message queuing |
| **Database** | `database.cc` | SQL-like queries, connection pooling |

## ⚙️ Configuration

Edit `omnetpp.ini` to configure:

```ini
# Routing: "OSPF-TE", "RIP", or "STATIC"
**.router.routingProtocol = "OSPF-TE"

# Protocol: "TCP", "UDP", or "AUTO"
**.client.protocol = "TCP"

# Security
**.router.synRateLimit = 200
**.dns.rateLimit = 2000
```

## 📊 Technical Specifications

| Feature | TCP | UDP | AUTO |
|---------|-----|-----|------|
| Connection Setup | 3-way handshake | No setup | Adaptive |
| Reliability | Guaranteed | Best effort | Dynamic |
| Use Case | Critical data | Real-time | Mixed traffic |

**Performance**: 1 Gbps throughput, 0.1-0.5ms latency, 30s simulation time

## 📄 License

This project is licensed under the LGPL License.

## 👥 Author

**Sajib Biswas** - [Sajib1472](https://github.com/Sajib1472)

---

*Educational project for network simulation concepts.*