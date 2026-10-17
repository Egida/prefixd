# Vendor Capability Matrix

FlowSpec support varies significantly across router vendors, platforms, and software versions. This page documents what has been tested with prefixd and known limitations.

## Support Matrix

| Capability | Juniper (Junos/Evolved) | Arista (EOS) | Cisco (IOS-XR) | Nokia (SR OS) | FRR |
|---|---|---|---|---|---|
| **BGP FlowSpec IPv4** | Verified | Verified | Expected | Expected | Verified |
| **BGP FlowSpec IPv6** | Verified | Expected | Expected | Not supported (SR Linux) | Verified |
| **Discard action** | Verified | Verified | Expected | Expected | Verified |
| **Rate-limit (police) action** | Verified | Not working (under investigation) | Expected | Expected | Verified |
| **Redirect-to-VRF** | Supported (untested) | Supported (untested) | Supported (untested) | Supported (untested) | Not supported |
| **Redirect-to-IP** | Supported (untested) | Supported (untested) | Supported (untested) | Not supported | Not supported |
| **Reconciliation (re-announce)** | Verified | Expected | Expected | Expected | Verified |
| **Withdraw** | Verified | Expected | Expected | Expected | Verified |
| **TTL expiry** | Verified | Expected | Expected | Expected | Verified |
| **Multiple FlowSpec rules** | Verified | Expected | Expected | Expected | Verified |
| **Destination port matching** | Verified | Verified | Expected | Expected | Verified |
| **Protocol matching** | Verified | Verified | Expected | Expected | Verified |

**Legend:**
- **Verified** — Tested end-to-end with prefixd in a lab or production environment
- **Expected** — Vendor documentation indicates support; not yet tested with prefixd
- **Not working** — Tested but not functioning; investigation ongoing
- **Not supported** — Vendor/platform does not support this feature
- **Supported (untested)** — Vendor supports it, but prefixd does not implement this action yet

## Tested Environments

### Juniper — Verified

| Detail | Value |
|---|---|
| Platform | PTX10002 (cJunosEvolved container) |
| Software | Junos Evolved 25.4R1.13-EVO |
| Lab method | Containerlab + cJunosEvolved |
| BGP session | eBGP with GoBGP (AS 65010 ↔ AS 65003) |
| AFI-SAFI | IPv4 FlowSpec only (ipv4-flowspec) |

**Verified operations:** Event ingestion → policy evaluation → GoBGP announce → Junos `inetflow.0` → rate-limit/discard applied → withdraw → rule removed → TTL expiry → automatic withdrawal.

**Known quirks:**
- GoBGP must advertise **only** `ipv4-flowspec` AFI-SAFI to Junos. If `inet-unicast` is also advertised, Junos rejects the session with Open Message Error subcode 7.
- The `no-validate` option is required on the import policy neighbor to accept FlowSpec without validation against unicast routes.
- "License key missing; requires 'BGP' license" warning appears on cJunosEvolved — this is cosmetic only, FlowSpec still works.
- The `FXP0ADDR` management IP token in cJunos startup config must be spelled exactly `FXP0ADDR` (not `FXP0ADDRESS`).

**Reference configuration:**
```junos
set policy-options policy-statement FLOWSPEC-IMPORT term accept-all then accept
set routing-options flow validation
set routing-options flow term-order standard
set protocols bgp group FLOWSPEC type external
set protocols bgp group FLOWSPEC import FLOWSPEC-IMPORT
set protocols bgp group FLOWSPEC peer-as 65010
set protocols bgp group FLOWSPEC neighbor 10.10.1.10 family inet flow no-validate FLOWSPEC-IMPORT
```

### Arista — Partially Verified

| Detail | Value |
|---|---|
| Platform | 7280SR2A (production hardware) |
| Software | EOS 4.33.5M |
| BGP session | eBGP with GoBGP |
| Reported by | Community user (Neptune Networks) |

**Verified operations:** FlowSpec announce, discard action, withdraw, destination port matching, protocol matching.

**Not working:** Rate-limit (police) action — rules are accepted by EOS but traffic policing is not applied. Under investigation; may be a platform-specific hardware table limitation on the 7280SR2A or an EOS configuration requirement.

**Known quirks:**
- FlowSpec must be explicitly enabled per address family (`address-family flow-spec ipv4`).
- TCAM capacity varies by platform and profile. Check `show hardware capacity` if rules are silently dropped.
- Some older EOS versions (< 4.20) do not support FlowSpec at all.

**Reference configuration:**
```eos
router bgp 65000
  neighbor 10.10.1.10 remote-as 65010
  !
  address-family flow-spec ipv4
    neighbor 10.10.1.10 activate
  !
  address-family flow-spec ipv6
    neighbor 10.10.1.10 activate
```

### FRR — Verified

| Detail | Value |
|---|---|
| Platform | Container (native Linux) |
| Software | FRR 10.x |
| Lab method | Containerlab |
| BGP session | eBGP with GoBGP |

**Verified operations:** FlowSpec announce, discard, withdraw, reconciliation.

**Known quirks:**
- FRR FlowSpec support is control-plane only by default — it receives and installs routes in the BGP table but does not program iptables/nftables rules without additional configuration.
- Useful for protocol-level testing but not for dataplane enforcement without extra setup.

### Cisco IOS-XR — Not Yet Tested

| Detail | Value |
|---|---|
| Target platforms | ASR 9000, NCS 5500/5700 |
| Expected software | IOS-XR 6.5+ |
| Lab method | XRd container (planned) |

**Expected reference configuration:**
```cisco
router bgp 65000
  neighbor 10.10.1.10
    remote-as 65010
    address-family ipv4 flowspec
```

**Known considerations (from vendor docs):**
- FlowSpec validation against unicast routes is enabled by default; may need `flowspec validation disable` depending on topology.
- `hw-module profile tcam` adjustments may be needed on NCS platforms.
- Rate-limit actions use QoS policy maps internally.

### Nokia SR OS — Not Yet Tested

| Detail | Value |
|---|---|
| Target platforms | 7750 SR |
| Expected software | SR OS 19+ |

**Important:** Nokia SR Linux (7220 IXR, 7250 IXR) does **not** support BGP FlowSpec. Only classic SR OS on 7750 SR supports it.

**Known considerations (from vendor docs):**
- FlowSpec is configured under `configure router bgp group <name> family flow-ipv4`.
- Rate-limit actions are supported via filter policies.

## Testing Your Router

Use the lab scripts to validate FlowSpec with your hardware:

```bash
# 1. Start prefixd stack
docker compose up -d

# 2. Configure your router to peer with GoBGP (see configs/gobgp.conf)
#    Default: GoBGP listens on port 179, AS 65010

# 3. Verify BGP session
docker exec prefixd-gobgp gobgp neighbor

# 4. Send a test event
curl -X POST http://localhost:8080/v1/events \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2026-01-01T00:00:00Z",
    "source": "test",
    "victim_ip": "203.0.113.10",
    "vector": "udp_flood",
    "pps": 100000,
    "confidence": 0.95
  }'

# 5. Verify FlowSpec rule in GoBGP RIB
docker exec prefixd-gobgp gobgp global rib -a ipv4-flowspec

# 6. Check your router's FlowSpec table
#    Juniper: show route table inetflow.0
#    Arista:  show bgp flow-spec ipv4
#    Cisco:   show bgp ipv4 flowspec
#    FRR:     show bgp ipv4 flowspec
```

## Contributing Test Results

If you've tested prefixd with a router not listed here, please open an issue with:

1. Router vendor, platform, and software version
2. Which actions work (discard, rate-limit, redirect)
3. Any quirks or configuration requirements
4. Whether you're willing to be credited

We'll update this matrix with your findings.
