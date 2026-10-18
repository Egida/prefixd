# prefixd Lab Environment

Containerlab topologies for testing FlowSpec with routers.

These legacy topologies use the explicit **GoBGP compatibility profile**. They
do not qualify rustbgpd or prove dataplane enforcement. For the primary stack,
use the [rustbgpd quickstart](../docs/tutorials/quickstart.md). Use the startup
commands below only for a fresh, isolated lab; changing an existing deployment's
target does not change its existing [speaker ownership binding](../docs/how-to/upgrading.md#speaker-ownership-upgrade).

## Lab Options

| Lab | Router | Virtualization | Notes |
|-----|--------|----------------|-------|
| `frr-flowspec.clab.yml` | FRR | None (native container) | Works everywhere |
| `cjunos-flowspec.clab.yml` | cJunosEvolved | KVM (Intel or AMD) | **Recommended for Juniper testing** |
| `vjunos-flowspec.clab.yml` | vJunos-router | Nested KVM | Bare metal only (no VMs) |

## cJunosEvolved Lab (Juniper PTX)

cJunosEvolved is a containerized Junos Evolved router emulating a PTX10002-36QDD. It peers with the prefixd docker-compose GoBGP instance over a shared Docker network.

```
prefixd -> prefixd-gobgp (AS 65010) -> cJunosEvolved (AS 65003)
                 │                            │
                 └── clab-mgmt-evo network ───┘
                     172.30.31.0/24
```

### Prerequisites

1. **KVM support**: `ls /dev/kvm`
2. **Download cJunosEvolved** from [Juniper](https://support.juniper.net/support/downloads/?p=cjunos-evolved) (free, no account)
3. **Load image**: `docker load -i cJunosEvolved-25.4R1.13-EVO.tar.gz`
4. **GoBGP compatibility stack running**, from the repository root:
   `docker compose --profile gobgp up -d --pull always --no-build`.
   Do not also enable the rustbgpd profile.

### Quick Start

```bash
# Deploy cJunos lab
cd lab
sudo clab deploy -t cjunos-flowspec.clab.yml

# First configure configs/gobgp.conf with this lab's neighbor 172.30.31.3,
# peer AS 65003 and IPv4 FlowSpec family; the shipped peer is a placeholder.
# Connect prefixd-gobgp to clab network
docker network connect clab-mgmt-evo prefixd-gobgp --ip 172.30.31.10

# Restart GoBGP after editing its config (same container/network namespace)
docker restart prefixd-gobgp

# Wait ~3-5 min for cJunos to boot, then verify BGP session
docker exec prefixd-gobgp gobgp neighbor
# Should show 172.30.31.3 as Established

# Inject test FlowSpec rule
docker exec prefixd-gobgp gobgp global rib add -a ipv4-flowspec \
  match destination 192.168.1.100/32 protocol tcp destination-port 80 \
  then discard

# Verify on cJunos (admin/admin@123)
ssh admin@172.30.31.3
show route table inetflow.0
```

### Important Notes

- cJunos shows "License key missing; requires 'BGP' license" - this is a warning only, FlowSpec still works
- GoBGP neighbors must be configured with `family ipv4-flowspec` ONLY - cJunos rejects `inet-unicast` capability in the Open message (Open Message Error subcode 7)
- The `FXP0ADDR` token in startup config is replaced by the entrypoint with the mgmt IP (note: it's `FXP0ADDR`, NOT `FXP0ADDRESS`)
- Boot time is ~3 minutes on modern hardware

### Cleanup

```bash
docker network disconnect clab-mgmt-evo prefixd-gobgp
sudo clab destroy -t cjunos-flowspec.clab.yml --cleanup
```

## FRR Lab

FRR (Free Range Routing) runs natively in containers without KVM. Works on any Linux host.

### Quick Start

```bash
# Start prefixd stack first
docker compose --profile gobgp up -d --pull always --no-build

# Configure configs/gobgp.conf with the FRR neighbor and AS from frr-bgpd.conf;
# the shipped peer is a documentation placeholder.

# Deploy FRR lab
cd lab
sudo clab deploy -t frr-flowspec.clab.yml

# Connect prefixd-gobgp to lab network with a fixed IP
docker network connect clab-mgmt prefixd-gobgp --ip 172.30.30.10

# Restart GoBGP to pick up FRR neighbor from configs/gobgp.conf
docker restart prefixd-gobgp

# Verify BGP session
docker exec prefixd-gobgp gobgp neighbor

# Check FlowSpec in FRR
docker exec clab-frr-flowspec-router vtysh -c "show bgp ipv4 flowspec"
```

### Cleanup

```bash
docker network disconnect clab-mgmt prefixd-gobgp
sudo clab destroy -t frr-flowspec.clab.yml --cleanup
```

---

## vJunos-router Lab

> **Warning**: vJunos-router **cannot run inside a VM** (documented Juniper limitation).
> It requires a bare-metal server with KVM (Intel VMX or AMD-V).
> If you're running in a VM or cloud instance, use cJunosEvolved or FRR instead.

See `vjunos-flowspec.clab.yml` for the topology definition.

---

## Resource Requirements

| Router | RAM | CPU | Boot Time | KVM Required |
|--------|-----|-----|-----------|--------------|
| FRR | 256 MB | 1 core | Instant | No |
| cJunosEvolved | 8 GB | 4 cores | ~3-5 min | Yes |
| vJunos-router | 5 GB | 4 cores | ~10 min | Yes (bare metal) |

## Legacy helper script

`test-flowspec.sh` is historical and is **not a current qualification gate**.
It still defaults to the unpublished `http://localhost:8080`, probes obsolete
`/healthz`, omits the required event timestamp, builds bearer headers through
unsafe shell word splitting, and reads mitigation `id` instead of
`mitigation_id`. Optional router checks also do not fail when receipt is absent.
Setting an endpoint alone does not repair this flow or authenticate it against
the default credentials-mode deployment. Repair these checks before relying on
its announce/withdraw result.

For maintained controller tests, use the owned fixtures in
[`scripts/test-gobgp.sh`](../scripts/test-gobgp.sh) and
[`scripts/test-rustbgpd.sh`](../scripts/test-rustbgpd.sh). They create separate
containers and do not attach to this lab. Hardware/vendor qualification still
needs explicit receiving-router and forwarding checks with retained receipts.

## Troubleshooting

### cJunos: Open Message Error
GoBGP is advertising `inet-unicast` alongside `inet-flow`. Configure the neighbor in `gobgp.conf` with only `ipv4-flowspec` AFI-SAFI.

### cJunos: ZTP running / config not applied
The startup config must use `FXP0ADDR` (not `FXP0ADDRESS`) for the management IP token.

### vJunos: stuck booting in VM
vJunos does not support nested virtualization. Use cJunosEvolved or FRR instead.

### BGP session stuck in Active/Idle
Check network connectivity between containers and ensure both sides are on the same Docker network.
