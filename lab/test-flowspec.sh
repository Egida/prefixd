#!/usr/bin/env bash
#
# End-to-end FlowSpec test for prefixd lab environments.
#
# Sends an attack event through the prefixd API and verifies that a FlowSpec
# rule appears in GoBGP's RIB. Optionally checks FRR or cJunos if reachable.
#
# Usage:
#   ./test-flowspec.sh              # Test with defaults
#   ./test-flowspec.sh --withdraw   # Test announce then withdraw
#
# Prerequisites:
#   - Fresh GoBGP compatibility stack (repository root):
#     docker compose --profile gobgp up -d --pull always --no-build
#   - This legacy script needs repair before qualification; see lab/README.md.
#   - At least one lab deployed (FRR or cJunos)
#   - GoBGP connected to lab network

set -euo pipefail

API="${PREFIXD_API:-http://localhost:8080}"
TOKEN="${PREFIXD_API_TOKEN:-}"
VICTIM_IP="203.0.113.99"
WITHDRAW=false

if [[ "${1:-}" == "--withdraw" ]]; then
    WITHDRAW=true
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }
info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

AUTH_HEADER=""
if [[ -n "$TOKEN" ]]; then
    AUTH_HEADER="-H \"Authorization: Bearer $TOKEN\""
fi

# 1. Check prefixd is healthy
info "Checking prefixd API at $API..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$API/healthz" 2>/dev/null || echo "000")
if [[ "$HTTP_CODE" == "200" ]]; then
    pass "prefixd API is healthy"
else
    fail "prefixd API not reachable (HTTP $HTTP_CODE). Is 'docker compose up -d' running?"
fi

# 2. Check GoBGP is running
info "Checking GoBGP..."
if docker exec prefixd-gobgp gobgp global rib -a ipv4-flowspec > /dev/null 2>&1; then
    pass "GoBGP is running"
else
    fail "GoBGP is not reachable. Is prefixd-gobgp container running?"
fi

# 3. Check BGP neighbors
info "Checking BGP neighbors..."
NEIGHBORS=$(docker exec prefixd-gobgp gobgp neighbor 2>/dev/null || echo "")
ESTABLISHED=$(echo "$NEIGHBORS" | grep -c "established" || true)
if [[ "$ESTABLISHED" -gt 0 ]]; then
    pass "$ESTABLISHED BGP neighbor(s) established"
    echo "$NEIGHBORS" | grep "established" | sed 's/^/       /'
else
    fail "No BGP neighbors established. Deploy a lab first (see lab/README.md)"
fi

# 4. Send attack event
info "Sending test attack event (victim: $VICTIM_IP, vector: udp_flood)..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API/v1/events" \
    -H "Content-Type: application/json" \
    ${TOKEN:+-H "Authorization: Bearer $TOKEN"} \
    -d "{
        \"source\": \"lab-test\",
        \"victim_ip\": \"$VICTIM_IP\",
        \"vector\": \"udp_flood\",
        \"bps\": 5000000000,
        \"pps\": 2000000,
        \"top_dst_ports\": [53, 123],
        \"confidence\": 0.95
    }" 2>/dev/null)

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "201" ]]; then
    pass "Event accepted (HTTP $HTTP_CODE)"
else
    fail "Event rejected (HTTP $HTTP_CODE): $BODY"
fi

# 5. Verify FlowSpec rule in GoBGP RIB
info "Waiting for FlowSpec rule to appear in GoBGP RIB..."
sleep 2

RIB=$(docker exec prefixd-gobgp gobgp global rib -a ipv4-flowspec 2>/dev/null || echo "")
if echo "$RIB" | grep -q "$VICTIM_IP"; then
    pass "FlowSpec rule found in GoBGP RIB"
    echo "$RIB" | grep "$VICTIM_IP" | sed 's/^/       /'
else
    fail "FlowSpec rule NOT found in GoBGP RIB for $VICTIM_IP"
fi

# 6. Check FRR if available
FRR_CONTAINER="clab-frr-flowspec-router"
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${FRR_CONTAINER}$"; then
    info "FRR lab detected, checking FlowSpec table..."
    FRR_ROUTES=$(docker exec "$FRR_CONTAINER" vtysh -c "show bgp ipv4 flowspec" 2>/dev/null || echo "")
    if echo "$FRR_ROUTES" | grep -q "$VICTIM_IP"; then
        pass "FlowSpec rule received by FRR"
    else
        info "FlowSpec rule not yet in FRR (may need a few seconds)"
    fi
fi

# 7. Check cJunos if reachable
CJUNOS_IP="172.30.31.3"
if ping -c 1 -W 1 "$CJUNOS_IP" > /dev/null 2>&1; then
    info "cJunosEvolved detected at $CJUNOS_IP"
    info "Verify manually: ssh admin@$CJUNOS_IP 'show route table inetflow.0'"
fi

# 8. Test withdrawal if requested
if [[ "$WITHDRAW" == "true" ]]; then
    info "Waiting 10s then checking for active mitigation to withdraw..."
    sleep 10

    MITIGATIONS=$(curl -s "$API/v1/mitigations" \
        ${TOKEN:+-H "Authorization: Bearer $TOKEN"} 2>/dev/null || echo "")

    MIT_ID=$(echo "$MITIGATIONS" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    mits = data if isinstance(data, list) else data.get('mitigations', [])
    for m in mits:
        if m.get('victim_ip','') == '$VICTIM_IP' and m.get('status','') == 'active':
            print(m['id'])
            break
except: pass
" 2>/dev/null || echo "")

    if [[ -n "$MIT_ID" ]]; then
        info "Withdrawing mitigation $MIT_ID..."
        W_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/v1/mitigations/$MIT_ID/withdraw" \
            -H "Content-Type: application/json" \
            ${TOKEN:+-H "Authorization: Bearer $TOKEN"} \
            -d '{"reason": "lab test complete", "operator": "test-script"}' 2>/dev/null)

        if [[ "$W_CODE" == "200" ]]; then
            pass "Mitigation withdrawn (HTTP $W_CODE)"
            sleep 2
            RIB_AFTER=$(docker exec prefixd-gobgp gobgp global rib -a ipv4-flowspec 2>/dev/null || echo "")
            if echo "$RIB_AFTER" | grep -q "$VICTIM_IP"; then
                fail "FlowSpec rule still in GoBGP RIB after withdrawal"
            else
                pass "FlowSpec rule removed from GoBGP RIB"
            fi
        else
            info "Withdrawal returned HTTP $W_CODE (may require auth token)"
        fi
    else
        info "No active mitigation found for $VICTIM_IP to withdraw"
    fi
fi

echo ""
echo -e "${GREEN}Lab test complete.${NC}"
