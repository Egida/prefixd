#!/usr/bin/env bash
# Load testing for prefixd
# Requires: hey (sudo apt install hey), curl, jq, awk
#
# Usage:
#   ./scripts/load-test.sh              # run default suite (moderate)
#   ./scripts/load-test.sh quick        # smoke test (5s per workload)
#   ./scripts/load-test.sh sustained    # sustained load (60s)
#   ./scripts/load-test.sh burst        # burst traffic (high concurrency)

set -euo pipefail

API="http://localhost"
PASS=0
FAIL=0
AUTH_ARGS=()
RESULTS_DIR=""
WORK_DIR=""
BG_PID=""
BG_OUTPUT=""
FG_PID=""
FG_OUTPUT=""
REGISTERING_HEY=0
SIGNAL_STATUS=0
LOG_SEQUENCE=0

# The generator writes the final attempt count after its complete error section.
# Go template variables must remain literal until hey renders the report.
# shellcheck disable=SC2016
HEY_TEMPLATE='
Summary:
  Total: {{formatNumber .Total.Seconds}} secs
  Slowest: {{formatNumber .Slowest}} secs
  Fastest: {{formatNumber .Fastest}} secs
  Average: {{formatNumber .Average}} secs
  Requests/sec: {{formatNumber .Rps}}

Response time histogram:
{{histogram .Histogram}}
Latency distribution:{{range .LatencyDistribution}}
  {{.Percentage}}%% in {{formatNumber .Latency}} secs{{end}}

Status code distribution:{{range $code,$num := .StatusCodeDist}}
  [{{$code}}] {{$num}} responses{{end}}
{{if gt (len .ErrorDist) 0}}Error distribution:{{range $err,$num := .ErrorDist}}
  [{{$num}}] {{$err}}{{end}}{{end}}
PREFIXD_HEY_COMPLETE {{.NumRes}} END
'

if [ -n "${PREFIXD_API_TOKEN:-}" ]; then
    AUTH_ARGS=(-H "Authorization: Bearer ${PREFIXD_API_TOKEN}")
fi

# --- helpers ---

log()  { printf "\033[1;34m[load]\033[0m %s\n" "$*"; }
pass() { printf "\033[1;32m  PASS\033[0m %s\n" "$*"; PASS=$((PASS + 1)); }
fail() { printf "\033[1;31m  FAIL\033[0m %s\n" "$*"; FAIL=$((FAIL + 1)); }

check_prereqs() {
    if ! command -v hey &>/dev/null; then
        echo "ERROR: hey not found. Install with: sudo apt install hey"
        exit 1
    fi
    if ! curl -sf "${AUTH_ARGS[@]}" "$API/v1/health" >/dev/null 2>&1; then
        echo "ERROR: prefixd not reachable at $API. Start docker compose first."
        exit 1
    fi
}

stop_hey() {
    local pid="$1" output="$2" status=0
    # An aborted workload cannot qualify; do not wait for SIGTERM handling.
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || status=$?
    printf '%s\n' "$status" > "${output%.log}.exit"
}

handle_signal() {
    SIGNAL_STATUS="$1"
    if [ "$REGISTERING_HEY" -eq 0 ]; then
        exit "$SIGNAL_STATUS"
    fi
    return 0
}

start_hey() {
    local pid_variable="$1" output="$2"
    shift 2
    : > "$output"
    # Defer trapped exit only until the owned child's PID is registered.
    REGISTERING_HEY=1
    hey -disable-redirects -o "$HEY_TEMPLATE" "$@" > "$output" 2>&1 &
    printf -v "$pid_variable" '%s' "$!"
    REGISTERING_HEY=0
    if [ "$SIGNAL_STATUS" -ne 0 ]; then
        exit "$SIGNAL_STATUS"
    fi
}

# Keep raw workloads (including failures); remove temporary working files.
cleanup() {
    if [ -n "$FG_PID" ]; then
        stop_hey "$FG_PID" "$FG_OUTPUT"
        FG_PID=""
    fi
    if [ -n "$BG_PID" ]; then
        stop_hey "$BG_PID" "$BG_OUTPUT"
        BG_PID=""
    fi
    if [ -n "$WORK_DIR" ]; then
        rm -rf -- "$WORK_DIR"
    fi
}

next_output() {
    LOG_SEQUENCE=$((LOG_SEQUENCE + 1))
    printf -v HEY_OUTPUT '%s/%02d-%s.log' "$RESULTS_DIR" "$LOG_SEQUENCE" "$1"
}

_hey_rps=""
_hey_latency_avg=""
_hey_latency_p99=""

# hey exits successfully for HTTP failures and some transport failures. Qualify
# metrics only after validating its complete status/error distribution.
parse_hey() {
    local output="$1" status="${2:-0}" expected="${3:-0}" metrics
    _hey_rps=""
    _hey_latency_avg=""
    _hey_latency_p99=""
    if [ "$status" -ne 0 ]; then
        return 1
    fi
    if ! metrics=$(awk -v expected="$expected" '
        function number(value) {
            return value ~ /^[0-9]+([.][0-9]+)?$/
        }
        ended && NF { bad=1; next }
        $1 == "PREFIXD_HEY_COMPLETE" {
            if (NF != 3 || $2 !~ /^[0-9]+$/ || $3 != "END") bad=1
            endings++; attempts=$2+0; ended=1; next
        }
        /^Summary:$/ { summaries++; next }
        $1 == "Requests/sec:" {
            rates++; rate=$2
            if (NF != 2 || !number(rate) || rate+0 <= 0) bad=1
        }
        $1 == "Average:" {
            averages++; average=$2
            if (NF != 3 || $3 != "secs" || !number(average)) bad=1
        }
        $1 == "99%" {
            percentiles++; p99=$3
            if (NF != 4 || $2 != "in" || $4 != "secs" || !number(p99)) bad=1
        }
        /^Error distribution:/ { bad=1 }
        /^Response time histogram:$/ { histograms++; histogram=1; next }
        histogram && !NF { histogram=0; next }
        histogram {
            if (NF != 3 || !number($1) || $2 !~ /^\[[0-9]+\]$/ || $3 !~ /^\|/) {
                bad=1
            } else {
                buckets++
                completed += substr($2, 2, length($2)-2)+0
            }
            next
        }
        /^Status code distribution:$/ { distributions++; statuses=1; next }
        statuses && NF {
            if (NF != 3 || $1 !~ /^\[[0-9][0-9][0-9]\]$/ ||
                $2 !~ /^[0-9]+$/ || $2+0 <= 0 || $3 != "responses") {
                bad=1
            } else {
                code=substr($1, 2, 3)+0
                if (code < 200 || code >= 300) bad=1
                responses += $2
            }
        }
        END {
            # hey 0.1.4 retains at most 1M response statuses; its tail is unobservable.
            if (bad || summaries != 1 || rates != 1 || averages != 1 ||
                percentiles != 1 || histograms != 1 || buckets != 11 ||
                distributions != 1 || responses <= 0 || completed >= 1000000 ||
                responses != completed || endings != 1 || responses != attempts ||
                (expected > 0 && responses != expected)) exit 1
            print rate, average, p99
        }
    ' "$output"); then
        return 1
    fi
    read -r _hey_rps _hey_latency_avg _hey_latency_p99 <<< "$metrics"
    echo "  Requests/sec: $_hey_rps"
    echo "  Avg latency:  ${_hey_latency_avg}s"
    echo "  P99 latency:  ${_hey_latency_p99}s"
    echo "  HTTP responses: all 2xx; no request errors"
}

run_hey() {
    local label="$1" expected="$2" status=0
    shift 2
    next_output "$label"
    local output="$HEY_OUTPUT"
    FG_OUTPUT="$output"
    start_hey FG_PID "$output" "$@"
    wait "$FG_PID" || status=$?
    printf '%s\n' "$status" > "${output%.log}.exit"
    FG_PID=""
    log "Raw workload output: $output"
    parse_hey "$output" "$status" "$expected"
}

# --- test functions ---

# Health endpoint (baseline — should be very fast)
test_health_throughput() {
    local duration=${1:-10}
    local concurrency=${2:-10}

    log "Health endpoint: ${concurrency}c x ${duration}s"
    if ! run_hey health 0 -z "${duration}s" -c "$concurrency" "${AUTH_ARGS[@]}" "$API/v1/health"; then
        fail "Health workload failed or contained invalid/non-2xx responses"
        return
    fi

    if awk -v measured="$_hey_rps" 'BEGIN { exit !(measured > 100) }'; then
        pass "Health endpoint: ${_hey_rps} req/s (target: >100)"
    else
        fail "Health endpoint too slow: ${_hey_rps} req/s (target: >100)"
    fi
}

# Read endpoint (mitigations list)
test_read_throughput() {
    local duration=${1:-10}
    local concurrency=${2:-10}

    log "GET /v1/mitigations: ${concurrency}c x ${duration}s"
    if ! run_hey mitigations 0 -z "${duration}s" -c "$concurrency" "${AUTH_ARGS[@]}" "$API/v1/mitigations"; then
        fail "Mitigations workload failed or contained invalid/non-2xx responses"
        return
    fi

    if awk -v measured="$_hey_rps" 'BEGIN { exit !(measured > 50) }'; then
        pass "Mitigations list: ${_hey_rps} req/s (target: >50)"
    else
        fail "Mitigations list too slow: ${_hey_rps} req/s (target: >50)"
    fi
}

# Event ingestion (write path — the critical one)
test_ingestion_throughput() {
    local duration=${1:-10}
    local concurrency=${2:-5}

    log "POST /v1/events (ingestion): ${concurrency}c x ${duration}s"

    # Create a temp body file — hey doesn't support dynamic bodies,
    # so all events hit the same IP (will extend existing mitigation)
    local body_file
    body_file=$(mktemp "$WORK_DIR/body-XXXXXX.json")
    local ts
    ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    echo "{\"source\":\"load-test\",\"timestamp\":\"$ts\",\"victim_ip\":\"198.51.100.1\",\"vector\":\"udp_flood\",\"bps\":1000000000,\"pps\":1000000,\"top_dst_ports\":[53],\"confidence\":0.95}" > "$body_file"

    if ! run_hey ingestion 0 -z "${duration}s" -c "$concurrency" \
        -m POST -H "Content-Type: application/json" "${AUTH_ARGS[@]}" \
        -D "$body_file" "$API/v1/events"; then
        rm -f "$body_file"
        fail "Ingestion workload failed or contained invalid/non-2xx responses"
        return
    fi
    rm -f "$body_file"

    if awk -v measured="$_hey_rps" 'BEGIN { exit !(measured > 10) }'; then
        pass "Event ingestion: ${_hey_rps} req/s (target: >10)"
    else
        fail "Event ingestion too slow: ${_hey_rps} req/s (target: >10)"
    fi

    if awk -v measured="$_hey_latency_p99" 'BEGIN { exit !(measured < 1.0) }'; then
        pass "Ingestion P99 latency: ${_hey_latency_p99}s (target: <1s)"
    else
        fail "Ingestion P99 latency too high: ${_hey_latency_p99}s (target: <1s)"
    fi
}

# Burst: high concurrency spike
test_burst() {
    local requests=${1:-500}
    local concurrency=${2:-50}

    log "Burst: ${requests} requests at ${concurrency} concurrency"

    local body_file
    body_file=$(mktemp "$WORK_DIR/body-XXXXXX.json")
    local ts
    ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    echo "{\"source\":\"load-test\",\"timestamp\":\"$ts\",\"victim_ip\":\"198.51.100.2\",\"vector\":\"syn_flood\",\"bps\":5000000000,\"pps\":5000000,\"top_dst_ports\":[80,443],\"confidence\":0.98}" > "$body_file"

    if ! run_hey burst "$requests" -n "$requests" -c "$concurrency" \
        -m POST -H "Content-Type: application/json" "${AUTH_ARGS[@]}" \
        -D "$body_file" "$API/v1/events"; then
        rm -f "$body_file"
        fail "Burst workload failed or contained invalid/non-2xx responses"
        return
    fi
    rm -f "$body_file"
    pass "Burst: all HTTP responses successful at ${concurrency} concurrency"

    if awk -v measured="$_hey_rps" 'BEGIN { exit !(measured > 5) }'; then
        pass "Burst throughput: ${_hey_rps} req/s"
    else
        fail "Burst throughput too low: ${_hey_rps} req/s"
    fi
}

# Metrics endpoint under load (should not block)
test_metrics_under_load() {
    local duration=${1:-10}

    log "Metrics endpoint during ingestion load: ${duration}s"

    local body_file
    body_file=$(mktemp "$WORK_DIR/body-XXXXXX.json")
    local ts
    ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    echo "{\"source\":\"load-test\",\"timestamp\":\"$ts\",\"victim_ip\":\"198.51.100.3\",\"vector\":\"udp_flood\",\"bps\":1000000000,\"pps\":1000000,\"top_dst_ports\":[53],\"confidence\":0.9}" > "$body_file"

    next_output metrics-ingestion
    BG_OUTPUT="$HEY_OUTPUT"
    start_hey BG_PID "$BG_OUTPUT" -z "${duration}s" -c 5 -m POST \
        -H "Content-Type: application/json" "${AUTH_ARGS[@]}" \
        -D "$body_file" "$API/v1/events"
    sleep 2

    local metrics_ok=0 metrics_p99="" ingestion_ok=0 background_status=0
    local metrics_summary="$WORK_DIR/metrics-summary.txt"
    local ingestion_summary="$WORK_DIR/ingestion-summary.txt"
    if run_hey metrics 0 -z "$((duration - 3))s" -c 2 "${AUTH_ARGS[@]}" "$API/metrics" > "$metrics_summary"; then
        metrics_ok=1
        metrics_p99="$_hey_latency_p99"
    fi
    wait "$BG_PID" || background_status=$?
    printf '%s\n' "$background_status" > "${BG_OUTPUT%.log}.exit"
    BG_PID=""
    rm -f "$body_file"
    log "Background ingestion output: $BG_OUTPUT"
    if parse_hey "$BG_OUTPUT" "$background_status" > "$ingestion_summary"; then
        ingestion_ok=1
    fi

    if [ "$metrics_ok" -ne 1 ] || [ "$ingestion_ok" -ne 1 ]; then
        fail "Metrics-under-load requires successful metrics AND background ingestion workloads"
        return
    fi
    cat "$metrics_summary" "$ingestion_summary"
    if awk -v measured="$metrics_p99" 'BEGIN { exit !(measured < 0.5) }'; then
        pass "Metrics P99 under load: ${metrics_p99}s (target: <0.5s)"
    else
        fail "Metrics too slow under load: ${metrics_p99}s (target: <0.5s)"
    fi
}

# Sustained load (longer duration)
test_sustained() {
    local duration=${1:-60}
    local concurrency=${2:-10}

    log "Sustained ingestion: ${concurrency}c x ${duration}s"

    local body_file
    body_file=$(mktemp "$WORK_DIR/body-XXXXXX.json")
    local ts
    ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    echo "{\"source\":\"load-test\",\"timestamp\":\"$ts\",\"victim_ip\":\"198.51.100.4\",\"vector\":\"udp_flood\",\"bps\":2000000000,\"pps\":2000000,\"top_dst_ports\":[53,123],\"confidence\":0.92}" > "$body_file"

    if ! run_hey sustained 0 -z "${duration}s" -c "$concurrency" \
        -m POST -H "Content-Type: application/json" "${AUTH_ARGS[@]}" \
        -D "$body_file" "$API/v1/events"; then
        rm -f "$body_file"
        fail "Sustained workload failed or contained invalid/non-2xx responses"
        return
    fi
    rm -f "$body_file"

    # After sustained load, check health
    sleep 2
    if curl -sf "${AUTH_ARGS[@]}" "$API/v1/health" >/dev/null 2>&1; then
        pass "API healthy after ${duration}s sustained load"
    else
        fail "API unhealthy after sustained load"
    fi

    if awk -v measured="$_hey_rps" 'BEGIN { exit !(measured > 10) }'; then
        pass "Sustained throughput: ${_hey_rps} req/s over ${duration}s"
    else
        fail "Sustained throughput degraded: ${_hey_rps} req/s over ${duration}s"
    fi

    # A failed or missing observation is not an idle pool.
    local pool_active
    if ! pool_active=$(curl -sf "${AUTH_ARGS[@]}" "$API/metrics" 2>/dev/null | awk '
        $1 == "prefixd_db_pool_connections{state=\"active\"}" {
            if (NF != 2 || $2 !~ /^[0-9]+([.][0-9]+)?$/) exit 1
            count++; value=$2
        }
        END { if (count != 1) exit 1; print value }
    '); then
        fail "DB pool observation unavailable after load"
        return
    fi
    log "Observed DB pool active connections after load: $pool_active"
}

# --- profiles ---

run_quick() {
    log "=== Quick Smoke Test (5s per workload) ==="
    echo ""
    test_health_throughput 5 5
    test_read_throughput 5 5
    test_ingestion_throughput 5 3
    echo ""
}

run_default() {
    log "=== Default Load Test Suite ==="
    echo ""
    test_health_throughput 10 10
    test_read_throughput 10 10
    test_ingestion_throughput 15 5
    test_burst 500 50
    test_metrics_under_load 10
    echo ""
}

run_sustained() {
    log "=== Sustained Load Test (60s) ==="
    echo ""
    test_sustained 60 10
    echo ""
}

run_burst() {
    log "=== Burst Test ==="
    echo ""
    test_burst 200 20
    test_burst 500 50
    test_burst 1000 100
    echo ""
}

# --- main ---

main() {
    RESULTS_DIR=$(mktemp -d "${TMPDIR:-/tmp}/prefixd-load-results-XXXXXX")
    WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/prefixd-load-body-XXXXXX")
    trap cleanup EXIT
    trap 'handle_signal 130' INT
    trap 'handle_signal 143' TERM
    log "Raw workload results retained in: $RESULTS_DIR"

    check_prereqs

    # Capture starting stats
    events_before=$(curl -sf "${AUTH_ARGS[@]}" "$API/v1/stats" 2>/dev/null | jq -er '.total_events | select(type == "number" and . >= 0 and floor == .)')
    log "Starting stats: $events_before events in database"
    echo ""

    profile="${1:-default}"

    case "$profile" in
        quick)     run_quick ;;
        default)   run_default ;;
        sustained) run_sustained ;;
        burst)     run_burst ;;
        all)
            run_quick
            run_default
            run_burst
            run_sustained
            ;;
        *)
            echo "Usage: $0 [quick|default|sustained|burst|all]"
            exit 1
            ;;
    esac

    # Final stats
    events_after=$(curl -sf "${AUTH_ARGS[@]}" "$API/v1/stats" 2>/dev/null | jq -er '.total_events | select(type == "number" and . >= 0 and floor == .)')
    events_ingested=$((events_after - events_before))
    log "Events ingested during test: $events_ingested ($events_before -> $events_after)"

    echo ""
    echo "=============================="
    echo " Load Test Results"
    echo "=============================="
    echo " PASS: $PASS"
    echo " FAIL: $FAIL"
    echo "=============================="

    if [ "$FAIL" -gt 0 ]; then
        exit 1
    fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
