#!/usr/bin/env bash
#
# Quickwork ApacheBench (ab) Benchmark Suite
#
# Usage: ./tests/benchmark_ab.sh [options]
#
# Options:
#   -p, --port PORT         Server port (default: 9999)
#   -k, --keep              Keep server running after final run
#   -v, --verbose           Show full ab output + debug logs
#   --threads CSV           Quickwork -j levels (default: 1,4,8)
#   --clients CSV           ab -c levels (default: 1,16,64)
#   --requests CSV          ab -n levels (default: 200,1000,5000)
#   --timeout SECONDS       ab -s timeout (default: 30)
#   -h, --help              Show this help
#
# Environment overrides:
#   THREAD_LEVELS_CSV, CLIENT_CONCURRENCY_CSV, CLIENT_REQUESTS_CSV
#   AB_TIMEOUT, AB_KEEPALIVE, AB_VERBOSE, QW_MAX_MEMORY, QW_KV_SIZE

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=run_tests.d/common.sh
source "${SCRIPT_DIR}/common.sh"

DEFAULT_THREAD_LEVELS_CSV="1,4,8"
DEFAULT_CLIENT_CONCURRENCY_CSV="1,16,64"
DEFAULT_CLIENT_REQUESTS_CSV="200,1000,5000"
DEFAULT_AB_TIMEOUT="30"
DEFAULT_AB_KEEPALIVE="1"
DEFAULT_AB_VERBOSE="0"
DEFAULT_QW_MAX_MEMORY="64"
DEFAULT_QW_KV_SIZE="100"

THREAD_LEVELS_CSV="${THREAD_LEVELS_CSV:-$DEFAULT_THREAD_LEVELS_CSV}"
CLIENT_CONCURRENCY_CSV="${CLIENT_CONCURRENCY_CSV:-$DEFAULT_CLIENT_CONCURRENCY_CSV}"
CLIENT_REQUESTS_CSV="${CLIENT_REQUESTS_CSV:-$DEFAULT_CLIENT_REQUESTS_CSV}"
AB_TIMEOUT="${AB_TIMEOUT:-$DEFAULT_AB_TIMEOUT}"
AB_KEEPALIVE="${AB_KEEPALIVE:-$DEFAULT_AB_KEEPALIVE}"
AB_VERBOSE="${AB_VERBOSE:-$DEFAULT_AB_VERBOSE}"
QW_MAX_MEMORY="${QW_MAX_MEMORY:-$DEFAULT_QW_MAX_MEMORY}"
QW_KV_SIZE="${QW_KV_SIZE:-$DEFAULT_QW_KV_SIZE}"

HANDLER_NAMES=(
    text
    json
    large
    async
    kv
    stream
    post_json
)

HANDLER_LABELS=(
    "Plain text (sync)"
    "JSON response"
    "Large body (64KB)"
    "Async delay (5ms)"
    "KV set/get"
    "StreamResponse (3 chunks)"
    "POST JSON parse"
)

HANDLER_METHODS=(
    "GET"
    "GET"
    "GET"
    "GET"
    "GET"
    "GET"
    "POST"
)

HANDLER_BODIES=(
    ""
    ""
    ""
    ""
    ""
    ""
    '{"name":"Bench","count":123}'
)

HANDLER_CONTENT_TYPES=(
    ""
    ""
    ""
    ""
    ""
    ""
    "application/json"
)

HANDLER_IDS=()
HANDLER_BODY_FILES=()

BODY_FILES=()

handler_code_for_index() {
    case "$1" in
        0)
            cat <<'EOF'
export default function(req) {
    return new Response("ok");
}
EOF
            ;;
        1)
            cat <<'EOF'
export default function(req) {
    return Response.json({ ok: true, ts: Date.now() });
}
EOF
            ;;
        2)
            cat <<'EOF'
export default function(req) {
    const data = "x".repeat(65536);
    return new Response(data);
}
EOF
            ;;
        3)
            cat <<'EOF'
export default async function(req) {
    await new Promise(resolve => setTimeout(resolve, 5));
    return new Response("ok");
}
EOF
            ;;
        4)
            cat <<'EOF'
import { kv } from "quickw";

export default function(req) {
    kv.set("bench:kv", "value");
    const value = kv.get("bench:kv");
    return Response.json({ value });
}
EOF
            ;;
        5)
            cat <<'EOF'
export default function(req) {
    const stream = new StreamResponse({
        headers: { "Content-Type": "text/plain" }
    });
    stream.write("chunk1\n");
    stream.write("chunk2\n");
    stream.write("chunk3\n");
    stream.close();
    return stream;
}
EOF
            ;;
        6)
            cat <<'EOF'
export default function(req) {
    const data = req.json();
    return Response.json({ received: data.name, count: data.count });
}
EOF
            ;;
        *)
            log_fail "Unknown handler index: $1"
            exit 1
            ;;
    esac
}

usage() {
    cat <<'EOF'
Quickwork ApacheBench (ab) Benchmark Suite

Usage: ./tests/benchmark_ab.sh [options]

Options:
  -p, --port PORT         Server port (default: 9999)
  -k, --keep              Keep server running after final run
  -v, --verbose           Show full ab output + debug logs
  --threads CSV           Quickwork -j levels (default: 1,4,8)
  --clients CSV           ab -c levels (default: 1,16,64)
  --requests CSV          ab -n levels (default: 200,1000,5000)
  --timeout SECONDS       ab -s timeout (default: 30)
  -h, --help              Show this help

Environment overrides:
  THREAD_LEVELS_CSV, CLIENT_CONCURRENCY_CSV, CLIENT_REQUESTS_CSV
  AB_TIMEOUT, AB_KEEPALIVE, AB_VERBOSE, QW_MAX_MEMORY, QW_KV_SIZE

Examples:
  ./tests/benchmark_ab.sh
  ./tests/benchmark_ab.sh --threads 1,2,4 --clients 1,8,32 --requests 200,1000,5000
  AB_KEEPALIVE=0 ./tests/benchmark_ab.sh
EOF
}

cleanup_body_files() {
    if [[ ${#BODY_FILES[@]} -eq 0 ]]; then
        return 0
    fi

    for file in "${BODY_FILES[@]}"; do
        rm -f "$file"
    done
}

trap 'cleanup; cleanup_body_files' EXIT

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -p|--port)
                PORT="$2"
                shift 2
                ;;
            -k|--keep)
                KEEP_SERVER=1
                shift
                ;;
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            --threads)
                THREAD_LEVELS_CSV="$2"
                shift 2
                ;;
            --clients)
                CLIENT_CONCURRENCY_CSV="$2"
                shift 2
                ;;
            --requests)
                CLIENT_REQUESTS_CSV="$2"
                shift 2
                ;;
            --timeout)
                AB_TIMEOUT="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

apply_defaults() {
    if [[ -z "${PORT:-}" ]]; then
        PORT=9999
    fi

    if [[ -z "${KEEP_SERVER:-}" ]]; then
        KEEP_SERVER=0
    fi

    if [[ -z "${VERBOSE:-}" ]]; then
        VERBOSE=0
    fi

    if [[ -z "${THREAD_LEVELS_CSV:-}" ]]; then
        THREAD_LEVELS_CSV="$DEFAULT_THREAD_LEVELS_CSV"
    fi

    if [[ -z "${CLIENT_CONCURRENCY_CSV:-}" ]]; then
        CLIENT_CONCURRENCY_CSV="$DEFAULT_CLIENT_CONCURRENCY_CSV"
    fi

    if [[ -z "${CLIENT_REQUESTS_CSV:-}" ]]; then
        CLIENT_REQUESTS_CSV="$DEFAULT_CLIENT_REQUESTS_CSV"
    fi

    if [[ -z "${AB_TIMEOUT:-}" ]]; then
        AB_TIMEOUT="$DEFAULT_AB_TIMEOUT"
    fi

    if [[ -z "${AB_KEEPALIVE:-}" ]]; then
        AB_KEEPALIVE="$DEFAULT_AB_KEEPALIVE"
    fi

    if [[ -z "${AB_VERBOSE:-}" ]]; then
        AB_VERBOSE="$DEFAULT_AB_VERBOSE"
    fi

    if [[ -z "${QW_MAX_MEMORY:-}" ]]; then
        QW_MAX_MEMORY="$DEFAULT_QW_MAX_MEMORY"
    fi

    if [[ -z "${QW_KV_SIZE:-}" ]]; then
        QW_KV_SIZE="$DEFAULT_QW_KV_SIZE"
    fi
}

ensure_dependencies() {
    if [[ ! -x "$QUICKWORK_BIN" ]]; then
        log_fail "Binary not found: $QUICKWORK_BIN"
        log "Please build the project first: ./build.sh"
        exit 1
    fi

    if ! command -v ab >/dev/null 2>&1; then
        log_fail "ab not found. Install ApacheBench (httpd tools) to run benchmarks."
        exit 1
    fi
}

start_server() {
    local threads="$1"

    log "Starting quickwork on port $PORT with -j $threads..."
    log_debug "Command: $QUICKWORK_BIN --port $PORT --kv-size $QW_KV_SIZE --max-memory $QW_MAX_MEMORY -j $threads"
    "$QUICKWORK_BIN" --port "$PORT" --kv-size "$QW_KV_SIZE" --max-memory "$QW_MAX_MEMORY" -j "$threads" &
    SERVER_PID=$!

    if ! wait_for_server "$BASE_URL"; then
        log_fail "Server failed to start for -j $threads"
        exit 1
    fi

    log "Server started (PID: $SERVER_PID)"
}

stop_server() {
    if [[ -n "${SERVER_PID:-}" ]]; then
        log "Stopping server (PID: $SERVER_PID)..."
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
    fi
}

create_body_files() {
    local name body body_file

    for idx in "${!HANDLER_NAMES[@]}"; do
        name="${HANDLER_NAMES[$idx]}"
        body="${HANDLER_BODIES[$idx]}"
        if [[ -n "$body" ]]; then
            body_file="$(mktemp -t "qw_ab_${name}_body")"
            printf '%s' "$body" > "$body_file"
            HANDLER_BODY_FILES[$idx]="$body_file"
            BODY_FILES+=("$body_file")
        fi
    done
}

register_handlers() {
    local name id code
    HANDLER_IDS=()

    for idx in "${!HANDLER_NAMES[@]}"; do
        name="${HANDLER_NAMES[$idx]}"
        log "Registering handler: ${HANDLER_LABELS[$idx]}"
        code=$(handler_code_for_index "$idx")
        id=$(register_handler "$code")
        if [[ -z "$id" ]]; then
            log_fail "Failed to register handler: $name"
            exit 1
        fi
        HANDLER_IDS[$idx]="$id"
        log_debug "Handler id for ${HANDLER_NAMES[$idx]}: ${HANDLER_IDS[$idx]}"
    done
}

run_ab_for_handler() {
    local handler_index="$1"
    local concurrency="$2"
    local requests="$3"
    local handler_id method content_type body_file

    handler_id="${HANDLER_IDS[$handler_index]}"
    method="${HANDLER_METHODS[$handler_index]}"
    content_type="${HANDLER_CONTENT_TYPES[$handler_index]}"
    body_file="${HANDLER_BODY_FILES[$handler_index]:-}"

    if [[ -z "$handler_id" ]]; then
        log_fail "Missing handler id for index $handler_index"
        exit 1
    fi

    if [[ "$requests" -lt "$concurrency" ]]; then
        log_debug "Adjusting requests to match concurrency ($requests -> $concurrency)"
        requests="$concurrency"
    fi

    local ab_args=(
        -n "$requests"
        -c "$concurrency"
        -s "$AB_TIMEOUT"
        -H "x-handler-id: $handler_id"
    )

    if [[ "$AB_VERBOSE" != "0" ]]; then
        ab_args+=(-v "$AB_VERBOSE")
    fi

    if [[ "$AB_KEEPALIVE" != "0" ]]; then
        ab_args+=(-k)
    fi

    if [[ "$method" == "POST" ]]; then
        ab_args+=(-p "$body_file" -T "$content_type")
    fi

    log "ab ${ab_args[*]} ${BASE_URL}/"

    local ab_output
    if ab_output=$(ab "${ab_args[@]}" "${BASE_URL}/" 2>&1); then
        if [[ $VERBOSE -eq 1 ]]; then
            printf '%s\n' "$ab_output"
        else
            local requests_per_sec failed_requests
            requests_per_sec=$(printf '%s\n' "$ab_output" | awk -F: '/Requests per second/ { gsub(/^[[:space:]]+/, "", $2); print $2; exit }')
            failed_requests=$(printf '%s\n' "$ab_output" | awk -F: '/Failed requests/ { gsub(/^[[:space:]]+/, "", $2); print $2; exit }')
            log "ab summary: requests/sec=${requests_per_sec:-unknown}, failed=${failed_requests:-unknown}"
        fi
    else
        local status=$?
        log_fail "ab failed (exit $status)"
        printf '%s\n' "$ab_output"
        return $status
    fi
}

main() {
    parse_args "$@"
    apply_defaults

    THREAD_LEVELS_CSV="${THREAD_LEVELS_CSV// /}"
    CLIENT_CONCURRENCY_CSV="${CLIENT_CONCURRENCY_CSV// /}"
    CLIENT_REQUESTS_CSV="${CLIENT_REQUESTS_CSV// /}"

    IFS=',' read -r -a THREAD_LEVELS <<< "$THREAD_LEVELS_CSV"
    IFS=',' read -r -a CLIENT_CONCURRENCY_LEVELS <<< "$CLIENT_CONCURRENCY_CSV"
    IFS=',' read -r -a CLIENT_REQUESTS_LEVELS <<< "$CLIENT_REQUESTS_CSV"

    if [[ ${#CLIENT_REQUESTS_LEVELS[@]} -eq 1 && ${#CLIENT_CONCURRENCY_LEVELS[@]} -gt 1 ]]; then
        local value="${CLIENT_REQUESTS_LEVELS[0]}"
        CLIENT_REQUESTS_LEVELS=()
        for _ in "${CLIENT_CONCURRENCY_LEVELS[@]}"; do
            CLIENT_REQUESTS_LEVELS+=("$value")
        done
    fi

    if [[ ${#CLIENT_REQUESTS_LEVELS[@]} -ne ${#CLIENT_CONCURRENCY_LEVELS[@]} ]]; then
        log_fail "Client requests levels must match client concurrency levels"
        exit 1
    fi

    BASE_URL="http://${HOST}:${PORT}"

    ensure_dependencies
    create_body_files

    log_section "Quickwork Benchmark (ab)"
    log "Host: $HOST"
    log "Port: $PORT"
    log "Quickwork threads (-j): ${THREAD_LEVELS[*]}"
    log "Client concurrency (-c): ${CLIENT_CONCURRENCY_LEVELS[*]}"
    log "Requests per level (-n): ${CLIENT_REQUESTS_LEVELS[*]}"
    log "Keep-alive: ${AB_KEEPALIVE}"
    log "ab verbosity: ${AB_VERBOSE}"
    log "Quickwork max memory (MB): ${QW_MAX_MEMORY}"
    log "Quickwork KV size: ${QW_KV_SIZE}"

    local thread_count=${#THREAD_LEVELS[@]}
    local thread_level_names=(low med high)
    if [[ $thread_count -ne 3 ]]; then
        thread_level_names=()
        for idx in "${!THREAD_LEVELS[@]}"; do
            thread_level_names+=("level$((idx + 1))")
        done
    fi

    local client_count=${#CLIENT_CONCURRENCY_LEVELS[@]}
    local client_level_names=(low med high)
    if [[ $client_count -ne 3 ]]; then
        client_level_names=()
        for idx in "${!CLIENT_CONCURRENCY_LEVELS[@]}"; do
            client_level_names+=("level$((idx + 1))")
        done
    fi

    for thread_idx in "${!THREAD_LEVELS[@]}"; do
        local threads="${THREAD_LEVELS[$thread_idx]}"
        local thread_label="${thread_level_names[$thread_idx]}"

        log_section "Quickwork threads ($thread_label): -j $threads"
        start_server "$threads"
        register_handlers

        for client_idx in "${!CLIENT_CONCURRENCY_LEVELS[@]}"; do
            local concurrency="${CLIENT_CONCURRENCY_LEVELS[$client_idx]}"
            local requests="${CLIENT_REQUESTS_LEVELS[$client_idx]}"
            local client_label="${client_level_names[$client_idx]}"

            log_section "Client concurrency ($client_label): -c $concurrency, -n $requests"

            local idx
            for idx in "${!HANDLER_NAMES[@]}"; do
                log "Handler: ${HANDLER_LABELS[$idx]}"
                run_ab_for_handler "$idx" "$concurrency" "$requests"
            done
        done

        if [[ $KEEP_SERVER -eq 1 && $thread_idx -eq $((thread_count - 1)) ]]; then
            log "Keeping server running after final run (PID: $SERVER_PID)"
        else
            stop_server
        fi
    done
}

main "$@"
