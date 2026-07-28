#!/bin/bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ONLINE_INTEGRITY_SCRIPT="$SCRIPT_DIR/online-integrity-test.sh"

RUNS="${1:-${ARKFILE_RSS_BASELINE_RUNS:-5}}"
PAUSE_SECONDS="${2:-${ARKFILE_RSS_BASELINE_PAUSE_SECONDS:-30}}"
OUTPUT_DIR="${3:-}"

usage() {
    printf 'Usage: sudo bash %s [runs] [pause-seconds] [output-directory]\n' "$0"
}

fail() {
    printf '[X] %s\n' "$1" >&2
    exit 1
}

if [ "$(id -u)" -ne 0 ]; then
    usage
    fail "CLI RSS baseline must run through sudo"
fi

CALLING_USER="${SUDO_USER:-}"
if [ -z "$CALLING_USER" ] || [ "$CALLING_USER" = root ] || [ "$CALLING_USER" = arkfile ]; then
    fail "Run this script through sudo as a regular non-arkfile user"
fi

if ! [[ "$RUNS" =~ ^[1-9][0-9]*$ ]]; then
    usage
    fail "Run count must be a positive integer"
fi
if ! [[ "$PAUSE_SECONDS" =~ ^[0-9]+$ ]]; then
    usage
    fail "Pause must be a non-negative integer"
fi
if [ ! -f "$ONLINE_INTEGRITY_SCRIPT" ]; then
    fail "Online integrity script not found: $ONLINE_INTEGRITY_SCRIPT"
fi

CALLING_HOME="$(getent passwd "$CALLING_USER" | awk -F: '{print $6; exit}')"
CALLING_GROUP="$(id -gn "$CALLING_USER")"
if [ -z "$CALLING_HOME" ] || [ ! -d "$CALLING_HOME" ]; then
    fail "Could not resolve home directory for $CALLING_USER"
fi

if [ -z "$OUTPUT_DIR" ]; then
    OUTPUT_DIR="$CALLING_HOME/arkfile-rss-baseline-$(date -u +%Y%m%dT%H%M%SZ)"
fi

case "$OUTPUT_DIR" in
    "$CALLING_HOME"/*) ;;
    *) fail "Output directory must be under $CALLING_HOME" ;;
esac
if [ -e "$OUTPUT_DIR" ]; then
    fail "Output directory already exists: $OUTPUT_DIR"
fi

install -d -m 700 -o "$CALLING_USER" -g "$CALLING_GROUP" "$OUTPUT_DIR" ||
    fail "Could not create output directory: $OUTPUT_DIR"

STATS_FILE="$OUTPUT_DIR/rss-stats.tsv"
SUMMARY_FILE="$OUTPUT_DIR/rss-summary.txt"
install -m 600 -o "$CALLING_USER" -g "$CALLING_GROUP" /dev/null "$STATS_FILE" ||
    fail "Could not create statistics file"
printf 'run\tminimum_kib\tmaximum_kib\tgrowth_kib\tlog\n' >"$STATS_FILE"

printf '[INFO] Running %d online integrity measurements with %ds pauses\n' "$RUNS" "$PAUSE_SECONDS"
printf '[INFO] Results directory: %s\n' "$OUTPUT_DIR"

completed=0
final_status=0

for ((run = 1; run <= RUNS; run++)); do
    log_file="$OUTPUT_DIR/run-$run.log"
    install -m 600 -o "$CALLING_USER" -g "$CALLING_GROUP" /dev/null "$log_file" ||
        fail "Could not create log file for run $run"

    printf '\n[RUN] Baseline measurement %d of %d\n' "$run" "$RUNS"
    bash "$ONLINE_INTEGRITY_SCRIPT" 2>&1 | tee "$log_file"
    status=${PIPESTATUS[0]}
    if [ "$status" -ne 0 ]; then
        printf '[X] Baseline measurement %d failed with status %d\n' "$run" "$status" >&2
        final_status="$status"
        break
    fi

    rss_line="$(awk '/CLI RSS range:/ {print; exit}' "$log_file")"
    if [ -z "$rss_line" ]; then
        printf '[X] Baseline measurement %d did not report CLI RSS statistics\n' "$run" >&2
        final_status=1
        break
    fi

    range="${rss_line#*CLI RSS range: }"
    minimum="${range%%-*}"
    remainder="${range#*-}"
    maximum="${remainder%% *}"
    growth="${range#*growth }"
    growth="${growth%% *}"

    if ! [[ "$minimum" =~ ^[0-9]+$ && "$maximum" =~ ^[0-9]+$ && "$growth" =~ ^[0-9]+$ ]]; then
        printf '[X] Could not parse CLI RSS statistics from run %d\n' "$run" >&2
        final_status=1
        break
    fi

    printf '%d\t%s\t%s\t%s\t%s\n' \
        "$run" "$minimum" "$maximum" "$growth" "$log_file" >>"$STATS_FILE"
    completed=$((completed + 1))

    if [ "$run" -lt "$RUNS" ]; then
        printf '[INFO] Waiting %ds before the next measurement\n' "$PAUSE_SECONDS"
        sleep "$PAUSE_SECONDS"
    fi
done

install -m 600 -o "$CALLING_USER" -g "$CALLING_GROUP" /dev/null "$SUMMARY_FILE" ||
    fail "Could not create summary file"

{
    printf 'Requested runs: %d\n' "$RUNS"
    printf 'Completed runs: %d\n' "$completed"
    if [ "$completed" -gt 0 ]; then
        awk -F '\t' '
            NR > 1 {
                if (count == 0 || $2 < minimum) minimum = $2
                if (count == 0 || $3 > maximum) maximum = $3
                if (count == 0 || $4 > growth) growth = $4
                count++
            }
            END {
                printf "Lowest observed RSS: %d KiB\n", minimum
                printf "Highest observed RSS: %d KiB\n", maximum
                printf "Highest observed growth: %d KiB\n", growth
            }
        ' "$STATS_FILE"
    fi
    printf 'Statistics: %s\n' "$STATS_FILE"
} >"$SUMMARY_FILE"

chown "$CALLING_USER:$CALLING_GROUP" "$STATS_FILE" "$SUMMARY_FILE" "$OUTPUT_DIR"/run-*.log 2>/dev/null || true

printf '\n[STATS] CLI RSS baseline\n'
sed 's/^/[INFO] /' "$SUMMARY_FILE"

if [ "$final_status" -ne 0 ]; then
    exit "$final_status"
fi

printf '[OK] All CLI RSS baseline measurements passed\n'
