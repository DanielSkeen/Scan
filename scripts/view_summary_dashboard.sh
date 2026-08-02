#!/usr/bin/env sh
set -eu

summary_file="${1:-scan_exit_db_summary.txt}"
rows="${ROWS:-10}"

if [ ! -f "$summary_file" ]; then
    echo "Summary file not found: $summary_file" >&2
    exit 1
fi

awk -v max_rows="$rows" '
function is_number(s) {
    return (s ~ /^-?[0-9]+(\.[0-9]+)?$/)
}

function extract_token(line, key,    pos, start, i, c, out) {
    pos = index(line, key "=")
    if (!pos) {
        return "-"
    }
    start = pos + length(key) + 1
    out = ""
    for (i = start; i <= length(line); i++) {
        c = substr(line, i, 1)
        if (c == " " || c == "\n" || c == "\r") {
            break
        }
        out = out c
    }
    return out == "" ? "-" : out
}

function extract_timestamp(line,    m) {
    if (match(line, /ts=[0-9-]+ [0-9:]+/)) {
        m = substr(line, RSTART + 3, RLENGTH - 3)
        return m
    }
    return "-"
}

function spark(value, minv, maxv,    palette, steps, idx, ratio) {
    if (!is_number(value)) {
        return "?"
    }
    if (maxv <= minv) {
        return "="
    }

    palette = ".:-=+*#%@"
    steps = length(palette)
    ratio = (value - minv) / (maxv - minv)
    idx = int(ratio * (steps - 1)) + 1
    if (idx < 1) idx = 1
    if (idx > steps) idx = steps
    return substr(palette, idx, 1)
}

BEGIN {
    count = 0
}

index($0, "[scan-ui] db row:") > 0 {
    if (count >= max_rows) {
        next
    }

    count++
    ts[count] = extract_timestamp($0)
    temp[count] = extract_token($0, "tempf")
    rh[count] = extract_token($0, "humidity")
    wind[count] = extract_token($0, "wind")
    gust[count] = extract_token($0, "gust")
    uv[count] = extract_token($0, "uv")
    solar[count] = extract_token($0, "solar")
    barom[count] = extract_token($0, "barom")
    total[count] = extract_token($0, "total")
    batt[count] = extract_token($0, "battout")

    if (is_number(temp[count])) {
        t = temp[count] + 0
        if (temp_seen == 0 || t < temp_min) temp_min = t
        if (temp_seen == 0 || t > temp_max) temp_max = t
        temp_seen = 1
    }

    if (is_number(solar[count])) {
        s = solar[count] + 0
        if (solar_seen == 0 || s < solar_min) solar_min = s
        if (solar_seen == 0 || s > solar_max) solar_max = s
        solar_seen = 1
    }
}

END {
    if (count == 0) {
        print "No packet rows found in " FILENAME
        exit 0
    }

    print "Weather Packet Dashboard (latest " count " rows)"
    print ""
    printf("%-8s | %-5s | %-2s | %-5s | %-5s | %-2s | %-6s | %-7s | %-9s | %-4s\n", "Time", "TempF", "RH", "Wind", "Gust", "UV", "Solar", "Barom", "TotalRain", "Batt")

    for (i = 1; i <= count; i++) {
        time_only = ts[i]
        if (length(time_only) >= 19) {
            time_only = substr(time_only, 12, 8)
        }

        printf("%-8s | %-5s | %-2s | %-5s | %-5s | %-2s | %-6s | %-7s | %-9s | %-4s\n",
            time_only, temp[i], rh[i], wind[i], gust[i], uv[i], solar[i], barom[i], total[i], batt[i])
    }

    print ""
    print "Temp trend:"
    for (i = 1; i <= count; i++) {
        time_only = ts[i]
        if (length(time_only) >= 19) {
            time_only = substr(time_only, 12, 8)
        }
        printf("  %-8s %s %s\n", time_only, spark(temp[i] + 0, temp_min, temp_max), temp[i])
    }

    print ""
    print "Solar trend:"
    for (i = 1; i <= count; i++) {
        time_only = ts[i]
        if (length(time_only) >= 19) {
            time_only = substr(time_only, 12, 8)
        }
        printf("  %-8s %s %s\n", time_only, spark(solar[i] + 0, solar_min, solar_max), solar[i])
    }
}
' "$summary_file"
