#include <arpa/inet.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sqlite3.h>
#include <SDL.h>
#ifdef SCAN_HAS_SDL_TTF
#include <SDL_ttf.h>
#endif
#include "scan.h"
#include "scan_app.h"
#include "wifi_scan.h"
#include "device_push.h"

#define UI_MAX_LINES 2048
#define UI_TRAFFIC_MAX_LINES 1024
#define UI_LINE_LEN 256
#define UI_FONT_SIZE 20
#define UI_PANEL_MARGIN 12
#define UI_SCROLLBAR_WIDTH 10
#define UI_PANEL_GAP 10
#define PUSH_LISTENER_PORT 8089
#define PUSH_POLL_INTERVAL_SEC 1.0f
#define PUSH_DB_PATH "scan_packets.db"
#define PUSH_DB_RETENTION_DAYS 90
#define RECENT_PACKET_ROWS 6
#define PUSH_DB_EXPORT_PATH "weather_packets.csv"
#define EXIT_DB_PREVIEW_ROWS 10
#define EXIT_DB_SUMMARY_PATH "scan_exit_db_summary.txt"
#define SINGLE_INSTANCE_LOCK_PATH "/tmp/scan.lock"

typedef struct {
    int listener_port;
    char db_path[512];
    int has_port_override;
    int has_db_override;
    int ui_mode;
    int scan_mode;
    int info_mode;
    int demo_push_mode;
    int export_csv_mode;
    const char *export_csv_path;
    int show_help;
} AppConfig;

static void app_config_init(AppConfig *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->listener_port = PUSH_LISTENER_PORT;
    snprintf(cfg->db_path, sizeof(cfg->db_path), "%s", PUSH_DB_PATH);
    cfg->export_csv_path = PUSH_DB_EXPORT_PATH;
}

static int parse_app_config(int argc, char **argv, AppConfig *cfg) {
    app_config_init(cfg);

    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (strcmp(arg, "--ui") == 0) {
            cfg->ui_mode = 1;
        } else if (strcmp(arg, "--scan") == 0) {
            cfg->scan_mode = 1;
        } else if (strcmp(arg, "--info") == 0) {
            cfg->info_mode = 1;
        } else if (strcmp(arg, "--demo-push") == 0) {
            cfg->demo_push_mode = 1;
        } else if (strcmp(arg, "--export-csv") == 0) {
            cfg->export_csv_mode = 1;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                cfg->export_csv_path = argv[++i];
            }
        } else if (strcmp(arg, "--port") == 0) {
            if (i + 1 >= argc || argv[i + 1][0] == '\0') {
                fprintf(stderr, "missing value for --port\n");
                return -1;
            }
            cfg->listener_port = atoi(argv[++i]);
            cfg->has_port_override = 1;
        } else if (strcmp(arg, "--db") == 0) {
            if (i + 1 >= argc || argv[i + 1][0] == '\0') {
                fprintf(stderr, "missing value for --db\n");
                return -1;
            }
            snprintf(cfg->db_path, sizeof(cfg->db_path), "%s", argv[++i]);
            cfg->has_db_override = 1;
        } else if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            cfg->show_help = 1;
        } else if (arg[0] == '-') {
            fprintf(stderr, "unknown option: %s\n", arg);
            return -1;
        }
    }

    return 0;
}

static void print_usage(const char *prog) {
    printf("Usage: %s [--ui] [--scan] [--info] [--demo-push] [--export-csv [file]] [--port N] [--db PATH]\n", prog);
    puts("  --ui             launch the SDL windowed UI");
    puts("  --scan           run the network scan once");
    puts("  --info           show app info");
    puts("  --demo-push     send a demo weather push");
    puts("  --export-csv    export stored packets to CSV");
    puts("  --port N         override the listener port");
    puts("  --db PATH        override the SQLite database path");
}

static int scan_ui_instance_running(int exclude_pid) {
    FILE *ps = popen("ps -axo pid=,command=", "r");
    if (!ps) {
        return -1;
    }

    char line[1024];
    int found = 0;
    while (fgets(line, sizeof(line), ps)) {
        int pid = 0;
        if (sscanf(line, "%d", &pid) != 1) {
            continue;
        }
        if (pid == exclude_pid) {
            continue;
        }
        if (strstr(line, "scan") && strstr(line, "--ui")) {
            found = 1;
            break;
        }
    }

    int status = pclose(ps);
    if (status != 0 && !found) {
        return -1;
    }
    return found;
}

static int acquire_single_instance_lock(const char *lock_path, int *lock_fd) {
    *lock_fd = open(lock_path, O_RDWR | O_CREAT, 0600);
    if (*lock_fd < 0) {
        fprintf(stderr, "[scan-ui] failed to open lock file %s: %s\n", lock_path, strerror(errno));
        return -1;
    }

    struct flock lock;
    memset(&lock, 0, sizeof(lock));
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;

    if (fcntl(*lock_fd, F_SETLK, &lock) == -1) {
        if (errno == EACCES || errno == EAGAIN) {
            fprintf(stderr, "[scan-ui] another instance is already running; refusing to start a duplicate.\n");
            close(*lock_fd);
            *lock_fd = -1;
            return 1;
        }

        fprintf(stderr, "[scan-ui] failed to lock %s: %s\n", lock_path, strerror(errno));
        close(*lock_fd);
        *lock_fd = -1;
        return -1;
    }

    if (ftruncate(*lock_fd, 0) == 0) {
        char pid_buf[32];
        int pid_len = snprintf(pid_buf, sizeof(pid_buf), "%d\n", getpid());
        if (pid_len > 0) {
            (void)write(*lock_fd, pid_buf, (size_t)pid_len);
        }
    }

    return 0;
}

static void release_single_instance_lock(int lock_fd, const char *lock_path) {
    if (lock_fd >= 0) {
        struct flock lock;
        memset(&lock, 0, sizeof(lock));
        lock.l_type = F_UNLCK;
        lock.l_whence = SEEK_SET;
        lock.l_start = 0;
        lock.l_len = 0;
        (void)fcntl(lock_fd, F_SETLK, &lock);
        close(lock_fd);
    }
    (void)unlink(lock_path);
}

static int run_info_mode(void) {
    puts(scan_banner());
    puts("targets: osx, raspberrypi, esp32");
    return 0;
}

static int run_scan_mode(void) {
    ScanResult result;
    char err[256] = {0};

    if (wifi_scan_collect(&result, err, sizeof(err)) != 0) {
        fprintf(stderr, "Wi-Fi scan failed: %s\n", err[0] ? err : "unknown error");
        return 1;
    }

    wifi_scan_print(&result);
    return 0;
}

static int append_line(char lines[][UI_LINE_LEN], int max_lines, int count, const char *fmt, ...) {
    if (count >= max_lines) {
        return count;
    }

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(lines[count], UI_LINE_LEN, fmt, ap);
    va_end(ap);
    return count + 1;
}

typedef struct {
    pthread_t thread;
    int active;
    int done;
    int scan_ok;
    char scan_err[256];
    ScanResult result;
} UiScanState;

static void *ui_scan_worker(void *arg) {
    UiScanState *state = (UiScanState *)arg;
    state->scan_ok = (wifi_scan_collect(&state->result, state->scan_err, sizeof(state->scan_err)) == 0);
    state->done = 1;
    return NULL;
}

static void start_ui_scan_worker(UiScanState *state) {
    if (!state || state->active) {
        return;
    }

    memset(state, 0, sizeof(*state));
    if (pthread_create(&state->thread, NULL, ui_scan_worker, state) != 0) {
        state->active = 0;
        state->done = 1;
        state->scan_ok = 0;
        snprintf(state->scan_err, sizeof(state->scan_err), "scan worker failed to start");
        return;
    }

    state->active = 1;
}

static int build_ui_lines(
    const ScanResult *result,
    int scan_ok,
    const char *scan_err,
    int scan_in_progress,
    char lines[][UI_LINE_LEN],
    int max_lines
) {
    int count = 0;
    count = append_line(lines, max_lines, count, "Scan - Local Network Overview");
    count = append_line(lines, max_lines, count, "Keys: R=refresh  MouseWheel/Up/Down/PgUp/PgDn/Home/End scroll  Esc=quit");
    count = append_line(lines, max_lines, count, "");

    if (!scan_ok) {
        if (scan_in_progress) {
            count = append_line(lines, max_lines, count, "Network scan warming up in background...");
            count = append_line(lines, max_lines, count, "Weather receiver is already live; results will appear shortly.");
            return count;
        }
        count = append_line(lines, max_lines, count, "Scan unavailable: %s", scan_err && scan_err[0] ? scan_err : "unknown error");
        return count;
    }

    count = append_line(lines, max_lines, count, "Local networks: %zu", result->interface_count);
    if (result->default_gateway_ip[0]) {
        count = append_line(lines, max_lines, count, "Default gateway: %s", result->default_gateway_ip);
    }
    if (result->weather_station_ip[0]) {
        count = append_line(lines, max_lines, count, "Weather station IP: %s", result->weather_station_ip);
        if (result->weather_ping_available) {
            count = append_line(
                lines,
                max_lines,
                count,
                "Weather ping: loss=%d%%  min/avg/max=%.1f/%.1f/%.1f ms",
                result->weather_ping_loss_pct,
                result->weather_ping_min_ms,
                result->weather_ping_avg_ms,
                result->weather_ping_max_ms
            );
        }
        count = append_line(lines, max_lines, count, "");
    }
    for (size_t i = 0; i < result->interface_count && i < 4; ++i) {
        const LocalInterfaceInfo *iface = &result->interfaces[i];
        count = append_line(lines, max_lines, count, "- %s  %s  %s", iface->interface, iface->ip, iface->cidr);
    }

    count = append_line(lines, max_lines, count, "");
    count = append_line(lines, max_lines, count, "Discovered hosts: %zu (probes: %zu)", result->device_count, result->probe_count);

    for (size_t i = 0; i < result->device_count; ++i) {
        const LocalDeviceInfo *d = &result->devices[i];
        count = append_line(
            lines,
            max_lines,
            count,
            "- %s%s  %s  %s%s",
            d->ip,
            d->is_gateway ? " [gw]" : "",
            d->hostname[0] ? d->hostname : "n/a",
            d->mac[0] ? d->mac : "n/a",
            d->has_rtt ? "  rtt" : ""
        );
        if (d->has_rtt) {
            count = append_line(lines, max_lines, count, "    latency: %.1f ms", d->rtt_ms);
        }
    }

    count = append_line(lines, max_lines, count, "");
    count = append_line(lines, max_lines, count, "Wi-Fi networks: %zu", result->wifi.count);
    for (size_t i = 0; i < result->wifi.count && i < 8; ++i) {
        const WifiNetworkInfo *n = &result->wifi.networks[i];
        count = append_line(lines, max_lines, count, "- %s%s", n->connected ? "* " : "", n->ssid);
    }

    return count;
}

#ifdef SCAN_HAS_SDL_TTF
static TTF_Font *open_ui_font(void) {
    const char *font_paths[] = {
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/System/Library/Fonts/Supplemental/Helvetica.ttc",
        "/System/Library/Fonts/SFNS.ttf",
        "/System/Library/Fonts/Supplemental/Avenir Next.ttc",
        "/System/Library/Fonts/Supplemental/Menlo.ttc"
    };

    for (size_t i = 0; i < sizeof(font_paths) / sizeof(font_paths[0]); ++i) {
        TTF_Font *font = TTF_OpenFont(font_paths[i], UI_FONT_SIZE);
        if (font) {
            return font;
        }
    }
    return NULL;
}

static void draw_text_line(SDL_Renderer *renderer, TTF_Font *font, int x, int y, const char *text, SDL_Color color) {
    SDL_Surface *surface = TTF_RenderUTF8_Blended(font, text, color);
    if (!surface) {
        return;
    }

    SDL_Texture *texture = SDL_CreateTextureFromSurface(renderer, surface);
    if (!texture) {
        SDL_FreeSurface(surface);
        return;
    }

    SDL_Rect dst = {x, y, surface->w, surface->h};
    SDL_RenderCopy(renderer, texture, NULL, &dst);

    SDL_DestroyTexture(texture);
    SDL_FreeSurface(surface);
}

static void begin_clip(SDL_Renderer *renderer, const SDL_Rect *clip) {
    SDL_RenderSetClipRect(renderer, clip);
}

static void end_clip(SDL_Renderer *renderer) {
    SDL_RenderSetClipRect(renderer, NULL);
}
#endif

typedef struct {
    sqlite3 *db;
    sqlite3_stmt *insert_stmt;
    char path[256];
    char last_error[256];
    int pruned_rows;
} PushStorage;

typedef struct {
    char weather_ip[16];
    time_t last_update;
    int messages_received;
    char station_type[64];
    char tempf[32];
    char humidity[32];
    char windspeedmph[32];
    char windgustmph[32];
    char winddir[32];
    char baromrelin[32];
    char baromabsin[32];
    char rainin[32];
    char rainratein[32];
    char eventrainin[32];
    char hourlyrainin[32];
    char dailyrainin[32];
    char weeklyrainin[32];
    char monthlyrainin[32];
    char yearlyrainin[32];
    char uv[32];
    char solarradiation[32];
    char indoortempf[32];
    char indoorhumidity[32];
    char channel_tempf[8][32];
    char channel_humidity[8][32];
    DevicePushField latest_fields[DEVICE_PUSH_MAX_FIELDS];
    int latest_field_count;
} WeatherPushData;

typedef struct {
    DevicePushListener listener;
    PushStorage storage;
    int storage_error_reported;
    WeatherPushData weather;
    char recent_packets[RECENT_PACKET_ROWS][UI_LINE_LEN];
    int recent_packet_count;
    char lines[UI_TRAFFIC_MAX_LINES][UI_LINE_LEN];
    int line_count;
    int listener_port;
} PushIngestState;

static int point_in_rect(int x, int y, const SDL_Rect *r) {
    return x >= r->x && y >= r->y && x < (r->x + r->w) && y < (r->y + r->h);
}

static int ingest_append_line(PushIngestState *state, const char *text) {
    if (state->line_count >= UI_TRAFFIC_MAX_LINES) {
        memmove(state->lines, state->lines + 1, (size_t)(UI_TRAFFIC_MAX_LINES - 1) * UI_LINE_LEN);
        state->line_count = UI_TRAFFIC_MAX_LINES - 1;
    }
    snprintf(state->lines[state->line_count], UI_LINE_LEN, "%s", text);
    state->line_count++;
    return state->line_count;
}

static const char *push_field_value(const DevicePushMessage *msg, const char *key) {
    for (int i = 0; i < msg->field_count; ++i) {
        if (strcasecmp(msg->fields[i].key, key) == 0) {
            return msg->fields[i].value;
        }
    }
    return "";
}

static void copy_if_present(char *dst, size_t dst_sz, const char *src) {
    if (src && src[0]) {
        snprintf(dst, dst_sz, "%s", src);
    }
}

static void push_storage_set_error(PushStorage *storage, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(storage->last_error, sizeof(storage->last_error), fmt, ap);
    va_end(ap);
}

static int push_storage_exec(PushStorage *storage, const char *sql) {
    char *err = NULL;
    int rc = sqlite3_exec(storage->db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        push_storage_set_error(storage, "sql exec failed: %s", err ? err : "unknown");
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

static int push_storage_apply_retention(PushStorage *storage, int retention_days) {
    if (retention_days <= 0) {
        storage->pruned_rows = 0;
        return 0;
    }

    const time_t now = time(NULL);
    const time_t cutoff = now - ((time_t)retention_days * 24 * 60 * 60);

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(
        storage->db,
        "DELETE FROM weather_packets WHERE received_at < ?;",
        -1,
        &stmt,
        NULL
    );
    if (rc != SQLITE_OK) {
        push_storage_set_error(storage, "retention prepare failed: %s", sqlite3_errmsg(storage->db));
        return -1;
    }

    rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)cutoff);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(stmt);
        push_storage_set_error(storage, "retention bind failed: %s", sqlite3_errmsg(storage->db));
        return -1;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        push_storage_set_error(storage, "retention delete failed: %s", sqlite3_errmsg(storage->db));
        return -1;
    }

    storage->pruned_rows = sqlite3_changes(storage->db);
    sqlite3_finalize(stmt);
    return 0;
}

static int push_storage_refresh_recent(PushStorage *storage, char rows[][UI_LINE_LEN], int max_rows) {
    if (!storage || !storage->db || !rows || max_rows <= 0) {
        return 0;
    }

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(
        storage->db,
        "SELECT received_at, station_id, tempf, humidity, windspeedmph "
        "FROM weather_packets ORDER BY id DESC LIMIT ?;",
        -1,
        &stmt,
        NULL
    );
    if (rc != SQLITE_OK) {
        push_storage_set_error(storage, "recent query prepare failed: %s", sqlite3_errmsg(storage->db));
        return -1;
    }

    rc = sqlite3_bind_int(stmt, 1, max_rows);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(stmt);
        push_storage_set_error(storage, "recent query bind failed: %s", sqlite3_errmsg(storage->db));
        return -1;
    }

    int count = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW && count < max_rows) {
        time_t ts = (time_t)sqlite3_column_int64(stmt, 0);
        const unsigned char *station = sqlite3_column_text(stmt, 1);
        const unsigned char *tempf = sqlite3_column_text(stmt, 2);
        const unsigned char *humidity = sqlite3_column_text(stmt, 3);
        const unsigned char *wind = sqlite3_column_text(stmt, 4);

        struct tm tm_snapshot;
        char time_buf[16] = "";
        localtime_r(&ts, &tm_snapshot);
        strftime(time_buf, sizeof(time_buf), "%H:%M:%S", &tm_snapshot);

        snprintf(
            rows[count],
            UI_LINE_LEN,
            "%s ID=%s T=%s RH=%s W=%s",
            time_buf,
            station ? (const char *)station : "-",
            tempf ? (const char *)tempf : "-",
            humidity ? (const char *)humidity : "-",
            wind ? (const char *)wind : "-"
        );
        count++;
    }

    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        push_storage_set_error(storage, "recent query step failed: %s", sqlite3_errmsg(storage->db));
        return -1;
    }

    return count;
}

static void copy_raw_field_value(const char *raw_fields, const char *key, char *out, size_t out_sz) {
    if (!out || out_sz == 0) {
        return;
    }
    out[0] = '\0';
    if (!raw_fields || !key || key[0] == '\0') {
        return;
    }

    size_t key_len = strlen(key);
    const char *cursor = raw_fields;
    while (cursor && *cursor) {
        const char *next = strchr(cursor, '&');
        const char *eq = strchr(cursor, '=');
        if (eq && (!next || eq < next)) {
            size_t token_key_len = (size_t)(eq - cursor);
            if (token_key_len == key_len && strncmp(cursor, key, key_len) == 0) {
                const char *value = eq + 1;
                size_t value_len = next ? (size_t)(next - value) : strlen(value);
                if (value_len >= out_sz) {
                    value_len = out_sz - 1;
                }
                memcpy(out, value, value_len);
                out[value_len] = '\0';
                return;
            }
        }
        cursor = next ? (next + 1) : NULL;
    }
}

static void push_storage_print_exit_summary(PushStorage *storage, int max_rows) {
    if (!storage || !storage->db || max_rows <= 0) {
        return;
    }

    FILE *summary_file = fopen(EXIT_DB_SUMMARY_PATH, "w");
    if (!summary_file) {
        fprintf(stderr, "[scan-ui] failed to open %s: %s\n", EXIT_DB_SUMMARY_PATH, strerror(errno));
    }

    sqlite3_stmt *count_stmt = NULL;
    sqlite3_stmt *rows_stmt = NULL;
    int total_rows = 0;

    if (sqlite3_prepare_v2(storage->db, "SELECT COUNT(*) FROM weather_packets;", -1, &count_stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(count_stmt) == SQLITE_ROW) {
            total_rows = sqlite3_column_int(count_stmt, 0);
        }
    }
    if (count_stmt) {
        sqlite3_finalize(count_stmt);
    }

    fprintf(stderr, "[scan-ui] db summary on exit: %d total packet(s) in %s\n", total_rows, storage->path);
    if (summary_file) {
        fprintf(summary_file, "[scan-ui] db summary on exit: %d total packet(s) in %s\n", total_rows, storage->path);
    }

    if (sqlite3_prepare_v2(
            storage->db,
            "SELECT received_at, station_id, tempf, humidity, windspeedmph, windgustmph, winddir, "
            "baromrelin, rainratein, eventrainin, dailyrainin, weeklyrainin, monthlyrainin, yearlyrainin, "
            "uv, solarradiation, indoortempf, indoorhumidity, field_count, raw_fields "
            "FROM weather_packets ORDER BY id DESC LIMIT ?;",
            -1,
            &rows_stmt,
            NULL
        ) != SQLITE_OK) {
        fprintf(stderr, "[scan-ui] db summary query failed: %s\n", sqlite3_errmsg(storage->db));
        if (summary_file) {
            fprintf(summary_file, "[scan-ui] db summary query failed: %s\n", sqlite3_errmsg(storage->db));
            fclose(summary_file);
        }
        return;
    }

    if (sqlite3_bind_int(rows_stmt, 1, max_rows) != SQLITE_OK) {
        fprintf(stderr, "[scan-ui] db summary bind failed: %s\n", sqlite3_errmsg(storage->db));
        if (summary_file) {
            fprintf(summary_file, "[scan-ui] db summary bind failed: %s\n", sqlite3_errmsg(storage->db));
            fclose(summary_file);
        }
        sqlite3_finalize(rows_stmt);
        return;
    }

    int printed = 0;
    int rc = SQLITE_OK;
    while ((rc = sqlite3_step(rows_stmt)) == SQLITE_ROW) {
        time_t ts = (time_t)sqlite3_column_int64(rows_stmt, 0);
        const unsigned char *station_id = sqlite3_column_text(rows_stmt, 1);
        const unsigned char *tempf = sqlite3_column_text(rows_stmt, 2);
        const unsigned char *humidity = sqlite3_column_text(rows_stmt, 3);
        const unsigned char *windspeed = sqlite3_column_text(rows_stmt, 4);
        const unsigned char *windgust = sqlite3_column_text(rows_stmt, 5);
        const unsigned char *winddir = sqlite3_column_text(rows_stmt, 6);
        const unsigned char *baromrelin = sqlite3_column_text(rows_stmt, 7);
        const unsigned char *rainratein = sqlite3_column_text(rows_stmt, 8);
        const unsigned char *eventrainin = sqlite3_column_text(rows_stmt, 9);
        const unsigned char *dailyrainin = sqlite3_column_text(rows_stmt, 10);
        const unsigned char *weeklyrainin = sqlite3_column_text(rows_stmt, 11);
        const unsigned char *monthlyrainin = sqlite3_column_text(rows_stmt, 12);
        const unsigned char *yearlyrainin = sqlite3_column_text(rows_stmt, 13);
        const unsigned char *uv = sqlite3_column_text(rows_stmt, 14);
        const unsigned char *solarradiation = sqlite3_column_text(rows_stmt, 15);
        const unsigned char *indoortempf = sqlite3_column_text(rows_stmt, 16);
        const unsigned char *indoorhumidity = sqlite3_column_text(rows_stmt, 17);
        int field_count = sqlite3_column_int(rows_stmt, 18);
        const unsigned char *raw_fields = sqlite3_column_text(rows_stmt, 19);

        char maxdailygust[32] = "";
        char totalrainin[32] = "";
        char battout[32] = "";
        copy_raw_field_value((const char *)raw_fields, "maxdailygust", maxdailygust, sizeof(maxdailygust));
        copy_raw_field_value((const char *)raw_fields, "totalrainin", totalrainin, sizeof(totalrainin));
        copy_raw_field_value((const char *)raw_fields, "battout", battout, sizeof(battout));

        struct tm tm_snapshot;
        char ts_buf[32] = "";
        localtime_r(&ts, &tm_snapshot);
        strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%d %H:%M:%S", &tm_snapshot);

        fprintf(
            stderr,
            "[scan-ui] db row: ts=%s ID=%s tempf=%s humidity=%s wind=%s gust=%s maxgust=%s dir=%s barom=%s "
            "rainrate=%s event=%s day=%s week=%s month=%s year=%s total=%s uv=%s solar=%s "
            "indoor_tempf=%s indoor_rh=%s battout=%s fields=%d raw=%s\n",
            ts_buf,
            station_id ? (const char *)station_id : "-",
            tempf ? (const char *)tempf : "-",
            humidity ? (const char *)humidity : "-",
            windspeed ? (const char *)windspeed : "-",
            windgust ? (const char *)windgust : "-",
            maxdailygust[0] ? maxdailygust : "-",
            winddir ? (const char *)winddir : "-",
            baromrelin ? (const char *)baromrelin : "-",
            rainratein ? (const char *)rainratein : "-",
            eventrainin ? (const char *)eventrainin : "-",
            dailyrainin ? (const char *)dailyrainin : "-",
            weeklyrainin ? (const char *)weeklyrainin : "-",
            monthlyrainin ? (const char *)monthlyrainin : "-",
            yearlyrainin ? (const char *)yearlyrainin : "-",
            totalrainin[0] ? totalrainin : "-",
            uv ? (const char *)uv : "-",
            solarradiation ? (const char *)solarradiation : "-",
            indoortempf ? (const char *)indoortempf : "-",
            indoorhumidity ? (const char *)indoorhumidity : "-",
            battout[0] ? battout : "-",
            field_count,
            raw_fields ? (const char *)raw_fields : "-"
        );
        if (summary_file) {
            fprintf(
                summary_file,
                "[scan-ui] db row: ts=%s ID=%s tempf=%s humidity=%s wind=%s gust=%s maxgust=%s dir=%s barom=%s "
                "rainrate=%s event=%s day=%s week=%s month=%s year=%s total=%s uv=%s solar=%s "
                "indoor_tempf=%s indoor_rh=%s battout=%s fields=%d raw=%s\n",
                ts_buf,
                station_id ? (const char *)station_id : "-",
                tempf ? (const char *)tempf : "-",
                humidity ? (const char *)humidity : "-",
                windspeed ? (const char *)windspeed : "-",
                windgust ? (const char *)windgust : "-",
                maxdailygust[0] ? maxdailygust : "-",
                winddir ? (const char *)winddir : "-",
                baromrelin ? (const char *)baromrelin : "-",
                rainratein ? (const char *)rainratein : "-",
                eventrainin ? (const char *)eventrainin : "-",
                dailyrainin ? (const char *)dailyrainin : "-",
                weeklyrainin ? (const char *)weeklyrainin : "-",
                monthlyrainin ? (const char *)monthlyrainin : "-",
                yearlyrainin ? (const char *)yearlyrainin : "-",
                totalrainin[0] ? totalrainin : "-",
                uv ? (const char *)uv : "-",
                solarradiation ? (const char *)solarradiation : "-",
                indoortempf ? (const char *)indoortempf : "-",
                indoorhumidity ? (const char *)indoorhumidity : "-",
                battout[0] ? battout : "-",
                field_count,
                raw_fields ? (const char *)raw_fields : "-"
            );
        }
        printed++;
    }

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "[scan-ui] db summary step failed: %s\n", sqlite3_errmsg(storage->db));
        if (summary_file) {
            fprintf(summary_file, "[scan-ui] db summary step failed: %s\n", sqlite3_errmsg(storage->db));
        }
    } else if (printed == 0) {
        fprintf(stderr, "[scan-ui] db row: no packet rows available\n");
        if (summary_file) {
            fprintf(summary_file, "[scan-ui] db row: no packet rows available\n");
        }
    }

    sqlite3_finalize(rows_stmt);
    if (summary_file) {
        fclose(summary_file);
        fprintf(stderr, "[scan-ui] db summary saved to %s\n", EXIT_DB_SUMMARY_PATH);
    }
}

static void csv_write_escaped(FILE *f, const char *text) {
    fputc('"', f);
    for (const char *p = text; p && *p; ++p) {
        if (*p == '"') {
            fputc('"', f);
        }
        fputc(*p, f);
    }
    fputc('"', f);
}

static int run_export_csv_mode(const AppConfig *cfg, const char *csv_path) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    const char *db_path = cfg && cfg->db_path[0] ? cfg->db_path : PUSH_DB_PATH;

    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        fprintf(stderr, "Failed to open %s: %s\n", db_path, sqlite3_errmsg(db));
        if (db) {
            sqlite3_close(db);
        }
        return 1;
    }

    FILE *out = fopen(csv_path, "w");
    if (!out) {
        fprintf(stderr, "Failed to open %s: %s\n", csv_path, strerror(errno));
        sqlite3_close(db);
        return 1;
    }

    const char *sql =
        "SELECT received_at, client_ip, method, path, station_id, station_type, tempf, humidity,"
        "windspeedmph, windgustmph, winddir, baromrelin, baromabsin, rainratein, eventrainin,"
        "hourlyrainin, dailyrainin, weeklyrainin, monthlyrainin, yearlyrainin, uv, solarradiation,"
        "indoortempf, indoorhumidity, field_count, raw_fields "
        "FROM weather_packets ORDER BY id;";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare export query: %s\n", sqlite3_errmsg(db));
        fclose(out);
        sqlite3_close(db);
        return 1;
    }

    fprintf(
        out,
        "received_at,client_ip,method,path,station_id,station_type,tempf,humidity,"
        "windspeedmph,windgustmph,winddir,baromrelin,baromabsin,rainratein,eventrainin,"
        "hourlyrainin,dailyrainin,weeklyrainin,monthlyrainin,yearlyrainin,uv,solarradiation,"
        "indoortempf,indoorhumidity,field_count,raw_fields\n"
    );

    int row_count = 0;
    int rc = SQLITE_OK;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        sqlite3_int64 received_at = sqlite3_column_int64(stmt, 0);
        fprintf(out, "%lld,", (long long)received_at);

        for (int i = 1; i <= 23; ++i) {
            const unsigned char *text = sqlite3_column_text(stmt, i);
            csv_write_escaped(out, text ? (const char *)text : "");
            fputc(',', out);
        }

        int field_count = sqlite3_column_int(stmt, 24);
        fprintf(out, "%d,", field_count);

        const unsigned char *raw_fields = sqlite3_column_text(stmt, 25);
        csv_write_escaped(out, raw_fields ? (const char *)raw_fields : "");
        fputc('\n', out);
        row_count++;
    }

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed during export: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        fclose(out);
        sqlite3_close(db);
        return 1;
    }

    sqlite3_finalize(stmt);
    fclose(out);
    sqlite3_close(db);

    printf("Exported %d packet rows to %s\n", row_count, csv_path);
    return 0;
}

static int push_storage_init(PushStorage *storage, const char *db_path) {
    memset(storage, 0, sizeof(*storage));
    snprintf(storage->path, sizeof(storage->path), "%s", db_path);

    int rc = sqlite3_open(storage->path, &storage->db);
    if (rc != SQLITE_OK) {
        push_storage_set_error(storage, "open failed: %s", storage->db ? sqlite3_errmsg(storage->db) : "unknown");
        if (storage->db) {
            sqlite3_close(storage->db);
            storage->db = NULL;
        }
        return -1;
    }

    if (push_storage_exec(storage, "PRAGMA journal_mode=WAL;") != 0) {
        return -1;
    }
    if (push_storage_exec(storage, "PRAGMA synchronous=NORMAL;") != 0) {
        return -1;
    }

    if (push_storage_exec(
            storage,
            "CREATE TABLE IF NOT EXISTS weather_packets ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "received_at INTEGER NOT NULL,"
            "client_ip TEXT,"
            "method TEXT,"
            "path TEXT,"
            "station_id TEXT,"
            "station_type TEXT,"
            "tempf TEXT,"
            "humidity TEXT,"
            "windspeedmph TEXT,"
            "windgustmph TEXT,"
            "winddir TEXT,"
            "baromrelin TEXT,"
            "baromabsin TEXT,"
            "rainratein TEXT,"
            "eventrainin TEXT,"
            "hourlyrainin TEXT,"
            "dailyrainin TEXT,"
            "weeklyrainin TEXT,"
            "monthlyrainin TEXT,"
            "yearlyrainin TEXT,"
            "uv TEXT,"
            "solarradiation TEXT,"
            "indoortempf TEXT,"
            "indoorhumidity TEXT,"
            "field_count INTEGER NOT NULL,"
            "raw_fields TEXT"
            ");") != 0) {
        return -1;
    }

    if (push_storage_exec(storage, "CREATE INDEX IF NOT EXISTS idx_weather_packets_received_at ON weather_packets(received_at);") != 0) {
        return -1;
    }
    if (push_storage_exec(storage, "CREATE INDEX IF NOT EXISTS idx_weather_packets_station_id ON weather_packets(station_id);") != 0) {
        return -1;
    }

    if (push_storage_apply_retention(storage, PUSH_DB_RETENTION_DAYS) != 0) {
        return -1;
    }

    const char *insert_sql =
        "INSERT INTO weather_packets ("
        "received_at, client_ip, method, path, station_id, station_type, tempf, humidity,"
        "windspeedmph, windgustmph, winddir, baromrelin, baromabsin, rainratein, eventrainin,"
        "hourlyrainin, dailyrainin, weeklyrainin, monthlyrainin, yearlyrainin, uv, solarradiation,"
        "indoortempf, indoorhumidity, field_count, raw_fields"
        ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);";

    rc = sqlite3_prepare_v2(storage->db, insert_sql, -1, &storage->insert_stmt, NULL);
    if (rc != SQLITE_OK) {
        push_storage_set_error(storage, "prepare failed: %s", sqlite3_errmsg(storage->db));
        return -1;
    }

    storage->last_error[0] = '\0';
    return 0;
}

static void push_storage_close(PushStorage *storage) {
    if (storage->insert_stmt) {
        sqlite3_finalize(storage->insert_stmt);
        storage->insert_stmt = NULL;
    }
    if (storage->db) {
        sqlite3_close(storage->db);
        storage->db = NULL;
    }
}

static void push_storage_build_raw_fields(const DevicePushMessage *msg, char *out, size_t out_sz) {
    if (out_sz == 0) {
        return;
    }
    out[0] = '\0';
    size_t used = 0;
    for (int i = 0; i < msg->field_count; ++i) {
        int written = snprintf(
            out + used,
            out_sz - used,
            "%s%s=%s",
            (i == 0) ? "" : "&",
            msg->fields[i].key,
            msg->fields[i].value
        );
        if (written < 0) {
            out[0] = '\0';
            return;
        }
        if ((size_t)written >= out_sz - used) {
            used = out_sz - 1;
            break;
        }
        used += (size_t)written;
    }
    out[used] = '\0';
}

static int bind_text_or_null(sqlite3_stmt *stmt, int idx, const char *val) {
    if (val && val[0]) {
        return sqlite3_bind_text(stmt, idx, val, -1, SQLITE_TRANSIENT);
    }
    return sqlite3_bind_null(stmt, idx);
}

static const char *pick_field_value(const DevicePushMessage *msg, const char *primary, const char *secondary, const char *tertiary) {
    const char *value = push_field_value(msg, primary);
    if (value && value[0]) {
        return value;
    }
    if (secondary) {
        value = push_field_value(msg, secondary);
        if (value && value[0]) {
            return value;
        }
    }
    if (tertiary) {
        value = push_field_value(msg, tertiary);
        if (value && value[0]) {
            return value;
        }
    }
    return NULL;
}

static int push_storage_insert(PushStorage *storage, const DevicePushMessage *msg) {
    if (!storage || !storage->db || !storage->insert_stmt || !msg) {
        return 0;
    }

    const char *station_id = pick_field_value(msg, "ID", "id", "stationid");
    const char *station_type = pick_field_value(msg, "stationtype", "station_type", "stationType");
    const char *tempf = pick_field_value(msg, "tempf", "temp", "temp_f");
    const char *humidity = pick_field_value(msg, "humidity", "rh", "humidity_pct");
    const char *windspeedmph = pick_field_value(msg, "windspeedmph", "windspeed", "windspeedmph");
    const char *windgustmph = pick_field_value(msg, "windgustmph", "windgust", "gustmph");
    const char *winddir = pick_field_value(msg, "winddir", "wind_direction", "direction");
    const char *baromrelin = pick_field_value(msg, "baromrelin", "barometer", "baromin");
    const char *baromabsin = pick_field_value(msg, "baromabsin", "baromabs", "baromabsin");
    const char *rainratein = pick_field_value(msg, "rainratein", "rainrate", "rain_rate");
    const char *eventrainin = pick_field_value(msg, "eventrainin", "eventrain", "event_rain");
    const char *hourlyrainin = pick_field_value(msg, "hourlyrainin", "hourlyrain", "hourly_rain");
    const char *dailyrainin = pick_field_value(msg, "dailyrainin", "dailyrain", "daily_rain");
    const char *weeklyrainin = pick_field_value(msg, "weeklyrainin", "weeklyrain", "weekly_rain");
    const char *monthlyrainin = pick_field_value(msg, "monthlyrainin", "monthlyrain", "monthly_rain");
    const char *yearlyrainin = pick_field_value(msg, "yearlyrainin", "yearlyrain", "yearly_rain");
    const char *uv = pick_field_value(msg, "uv", "solaruv", "uvindex");
    const char *solarradiation = pick_field_value(msg, "solarradiation", "solar", "solarrad");
    const char *indoortempf = pick_field_value(msg, "indoortempf", "tempinf", "indoortemp");
    const char *indoorhumidity = pick_field_value(msg, "indoorhumidity", "humidityin", "indoorrh");

    char raw_fields[4096];
    push_storage_build_raw_fields(msg, raw_fields, sizeof(raw_fields));

    sqlite3_stmt *stmt = storage->insert_stmt;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    int rc = SQLITE_OK;
    rc |= sqlite3_bind_int64(stmt, 1, (sqlite3_int64)msg->received_at);
    rc |= bind_text_or_null(stmt, 2, msg->client_ip);
    rc |= bind_text_or_null(stmt, 3, msg->method);
    rc |= bind_text_or_null(stmt, 4, msg->path);
    rc |= bind_text_or_null(stmt, 5, station_id);
    rc |= bind_text_or_null(stmt, 6, station_type);
    rc |= bind_text_or_null(stmt, 7, tempf);
    rc |= bind_text_or_null(stmt, 8, humidity);
    rc |= bind_text_or_null(stmt, 9, windspeedmph);
    rc |= bind_text_or_null(stmt, 10, windgustmph);
    rc |= bind_text_or_null(stmt, 11, winddir);
    rc |= bind_text_or_null(stmt, 12, baromrelin);
    rc |= bind_text_or_null(stmt, 13, baromabsin);
    rc |= bind_text_or_null(stmt, 14, rainratein);
    rc |= bind_text_or_null(stmt, 15, eventrainin);
    rc |= bind_text_or_null(stmt, 16, hourlyrainin);
    rc |= bind_text_or_null(stmt, 17, dailyrainin);
    rc |= bind_text_or_null(stmt, 18, weeklyrainin);
    rc |= bind_text_or_null(stmt, 19, monthlyrainin);
    rc |= bind_text_or_null(stmt, 20, yearlyrainin);
    rc |= bind_text_or_null(stmt, 21, uv);
    rc |= bind_text_or_null(stmt, 22, solarradiation);
    rc |= bind_text_or_null(stmt, 23, indoortempf);
    rc |= bind_text_or_null(stmt, 24, indoorhumidity);
    rc |= sqlite3_bind_int(stmt, 25, msg->field_count);
    rc |= bind_text_or_null(stmt, 26, raw_fields);

    if (rc != SQLITE_OK) {
        push_storage_set_error(storage, "bind failed: %s", sqlite3_errmsg(storage->db));
        return -1;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        push_storage_set_error(storage, "insert failed: %s", sqlite3_errmsg(storage->db));
        return -1;
    }

    return 0;
}

static int weather_push_parser(const DevicePushMessage *msg, void *user_data) {
    PushIngestState *state = (PushIngestState *)user_data;
    WeatherPushData *weather = &state->weather;

    if (push_storage_insert(&state->storage, msg) != 0 && !state->storage_error_reported) {
        char line[UI_LINE_LEN];
        snprintf(line, sizeof(line), "Storage write failed: %s", state->storage.last_error[0] ? state->storage.last_error : "unknown");
        ingest_append_line(state, line);
        fprintf(stderr, "[scan-ui] %s\n", line);
        state->storage_error_reported = 1;
    }

    int refreshed = push_storage_refresh_recent(&state->storage, state->recent_packets, RECENT_PACKET_ROWS);
    if (refreshed >= 0) {
        state->recent_packet_count = refreshed;
    }

    const char *stationtype = pick_field_value(msg, "stationtype", "station_type", "stationType");
    const char *tempf = pick_field_value(msg, "tempf", "temp", "temp_f");
    const char *humidity = pick_field_value(msg, "humidity", "rh", "humidity_pct");
    const char *windspeedmph = pick_field_value(msg, "windspeedmph", "windspeed", "windspeedmph");
    const char *windgustmph = pick_field_value(msg, "windgustmph", "windgust", "gustmph");
    const char *winddir = pick_field_value(msg, "winddir", "wind_direction", "direction");
    const char *baromrelin = pick_field_value(msg, "baromrelin", "barometer", "baromin");
    const char *baromabsin = pick_field_value(msg, "baromabsin", "baromabs", "baromabsin");
    const char *rainin = pick_field_value(msg, "rainin", "totalrainin", "rain_total");
    const char *rainratein = pick_field_value(msg, "rainratein", "rainrate", "rain_rate");
    const char *eventrainin = pick_field_value(msg, "eventrainin", "eventrain", "event_rain");
    const char *hourlyrainin = pick_field_value(msg, "hourlyrainin", "hourlyrain", "hourly_rain");
    const char *dailyrainin = pick_field_value(msg, "dailyrainin", "dailyrain", "daily_rain");
    const char *weeklyrainin = pick_field_value(msg, "weeklyrainin", "weeklyrain", "weekly_rain");
    const char *monthlyrainin = pick_field_value(msg, "monthlyrainin", "monthlyrain", "monthly_rain");
    const char *yearlyrainin = pick_field_value(msg, "yearlyrainin", "yearlyrain", "yearly_rain");
    const char *uv = pick_field_value(msg, "uv", "solaruv", "uvindex");
    const char *solarradiation = pick_field_value(msg, "solarradiation", "solar", "solarrad");
    const char *indoortempf = pick_field_value(msg, "indoortempf", "tempinf", "indoortemp");
    const char *indoorhumidity = pick_field_value(msg, "indoorhumidity", "humidityin", "indoorrh");

    copy_if_present(weather->station_type, sizeof(weather->station_type), stationtype);
    copy_if_present(weather->tempf, sizeof(weather->tempf), tempf);
    copy_if_present(weather->humidity, sizeof(weather->humidity), humidity);
    copy_if_present(weather->windspeedmph, sizeof(weather->windspeedmph), windspeedmph);
    copy_if_present(weather->windgustmph, sizeof(weather->windgustmph), windgustmph);
    copy_if_present(weather->winddir, sizeof(weather->winddir), winddir);
    copy_if_present(weather->baromrelin, sizeof(weather->baromrelin), baromrelin);
    copy_if_present(weather->baromabsin, sizeof(weather->baromabsin), baromabsin);
    copy_if_present(weather->rainin, sizeof(weather->rainin), rainin);
    copy_if_present(weather->rainratein, sizeof(weather->rainratein), rainratein);
    copy_if_present(weather->eventrainin, sizeof(weather->eventrainin), eventrainin);
    copy_if_present(weather->hourlyrainin, sizeof(weather->hourlyrainin), hourlyrainin);
    copy_if_present(weather->dailyrainin, sizeof(weather->dailyrainin), dailyrainin);
    copy_if_present(weather->weeklyrainin, sizeof(weather->weeklyrainin), weeklyrainin);
    copy_if_present(weather->monthlyrainin, sizeof(weather->monthlyrainin), monthlyrainin);
    copy_if_present(weather->yearlyrainin, sizeof(weather->yearlyrainin), yearlyrainin);
    copy_if_present(weather->uv, sizeof(weather->uv), uv);
    copy_if_present(weather->solarradiation, sizeof(weather->solarradiation), solarradiation);
    copy_if_present(weather->indoortempf, sizeof(weather->indoortempf), indoortempf);
    copy_if_present(weather->indoorhumidity, sizeof(weather->indoorhumidity), indoorhumidity);

    for (int i = 0; i < msg->field_count; ++i) {
        int channel = 0;
        if (sscanf(msg->fields[i].key, "temp%df", &channel) == 1 && channel >= 1 && channel <= 8) {
            snprintf(weather->channel_tempf[channel - 1], sizeof(weather->channel_tempf[channel - 1]), "%s", msg->fields[i].value);
        } else if (sscanf(msg->fields[i].key, "humidity%d", &channel) == 1 && channel >= 1 && channel <= 8) {
            snprintf(weather->channel_humidity[channel - 1], sizeof(weather->channel_humidity[channel - 1]), "%s", msg->fields[i].value);
        }
    }
    if (!weather->weather_ip[0] && msg->client_ip[0]) {
        snprintf(weather->weather_ip, sizeof(weather->weather_ip), "%s", msg->client_ip);
    }

    weather->latest_field_count = msg->field_count;
    if (weather->latest_field_count > DEVICE_PUSH_MAX_FIELDS) {
        weather->latest_field_count = DEVICE_PUSH_MAX_FIELDS;
    }
    for (int i = 0; i < weather->latest_field_count; ++i) {
        snprintf(weather->latest_fields[i].key, sizeof(weather->latest_fields[i].key), "%s", msg->fields[i].key);
        snprintf(weather->latest_fields[i].value, sizeof(weather->latest_fields[i].value), "%s", msg->fields[i].value);
    }

    weather->last_update = msg->received_at;
    weather->messages_received++;

    char timestamp[32] = "";
    struct tm tm_snapshot;
    localtime_r(&msg->received_at, &tm_snapshot);
    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", &tm_snapshot);

    char summary[UI_LINE_LEN];
    snprintf(
        summary,
        sizeof(summary),
        "%s from %s tempf=%s humidity=%s wind=%s gust=%s barom=%s rainrate=%s",
        timestamp,
        msg->client_ip[0] ? msg->client_ip : "unknown",
        weather->tempf[0] ? weather->tempf : "-",
        weather->humidity[0] ? weather->humidity : "-",
        weather->windspeedmph[0] ? weather->windspeedmph : "-",
        weather->windgustmph[0] ? weather->windgustmph : "-",
        weather->baromrelin[0] ? weather->baromrelin : "-",
        weather->rainratein[0] ? weather->rainratein : "-"
    );
    ingest_append_line(state, summary);

    return 0;
}

static void push_ingest_reset(PushIngestState *state, const char *weather_ip, int listener_port) {
    device_push_listener_stop(&state->listener);
    memset(&state->weather, 0, sizeof(state->weather));
    state->line_count = 0;

    fprintf(stderr, "[scan-ui] push-listener reset: requested weather_ip=%s\n",
            (weather_ip && weather_ip[0]) ? weather_ip : "n/a");

    if (weather_ip && weather_ip[0] != '\0') {
        snprintf(state->weather.weather_ip, sizeof(state->weather.weather_ip), "%s", weather_ip);
    }
    state->recent_packet_count = 0;
    state->listener_port = listener_port;
    ingest_append_line(state, "Weather push listener");
    if (state->storage.db) {
        char storage_line[UI_LINE_LEN];
        snprintf(storage_line, sizeof(storage_line), "Storage DB: %s", state->storage.path);
        ingest_append_line(state, storage_line);
        snprintf(storage_line, sizeof(storage_line), "Retention: %d days (startup prune=%d)", PUSH_DB_RETENTION_DAYS, state->storage.pruned_rows);
        ingest_append_line(state, storage_line);
        int refreshed = push_storage_refresh_recent(&state->storage, state->recent_packets, RECENT_PACKET_ROWS);
        if (refreshed >= 0) {
            state->recent_packet_count = refreshed;
        }
    }

    if (device_push_listener_start(&state->listener, listener_port, weather_push_parser, state) != 0) {
        char line[UI_LINE_LEN];
        snprintf(line, sizeof(line), "Failed to bind listener on %d: %s", listener_port, state->listener.last_error);
        ingest_append_line(state, line);
        fprintf(stderr, "[scan-ui] push-listener start failed: %s\n", state->listener.last_error);
        return;
    }

    fprintf(stderr, "[scan-ui] push-listener started on port %d\n", listener_port);

    char line[UI_LINE_LEN];
    snprintf(line, sizeof(line), "Listening on 0.0.0.0:%d for station pushes", listener_port);
    ingest_append_line(state, line);
    snprintf(
        line,
        sizeof(line),
        "Configure WS-2902 custom upload to %s:%d",
        state->weather.weather_ip[0] ? state->weather.weather_ip : "<your-mac-ip>",
        listener_port
    );
    ingest_append_line(state, line);
}

static void push_ingest_poll(PushIngestState *state) {
    int handled = 0;
    if (state->listener.server_fd < 0) {
        return;
    }

    if (device_push_listener_poll(&state->listener, 8, &handled) != 0) {
        char line[UI_LINE_LEN];
        snprintf(line, sizeof(line), "Listener error: %s", state->listener.last_error);
        ingest_append_line(state, line);
        device_push_listener_stop(&state->listener);
        return;
    }

    if (state->storage.db) {
        int refreshed = push_storage_refresh_recent(&state->storage, state->recent_packets, RECENT_PACKET_ROWS);
        if (refreshed >= 0) {
            state->recent_packet_count = refreshed;
        }
    }

    (void)handled;
}

static void push_ingest_stop(PushIngestState *state) {
    device_push_listener_stop(&state->listener);
    push_storage_close(&state->storage);
}

static int build_weather_detail_lines(const PushIngestState *state, char lines[][UI_LINE_LEN], int max_lines) {
    int count = 0;

    count = append_line(lines, max_lines, count, "Weather Station Data");
    count = append_line(lines, max_lines, count, "Live values from incoming station pushes");
    count = append_line(lines, max_lines, count, "IP: %s", state->weather.weather_ip[0] ? state->weather.weather_ip : "n/a");
    count = append_line(lines, max_lines, count, "Station: %s", state->weather.station_type[0] ? state->weather.station_type : "n/a");
    count = append_line(lines, max_lines, count, "Temp: %s°F | RH: %s%% | Wind: %s mph",
        state->weather.tempf[0] ? state->weather.tempf : "n/a",
        state->weather.humidity[0] ? state->weather.humidity : "n/a",
        state->weather.windspeedmph[0] ? state->weather.windspeedmph : "n/a");
    count = append_line(lines, max_lines, count, "Gust: %s mph | Dir: %s°",
        state->weather.windgustmph[0] ? state->weather.windgustmph : "n/a",
        state->weather.winddir[0] ? state->weather.winddir : "n/a");
    count = append_line(lines, max_lines, count, "Barom rel/abs: %s / %s inHg",
        state->weather.baromrelin[0] ? state->weather.baromrelin : "n/a",
        state->weather.baromabsin[0] ? state->weather.baromabsin : "n/a");
    count = append_line(lines, max_lines, count, "Rain rate/event/day: %s / %s / %s in",
        state->weather.rainratein[0] ? state->weather.rainratein : "n/a",
        state->weather.eventrainin[0] ? state->weather.eventrainin : "n/a",
        state->weather.dailyrainin[0] ? state->weather.dailyrainin : "n/a");
    count = append_line(lines, max_lines, count, "UV: %s | Solar: %s W/m²",
        state->weather.uv[0] ? state->weather.uv : "n/a",
        state->weather.solarradiation[0] ? state->weather.solarradiation : "n/a");
    count = append_line(lines, max_lines, count, "Indoor: %s°F / %s%%",
        state->weather.indoortempf[0] ? state->weather.indoortempf : "n/a",
        state->weather.indoorhumidity[0] ? state->weather.indoorhumidity : "n/a");

    if (state->weather.last_update > 0) {
        char ts[32] = "";
        struct tm tm_snapshot;
        localtime_r(&state->weather.last_update, &tm_snapshot);
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_snapshot);
        count = append_line(lines, max_lines, count, "Last push: %s", ts);
    }

    count = append_line(lines, max_lines, count, "Recent packets from DB:");
    if (state->recent_packet_count <= 0) {
        count = append_line(lines, max_lines, count, "- none yet");
    } else {
        int packet_limit = state->recent_packet_count;
        if (packet_limit > 6) {
            packet_limit = 6;
        }
        for (int i = 0; i < packet_limit; ++i) {
            count = append_line(lines, max_lines, count, "- %s", state->recent_packets[i]);
        }
    }

    return count;
}

static void render_weather_detail_window(
    SDL_Renderer *renderer,
    TTF_Font *font,
    const PushIngestState *state
) {
    int win_w = 0;
    int win_h = 0;
    SDL_GetRendererOutputSize(renderer, &win_w, &win_h);

    SDL_Color bg = {8, 18, 30, 255};
    SDL_Color panel = {18, 28, 44, 255};
    SDL_Color accent = {124, 183, 255, 255};
    SDL_Color text = {230, 239, 255, 255};
    SDL_Color muted = {175, 187, 205, 255};

    SDL_SetRenderDrawColor(renderer, bg.r, bg.g, bg.b, bg.a);
    SDL_RenderClear(renderer);

    SDL_Rect outer = {8, 8, win_w - 16, win_h - 16};
    SDL_SetRenderDrawColor(renderer, panel.r, panel.g, panel.b, panel.a);
    SDL_RenderFillRect(renderer, &outer);
    SDL_SetRenderDrawColor(renderer, accent.r, accent.g, accent.b, accent.a);
    SDL_RenderDrawRect(renderer, &outer);

    SDL_Rect title_bar = {16, 16, win_w - 32, 34};
    SDL_SetRenderDrawColor(renderer, 28, 42, 64, 255);
    SDL_RenderFillRect(renderer, &title_bar);

#ifdef SCAN_HAS_SDL_TTF
    if (font) {
        int line_h = UI_FONT_SIZE + 4;
        int y = 58;
        draw_text_line(renderer, font, 24, y, "Weather Station Data", accent);
        y += line_h;
        draw_text_line(renderer, font, 24, y, "Live values from incoming station pushes", muted);
        y += line_h + 6;

        char lines[256][UI_LINE_LEN];
        int line_count = build_weather_detail_lines(state, lines, 256);
        int visible_lines = (win_h - 88) / line_h;
        if (visible_lines < 1) {
            visible_lines = 1;
        }
        for (int i = 0; i < line_count && i < visible_lines; ++i) {
            draw_text_line(renderer, font, 24, y, lines[i], text);
            y += line_h;
        }
    }
#else
    (void)font;
    (void)state;
#endif
}

static int draw_weather_summary(
    SDL_Renderer *renderer,
    TTF_Font *font,
    const SDL_Rect *traffic_panel,
    const PushIngestState *state,
    SDL_Color color,
    int line_h
) {
    char line[UI_LINE_LEN];
    int y = traffic_panel->y + 10;
    int lines_used = 0;

    SDL_Color banner_color = {123, 209, 255, 255};
    SDL_Color accent = {255, 212, 123, 255};

    snprintf(line, sizeof(line), "LIVE WEATHER  packets=%d", state->weather.messages_received);
    draw_text_line(renderer, font, traffic_panel->x + 10, y, line, banner_color);
    y += line_h;
    lines_used++;

    if (state->weather.last_update > 0) {
        char ts[32] = "";
        struct tm tm_snapshot;
        localtime_r(&state->weather.last_update, &tm_snapshot);
        strftime(ts, sizeof(ts), "%H:%M:%S", &tm_snapshot);
        snprintf(line, sizeof(line), "Last update: %s  Station: %s", ts, state->weather.station_type[0] ? state->weather.station_type : "n/a");
        draw_text_line(renderer, font, traffic_panel->x + 10, y, line, accent);
        y += line_h;
        lines_used++;
    } else {
        draw_text_line(renderer, font, traffic_panel->x + 10, y, "Last update: waiting for first packet", accent);
        y += line_h;
        lines_used++;
    }

    snprintf(line, sizeof(line), "T=%s°F | RH=%s%% | Wind=%s mph | Gust=%s mph",
        state->weather.tempf[0] ? state->weather.tempf : "n/a",
        state->weather.humidity[0] ? state->weather.humidity : "n/a",
        state->weather.windspeedmph[0] ? state->weather.windspeedmph : "n/a",
        state->weather.windgustmph[0] ? state->weather.windgustmph : "n/a");
    draw_text_line(renderer, font, traffic_panel->x + 10, y, line, color);
    y += line_h;
    lines_used++;

    snprintf(line, sizeof(line), "Barom=%s / %s inHg | Rain=%s / %s in",
        state->weather.baromrelin[0] ? state->weather.baromrelin : "n/a",
        state->weather.baromabsin[0] ? state->weather.baromabsin : "n/a",
        state->weather.rainratein[0] ? state->weather.rainratein : "n/a",
        state->weather.dailyrainin[0] ? state->weather.dailyrainin : "n/a");
    draw_text_line(renderer, font, traffic_panel->x + 10, y, line, color);
    y += line_h;
    lines_used++;

    snprintf(line, sizeof(line), "UV=%s | Solar=%s W/m² | Indoor=%s°F/%s%%",
        state->weather.uv[0] ? state->weather.uv : "n/a",
        state->weather.solarradiation[0] ? state->weather.solarradiation : "n/a",
        state->weather.indoortempf[0] ? state->weather.indoortempf : "n/a",
        state->weather.indoorhumidity[0] ? state->weather.indoorhumidity : "n/a");
    draw_text_line(renderer, font, traffic_panel->x + 10, y, line, color);
    y += line_h;
    lines_used++;

    draw_text_line(renderer, font, traffic_panel->x + 10, y, "Recent packets:", color);
    y += line_h;
    lines_used++;

    int packet_limit = state->recent_packet_count;
    if (packet_limit > 3) {
        packet_limit = 3;
    }
    if (packet_limit <= 0) {
        draw_text_line(renderer, font, traffic_panel->x + 10, y, "- none yet", color);
        y += line_h;
        lines_used++;
    } else {
        for (int i = 0; i < packet_limit; ++i) {
            snprintf(line, sizeof(line), "- %s", state->recent_packets[i]);
            draw_text_line(renderer, font, traffic_panel->x + 10, y, line, color);
            y += line_h;
            lines_used++;
        }
    }

    return lines_used;
}

static int draw_weather_detail_panel(
    SDL_Renderer *renderer,
    TTF_Font *font,
    const SDL_Rect *traffic_panel,
    const PushIngestState *state,
    SDL_Color color,
    int line_h
) {
    const WeatherPushData *weather = &state->weather;
    char line[UI_LINE_LEN];
    int y = traffic_panel->y + 10;
    int lines_used = 0;

    draw_text_line(renderer, font, traffic_panel->x + 10, y, "Weather Push", color);
    y += line_h;
    lines_used++;

    snprintf(line, sizeof(line), "IP: %s", weather->weather_ip[0] ? weather->weather_ip : "n/a");
    draw_text_line(renderer, font, traffic_panel->x + 10, y, line, color);
    y += line_h;
    lines_used++;

    snprintf(line, sizeof(line), "Station: %s", weather->station_type[0] ? weather->station_type : "n/a");
    draw_text_line(renderer, font, traffic_panel->x + 10, y, line, color);
    y += line_h;
    lines_used++;

    snprintf(
        line,
        sizeof(line),
        "TempF: %s  RH: %s  Wind: %s mph",
        weather->tempf[0] ? weather->tempf : "-",
        weather->humidity[0] ? weather->humidity : "-",
        weather->windspeedmph[0] ? weather->windspeedmph : "-"
    );
    draw_text_line(renderer, font, traffic_panel->x + 10, y, line, color);
    y += line_h;
    lines_used++;

    snprintf(
        line,
        sizeof(line),
        "Gust: %s mph  Dir: %s deg",
        weather->windgustmph[0] ? weather->windgustmph : "-",
        weather->winddir[0] ? weather->winddir : "-"
    );
    draw_text_line(renderer, font, traffic_panel->x + 10, y, line, color);
    y += line_h;
    lines_used++;

    snprintf(
        line,
        sizeof(line),
        "Barom rel/abs: %s / %s inHg",
        weather->baromrelin[0] ? weather->baromrelin : "-",
        weather->baromabsin[0] ? weather->baromabsin : "-"
    );
    draw_text_line(renderer, font, traffic_panel->x + 10, y, line, color);
    y += line_h;
    lines_used++;

    snprintf(
        line,
        sizeof(line),
        "Rain rate: %s  event/day: %s / %s in",
        weather->rainratein[0] ? weather->rainratein : "-",
        weather->eventrainin[0] ? weather->eventrainin : "-",
        weather->dailyrainin[0] ? weather->dailyrainin : "-"
    );
    draw_text_line(renderer, font, traffic_panel->x + 10, y, line, color);
    y += line_h;
    lines_used++;

    snprintf(
        line,
        sizeof(line),
        "Rain hr/wk/mo/yr: %s / %s / %s / %s in",
        weather->hourlyrainin[0] ? weather->hourlyrainin : "-",
        weather->weeklyrainin[0] ? weather->weeklyrainin : "-",
        weather->monthlyrainin[0] ? weather->monthlyrainin : "-",
        weather->yearlyrainin[0] ? weather->yearlyrainin : "-"
    );
    draw_text_line(renderer, font, traffic_panel->x + 10, y, line, color);
    y += line_h;
    lines_used++;

    snprintf(
        line,
        sizeof(line),
        "UV: %s  Solar: %s W/m2",
        weather->uv[0] ? weather->uv : "-",
        weather->solarradiation[0] ? weather->solarradiation : "-"
    );
    draw_text_line(renderer, font, traffic_panel->x + 10, y, line, color);
    y += line_h;
    lines_used++;

    snprintf(
        line,
        sizeof(line),
        "Indoor TempF: %s  Indoor RH: %s",
        weather->indoortempf[0] ? weather->indoortempf : "-",
        weather->indoorhumidity[0] ? weather->indoorhumidity : "-"
    );
    draw_text_line(renderer, font, traffic_panel->x + 10, y, line, color);
    y += line_h;
    lines_used++;

    int extra_shown = 0;
    for (int i = 0; i < 8 && extra_shown < 4; ++i) {
        if (!weather->channel_tempf[i][0] && !weather->channel_humidity[i][0]) {
            continue;
        }
        snprintf(
            line,
            sizeof(line),
            "Ch%d Temp/RH: %s / %s",
            i + 1,
            weather->channel_tempf[i][0] ? weather->channel_tempf[i] : "-",
            weather->channel_humidity[i][0] ? weather->channel_humidity[i] : "-"
        );
        draw_text_line(renderer, font, traffic_panel->x + 10, y, line, color);
        y += line_h;
        lines_used++;
        extra_shown++;
    }

    if (weather->last_update > 0) {
        char ts[32] = "";
        struct tm tm_snapshot;
        localtime_r(&weather->last_update, &tm_snapshot);
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_snapshot);
        snprintf(line, sizeof(line), "Last push: %s", ts);
        draw_text_line(renderer, font, traffic_panel->x + 10, y, line, color);
        y += line_h;
        lines_used++;
    }

    snprintf(line, sizeof(line), "Parsed fields (last push): %d", weather->latest_field_count);
    draw_text_line(renderer, font, traffic_panel->x + 10, y, line, color);
    y += line_h;
    lines_used++;

    if (weather->latest_field_count > 0) {
        draw_text_line(renderer, font, traffic_panel->x + 10, y, "Latest collected fields:", color);
        y += line_h;
        lines_used++;
        int to_show = weather->latest_field_count;
        if (to_show > 10) {
            to_show = 10;
        }
        for (int i = 0; i < to_show; ++i) {
            snprintf(
                line,
                sizeof(line),
                "- %s = %s",
                weather->latest_fields[i].key,
                weather->latest_fields[i].value
            );
            draw_text_line(renderer, font, traffic_panel->x + 10, y, line, color);
            y += line_h;
            lines_used++;
        }
        if (weather->latest_field_count > to_show) {
            snprintf(line, sizeof(line), "... and %d more", weather->latest_field_count - to_show);
            draw_text_line(renderer, font, traffic_panel->x + 10, y, line, color);
            y += line_h;
            lines_used++;
        }
    }

    draw_text_line(renderer, font, traffic_panel->x + 10, y, "Recent packets from DB:", color);
    y += line_h;
    lines_used++;

    if (state->recent_packet_count <= 0) {
        draw_text_line(renderer, font, traffic_panel->x + 10, y, "- none yet", color);
        y += line_h;
        lines_used++;
    } else {
        for (int i = 0; i < state->recent_packet_count; ++i) {
            snprintf(line, sizeof(line), "- %s", state->recent_packets[i]);
            draw_text_line(renderer, font, traffic_panel->x + 10, y, line, color);
            y += line_h;
            lines_used++;
        }
    }

    return lines_used;
}

static void compute_panels(int win_w, int win_h, SDL_Rect *main_panel, SDL_Rect *traffic_panel) {
    int inner_x = UI_PANEL_MARGIN;
    int inner_y = UI_PANEL_MARGIN;
    int inner_w = win_w - (UI_PANEL_MARGIN * 2);
    int inner_h = win_h - (UI_PANEL_MARGIN * 2);
    if (inner_w < 200) {
        inner_w = 200;
    }
    if (inner_h < 120) {
        inner_h = 120;
    }

    int left_w = (inner_w * 55) / 100;
    int right_w = inner_w - left_w - UI_PANEL_GAP;
    if (right_w < 360) {
        right_w = 360;
        left_w = inner_w - right_w - UI_PANEL_GAP;
    }
    if (left_w < 360) {
        left_w = 360;
        right_w = inner_w - left_w - UI_PANEL_GAP;
    }
    if (right_w < 240) {
        right_w = 240;
    }

    *main_panel = (SDL_Rect){inner_x, inner_y, left_w, inner_h};
    *traffic_panel = (SDL_Rect){inner_x + left_w + UI_PANEL_GAP, inner_y, right_w, inner_h};
}

static const char *window_event_name(Uint8 ev) {
    switch (ev) {
        case SDL_WINDOWEVENT_SHOWN: return "shown";
        case SDL_WINDOWEVENT_HIDDEN: return "hidden";
        case SDL_WINDOWEVENT_EXPOSED: return "exposed";
        case SDL_WINDOWEVENT_MOVED: return "moved";
        case SDL_WINDOWEVENT_RESIZED: return "resized";
        case SDL_WINDOWEVENT_SIZE_CHANGED: return "size_changed";
        case SDL_WINDOWEVENT_MINIMIZED: return "minimized";
        case SDL_WINDOWEVENT_MAXIMIZED: return "maximized";
        case SDL_WINDOWEVENT_RESTORED: return "restored";
        case SDL_WINDOWEVENT_ENTER: return "mouse_enter";
        case SDL_WINDOWEVENT_LEAVE: return "mouse_leave";
        case SDL_WINDOWEVENT_FOCUS_GAINED: return "focus_gained";
        case SDL_WINDOWEVENT_FOCUS_LOST: return "focus_lost";
        case SDL_WINDOWEVENT_CLOSE: return "close";
        default: return "other";
    }
}

static int find_available_listener_port(int preferred_port, int *selected_port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    int yes = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)preferred_port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        if (errno != EADDRINUSE && errno != EADDRNOTAVAIL) {
            close(fd);
            return -1;
        }
        addr.sin_port = 0;
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            close(fd);
            return -1;
        }
    }

    socklen_t addr_len = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *)&addr, &addr_len) != 0) {
        close(fd);
        return -1;
    }

    *selected_port = ntohs(addr.sin_port);
    close(fd);
    return 0;
}

static int send_demo_push_payload(const char *host, int port, const char *payload) {
    int sock = -1;
    struct sockaddr_in addr;
    char request[4096];
    int request_len;
    int rc = -1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        fprintf(stderr, "invalid demo host: %s\n", host);
        return -1;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("connect");
        close(sock);
        return -1;
    }

    request_len = snprintf(
        request,
        sizeof(request),
        "GET /weatherstation/updateweatherstation.php?%s HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Connection: close\r\n"
        "\r\n",
        payload
    );
    if (request_len < 0 || (size_t)request_len >= sizeof(request)) {
        fprintf(stderr, "demo request too large\n");
        close(sock);
        return -1;
    }

    if (send(sock, request, (size_t)request_len, 0) < 0) {
        perror("send");
        close(sock);
        return -1;
    }

    close(sock);
    return 0;
}

static int run_demo_push_mode(const AppConfig *cfg) {
    PushIngestState ingest;
    int handled = 0;
    int attempts = 0;
    const char *payload = "stationtype=AMBWeatherPro_V5.2.2&tempf=92.3&humidity=34&windspeedmph=1.12&windgustmph=2.24";
    const char *db_path = cfg && cfg->db_path[0] ? cfg->db_path : PUSH_DB_PATH;
    int listener_port = cfg ? cfg->listener_port : PUSH_LISTENER_PORT;

    memset(&ingest, 0, sizeof(ingest));
    ingest.storage_error_reported = 0;

    if (push_storage_init(&ingest.storage, db_path) != 0) {
        fprintf(stderr, "[scan-ui] sqlite init failed for %s: %s\n", db_path, ingest.storage.last_error[0] ? ingest.storage.last_error : "unknown");
        return 1;
    }

    if (find_available_listener_port(listener_port, &listener_port) != 0) {
        fprintf(stderr, "[scan-ui] failed to find a free demo listener port, using %d\n", listener_port);
        push_ingest_stop(&ingest);
        return 1;
    }

    push_ingest_reset(&ingest, "127.0.0.1", listener_port);

    if (send_demo_push_payload("127.0.0.1", listener_port, payload) != 0) {
        fprintf(stderr, "[scan-ui] failed to send demo payload\n");
        push_ingest_stop(&ingest);
        return 1;
    }

    while (attempts < 50) {
        if (device_push_listener_poll(&ingest.listener, 1, &handled) != 0) {
            fprintf(stderr, "[scan-ui] demo listener poll failed: %s\n", ingest.listener.last_error);
            push_ingest_stop(&ingest);
            return 1;
        }
        if (handled > 0) {
            break;
        }
        usleep(100000);
        attempts++;
    }

    push_ingest_stop(&ingest);
    if (handled > 0) {
        puts("demo push delivered");
        return 0;
    }
    fprintf(stderr, "[scan-ui] demo push was not handled\n");
    return 1;
}

static int run_ui_mode(const AppConfig *cfg) {
    ScanResult result;
    char scan_err[256] = {0};
    int scan_ok = 0;
    int scan_in_progress = 1;
    UiScanState scan_state;
    memset(&result, 0, sizeof(result));
    memset(&scan_state, 0, sizeof(scan_state));

    if (SDL_Init(SDL_INIT_VIDEO) != 0) {
        fprintf(stderr, "SDL_Init failed: %s\n", SDL_GetError());
        return 1;
    }

    SDL_Window *window = SDL_CreateWindow(
        "Scan",
        SDL_WINDOWPOS_CENTERED,
        SDL_WINDOWPOS_CENTERED,
        1280,
        720,
        SDL_WINDOW_SHOWN
    );
    if (!window) {
        fprintf(stderr, "SDL_CreateWindow failed: %s\n", SDL_GetError());
        SDL_Quit();
        return 1;
    }

    SDL_Renderer *renderer = SDL_CreateRenderer(window, -1, SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
    if (!renderer) {
        renderer = SDL_CreateRenderer(window, -1, SDL_RENDERER_ACCELERATED);
    }
    if (!renderer) {
        fprintf(stderr, "SDL_CreateRenderer failed: %s\n", SDL_GetError());
        SDL_DestroyWindow(window);
        SDL_Quit();
        return 1;
    }

    SDL_Window *weather_window = SDL_CreateWindow(
        "Weather Station Data",
        SDL_WINDOWPOS_CENTERED,
        SDL_WINDOWPOS_CENTERED,
        900,
        700,
        SDL_WINDOW_SHOWN | SDL_WINDOW_RESIZABLE
    );
    SDL_Renderer *weather_renderer = NULL;
    if (weather_window) {
        weather_renderer = SDL_CreateRenderer(weather_window, -1, SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
        if (!weather_renderer) {
            weather_renderer = SDL_CreateRenderer(weather_window, -1, SDL_RENDERER_ACCELERATED);
        }
        if (!weather_renderer) {
            fprintf(stderr, "SDL_CreateRenderer for weather window failed: %s\n", SDL_GetError());
            SDL_DestroyWindow(weather_window);
            weather_window = NULL;
        }
    }

#ifdef SCAN_HAS_SDL_TTF
    if (TTF_Init() != 0) {
        fprintf(stderr, "TTF_Init failed: %s\n", TTF_GetError());
        SDL_DestroyRenderer(renderer);
        SDL_DestroyWindow(window);
        SDL_Quit();
        return 1;
    }

    TTF_Font *font = open_ui_font();
    if (!font) {
        fprintf(stderr, "Failed to open a UI font for results view.\n");
        TTF_Quit();
        SDL_DestroyRenderer(renderer);
        SDL_DestroyWindow(window);
        SDL_Quit();
        return 1;
    }
#endif

    ScanAppState app;
    scan_app_init(&app);

    start_ui_scan_worker(&scan_state);

    Uint64 prev_ticks = SDL_GetPerformanceCounter();
    char lines[UI_MAX_LINES][UI_LINE_LEN];
    int line_count = build_ui_lines(&result, scan_ok, scan_err, scan_in_progress, lines, UI_MAX_LINES);
    int scroll_offset = 0;
    const char *db_path = cfg && cfg->db_path[0] ? cfg->db_path : PUSH_DB_PATH;
    int listener_port = cfg ? cfg->listener_port : PUSH_LISTENER_PORT;
    PushIngestState ingest;
    memset(&ingest, 0, sizeof(ingest));
    ingest.storage_error_reported = 0;
    if (push_storage_init(&ingest.storage, db_path) != 0) {
        fprintf(stderr, "[scan-ui] sqlite init failed for %s: %s\n", db_path, ingest.storage.last_error[0] ? ingest.storage.last_error : "unknown");
    } else {
        fprintf(stderr, "[scan-ui] sqlite ready: %s\n", ingest.storage.path);
    }
    int traffic_scroll_offset = 0;
    if (find_available_listener_port(listener_port, &listener_port) != 0) {
        listener_port = cfg ? cfg->listener_port : PUSH_LISTENER_PORT;
        fprintf(stderr, "[scan-ui] failed to find a free listener port, using %d\n", listener_port);
    }
    push_ingest_reset(&ingest, result.weather_station_ip, listener_port);
    float push_poll_accum = 0.0f;
#ifndef SCAN_HAS_SDL_TTF
    (void)lines;
    (void)line_count;
#endif

    int win_w = 1280;
    int win_h = 720;
    SDL_GetWindowSize(window, &win_w, &win_h);

#ifndef SCAN_HAS_SDL_TTF
    (void)scroll_offset;
    (void)traffic_scroll_offset;
    (void)push_poll_accum;
    (void)win_w;
    (void)win_h;
#endif

    SDL_Rect main_panel = {0, 0, win_w, win_h};
    SDL_Rect traffic_panel = {0, 0, 0, 0};
    compute_panels(win_w, win_h, &main_panel, &traffic_panel);

    fprintf(stderr, "[scan-ui] start: window=%dx%d listener_port=%d weather_ip=%s\n",
            win_w,
            win_h,
            listener_port,
            ingest.weather.weather_ip[0] ? ingest.weather.weather_ip : "n/a");

    char quit_reason[128];
    snprintf(quit_reason, sizeof(quit_reason), "%s", "loop ended without explicit quit reason");

    while (app.running) {
        SDL_Event ev;
        while (SDL_PollEvent(&ev)) {
            if (ev.type == SDL_QUIT) {
                snprintf(quit_reason, sizeof(quit_reason), "%s", "SDL_QUIT event");
                fprintf(stderr, "[scan-ui] event: SDL_QUIT\n");
                app.running = 0;
            } else if (ev.type == SDL_MOUSEWHEEL) {
#ifdef SCAN_HAS_SDL_TTF
                int mx = 0;
                int my = 0;
                SDL_GetMouseState(&mx, &my);
                if (point_in_rect(mx, my, &traffic_panel)) {
                    traffic_scroll_offset -= ev.wheel.y;
                    if (traffic_scroll_offset < 0) {
                        traffic_scroll_offset = 0;
                    }
                } else {
                    scroll_offset -= ev.wheel.y;
                    if (scroll_offset < 0) {
                        scroll_offset = 0;
                    }
                }
#endif
            } else if (ev.type == SDL_KEYDOWN && ev.key.keysym.sym == SDLK_ESCAPE) {
                snprintf(quit_reason, sizeof(quit_reason), "%s", "Escape key");
                fprintf(stderr, "[scan-ui] event: Escape pressed\n");
                app.running = 0;
            } else if (ev.type == SDL_KEYDOWN && ev.key.keysym.sym == SDLK_DOWN) {
#ifdef SCAN_HAS_SDL_TTF
                scroll_offset += 1;
#endif
            } else if (ev.type == SDL_KEYDOWN && ev.key.keysym.sym == SDLK_UP) {
#ifdef SCAN_HAS_SDL_TTF
                scroll_offset -= 1;
                if (scroll_offset < 0) {
                    scroll_offset = 0;
                }
#endif
            } else if (ev.type == SDL_KEYDOWN && ev.key.keysym.sym == SDLK_PAGEDOWN) {
#ifdef SCAN_HAS_SDL_TTF
                scroll_offset += 8;
#endif
            } else if (ev.type == SDL_KEYDOWN && ev.key.keysym.sym == SDLK_PAGEUP) {
#ifdef SCAN_HAS_SDL_TTF
                scroll_offset -= 8;
                if (scroll_offset < 0) {
                    scroll_offset = 0;
                }
#endif
            } else if (ev.type == SDL_KEYDOWN && ev.key.keysym.sym == SDLK_HOME) {
#ifdef SCAN_HAS_SDL_TTF
                scroll_offset = 0;
#endif
            } else if (ev.type == SDL_KEYDOWN && ev.key.keysym.sym == SDLK_END) {
#ifdef SCAN_HAS_SDL_TTF
                scroll_offset = line_count;
#endif
            } else if (ev.type == SDL_KEYDOWN && ev.key.keysym.sym == SDLK_r) {
                scan_err[0] = '\0';
                scan_ok = 0;
                scan_in_progress = 1;
                start_ui_scan_worker(&scan_state);
                line_count = build_ui_lines(&result, scan_ok, scan_err, scan_in_progress, lines, UI_MAX_LINES);
                scroll_offset = 0;
                traffic_scroll_offset = 0;
                push_ingest_reset(&ingest, result.weather_station_ip, ingest.listener_port);
                push_poll_accum = 0.0f;
            } else if (ev.type == SDL_WINDOWEVENT && ev.window.event == SDL_WINDOWEVENT_SIZE_CHANGED) {
                win_w = ev.window.data1;
                win_h = ev.window.data2;
                compute_panels(win_w, win_h, &main_panel, &traffic_panel);
                fprintf(stderr, "[scan-ui] window: size_changed -> %dx%d\n", win_w, win_h);
            } else if (ev.type == SDL_WINDOWEVENT) {
                fprintf(stderr, "[scan-ui] window: %s (%u,%d,%d)\n",
                        window_event_name(ev.window.event),
                        ev.window.event,
                        ev.window.data1,
                        ev.window.data2);
                if (ev.window.event == SDL_WINDOWEVENT_CLOSE) {
                    snprintf(quit_reason, sizeof(quit_reason), "%s", "window close event");
                }
            }
        }

        Uint64 now_ticks = SDL_GetPerformanceCounter();
        float dt = (float)(now_ticks - prev_ticks) / (float)SDL_GetPerformanceFrequency();
        prev_ticks = now_ticks;
        scan_app_update(&app, dt);

        if (scan_state.active && scan_state.done) {
            scan_ok = scan_state.scan_ok;
            snprintf(scan_err, sizeof(scan_err), "%s", scan_state.scan_err);
            result = scan_state.result;
            scan_in_progress = 0;
            line_count = build_ui_lines(&result, scan_ok, scan_err, scan_in_progress, lines, UI_MAX_LINES);
            scroll_offset = 0;
        }

        push_poll_accum += dt;
        if (push_poll_accum >= PUSH_POLL_INTERVAL_SEC) {
            push_ingest_poll(&ingest);
            push_poll_accum = 0.0f;
        }

        SDL_SetRenderDrawColor(renderer, 14, 22, 34, 255);
        SDL_RenderClear(renderer);

#ifdef SCAN_HAS_SDL_TTF
        SDL_SetRenderDrawColor(renderer, 20, 30, 46, 255);
        SDL_RenderFillRect(renderer, &main_panel);
        SDL_RenderFillRect(renderer, &traffic_panel);
        SDL_SetRenderDrawColor(renderer, 62, 93, 130, 255);
        SDL_RenderDrawRect(renderer, &main_panel);
        SDL_RenderDrawRect(renderer, &traffic_panel);

        SDL_Color color = {225, 236, 245, 255};
        SDL_Color header_color = {123, 209, 255, 255};
        SDL_Color muted_color = {168, 186, 208, 255};
        SDL_Color accent_color = {255, 212, 123, 255};
        int y = main_panel.y + 10;
        int line_h = TTF_FontLineSkip(font) + 4;
        SDL_Rect main_clip = {
            main_panel.x + 8,
            main_panel.y + 8,
            main_panel.w - UI_SCROLLBAR_WIDTH - 20,
            main_panel.h - 16
        };
        begin_clip(renderer, &main_clip);
        int visible_lines = (main_panel.h - 20) / line_h;
        if (visible_lines < 1) {
            visible_lines = 1;
        }
        int max_offset = line_count - visible_lines;
        if (max_offset < 0) {
            max_offset = 0;
        }
        if (scroll_offset > max_offset) {
            scroll_offset = max_offset;
        }

        draw_text_line(renderer, font, main_panel.x + 14, y, "Local network overview", header_color);
        y += line_h;
        draw_text_line(renderer, font, main_panel.x + 14, y, "Use R to refresh, scroll to move, Esc to quit", muted_color);
        y += line_h + 4;
        char quick_status[UI_LINE_LEN];
        snprintf(
            quick_status,
            sizeof(quick_status),
            "Live: packets=%d | station=%s | temp=%s°F | wind=%s mph",
            ingest.weather.messages_received,
            ingest.weather.station_type[0] ? ingest.weather.station_type : "n/a",
            ingest.weather.tempf[0] ? ingest.weather.tempf : "n/a",
            ingest.weather.windspeedmph[0] ? ingest.weather.windspeedmph : "n/a"
        );
        draw_text_line(renderer, font, main_panel.x + 10, y, quick_status, accent_color);
        y += line_h + 2;

        for (int i = scroll_offset; i < line_count && (i - scroll_offset) < visible_lines; ++i) {
            draw_text_line(renderer, font, main_panel.x + 10, y, lines[i], color);
            y += line_h;
        }
        end_clip(renderer);

        if (line_count > visible_lines) {
            SDL_Rect bar = {
                main_panel.x + main_panel.w - UI_SCROLLBAR_WIDTH - 6,
                main_panel.y + 10,
                UI_SCROLLBAR_WIDTH,
                main_panel.h - 20
            };
            SDL_SetRenderDrawColor(renderer, 42, 64, 92, 255);
            SDL_RenderFillRect(renderer, &bar);

            float ratio = (float)visible_lines / (float)line_count;
            int thumb_h = (int)(bar.h * ratio);
            if (thumb_h < 24) {
                thumb_h = 24;
            }
            if (thumb_h > bar.h) {
                thumb_h = bar.h;
            }

            int travel = bar.h - thumb_h;
            int thumb_y = bar.y;
            if (max_offset > 0 && travel > 0) {
                thumb_y = bar.y + (scroll_offset * travel) / max_offset;
            }

            SDL_Rect thumb = {bar.x, thumb_y, bar.w, thumb_h};
            SDL_SetRenderDrawColor(renderer, 122, 172, 224, 255);
            SDL_RenderFillRect(renderer, &thumb);
        }

        SDL_Color traffic_color = {205, 226, 255, 255};
        SDL_Rect traffic_clip = {
            traffic_panel.x + 8,
            traffic_panel.y + 8,
            traffic_panel.w - UI_SCROLLBAR_WIDTH - 20,
            traffic_panel.h - 16
        };
        begin_clip(renderer, &traffic_clip);
        int summary_lines = draw_weather_summary(renderer, font, &traffic_panel, &ingest, traffic_color, line_h);
        if (summary_lines < 1) {
            summary_lines = 1;
        }
        int ty = traffic_panel.y + 10 + (summary_lines * line_h);
        int traffic_visible_lines = (traffic_panel.h - 20) / line_h - summary_lines;
        if (traffic_visible_lines < 1) {
            traffic_visible_lines = 1;
        }
        int traffic_max_offset = ingest.line_count - traffic_visible_lines;
        if (traffic_max_offset < 0) {
            traffic_max_offset = 0;
        }
        if (traffic_scroll_offset > traffic_max_offset) {
            traffic_scroll_offset = traffic_max_offset;
        }

        for (int i = traffic_scroll_offset; i < ingest.line_count && (i - traffic_scroll_offset) < traffic_visible_lines; ++i) {
            draw_text_line(renderer, font, traffic_panel.x + 10, ty, ingest.lines[i], color);
            ty += line_h;
        }
        end_clip(renderer);

        if (ingest.line_count > traffic_visible_lines) {
            SDL_Rect tbar = {
                traffic_panel.x + traffic_panel.w - UI_SCROLLBAR_WIDTH - 6,
                traffic_panel.y + 10,
                UI_SCROLLBAR_WIDTH,
                traffic_panel.h - 20
            };
            SDL_SetRenderDrawColor(renderer, 42, 64, 92, 255);
            SDL_RenderFillRect(renderer, &tbar);

            float tratio = (float)traffic_visible_lines / (float)ingest.line_count;
            int tthumb_h = (int)(tbar.h * tratio);
            if (tthumb_h < 24) {
                tthumb_h = 24;
            }
            if (tthumb_h > tbar.h) {
                tthumb_h = tbar.h;
            }

            int ttravel = tbar.h - tthumb_h;
            int tthumb_y = tbar.y;
            if (traffic_max_offset > 0 && ttravel > 0) {
                tthumb_y = tbar.y + (traffic_scroll_offset * ttravel) / traffic_max_offset;
            }

            SDL_Rect tthumb = {tbar.x, tthumb_y, tbar.w, tthumb_h};
            SDL_SetRenderDrawColor(renderer, 122, 172, 224, 255);
            SDL_RenderFillRect(renderer, &tthumb);
        }
#endif

        SDL_RenderPresent(renderer);
        if (weather_renderer) {
            render_weather_detail_window(weather_renderer, font, &ingest);
            SDL_RenderPresent(weather_renderer);
        }
    }

    fprintf(stderr, "[scan-ui] exit: %s\n", quit_reason);

    push_storage_print_exit_summary(&ingest.storage, EXIT_DB_PREVIEW_ROWS);

    push_ingest_stop(&ingest);

#ifdef SCAN_HAS_SDL_TTF
    TTF_CloseFont(font);
    TTF_Quit();
#endif
    if (weather_renderer) {
        SDL_DestroyRenderer(weather_renderer);
    }
    if (weather_window) {
        SDL_DestroyWindow(weather_window);
    }
    SDL_DestroyRenderer(renderer);
    SDL_DestroyWindow(window);
    SDL_Quit();
    return 0;
}

int main(int argc, char **argv) {
    AppConfig cfg;
    int lock_fd = -1;
    int should_guard = 0;

    if (parse_app_config(argc, argv, &cfg) != 0) {
        return 1;
    }

    if (cfg.show_help) {
        print_usage(argv[0]);
        return 0;
    }

    if (cfg.ui_mode) {
        should_guard = 1;
    }

    if (should_guard) {
        int other_running = scan_ui_instance_running(getpid());
        if (other_running > 0) {
            fprintf(stderr, "[scan-ui] another instance is already running; refusing to start a duplicate.\n");
            return 0;
        }
        if (other_running < 0) {
            fprintf(stderr, "[scan-ui] failed to inspect existing processes; continuing with lock fallback.\n");
        }
    }

    int lock_rc = acquire_single_instance_lock(SINGLE_INSTANCE_LOCK_PATH, &lock_fd);
    if (lock_rc != 0) {
        release_single_instance_lock(lock_fd, SINGLE_INSTANCE_LOCK_PATH);
        return lock_rc == 1 ? 0 : 1;
    }

    int rc = 0;
    if (cfg.info_mode) {
        rc = run_info_mode();
    } else if (cfg.export_csv_mode) {
        rc = run_export_csv_mode(&cfg, cfg.export_csv_path);
    } else if (cfg.ui_mode) {
        rc = run_ui_mode(&cfg);
    } else if (cfg.demo_push_mode) {
        rc = run_demo_push_mode(&cfg);
    } else if (cfg.scan_mode) {
        rc = run_scan_mode();
    } else {
        rc = run_scan_mode();
    }

    release_single_instance_lock(lock_fd, SINGLE_INSTANCE_LOCK_PATH);
    return rc;
}
