#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
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

static int build_ui_lines(
    const ScanResult *result,
    int scan_ok,
    const char *scan_err,
    char lines[][UI_LINE_LEN],
    int max_lines
) {
    int count = 0;
    count = append_line(lines, max_lines, count, "Scan - Local Network Overview");
    count = append_line(lines, max_lines, count, "Keys: R=refresh  MouseWheel/Up/Down/PgUp/PgDn/Home/End scroll  Esc=quit");
    count = append_line(lines, max_lines, count, "");

    if (!scan_ok) {
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
    WeatherPushData weather;
    char lines[UI_TRAFFIC_MAX_LINES][UI_LINE_LEN];
    int line_count;
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

static int weather_push_parser(const DevicePushMessage *msg, void *user_data) {
    PushIngestState *state = (PushIngestState *)user_data;
    WeatherPushData *weather = &state->weather;

    const char *stationtype = push_field_value(msg, "stationtype");
    const char *tempf = push_field_value(msg, "tempf");
    const char *humidity = push_field_value(msg, "humidity");
    const char *windspeedmph = push_field_value(msg, "windspeedmph");
    const char *windgustmph = push_field_value(msg, "windgustmph");
    const char *winddir = push_field_value(msg, "winddir");
    const char *baromrelin = push_field_value(msg, "baromrelin");
    const char *baromabsin = push_field_value(msg, "baromabsin");
    const char *rainin = push_field_value(msg, "rainin");
    const char *rainratein = push_field_value(msg, "rainratein");
    const char *eventrainin = push_field_value(msg, "eventrainin");
    const char *hourlyrainin = push_field_value(msg, "hourlyrainin");
    const char *dailyrainin = push_field_value(msg, "dailyrainin");
    const char *weeklyrainin = push_field_value(msg, "weeklyrainin");
    const char *monthlyrainin = push_field_value(msg, "monthlyrainin");
    const char *yearlyrainin = push_field_value(msg, "yearlyrainin");
    const char *uv = push_field_value(msg, "uv");
    const char *solarradiation = push_field_value(msg, "solarradiation");
    const char *indoortempf = push_field_value(msg, "indoortempf");
    const char *indoorhumidity = push_field_value(msg, "indoorhumidity");

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

static void push_ingest_reset(PushIngestState *state, const char *weather_ip) {
    device_push_listener_stop(&state->listener);
    memset(&state->weather, 0, sizeof(state->weather));
    state->line_count = 0;

    fprintf(stderr, "[scan-ui] push-listener reset: requested weather_ip=%s\n",
            (weather_ip && weather_ip[0]) ? weather_ip : "n/a");

    if (weather_ip && weather_ip[0] != '\0') {
        snprintf(state->weather.weather_ip, sizeof(state->weather.weather_ip), "%s", weather_ip);
    }
    ingest_append_line(state, "Weather push listener");

    if (device_push_listener_start(&state->listener, PUSH_LISTENER_PORT, weather_push_parser, state) != 0) {
        char line[UI_LINE_LEN];
        snprintf(line, sizeof(line), "Failed to bind listener on %d: %s", PUSH_LISTENER_PORT, state->listener.last_error);
        ingest_append_line(state, line);
        fprintf(stderr, "[scan-ui] push-listener start failed: %s\n", state->listener.last_error);
        return;
    }

    fprintf(stderr, "[scan-ui] push-listener started on port %d\n", PUSH_LISTENER_PORT);

    char line[UI_LINE_LEN];
    snprintf(line, sizeof(line), "Listening on 0.0.0.0:%d for station pushes", PUSH_LISTENER_PORT);
    ingest_append_line(state, line);
    snprintf(
        line,
        sizeof(line),
        "Configure WS-2902 custom upload to %s:%d",
        state->weather.weather_ip[0] ? state->weather.weather_ip : "<your-mac-ip>",
        PUSH_LISTENER_PORT
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

    (void)handled;
}

static void push_ingest_stop(PushIngestState *state) {
    device_push_listener_stop(&state->listener);
}

static int draw_weather_summary(
    SDL_Renderer *renderer,
    TTF_Font *font,
    const SDL_Rect *traffic_panel,
    const WeatherPushData *weather,
    SDL_Color color,
    int line_h
) {
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

static int run_ui_mode(void) {
    ScanResult result;
    char scan_err[256] = {0};
    int scan_ok = (wifi_scan_collect(&result, scan_err, sizeof(scan_err)) == 0);

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

    Uint64 prev_ticks = SDL_GetPerformanceCounter();
    char lines[UI_MAX_LINES][UI_LINE_LEN];
    int line_count = build_ui_lines(&result, scan_ok, scan_err, lines, UI_MAX_LINES);
    int scroll_offset = 0;
    PushIngestState ingest;
    memset(&ingest, 0, sizeof(ingest));
    int traffic_scroll_offset = 0;
    push_ingest_reset(&ingest, result.weather_station_ip);
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
            PUSH_LISTENER_PORT,
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
                scan_ok = (wifi_scan_collect(&result, scan_err, sizeof(scan_err)) == 0);
                line_count = build_ui_lines(&result, scan_ok, scan_err, lines, UI_MAX_LINES);
                scroll_offset = 0;
                traffic_scroll_offset = 0;
                push_ingest_reset(&ingest, result.weather_station_ip);
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
        int summary_lines = draw_weather_summary(renderer, font, &traffic_panel, &ingest.weather, traffic_color, line_h);
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
    }

    fprintf(stderr, "[scan-ui] exit: %s\n", quit_reason);

    push_ingest_stop(&ingest);

#ifdef SCAN_HAS_SDL_TTF
    TTF_CloseFont(font);
    TTF_Quit();
#endif
    SDL_DestroyRenderer(renderer);
    SDL_DestroyWindow(window);
    SDL_Quit();
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--info") == 0) {
        return run_info_mode();
    }
    if (argc > 1 && strcmp(argv[1], "--ui") == 0) {
        return run_ui_mode();
    }
    if (argc > 1 && strcmp(argv[1], "--scan") == 0) {
        return run_scan_mode();
    }

    return run_scan_mode();
}
