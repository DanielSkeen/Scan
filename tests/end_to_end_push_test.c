#include "device_push.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sqlite3.h>

struct TestState {
    int parser_calls;
    int field_count;
    char last_station_type[64];
    char last_tempf[32];
    char last_humidity[32];
};

static int parser_cb(const DevicePushMessage *msg, void *user_data) {
    struct TestState *state = (struct TestState *)user_data;
    state->parser_calls++;
    state->field_count = msg->field_count;

    for (int i = 0; i < msg->field_count; ++i) {
        if (strcmp(msg->fields[i].key, "stationtype") == 0) {
            snprintf(state->last_station_type, sizeof(state->last_station_type), "%s", msg->fields[i].value);
        } else if (strcmp(msg->fields[i].key, "tempf") == 0) {
            snprintf(state->last_tempf, sizeof(state->last_tempf), "%s", msg->fields[i].value);
        } else if (strcmp(msg->fields[i].key, "humidity") == 0) {
            snprintf(state->last_humidity, sizeof(state->last_humidity), "%s", msg->fields[i].value);
        }
    }
    return 0;
}

int main(void) {
    struct TestState state = {0};
    DevicePushListener listener;
    int handled = 0;
    int port = 18090;
    int client_fd;
    struct sockaddr_in addr;
    const char *payload = "stationtype=AMBWeatherPro_V5.2.2&tempf=92.3&humidity=34&windspeedmph=1.12&windgustmph=2.24";
    char request[4096];
    int request_len;
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int rc;

    if (device_push_listener_start(&listener, port, parser_cb, &state) != 0) {
        fprintf(stderr, "listener start failed: %s\n", listener.last_error);
        return 1;
    }

    client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0) {
        perror("socket");
        device_push_listener_stop(&listener);
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(client_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("connect");
        close(client_fd);
        device_push_listener_stop(&listener);
        return 1;
    }

    request_len = snprintf(
        request,
        sizeof(request),
        "GET /weatherstation/updateweatherstation.php?%s HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Content-Length: 0\r\n"
        "\r\n",
        payload
    );

    if (send(client_fd, request, (size_t)request_len, 0) < 0) {
        perror("send");
        close(client_fd);
        device_push_listener_stop(&listener);
        return 1;
    }

    if (device_push_listener_poll(&listener, 1, &handled) != 0) {
        fprintf(stderr, "listener poll failed: %s\n", listener.last_error);
        close(client_fd);
        device_push_listener_stop(&listener);
        return 1;
    }

    close(client_fd);
    device_push_listener_stop(&listener);

    if (state.parser_calls != 1 || state.field_count < 3) {
        fprintf(stderr, "parser did not receive the expected fields\n");
        return 2;
    }

    rc = sqlite3_open("/tmp/scan_end_to_end_test.db", &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "sqlite open failed: %d\n", rc);
        return 3;
    }

    rc = sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS weather_packets (station_type TEXT, tempf TEXT, humidity TEXT);", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "sqlite create table failed: %d\n", rc);
        sqlite3_close(db);
        return 4;
    }

    rc = sqlite3_prepare_v2(db, "INSERT INTO weather_packets (station_type, tempf, humidity) VALUES (?, ?, ?);", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "sqlite prepare failed: %d\n", rc);
        sqlite3_close(db);
        return 5;
    }

    rc = sqlite3_bind_text(stmt, 1, state.last_station_type, -1, SQLITE_TRANSIENT);
    rc |= sqlite3_bind_text(stmt, 2, state.last_tempf, -1, SQLITE_TRANSIENT);
    rc |= sqlite3_bind_text(stmt, 3, state.last_humidity, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "sqlite bind failed: %d\n", rc);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 6;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "sqlite insert failed: %d\n", rc);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 7;
    }

    sqlite3_finalize(stmt);
    stmt = NULL;

    rc = sqlite3_prepare_v2(db, "SELECT station_type, tempf, humidity FROM weather_packets LIMIT 1;", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "sqlite select prepare failed: %d\n", rc);
        sqlite3_close(db);
        return 8;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        fprintf(stderr, "sqlite select returned no row\n");
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 9;
    }

    const unsigned char *station_type = sqlite3_column_text(stmt, 0);
    const unsigned char *tempf = sqlite3_column_text(stmt, 1);
    const unsigned char *humidity = sqlite3_column_text(stmt, 2);

    if (!station_type || !tempf || !humidity || strcmp((const char *)station_type, "AMBWeatherPro_V5.2.2") != 0 || strcmp((const char *)tempf, "92.3") != 0 || strcmp((const char *)humidity, "34") != 0) {
        fprintf(stderr, "sqlite values did not match the parsed payload\n");
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 10;
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    printf("end-to-end-push-test passed\n");
    return 0;
}
