#include "device_push.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define REQUEST_BUF_SIZE 8192

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static void url_decode(const char *src, char *dst, size_t dst_len) {
    size_t out = 0;
    for (size_t i = 0; src[i] != '\0' && out + 1 < dst_len; ++i) {
        if (src[i] == '+') {
            dst[out++] = ' ';
        } else if (src[i] == '%' && src[i + 1] && src[i + 2]) {
            int hi = hex_value(src[i + 1]);
            int lo = hex_value(src[i + 2]);
            if (hi >= 0 && lo >= 0) {
                dst[out++] = (char)((hi << 4) | lo);
                i += 2;
            }
        } else {
            dst[out++] = src[i];
        }
    }
    dst[out] = '\0';
}

static int parse_query_fields(const char *query, DevicePushField *fields, int max_fields) {
    int count = 0;
    const char *cursor = query;

    while (*cursor != '\0' && count < max_fields) {
        const char *amp = strchr(cursor, '&');
        size_t span = amp ? (size_t)(amp - cursor) : strlen(cursor);
        if (span > 0) {
            char chunk[512];
            if (span >= sizeof(chunk)) {
                span = sizeof(chunk) - 1;
            }
            memcpy(chunk, cursor, span);
            chunk[span] = '\0';

            char *eq = strchr(chunk, '=');
            if (eq) {
                *eq = '\0';
                url_decode(chunk, fields[count].key, sizeof(fields[count].key));
                url_decode(eq + 1, fields[count].value, sizeof(fields[count].value));
            } else {
                url_decode(chunk, fields[count].key, sizeof(fields[count].key));
                fields[count].value[0] = '\0';
            }
            count++;
        }

        if (!amp) {
            break;
        }
        cursor = amp + 1;
    }

    return count;
}

static int append_parsed_fields(const char *payload, DevicePushField *fields, int start_idx, int max_fields) {
    if (!payload || payload[0] == '\0' || start_idx >= max_fields) {
        return start_idx;
    }
    int added = parse_query_fields(payload, fields + start_idx, max_fields - start_idx);
    return start_idx + added;
}

static void send_success_response(int client_fd) {
    const char *body = "success\n";
    char response[256];
    int body_len = (int)strlen(body);

    int response_len = snprintf(
        response,
        sizeof(response),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        body_len,
        body
    );

    if (response_len > 0) {
        (void)send(client_fd, response, (size_t)response_len, 0);
    }
}

static int handle_client(DevicePushListener *listener, int client_fd, const struct sockaddr_in *client_addr) {
    char request[REQUEST_BUF_SIZE];
    ssize_t n = recv(client_fd, request, sizeof(request) - 1, 0);
    if (n <= 0) {
        send_success_response(client_fd);
        return 0;
    }
    request[n] = '\0';

    DevicePushMessage msg;
    memset(&msg, 0, sizeof(msg));

    char uri[1024] = {0};
    if (sscanf(request, "%7s %1023s", msg.method, uri) != 2) {
        send_success_response(client_fd);
        return 0;
    }

    const char *query = strchr(uri, '?');
    const char *body = strstr(request, "\r\n\r\n");
    if (body) {
        body += 4;
    }

    msg.field_count = 0;
    if (query) {
        size_t path_len = (size_t)(query - uri);
        if (path_len >= sizeof(msg.path)) {
            path_len = sizeof(msg.path) - 1;
        }
        memcpy(msg.path, uri, path_len);
        msg.path[path_len] = '\0';
        msg.field_count = append_parsed_fields(query + 1, msg.fields, msg.field_count, DEVICE_PUSH_MAX_FIELDS);
    } else {
        snprintf(msg.path, sizeof(msg.path), "%s", uri);
    }

    if (body && body[0] != '\0') {
        msg.field_count = append_parsed_fields(body, msg.fields, msg.field_count, DEVICE_PUSH_MAX_FIELDS);
    }

    if (client_addr) {
        (void)inet_ntop(AF_INET, &client_addr->sin_addr, msg.client_ip, sizeof(msg.client_ip));
    }

    msg.received_at = time(NULL);

    send_success_response(client_fd);

    if (listener->parser) {
        return listener->parser(&msg, listener->parser_user_data);
    }

    return 0;
}

int device_push_listener_start(
    DevicePushListener *listener,
    int port,
    DevicePushParser parser,
    void *parser_user_data
) {
    if (!listener || port <= 0 || !parser) {
        return -1;
    }

    memset(listener, 0, sizeof(*listener));
    listener->server_fd = -1;
    listener->port = port;
    listener->parser = parser;
    listener->parser_user_data = parser_user_data;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        snprintf(listener->last_error, sizeof(listener->last_error), "socket failed: %s", strerror(errno));
        return -1;
    }

    int yes = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        snprintf(listener->last_error, sizeof(listener->last_error), "bind %d failed: %s", port, strerror(errno));
        close(fd);
        return -1;
    }

    if (listen(fd, 16) < 0) {
        snprintf(listener->last_error, sizeof(listener->last_error), "listen failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    listener->server_fd = fd;
    listener->last_error[0] = '\0';
    return 0;
}

void device_push_listener_stop(DevicePushListener *listener) {
    if (!listener) {
        return;
    }

    if (listener->server_fd >= 0) {
        close(listener->server_fd);
        listener->server_fd = -1;
    }
}

int device_push_listener_poll(DevicePushListener *listener, int max_requests, int *handled_requests) {
    if (!listener || listener->server_fd < 0 || max_requests <= 0) {
        return -1;
    }

    int handled = 0;
    for (int i = 0; i < max_requests; ++i) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(listener->server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_fd < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                break;
            }
            snprintf(listener->last_error, sizeof(listener->last_error), "accept failed: %s", strerror(errno));
            if (handled_requests) {
                *handled_requests = handled;
            }
            return -1;
        }

        (void)handle_client(listener, client_fd, &client_addr);
        close(client_fd);
        handled++;
    }

    if (handled_requests) {
        *handled_requests = handled;
    }
    return 0;
}
