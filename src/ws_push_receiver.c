#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEFAULT_PORT 8089
#define REQUEST_BUF 8192

typedef struct {
    char key[64];
    char value[256];
} Pair;

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

static int parse_pairs(const char *query, Pair *pairs, int max_pairs) {
    int count = 0;
    const char *cursor = query;
    while (*cursor != '\0' && count < max_pairs) {
        const char *amp = strchr(cursor, '&');
        size_t span = amp ? (size_t)(amp - cursor) : strlen(cursor);
        if (span > 0) {
            char chunk[384];
            if (span >= sizeof(chunk)) {
                span = sizeof(chunk) - 1;
            }
            memcpy(chunk, cursor, span);
            chunk[span] = '\0';

            char *eq = strchr(chunk, '=');
            if (eq) {
                *eq = '\0';
                url_decode(chunk, pairs[count].key, sizeof(pairs[count].key));
                url_decode(eq + 1, pairs[count].value, sizeof(pairs[count].value));
            } else {
                url_decode(chunk, pairs[count].key, sizeof(pairs[count].key));
                pairs[count].value[0] = '\0';
            }
            count++;
        }
        if (!amp) break;
        cursor = amp + 1;
    }
    return count;
}

static void print_pairs(const Pair *pairs, int count) {
    puts("PUSH:");
    for (int i = 0; i < count; ++i) {
        printf("  %s = %s\n", pairs[i].key, pairs[i].value);
    }
}

static void send_success(int client_fd) {
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
        send(client_fd, response, (size_t)response_len, 0);
    }
}

static void handle_client(int client_fd) {
    char request[REQUEST_BUF];
    ssize_t n = recv(client_fd, request, sizeof(request) - 1, 0);
    if (n <= 0) {
        return;
    }
    request[n] = '\0';

    char method[8] = {0};
    char uri[1024] = {0};
    if (sscanf(request, "%7s %1023s", method, uri) != 2) {
        send_success(client_fd);
        return;
    }

    const char *query = strchr(uri, '?');
    if (query && query[1] != '\0') {
        Pair pairs[64];
        int pair_count = parse_pairs(query + 1, pairs, 64);
        printf("%s %s\n", method, uri);
        print_pairs(pairs, pair_count);
    } else {
        printf("%s %s\n", method, uri);
    }

    fflush(stdout);
    send_success(client_fd);
}

int main(int argc, char **argv) {
    int port = DEFAULT_PORT;
    if (argc > 1) {
        port = atoi(argv[1]);
        if (port <= 0) {
            port = DEFAULT_PORT;
        }
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    int yes = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 8) < 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    printf("Listening on 0.0.0.0:%d\n", port);
    fflush(stdout);

    for (;;) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }
        handle_client(client_fd);
        close(client_fd);
    }

    close(server_fd);
    return 0;
}