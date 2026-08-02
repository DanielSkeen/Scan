#include "device_push.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct TestState {
    int parser_calls;
    int field_count;
};

static int parser_cb(const DevicePushMessage *msg, void *user_data) {
    struct TestState *state = (struct TestState *)user_data;
    state->parser_calls++;
    state->field_count = msg->field_count;
    return 0;
}

static int run_large_request_test(int port) {
    struct TestState state = {0, 0};
    DevicePushListener listener;
    int handled = 0;
    int client_fd;
    struct sockaddr_in addr;
    char body[12000];
    char request[14000];
    int request_len;

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

    memset(body, 0, sizeof(body));
    snprintf(body, sizeof(body), "field1=%s&field2=%s", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    request_len = snprintf(
        request,
        sizeof(request),
        "POST /push HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: %zu\r\n"
        "\r\n"
        "%s",
        strlen(body),
        body
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

    if (state.parser_calls != 1 || state.field_count < 2) {
        fprintf(stderr, "expected parser to receive at least 2 fields, got %d fields in %d calls\n", state.field_count, state.parser_calls);
        return 2;
    }

    return 0;
}

static int run_malformed_request_test(int port) {
    struct TestState state = {0, 0};
    DevicePushListener listener;
    int handled = 0;
    int client_fd;
    struct sockaddr_in addr;
    const char *request = "BADREQUEST\r\n\r\n";

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

    if (send(client_fd, request, strlen(request), 0) < 0) {
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

    if (state.parser_calls != 0) {
        fprintf(stderr, "malformed request should not invoke parser, got %d calls\n", state.parser_calls);
        return 2;
    }

    return 0;
}

int main(void) {
    int port = 18089;

    if (run_large_request_test(port) != 0) {
        return 1;
    }

    if (run_malformed_request_test(port + 1) != 0) {
        return 1;
    }

    printf("large-request-test passed\n");
    printf("malformed-request-test passed\n");
    return 0;
}

