#ifndef DEVICE_PUSH_H
#define DEVICE_PUSH_H

#include <stddef.h>
#include <time.h>

#define DEVICE_PUSH_MAX_FIELDS 96

typedef struct {
    char key[64];
    char value[256];
} DevicePushField;

typedef struct {
    char method[8];
    char path[256];
    char client_ip[64];
    time_t received_at;
    DevicePushField fields[DEVICE_PUSH_MAX_FIELDS];
    int field_count;
} DevicePushMessage;

typedef int (*DevicePushParser)(const DevicePushMessage *msg, void *user_data);

typedef struct {
    int server_fd;
    int port;
    DevicePushParser parser;
    void *parser_user_data;
    char last_error[128];
} DevicePushListener;

int device_push_listener_start(
    DevicePushListener *listener,
    int port,
    DevicePushParser parser,
    void *parser_user_data
);

void device_push_listener_stop(DevicePushListener *listener);

int device_push_listener_poll(DevicePushListener *listener, int max_requests, int *handled_requests);

#endif