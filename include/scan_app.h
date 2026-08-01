#ifndef SCAN_APP_H
#define SCAN_APP_H

typedef struct {
    int running;
    float elapsed_seconds;
} ScanAppState;

void scan_app_init(ScanAppState *state);
void scan_app_update(ScanAppState *state, float dt_seconds);

#endif
