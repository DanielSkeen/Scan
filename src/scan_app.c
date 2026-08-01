#include "scan_app.h"

void scan_app_init(ScanAppState *state) {
    state->running = 1;
    state->elapsed_seconds = 0.0f;
}

void scan_app_update(ScanAppState *state, float dt_seconds) {
    state->elapsed_seconds += dt_seconds;
}
