CC = clang
CFLAGS = -Wall -Wextra -O2 -Iinclude
TARGET = scan
UNAME_S := $(shell uname -s)

SRC_COMMON = src/main.c src/scan_app.c src/device_push.c

ifeq ($(UNAME_S),Darwin)
SRC_PLATFORM = src/wifi_scan_macos.c
else
SRC_PLATFORM = src/wifi_scan_stub.c
endif

SRC = $(SRC_COMMON) $(SRC_PLATFORM)

SDL_CFLAGS := $(shell sdl2-config --cflags 2>/dev/null)
SDL_LIBS := $(shell sdl2-config --libs 2>/dev/null)
TTF_CFLAGS := $(shell if [ -f /opt/homebrew/include/SDL2/SDL_ttf.h ]; then echo -DSCAN_HAS_SDL_TTF=1; fi)
TTF_LIBS := $(shell ls /opt/homebrew/lib/libSDL2_ttf* >/dev/null 2>&1 && echo -lSDL2_ttf)

ifeq ($(strip $(SDL_CFLAGS)),)
SDL_CFLAGS := $(shell pkg-config --cflags sdl2 2>/dev/null)
endif

ifeq ($(strip $(SDL_LIBS)),)
SDL_LIBS := $(shell pkg-config --libs sdl2 2>/dev/null)
endif

.PHONY: all clean test run
.PHONY: receiver receiver-run

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SDL_CFLAGS) $(TTF_CFLAGS) -o $@ $(SRC) $(SDL_LIBS) $(TTF_LIBS)

run: $(TARGET)
	./$(TARGET)

test: $(TARGET)
	./tests/test_smoke.sh

receiver: src/ws_push_receiver.c
	$(CC) $(CFLAGS) -o ws_push_receiver src/ws_push_receiver.c

receiver-run: receiver
	./ws_push_receiver

clean:
	rm -f $(TARGET) ws_push_receiver
