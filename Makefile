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

.PHONY: all clean test run release
.PHONY: receiver receiver-run

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SDL_CFLAGS) $(TTF_CFLAGS) -o $@ $(SRC) $(SDL_LIBS) $(TTF_LIBS)

run: $(TARGET)
	./$(TARGET)

test: $(TARGET)
	./tests/test_smoke.sh

release: test
	@if [ -z "$(VERSION)" ]; then \
		echo "Usage: make release VERSION=v0.1.0"; \
		exit 1; \
	fi
	@if ! echo "$(VERSION)" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$$'; then \
		echo "VERSION must look like vMAJOR.MINOR.PATCH (example: v1.2.3)"; \
		exit 1; \
	fi
	@if ! git diff --quiet || ! git diff --cached --quiet; then \
		echo "Working tree is not clean. Commit or stash changes first."; \
		exit 1; \
	fi
	@if [ "`git branch --show-current`" != "main" ]; then \
		echo "Releases must be created from main."; \
		exit 1; \
	fi
	@if git rev-parse -q --verify "refs/tags/$(VERSION)" >/dev/null; then \
		echo "Tag $(VERSION) already exists locally."; \
		exit 1; \
	fi
	@if git ls-remote --exit-code --tags origin "refs/tags/$(VERSION)" >/dev/null 2>&1; then \
		echo "Tag $(VERSION) already exists on origin."; \
		exit 1; \
	fi
	@git tag -a "$(VERSION)" -m "Release $(VERSION)"
	@git push origin main --follow-tags
	@echo "Released $(VERSION)"

receiver: src/ws_push_receiver.c
	$(CC) $(CFLAGS) -o ws_push_receiver src/ws_push_receiver.c

receiver-run: receiver
	./ws_push_receiver

clean:
	rm -f $(TARGET) ws_push_receiver
