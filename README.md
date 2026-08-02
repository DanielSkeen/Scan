# Scan

Common C base for:
- macOS
- Raspberry Pi (Linux)
- ESP32 (ESP-IDF)

This starter includes:
- shared core app logic in src/scan_app.c
- a simple desktop window using SDL2 in src/main.c
- an ESP32 app entry scaffold in esp32/main/main.c

## Desktop (macOS / Raspberry Pi)

Requirements:
- SDL2 development package

Build:

make

Run default scan mode (prints local subnets, discovered hosts, and nearby + connected Wi-Fi details):

./scan

Run window mode:

./scan --ui

In UI mode, scan results are rendered in the main window.
The left panel shows full scan details, including weather station ping summary.
The right panel includes an integrated push listener summary and live push log.
Press R to refresh, Esc to quit, and use mouse wheel or arrow/page/home/end keys to scroll.

WS-2902 local push integration:
- Scan UI listens on port 8089 for weather station HTTP push data.
- Configure the station custom upload target to <your-mac-ip>:8089.
- Upload path should be /weatherstation/updateweatherstation.php?
- The app parses incoming fields once they arrive and updates the right panel.

Run info mode (no window):

./scan --info

Run scan mode explicitly:

./scan --scan

Smoke test:

make test

Release (one command):

- ensure all changes are committed on main
- run: make release VERSION=v0.1.0

What this does:
- runs the smoke test
- creates an annotated tag
- pushes main and the new tag to GitHub

## ESP32 (ESP-IDF)

The ESP32 project root is esp32.
It builds the same shared core (src/scan_app.c) with an ESP-IDF entry point.

Typical flow:
- cd esp32
- idf.py set-target esp32
- idf.py build
- idf.py flash monitor

Note: the current ESP32 side is a base scaffold without a display backend yet.

## Wi-Fi Scanning Notes

- macOS backend is implemented using system_profiler SPAirPortDataType JSON output.
- It also inspects active local IPv4 interfaces, probes /24-or-smaller subnets, and reads ARP data.
- For discovered local devices it reports IP, reverse-DNS hostname (when available), MAC, and interface.
- It also identifies the default gateway and measures per-host ping latency (RTT) when available.
- It reports SSID, channel, security mode, signal/noise, and PHY mode when available.
- Depending on macOS privacy controls, SSID names may appear as <redacted>.
- Raspberry Pi and ESP32 currently use a stub backend and are ready for platform-specific scan integration.
