# netscanner — QWEN Context

## Project Overview

**netscanner** is a terminal-based network scanner and diagnostic tool written in Rust. It provides a modern TUI (Terminal User Interface) built with [ratatui](https://github.com/ratatui-org/ratatui) and [crossterm](https://github.com/crossterm-rs/crossterm) for interactive network operations including:

- **Interface management** — list and switch hardware/network interfaces
- **WiFi scanning** — discover WiFi networks, monitor signal strength with real-time charts
- **Network discovery** — ping CIDR ranges with hostname, OUI, and MAC address resolution
- **Packet capture/dumping** — TCP, UDP, ICMP, ARP, ICMPv6 packet inspection with start/pause
- **Port scanning** — TCP port scanning across common ports
- **Packet logging & filtering** — filter captured packets by type
- **CSV export** — export scanned IPs, open ports, and packet logs
- **Traffic counting** — real-time traffic statistics with DNS records

Must be run with root privileges (requires raw packet access).

## Architecture

The project follows a component-based TUI architecture:

```
main.rs
├── cli.rs          # CLI argument parsing (clap, derive API)
├── app.rs          # Application state, main event loop, component orchestration
├── tui.rs          # TUI backend (crossterm, ratatui, tokio async event loop)
├── action.rs       # Action enum — all internal commands/events
├── mode.rs         # Normal/Input mode state
├── config.rs       # Config loading (json5 defaults + user overrides), keybinding parser
├── enums.rs        # Shared enums (TabsEnum, PacketTypeEnum, ExportData, packet info structs)
├── utils.rs        # Helpers (logging, panic handler, version, paths)
├── layout.rs       # Terminal layout management
├── components/     # TUI components (each implements the Component trait)
│   ├── discovery.rs    # CIDR ping scan with hostname/MAC resolution
│   ├── packetdump.rs   # Live packet capture (pnet library)
│   ├── ports.rs        # TCP port scanner
│   ├── sniff.rs        # Traffic sniffer component
│   ├── interfaces.rs   # Network interface list/switch
│   ├── wifi_scan.rs    # WiFi network scan
│   ├── wifi_interface.rs
│   ├── wifi_chart.rs   # WiFi signal strength charts
│   ├── tabs.rs         # Tab navigation
│   ├── title.rs        # App title bar
│   └── export.rs       # CSV export
└── widgets/
    └── scroll_traffic.rs   # Custom scrollable traffic widget
```

Key design patterns:
- **Component trait** — all UI panels implement a common `Component` trait with `handle_events()`, `update()`, `draw()`
- **Unbounded channel** — `App` uses `tokio::sync::mpsc::UnboundedSender/Receiver` for action dispatch (Action pattern)
- **Event loop** — crossterm events → action → component handlers → render cycle via ratatui
- **Async-first** — tokio runtime for all I/O (packet capture, pinging, port scanning)

## Building and Running

```bash
# Build (release)
cargo build --release

# Run (requires root/sudo)
sudo cargo run --release
sudo ./target/release/netscanner

# Install globally
cargo install netscanner
```

### Windows-specific

Windows requires [Npcap](https://npcap.com/dist/npcap-1.80.exe) installed before building/running. The `build.rs` script automatically downloads the Npcap SDK for compilation on Windows.

### Debian package

```bash
cargo deb
```

Uses `cargo-deb` (configured via `[package.metadata.deb]` in `Cargo.toml`).

## Configuration

### Config file

User configuration goes in the platform-appropriate config directory (auto-detected via `directories` crate):
- `config.json5` (preferred), `config.json`, `config.yaml`, `config.toml`, or `config.ini`

The default keybindings and styles are embedded at compile time via `include_str!("../.config/config.json5")` and can be overridden by user config files.

### Environment variables (`.envrc`)

```
export NETSCANNER_CONFIG=`pwd`/.config
export NETSCANNER_DATA=`pwd`/.data
export NETSCANNER_LOG_LEVEL=debug
```

### Keybindings (default)

| Key | Action |
|-----|--------|
| `q` / `Ctrl-d` / `Ctrl-c` | Quit |
| `Ctrl-z` | Suspend |
| `i` | Toggle input mode |
| `g` | Toggle graph |
| `d` | Toggle dump |
| `f` | Interface switch |
| `c` | Clear |
| `s` | Scan CIDR |
| `e` | Export CSV |
| `1` / `2` / `3` / `4` | Jump to Discovery / Packets / Ports / Sniffer tab |
| Arrow keys | Navigation |

## Development Conventions

- **Rust edition**: 2024 (set in `Cargo.toml`)
- **Toolchain**: stable (per `rust-toolchain.toml`)
- **Release profile**: strip symbols, optimize for size (`opt-level = "z"`), LTO enabled
- **Error handling**: `color_eyre` for eye-candy error reports, `human-panic` for crash reporting
- **Logging**: `tracing` + `tracing-subscriber` with `env-filter`
- **CLI**: `clap` with derive API, version shown via custom `utils::version()` (git describe)
- **Testing**: `pretty_assertions` for test assertions; config parsing has unit tests in `config.rs`
- **Build script**: `build.rs` injects git describe version at compile time; downloads Npcap SDK on Windows

## Important Notes

- **Root required**: Raw packet capture (`pnet` library) needs elevated privileges
- **Permission workaround** after `cargo install`:
  ```bash
  sudo chown root:user ~/.cargo/bin/netscanner
  sudo chmod u+s ~/.cargo/bin/netscanner
  ```
- **IPv6 scanning/dumping** is listed as a TODO item
- Export default path is `$HOME` on Linux & macOS
