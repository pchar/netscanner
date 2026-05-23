# Project Summary

## Overall Goal
Fix the netscanner CLI application to ensure UI responsiveness by routing all network I/O to background threads, implement proper MAC address resolution on macOS, and add interactive sorting to the discovery view.

## Key Knowledge

### Architecture & Tech Stack
- **Language**: Rust 2024 edition, tokio async runtime
- **TUI**: ratatui + crossterm with component-based architecture
- **Packet capture**: pnet library (requires root/sudo for raw packet access)
- **Build**: `cargo build --release`, tests: `cargo test` (13 tests)
- **Releases**: `cargo deb` for Debian packaging

### Remote Setup
- **Fork remote**: pchar (https://github.com/pchar/netscanner.git)
- **Origin remote**: Chleba/netscanner.git
- **Tagging**: Auto-increment patch version on successful build+test

### macOS-Specific Constraints
- macOS intercepts `Ctrl-c`, `Ctrl-d`, `Ctrl-z` at OS level → use `Alt-q` or `F10` instead
- On macOS, ARP responses are handled **internally by the OS** and never appear on the wire, so `pnet` cannot capture them
- Solution: Read system ARP cache via `arp -a` command after each IP responds to ping

### ARP/MAC Resolution Flow (critical)
1. Ping worker detects IP responds to ICMP echo
2. **Add IP entry to `scanned_ips` vector FIRST**
3. Call `update_mac_from_arp_cache(ip)` to read `arp -a` output
4. Parse MAC address from ARP cache (handles short formats like `ec:97:e0:13:df:b`)
5. Retry 3 times with 100ms initial delay + 50ms between retries
6. Lookup OUI vendor via `oui` database

### Component Architecture
- `src/components/discovery.rs` — CIDR ping scan, MAC/vendor resolution
- `src/components/packetdump.rs` — Live packet capture
- `src/components/ports.rs` — TCP port scanner (only tracks responding IPs)
- `src/components/sniff.rs` — Traffic sniffer
- `src/components/interfaces.rs` — Network interface list
- `src/components/wifi_scan.rs`, `wifi_chart.rs`, `wifi_interface.rs` — WiFi features
- NetworkExecutor with 3 worker threads for parallel ICMP pings

### Tagging Convention
- Version bumps: tag after successful `cargo build --release && cargo test`
- Push to `pchar/main` and tag simultaneously

## Recent Actions

### v0.7.1 - v0.7.4: MAC Address Resolution
- **v0.7.2**: Implemented `update_mac_from_arp_cache()` using `arp -a` command
- **v0.7.3**: Lowered MAC length check to 11 chars for short formats (e.g., `ec:97:e0:13:df:b`)
- **v0.7.4** (ROOT CAUSE FIX): Bug was `update_mac_from_arp_cache()` called **before** adding IP to `scanned_ips` — `find()` always returned `None`, so MACs were never stored

### v0.7.5 - v0.8.0: Interactive Sorting
- Added `SortColumn` enum: `Ip`, `Mac`, `Hostname`, `Vendor`
- Press `o` to toggle sort menu popup
- Popup shows: `1=IP`, `2=MAC`, `3=Hostname`, `4=Vendor`, `q/ESC` to close
- Sort mode displayed in bottom-right: `order hostname` (green bold) or `order ip`
- Sorted case-insensitively by hostname when enabled

### v0.8.1: Sort Display Improvements
- Removed pipe borders from sort label
- Made sort column green + bold for better visibility
- Clean display: `order hostname` without `|sort hostname|`

### Keybindings Analysis (v0.8.1)
- **30 keybindings** in config file (`.config/config.json5`)
- **7 hardcoded** in discovery.rs
- **Only 1 conflict**: `k` key overridden to `StopScan` when scanning (intentional)
- No other conflicts found — numeric keys `1-4` scoped to sort popup only

## Current Plan

### Completed
1. [DONE] Fix keybindings for macOS (Alt-q, F10)
2. [DONE] Fix port scan freeze (remove unused JoinHandle)
3. [DONE] Fix discovery scan freeze (3 worker threads with std::thread::spawn)
4. [DONE] Fix "Too many open files" crash (semaphore limit 3)
5. [DONE] Fix nested runtime crash (use std::thread::spawn with mini tokio)
6. [DONE] Create NetworkExecutor with 3 worker threads
7. [DONE] Route all network I/O through NetworkExecutor
8. [DONE] Fix MAC address display via `arp -a` system cache
9. [DONE] Fix order of operations: add IP to scanned_ips BEFORE resolving MAC
10. [DONE] Add interactive sort menu with popup (o key)
11. [DONE] Add hostname alphabetical and IP order sorting
12. [DONE] Report all keybindings and verify no conflicts
13. [DONE] Save keybindings reference to memory

### Current Version
- **v0.8.1** pushed to `pchar/main`

### Remaining Work
- None explicitly requested — all user tasks completed

---

## Summary Metadata
**Update time**: 2026-05-23T12:04:22.427Z 
