# Changelog

## [3.1.0] - 2024-05-15  ← Current

### Fixed
- **WSL2 DISPLAY bug**: `ip route` used instead of `grep nameserver` (eliminates 8.8.8.8 bug)
- **Regex scans JS content**: Fixed — tool now fetches actual JS file content then runs regex patterns on it (was matching URL strings before)
- **All buttons wired**: Export, Copy, Stop, Reload, Apply Proxies, Save Log, Quick view PDF/JSON
- **Per-row Copy button**: Click ⎘ Copy in results table to copy that row's value

### Added
- **Pixel-perfect reference UI**: Header scan status + elapsed timer, per-row Copy, code viewer pane, donut chart, findings timeline chart
- **Code Viewer**: Shows actual JS source around the finding line with syntax highlighting
- **Donut Chart**: Real-time severity breakdown visualization
- **Findings Over Time**: Live sparkline chart updates as scan runs
- **Thread usage bar**: Animated mini bar chart in Options header
- **Scan Depth slider**: 1–5 depth setting
- **URL validation**: Green ✓✓ / red ✗ tick next to URL field
- **Quick view PDF/JSON**: Buttons in Output Directory section
- **Proxy presets**: Proxy presets / Different proxy / UMSP proxy quick-load buttons
- **Validation list counter**: Shows loaded proxy count
- **Elapsed timer**: Real-time elapsed time in header progress area
- **Scan Status header**: Live status with color (amber=running, green=complete)
- **Status bar**: Thread count, scan summary with finding counts
- **`_code_cache`**: Caches fetched JS content per-source for code viewer

### Changed
- Left panel fully scrollable with mousewheel
- Results split-pane: table top, code viewer bottom
- Right-side charts panel alongside results table
- Header bar shows scan progress + elapsed (not just window title)

---

## [3.0.0] - 2024-05-01

### Fixed
- WSL2 display resolution (partial)
- Proxy rotation
- Rate-limit bypass (UA rotation, exponential backoff)

### Added
- Glass morphism panels
- Proxy manager with SOCKS5 support
- Delay/retry options

---

## [2.1.0] - 2024-04-15

### Added
- Patterns tab, Log tab
- Auto-Update, Reload Patterns
- mohidqx GitHub logo

---

## [2.0.0] - 2024-04-01

### Added
- Initial dark GUI
- Multi-threaded scanning
- JSON/CSV/TXT export

---

## [1.0.0] - 2024-03-15

### Added
- CLI release
- 200+ regex patterns
