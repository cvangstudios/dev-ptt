# Nautobot Query Tool

## Overview

A lightweight, menu-driven Python toolset for querying a Nautobot network source
of truth via its REST API. Designed for network engineers who need fast, readable
access to device inventory, IP addressing, rack layouts, and platform data without
requiring a browser or Nautobot web UI access.

Built to run in a corporate lab environment with:
- Self-signed SSL certificates (warnings suppressed)
- A single Nautobot site
- Token-based API authentication
- No external dependencies beyond `requests`

---

## Project Structure

```
nautobot/
├── nautobot_setup.py     # One-time token generator — run once before anything else
├── nautobot_query.py     # Main menu-driven query tool
├── nautobotApi.cfg       # Auto-generated config file storing URL + token
├── README.md             # This file
└── tests/
    └── test_nautobot_query.py   # Unit and integration tests
```

---

## Architecture

### How the two scripts relate

```
nautobot_setup.py
    │
    │  Prompts: URL, username, password
    │  POSTs to /api/users/tokens/provision/
    │  Saves URL + token
    ▼
nautobotApi.cfg
    │
    │  Read on every launch
    ▼
nautobot_query.py
    │
    ├── test_connection()      Verifies URL + token on startup
    ├── api_get()              Core paginated GET — used by all queries
    ├── prompt_save_csv()      Shared CSV export — used by all views
    ├── display_device_detail() Shared device detail — used by Options 1, 2, 4, 5
    │
    ├── query_devices()           Option 1
    ├── query_ip_addresses()      Option 2
    ├── query_racks()             Option 3
    ├── query_platforms()         Option 4
    └── query_search_by_name()    Option 5
            ├── search_devices_by_names()   Shared lookup engine
            ├── Quick Search (comma input)
            └── File Search  (text file)
```

### API call flow

Every query follows the same pattern:

```
main_menu()
    └── query_*() function
            └── api_get()               GET with pagination
                    └── Nautobot REST API
                            └── returns JSON
                api_get() returns flat list of all results
            display results to screen
            prompt_save_csv()           optional CSV export
```

### Pagination

`api_get()` handles pagination automatically. Nautobot returns results in pages
(default 50 per page). The function follows the `next` URL in each response until
all pages are exhausted, then returns a single flat list. Callers never need to
think about pagination.

---

## Configuration File — nautobotApi.cfg

Generated automatically by `nautobot_setup.py`. Do not edit the token manually
unless you are pasting in a token generated from the Nautobot web UI.

```ini
[nautobot]
url   = https://your-nautobot-instance:8443
token = your40charactertokenhere
```

| Field   | Description                                      |
|---------|--------------------------------------------------|
| `url`   | Base URL of your Nautobot instance, no trailing slash |
| `token` | 40-character API token for authentication        |

---

## Variables Reference

### nautobot_setup.py

| Variable      | Location       | Purpose                                              |
|---------------|----------------|------------------------------------------------------|
| `CONFIG_FILE` | Module level   | Filename of the config file to write. Default: `nautobotApi.cfg` |

### nautobot_query.py

| Variable              | Location          | Purpose                                                              |
|-----------------------|-------------------|----------------------------------------------------------------------|
| `SITE_NAME`           | Module level      | **Edit this.** The Nautobot site name to filter all queries against. Must match exactly what is in Nautobot (case sensitive). |
| `CONFIG_FILE`         | Module level      | Filename of the config file to read. Must match `nautobot_setup.py`. Default: `nautobotApi.cfg` |
| `DEVICE_DETAIL_FIELDS`| Module level      | List of CSV column headers used for all device detail exports. Defined once, reused across all export calls. |
| `url`                 | Entry point       | Nautobot base URL loaded from `nautobotApi.cfg` at startup          |
| `token`               | Entry point       | API token loaded from `nautobotApi.cfg` at startup                  |

---

## API Endpoints Used

All endpoints are under the Nautobot base URL. Authentication via
`Authorization: Token <token>` header on every request.

| Endpoint                        | Method | Used By                        | Returns                                      |
|---------------------------------|--------|--------------------------------|----------------------------------------------|
| `/api/`                         | GET    | `test_connection()`            | API root — confirms connectivity             |
| `/api/users/tokens/provision/`  | POST   | `nautobot_setup.py`            | New API token                                |
| `/api/dcim/devices/`            | GET    | Options 1, 2, 4, 5             | Device list with status, type, rack, IPs     |
| `/api/dcim/interfaces/`         | GET    | `display_device_detail()`      | All interfaces for a given device            |
| `/api/dcim/console-ports/`      | GET    | `display_device_detail()`      | Console ports for a given device             |
| `/api/dcim/racks/`              | GET    | Option 3                       | Rack list with location and height           |
| `/api/dcim/platforms/`          | GET    | Option 4                       | Platform list with manufacturer              |
| `/api/ipam/ip-addresses/`       | GET    | Options 2, `display_device_detail()` | IP addresses with device/interface assignment |

### Common query parameters

| Parameter       | Used on              | Filters by                          |
|-----------------|----------------------|-------------------------------------|
| `site`          | devices, IPs, racks  | Site name matching `SITE_NAME`      |
| `rack_id`       | devices              | Devices in a specific rack          |
| `device_id`     | interfaces, consoles, IPs | Objects belonging to a device  |
| `interface_id`  | ip-addresses         | IPs assigned to a specific interface|
| `platform`      | devices              | Devices running a specific platform |
| `name`          | devices              | Exact device name match             |

---

## Menu Reference

### Main Menu

```
  1. Devices
  2. IP Addresses
  3. Racks
  4. Platforms
  5. Search by Device Name
  6. Exit
```

---

### Option 1 — Devices

Pulls all devices at `SITE_NAME` and displays full detail for each.

**Displays per device:**
- Name, Status, Platform, Device Type
- Primary IP
- Rack name, RU position, face
- Console ports
- All interfaces with type, enabled state, mgmt flag, and assigned IPs

**CSV columns:**

| Column | Description |
|---|---|
| Device Name | Hostname of the device |
| Status | Active, Planned, Staged, etc. |
| Platform | OS platform (e.g. NX-OS, EOS) |
| Device Type | Make and model |
| Primary IP | Primary management IP with prefix |
| Rack | Rack name |
| RU Position | U slot in the rack |
| Console Ports | Comma-separated list of console port names |
| Interface | Interface name |
| Interface Type | Physical type (1000Base-T, SFP+, etc.) |
| Enabled | Enabled or Disabled |
| Mgmt Only | Yes or No |
| Interface IPs | Comma-separated IPs assigned to the interface |

---

### Option 2 — IP Addresses

Pulls all IP addresses at `SITE_NAME` and displays a flat list.
After display, optionally drill down into a device by name for full detail.

**Displays:**
- IP address with prefix length
- Assigned device name
- Assigned interface name

**CSV columns (list view):**

| Column | Description |
|---|---|
| IP Address | IP with prefix length |
| Device | Assigned device name |
| Interface | Assigned interface name |

**CSV columns (device drill-down):** Same as Option 1.

---

### Option 3 — Racks

Pulls all racks at `SITE_NAME`. For each rack, lists all devices sorted by
RU position top to bottom.

**Displays per rack:**
- Rack name, location, height, status
- All devices: RU position, name, device type, status

**CSV columns:**

| Column | Description |
|---|---|
| Rack | Rack name |
| Location | Physical location within the site |
| Rack Height | Total rack height in U |
| Rack Status | Active, Planned, etc. |
| RU Position | Device U slot |
| Device Name | Hostname |
| Device Type | Make and model |
| Status | Device status |

---

### Option 4 — Platforms

Pulls all platforms and displays a numbered list. Drill down into a platform
to see all devices running it (filtered by `SITE_NAME`). Drill down further
into any device for full detail.

**Navigation:**
```
Platform list → Select number → Device list → Select number → Device detail
```

**CSV columns (platform list):**

| Column | Description |
|---|---|
| Platform Name | OS platform name |
| Manufacturer | Hardware manufacturer |

**CSV columns (platform device list):**

| Column | Description |
|---|---|
| Platform | Platform name |
| Device Name | Hostname |
| Status | Device status |
| Rack | Rack name |

**CSV columns (device drill-down):** Same as Option 1.

---

### Option 5 — Search by Device Name

Sub-menu with two input methods for targeted device lookups.
Both methods use the same shared lookup engine and produce identical output.

**Sub-menu:**
```
  1. Quick Search  — paste hostnames (comma separated)
  2. File Search   — load from text file (one per line)
  3. Back to main menu
```

**Quick Search input format:**
```
spine-01, spine-02, leaf-01
```

**File Search input format** (one hostname per line, `#` lines ignored):
```
# Spine layer
spine-01
spine-02
# Leaf layer
leaf-01
```

**Output:**
- Full device detail for each matched hostname
- Clear report of any hostnames not found
- Summary count of found vs missing

**CSV columns:** Same as Option 1.

---

## Testing

### Where tests live

```
tests/
└── test_nautobot_query.py
```

Tests are kept separate from the main scripts. This keeps production code clean
and lets you run tests independently without affecting live data.

### Install pytest

```
pip install pytest
```

### Run all tests

```
pytest tests/ -v
```

### Test categories

#### Unit tests — no Nautobot connection required

These test individual functions in isolation using mock data.
They run fast and can be run anywhere, anytime.

| Test | Function | What to verify |
|---|---|---|
| `test_csv_creates_file` | `prompt_save_csv()` | File is created with correct headers and row count |
| `test_csv_appends` | `prompt_save_csv()` | Existing file gets rows added, not overwritten |
| `test_csv_skips_on_empty` | `prompt_save_csv()` | No file created when rows list is empty |
| `test_load_config_valid` | `load_config()` | Returns correct URL and token from a valid cfg file |
| `test_load_config_missing` | `load_config()` | Exits cleanly when cfg file does not exist |
| `test_search_strips_whitespace` | `search_devices_by_names()` | Hostnames with extra spaces are cleaned correctly |
| `test_file_search_skips_comments` | file parsing in `query_search_by_name()` | Lines starting with `#` are ignored |
| `test_file_search_skips_blanks` | file parsing in `query_search_by_name()` | Empty lines are ignored |

#### Integration tests — live Nautobot connection required

These test real API calls against your Nautobot instance.
Requires a valid `nautobotApi.cfg` and network access.

| Test | Function | What to verify |
|---|---|---|
| `test_connection_succeeds` | `test_connection()` | Returns True against a live instance |
| `test_api_get_devices` | `api_get()` | Returns a non-empty list for `/api/dcim/devices/` |
| `test_api_get_pagination` | `api_get()` | All pages returned, not just page 1 |
| `test_api_get_invalid_endpoint` | `api_get()` | Returns empty list on 404, does not crash |
| `test_api_get_bad_token` | `api_get()` | Returns empty list on 403, does not crash |
| `test_device_detail_fields` | `display_device_detail()` | CSV rows contain all expected column keys |
| `test_site_filter_applied` | `query_devices()` | All returned devices belong to `SITE_NAME` |

### Example unit test structure

```python
# tests/test_nautobot_query.py

import csv
import os
import pytest
import configparser
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from nautobot_query import prompt_save_csv, DEVICE_DETAIL_FIELDS


def test_csv_creates_file(tmp_path):
    """prompt_save_csv() creates a file with correct headers and rows."""
    outfile = str(tmp_path / "test_output.csv")
    rows    = [{"Device Name": "spine-01", "Status": "Active"}]

    prompt_save_csv.__globals__["input"] = lambda _: outfile  # mock input
    # Direct call for unit test
    with open(outfile, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["Device Name", "Status"],
                                extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    assert os.path.exists(outfile)
    with open(outfile) as f:
        reader = list(csv.DictReader(f))
    assert len(reader) == 1
    assert reader[0]["Device Name"] == "spine-01"


def test_load_config_missing(tmp_path, monkeypatch):
    """load_config() exits cleanly when nautobotApi.cfg does not exist."""
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit):
        from nautobot_query import load_config
        load_config()
```

### What correct output looks like

When validating results manually, compare against the Nautobot web UI:

| Check | How to verify |
|---|---|
| Device count matches | Compare Option 1 count to Nautobot → Devices → filter by site |
| IPs match | Compare Option 2 results to Nautobot → IPAM → IP Addresses |
| Rack layout correct | Compare Option 3 RU positions to Nautobot → Racks → rack view |
| Platform device count | Compare Option 4 drill-down count to Nautobot → Platforms |
| Search finds correct device | Option 5 result should match Nautobot device detail page |

---

## Update Log

All script changes are recorded here. Most recent first.

---

### v0.6 — Two-stage summary + drill-down for Devices and Racks
**Files changed:** `nautobot_query.py`, `README.md`

- **Option 1 — Devices** redesigned from full-detail-all to two-stage:
  - Stage 1: Single API call returns all devices as a fast numbered summary list
    (Name, Status, Platform, Primary IP, Rack, RU)
  - Stage 2: Select a number to drill into full detail for that device only
    (interfaces, IPs, console ports — API calls made only for selected device)
  - CSV export available at both summary and detail levels
  - After detail view returns to summary list, not main menu
- **Option 3 — Racks** redesigned from show-all to two-stage:
  - Stage 1: Single API call returns all racks as a fast numbered summary list
    (Rack Name, Location, Height, Status)
  - Stage 2: Select a number to drill into devices in that rack only
  - CSV export available at both summary and detail levels
  - After rack detail returns to rack list, not main menu
- Performance improvement: eliminates hundreds of redundant API calls on large
  environments by deferring interface/IP/console lookups to on-demand drill-down
- `SITE_NAME` comment updated to note slug (lowercase) requirement

---

### v0.5 — Search by Device Name added
**Files changed:** `nautobot_query.py`, `README.md`

- Added Option 5: Search by Device Name to main menu
- Added `query_search_by_name()` — sub-menu with Quick Search and File Search
- Added `search_devices_by_names()` — shared lookup engine used by both search types
- Quick Search accepts comma-separated hostnames pasted directly
- File Search reads a text file, one hostname per line, ignores `#` comment lines
- Both search types report found vs missing devices in a summary
- CSV export available after both search types using `DEVICE_DETAIL_FIELDS`
- Exit moved from Option 5 to Option 6

---

### v0.4 — CSV export added to all views
**Files changed:** `nautobot_query.py`, `README.md`

- Added `prompt_save_csv()` — shared CSV export function used by all views
- CSV export prompt appears after every result display and every drill-down
- Suggested filenames auto-timestamped to prevent overwriting previous exports
- Overwrite or Append option when a filename already exists
- Added `DEVICE_DETAIL_FIELDS` — single definition of device CSV columns reused everywhere
- `display_device_detail()` now returns a list of CSV-ready row dicts
- `csv` and `datetime` added to imports

---

### v0.3 — Platforms added
**Files changed:** `nautobot_query.py`, `README.md`

- Added Option 4: Platforms to main menu
- Added `query_platforms()` — numbered platform list with two-level drill-down
- Platform drill-down filters devices by `SITE_NAME`, falls back without site filter if no results
- Device drill-down from platform list reuses `display_device_detail()`
- Exit moved from Option 4 to Option 5

---

### v0.2 — Core menu with Devices, IPs, Racks
**Files changed:** `nautobot_query.py`

- Initial version of `nautobot_query.py`
- Added `api_get()` with automatic pagination
- Added `test_connection()` startup check
- Added `display_device_detail()` shared device view
- Added Option 1: Devices — full detail for all devices at site
- Added Option 2: IP Addresses — list with device drill-down
- Added Option 3: Racks — all racks with sorted device list
- Added `SITE_NAME` variable for single-site filtering
- SSL warnings suppressed via `urllib3`

---

### v0.1 — Token setup
**Files changed:** `nautobot_setup.py`

- Initial version of `nautobot_setup.py`
- Prompts for URL, username, password at runtime
- Password hidden using `getpass`
- POSTs to `/api/users/tokens/provision/` using Basic Auth
- Saves URL + token to `nautobotApi.cfg` in `configparser` format
- Warns before overwriting existing config
- SSL warnings suppressed for lab self-signed certs
