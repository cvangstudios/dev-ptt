# Network Parser - Parallel Network Automation Tool

A simple, powerful Python script for collecting and parsing network device configurations in parallel, with automatic device type detection and intelligent credential management.

## 🌟 Key Features

- **Parallel Processing**: Process multiple devices simultaneously (5-10x faster than sequential)
- **Auto Device Detection**: Automatically identifies device type (Cisco IOS/NX-OS/XR, Arista EOS, Juniper)
- **Smart Credential Management**: Automatic fallback from primary to backup credentials
- **Zero Interaction Mode**: Fully automated with embedded credentials
- **Comprehensive Logging**: Dual logging to console and file for complete audit trail
- **Multiple Output Formats**: Raw text, parsed JSON, and CSV outputs
- **NTC Template Parsing**: Automatic structured data extraction using TextFSM templates
- **Organized Output**: Device-specific folders with hostname_IP naming convention

## 📋 Prerequisites

### Required Python Packages
```bash
pip install netmiko
pip install ntc-templates
```

### Python Version
- Python 3.6 or higher

## 🚀 Quick Start

### 1. Basic Setup

Create a `devices.txt` file with one IP/hostname per line:
```
192.168.1.1
192.168.1.2
10.0.0.1
switch1.domain.com
core-router.local
# Comments start with #
# 192.168.1.100  # This device is disabled
```

### 2. Update Embedded Credentials

Edit the script and update the credentials at the top:
```python
# Primary credentials (tried first)
PRIMARY_USERNAME = "admin"
PRIMARY_PASSWORD = "cisco123"
PRIMARY_ENABLE = "cisco123"

# Backup credentials (tried if primary fails)
BACKUP_USERNAME = "netadmin"
BACKUP_PASSWORD = "backup123"
BACKUP_ENABLE = "backup123"
```

### 3. Run the Script

```bash
# Simplest - uses embedded credentials, parallel processing
python netparse_parallel.py

# That's it! The script handles everything automatically
```

## 📁 Required Files Structure

```
.
├── netparse_parallel.py           # Main script
├── devices.txt                    # List of devices (one per line)
├── cisco_ios_commands.txt         # Commands for Cisco IOS devices
├── cisco_nxos_commands.txt        # Commands for Nexus devices
├── cisco_xr_commands.txt          # Commands for IOS-XR devices
├── arista_eos_commands.txt        # Commands for Arista devices
├── juniper_junos_commands.txt     # Commands for Juniper devices
├── outputs/                       # Created automatically
│   ├── consolidated/              # Merged outputs from all devices
│   ├── router1_192.168.1.1/      # Device-specific outputs
│   └── switch1_192.168.1.2/      # Device-specific outputs
└── logs/                          # Created automatically
    └── netparse_20240115_143022.log  # Timestamped log file
```

## 📝 Command List Files

Create command files for each device type. Example `cisco_ios_commands.txt`:
```
show version
show inventory
show cdp neighbors detail
show interfaces status
show ip interface brief
show vlan brief
show mac address-table
show ip arp
show spanning-tree summary
show ip route summary
show running-config
# Comments are supported
# show processes cpu  # Disabled for now
```

## 🎮 Command Line Options

### Basic Usage
```bash
python netparse_parallel.py [options]
```

### All Options

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `-u`, `--username` | Override primary username | Embedded value | `-u admin` |
| `-p`, `--password` | Override primary password | Embedded value | `-p secret123` |
| `-e`, `--enable` | Override enable password | Same as password | `-e enable123` |
| `-f`, `--file` | Specify device list file | `devices.txt` | `-f routers.txt` |
| `--workers` | Number of parallel workers | 5 | `--workers 10` |
| `--sequential` | Disable parallel processing | False (parallel on) | `--sequential` |
| `--debug` | Enable debug output to console | False | `--debug` |

### Usage Examples

```bash
# Default - parallel with embedded credentials
python netparse_parallel.py

# Faster processing with more workers
python netparse_parallel.py --workers 10

# Use different device file
python netparse_parallel.py -f datacenter_devices.txt

# Override credentials
python netparse_parallel.py -u newadmin -p newpass123

# Sequential mode for troubleshooting
python netparse_parallel.py --sequential

# Debug mode with verbose output
python netparse_parallel.py --debug

# Combined options
python netparse_parallel.py --workers 20 -f core_devices.txt --debug

# Override just the username (password still uses embedded)
python netparse_parallel.py -u different_user
```

## 📊 Output Files

### 1. Device-Specific Folders
Each device gets its own folder named `hostname_IP`:
```
outputs/
├── router1_192.168.1.1/
│   ├── show_version_20240115_143022.txt         # Raw output
│   ├── show_version_20240115_143022.json        # Parsed JSON
│   ├── show_interfaces_status_20240115_143023.txt
│   ├── show_interfaces_status_20240115_143023.json
│   └── show_interfaces_status_20240115_143023.csv
```

### 2. Consolidated Outputs
Combined data from all devices:
```
outputs/consolidated/
├── show_interfaces_status_20240115_143030.csv   # All devices in one CSV
├── show_interfaces_status_20240115_143030.json  # All devices in one JSON
├── show_cdp_neighbors_detail_20240115_143031.csv
└── show_cdp_neighbors_detail_20240115_143031.json
```

### 3. Log Files
Detailed logs with timestamps:
```
logs/
└── netparse_20240115_143022.log    # Complete session log
```

## 🔄 How It Works

### Connection Flow
1. **Connect** to device using primary credentials
2. **Set** `terminal length 0` immediately (prevents paging)
3. **Run** `show version` to detect device type
4. **Load** appropriate command list for device type
5. **Execute** commands and collect outputs
6. **Parse** outputs using NTC templates
7. **Save** raw, JSON, and CSV formats
8. **Consolidate** data from all devices

### Credential Handling
```
Device Connection
    ├─→ Try Primary Credentials
    │   ├─→ Success: Continue
    │   └─→ Fail: Try Backup
    │       ├─→ Success: Continue
    │       └─→ Fail: Mark device failed
```

### Parallel Processing
- Default: 5 simultaneous connections
- Adjustable: 1-30 workers recommended
- Each device processed independently
- Failures don't affect other devices

## 📈 Performance Guide

### Worker Count Recommendations

| Network Size | Workers | Expected Time | Notes |
|--------------|---------|---------------|-------|
| 10 devices | 5 | ~2 minutes | Default settings |
| 50 devices | 10 | ~5 minutes | Good balance |
| 100 devices | 15 | ~7 minutes | Monitor network load |
| 500 devices | 20 | ~25 minutes | Check device CPU |
| 1000+ devices | 25-30 | ~40 minutes | Maximum recommended |

### Performance Tips
- Start with default 5 workers
- Increase gradually if no issues
- Monitor device CPU/memory
- Check for security alerts
- Consider network bandwidth

## 🔍 Searching Logs

The script creates detailed log files in the `logs/` directory:

```bash
# View the latest log
ls -lt logs/ | head -2

# Find all errors
grep ERROR logs/netparse_20240115_143022.log

# Find authentication failures
grep "Authentication failed" logs/netparse_20240115_143022.log

# Find devices that used backup credentials
grep "backup credentials" logs/netparse_20240115_143022.log

# Find parsing failures
grep "parsing not available" logs/netparse_20240115_143022.log

# Find specific device
grep "192.168.1.1" logs/netparse_20240115_143022.log

# Count successes
grep "Successfully processed" logs/netparse_20240115_143022.log | wc -l

# Follow log in real-time (while running)
tail -f logs/netparse_20240115_143022.log
```

## 🛠️ Troubleshooting

### Common Issues and Solutions

#### 1. Authentication Failures
```
ERROR - Authentication failed for 192.168.1.1
```
**Solution**: Update PRIMARY_USERNAME/PASSWORD or BACKUP_USERNAME/PASSWORD in script

#### 2. Connection Timeouts
```
ERROR - Failed to connect to 192.168.1.1: Connection timeout
```
**Solutions**:
- Verify device is reachable: `ping 192.168.1.1`
- Check SSH is enabled on device
- Reduce workers if many timeouts: `--workers 3`

#### 3. Command Not Found
```
WARNING - No command list found for cisco_nxos
```
**Solution**: Create `cisco_nxos_commands.txt` with appropriate commands

#### 4. Parsing Failures
```
DEBUG - NTC parsing not available for 'show vlan' on cisco_nxos
```
**Note**: This is normal - not all commands have NTC templates. Raw output is still saved.

#### 5. CSV Save Errors
```
ERROR - Failed to save CSV for 'show inventory': dict contains fields not in fieldnames
```
**Note**: Already fixed in latest version - script handles different field names from different device types

### Debug Mode

Enable debug mode for detailed troubleshooting:
```bash
python netparse_parallel.py --debug
```

This shows:
- Detailed connection attempts
- Command execution details  
- Parse attempts and results
- File operations
- Credential usage

## 🏆 Best Practices

### 1. Device Lists
- Keep device lists organized by location/type
- Use comments to document devices
- Create separate files for different environments:
  - `production_devices.txt`
  - `lab_devices.txt`
  - `datacenter_devices.txt`

### 2. Command Lists
- Start with read-only commands
- Avoid commands that change configuration
- Test new commands on single device first
- Add comments to document command purpose

### 3. Credentials
- Use strong passwords
- Update credentials regularly
- Consider using different backup credentials per environment
- Never commit credentials to version control

### 4. Performance
- Start with fewer workers (5)
- Increase gradually based on results
- Monitor first run before scheduling
- Use `--sequential` for troubleshooting

### 5. Maintenance
- Review logs regularly
- Archive old outputs periodically
- Clean up logs older than X days
- Monitor disk space usage

## 📊 Sample Output

### Console Output
```
Using embedded credentials (Primary: admin, Backup: netadmin)
📝 Log file: logs/netparse_20240115_143022.log
Processing 50 devices in parallel (workers: 5)
============================================================
[1/50] ✓ 192.168.1.1
[2/50] ✓ 192.168.1.2
[3/50] ✗ 192.168.1.3
[4/50] ✓ 192.168.1.4
...

SUMMARY
============================================================
Successful: 48/50
Credentials: Primary=45, Backup=3
Failed: 2
  - switch3_192.168.1.3 (cisco_ios)
  - router5_192.168.1.5 (unknown)

Consolidated outputs:
  show interfaces status: outputs/consolidated/show_interfaces_status_20240115_143030.csv (1250 entries) [cisco_ios:950, arista_eos:300]
  show cdp neighbors detail: outputs/consolidated/show_cdp_neighbors_detail_20240115_143031.csv (425 entries) [cisco_ios:425]

Device outputs: outputs/<hostname>_<IP>/
Example: outputs/router1_192.168.1.1/

📁 Complete log saved: logs/netparse_20240115_143022.log
   Tip: Use 'grep ERROR logs/netparse_20240115_143022.log' to find all errors
   Tip: Use 'grep "Authentication failed" logs/netparse_20240115_143022.log' to find auth issues
```

## 🔒 Security Considerations

1. **Credentials**: Stored in script - protect file permissions
   ```bash
   chmod 600 netparse_parallel.py
   ```

2. **Logs**: May contain sensitive information
   ```bash
   chmod 700 logs/
   ```

3. **Outputs**: Device configurations may be sensitive
   ```bash
   chmod -R 700 outputs/
   ```

4. **Network Load**: Parallel connections may trigger security monitoring
   - Start with few workers
   - Coordinate with security team
   - Monitor for alerts

## 📝 Version History

### Current Version Features
- Parallel processing with configurable workers
- Automatic device type detection
- Primary/backup credential management
- Comprehensive logging to file
- Multiple output formats (raw, JSON, CSV)
- Hostname_IP folder naming
- Consolidated outputs across devices
- Enhanced error messages with device context
- Support for mixed device environments

## 📧 Support

For issues or questions:
1. Check the log file for detailed error messages
2. Run with `--debug` flag for verbose output
3. Verify device connectivity and SSH access
4. Ensure command files exist for your device types
5. Confirm NTC-templates is installed correctly

## 📄 License

This script is provided as-is for network automation purposes. Modify as needed for your environment.

---

**Remember**: Always test on a small subset of devices before running on your entire network!
