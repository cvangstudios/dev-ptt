# SecureCRT Python 3.x Scripts Collection

This package is a modernized implementation of Jamie Caesar's SecureCRT Tools collection, designed to work with SecureCRT 9.0+ and Python 3.x, taking advantage of external Python libraries.

## Overview

This collection of network automation scripts for SecureCRT has been updated to:

1. Use Python 3.x (requires SecureCRT 9.0 or later)
2. Take advantage of external Python libraries like Netmiko, TextFSM, etc.
3. Maintain Jamie Caesar's folder structure and script patterns
4. Support all the original single-device scripts for Cisco devices

## Requirements

- SecureCRT 9.0 or later
- Python 3.6 or later installed on your system
- Required Python packages (install via pip)

## Setup Instructions

### 1. Configure SecureCRT to use Python 3.x

1. In SecureCRT, go to **Options > Global Options > Terminal > Mapped Keys**
2. Click the **Edit Default** button
3. In the "Default Key Mappings" dialog, click **Edit**
4. Under "Language", select **Python** and click the "..." button
5. Browse to your Python 3.x installation (e.g., `C:\Python39\python.exe`)
6. Click **OK** to save your changes

### 2. Install Required Python Packages

```bash
pip install netmiko textfsm ntc-templates pandas openpyxl tabulate pyyaml
```

### 3. Copy Scripts to SecureCRT Scripts Directory

1. In SecureCRT, go to **Scripts > Open Scripts Directory**
2. Copy the contents of this repository into that directory
3. Restart SecureCRT

## Folder Structure

The folder structure matches Jamie Caesar's original project:

```
securecrt_tools/
├── README.md                      # This file
├── requirements.txt               # Python dependencies
├── s_scripts/                     # Single-device scripts
│   ├── cisco/                     # Cisco device scripts
│   │   ├── cdp_to_csv.py          # Get CDP neighbors to CSV
│   │   ├── interface_stats.py     # Get interface statistics
│   │   ├── mac_table.py           # Get MAC address table
│   │   ├── ...
│   ├── juniper/                   # Juniper device scripts
│   └── multivendor/               # Multivendor scripts
├── m_scripts/                     # Multi-device scripts
└── lib/                           # Library modules
    ├── script_class.py            # Script base class
    ├── textfsm_parser.py          # TextFSM parser module
    ├── utils.py                   # Utility functions
    └── templates/                 # TextFSM templates
        ├── cisco_ios_show_cdp_neighbors_detail.textfsm
        ├── cisco_ios_show_inventory.textfsm
        ├── ...
```

## Running Scripts

### From SecureCRT

1. Connect to a device
2. Go to **Scripts > s_scripts > cisco > [script_name]**
3. The script will run in the connected session

### From Command Line (via SecureCRT)

```
"C:\Program Files\VanDyke Software\SecureCRT\SecureCRT.exe" /SCRIPT "C:\Path\To\Scripts\s_scripts\cisco\cdp_to_csv.py" /ARG hostname=192.168.1.1 username=admin password=secret
```

## Available Scripts

### Single-Device Cisco Scripts

- **cdp_to_csv.py** - Extract CDP neighbor information to CSV
- **interface_stats.py** - Extract interface statistics
- **mac_table.py** - Extract MAC address table
- **running_config.py** - Save running configuration
- **save_output.py** - Save output of any command
- **show_inventory.py** - Extract device inventory information
- **show_version.py** - Extract version information
- **snmp_config.py** - Create or modify SNMP configuration
- **create_interface_descriptions.py** - Generate interface descriptions based on CDP
- **clean_interface_descriptions.py** - Clean up interface descriptions
- **interface_errors.py** - Extract interface errors
- **interface_status.py** - Extract interface status information
- **interface_transceiver.py** - Extract transceiver information
- **vlan_data.py** - Extract VLAN information
- **wireless_clients.py** - Extract wireless client information (for WLC)

## Compatibility

This package has been tested with:

- SecureCRT 9.0+
- Python 3.6+
- NetworkTNG release of TextFSM templates
- Cisco IOS, IOS-XE, IOS-XR, and NX-OS devices

## Credits

Based on Jamie Caesar's original SecureCRT Tools collection:
https://github.com/jamiecaesar/securecrt-tools
