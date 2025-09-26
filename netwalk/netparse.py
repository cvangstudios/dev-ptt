#!/usr/bin/env python3
"""
kiss_network.py

Smart network automation that:
- Reads devices from simple text file (one IP per line)
- Auto-detects device type from "show version"
- Runs commands from device-specific command lists
- Uses appropriate NTC templates automatically
- Organizes output by device hostname

Command lists:
- cisco_ios_commands.txt
- cisco_nxos_commands.txt
- cisco_xr_commands.txt
- arista_eos_commands.txt
- juniper_junos_commands.txt

Usage:
    python kiss_network.py -u admin -p password
    python kiss_network.py -u admin -p password --debug
"""

import sys
import csv
import json
import argparse
import logging
from datetime import datetime
from pathlib import Path
from netmiko import ConnectHandler
from ntc_templates.parse import parse_output

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SimpleNetworkCollector:
    """
    Simple network data collector.
    Reads devices.txt, auto-detects device type, outputs CSV.
    """
    
    def __init__(self, username, password, enable_password=None):
        """Initialize with credentials."""
        self.username = username
        self.password = password
        self.enable_password = enable_password or password
        
        # Create output directories
        self.output_dir = Path("outputs")
        self.output_dir.mkdir(exist_ok=True)
        
        # Consolidated outputs go here
        (self.output_dir / "consolidated").mkdir(exist_ok=True)
        
        # Device type mapping based on show version output
        self.device_type_map = {
            'NX-OS': 'cisco_nxos',
            'Nexus': 'cisco_nxos',
            'IOS XE': 'cisco_ios',  # IOS-XE uses cisco_ios in netmiko
            'IOS-XE': 'cisco_ios',
            'Cisco IOS XE': 'cisco_ios',
            'IOS XR': 'cisco_xr',
            'IOS-XR': 'cisco_xr',
            'Arista EOS': 'arista_eos',
            'EOS': 'arista_eos',
            'vEOS': 'arista_eos',
            'Junos': 'juniper_junos',
            'JUNOS': 'juniper_junos',
            # Default fallback
            'Cisco IOS': 'cisco_ios',
            'IOS': 'cisco_ios',
        }
    
    def load_devices(self, filename="devices.txt"):
        """
        Load devices from simple text file.
        One IP or hostname per line.
        Lines starting with # are comments.
        """
        devices = []
        
        try:
            with open(filename, 'r') as f:
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comments
                    if line and not line.startswith('#'):
                        devices.append(line)
            
            logger.info(f"Loaded {len(devices)} devices from {filename}")
            return devices
            
        except FileNotFoundError:
            logger.error(f"File not found: {filename}")
            print(f"\nPlease create {filename} with one IP/hostname per line")
            print("Example:")
            print("192.168.1.1")
            print("192.168.1.2")
            print("switch1.domain.com")
            return []
    
    def load_command_list(self, device_type):
        """
        Load command list for specific device type.
        
        Looks for files like:
        - cisco_ios_commands.txt
        - cisco_nxos_commands.txt
        - arista_eos_commands.txt
        
        Returns:
            List of commands to run on this device type
        """
        # Map device types to command list files
        command_files = {
            'cisco_ios': 'cisco_ios_commands.txt',
            'cisco_nxos': 'cisco_nxos_commands.txt',
            'cisco_xr': 'cisco_xr_commands.txt',
            'cisco_iosxr': 'cisco_xr_commands.txt',
            'arista_eos': 'arista_eos_commands.txt',
            'juniper_junos': 'juniper_junos_commands.txt',
            'juniper': 'juniper_junos_commands.txt',
        }
        
        # Get the appropriate command file
        command_file = command_files.get(device_type, f'{device_type}_commands.txt')
        
        # Look for command file in current directory or commands subdirectory
        search_paths = [
            Path(command_file),
            Path('commands') / command_file,
            Path('.') / command_file
        ]
        
        commands = []
        file_found = None
        
        for filepath in search_paths:
            if filepath.exists():
                file_found = filepath
                break
        
        if file_found:
            logger.info(f"Loading commands from {file_found}")
            with open(file_found, 'r') as f:
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comments
                    if line and not line.startswith('#'):
                        commands.append(line)
            logger.info(f"Loaded {len(commands)} commands for {device_type}")
        else:
            logger.warning(f"No command list found for {device_type}, trying default_commands.txt")
            # Try default commands
            if Path('default_commands.txt').exists():
                with open('default_commands.txt', 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            commands.append(line)
                logger.info(f"Loaded {len(commands)} default commands")
            else:
                # Fallback to basic commands
                logger.warning("No command lists found, using basic defaults")
                commands = ['show version', 'show inventory']
        
        return commands
    
    def detect_device_type(self, connection):
        """
        Auto-detect device type from show version.
        Returns the detected netmiko device_type string.
        """
        try:
            # Get show version output
            output = connection.send_command("show version")
            
            # Check against known patterns
            for pattern, device_type in self.device_type_map.items():
                if pattern in output:
                    logger.info(f"Detected device type: {device_type} (matched '{pattern}')")
                    return device_type
            
            # Default to cisco_ios if nothing matches
            logger.warning("Could not detect device type, defaulting to cisco_ios")
            return 'cisco_ios'
            
        except Exception as e:
            logger.error(f"Error detecting device type: {e}")
            return 'cisco_ios'
    
    def connect_to_device(self, host):
        """
        Connect to device and auto-detect type.
        Gets hostname from prompt or 'show run | include hostname'.
        
        Returns:
            tuple: (connection, hostname, device_type) or (None, None, None) if failed
        """
        try:
            # Initial connection with autodetect
            device = {
                'device_type': 'autodetect',
                'host': host,
                'username': self.username,
                'password': self.password,
                'secret': self.enable_password,
                'timeout': 30,
            }
            
            logger.info(f"Connecting to {host}...")
            
            # Try to connect with autodetect
            try:
                from netmiko.ssh_autodetect import SSHDetect
                guesser = SSHDetect(**device)
                device_type = guesser.autodetect()
                device['device_type'] = device_type
                logger.info(f"Auto-detected (netmiko): {device_type}")
            except:
                # If autodetect fails, connect as generic and detect manually
                device['device_type'] = 'cisco_ios'
                logger.debug("Netmiko autodetect failed, trying manual detection")
            
            # Connect
            connection = ConnectHandler(**device)
            
            # Get hostname - try multiple methods
            hostname = None
            
            # Method 1: Get from prompt (most reliable)
            try:
                prompt = connection.find_prompt()
                # Remove prompt characters and clean up
                hostname = prompt.replace('#', '').replace('>', '').replace('(config)', '').strip()
                logger.debug(f"Got hostname from prompt: {hostname}")
            except:
                pass
            
            # Method 2: Get from 'show run | include hostname'
            if not hostname or hostname == host:
                try:
                    output = connection.send_command("show run | include hostname")
                    match = re.search(r'hostname\s+(\S+)', output)
                    if match:
                        hostname = match.group(1)
                        logger.debug(f"Got hostname from config: {hostname}")
                except:
                    pass
            
            # Method 3: Get from 'show version' (fallback)
            if not hostname or hostname == host:
                try:
                    output = connection.send_command("show version")
                    # Try to find hostname in version output
                    match = re.search(r'^(\S+)\s+uptime', output, re.MULTILINE)
                    if match:
                        hostname = match.group(1)
                        logger.debug(f"Got hostname from show version: {hostname}")
                except:
                    pass
            
            # Final fallback: use the IP/host provided
            if not hostname:
                hostname = host.replace('.', '_').replace(':', '_')
                logger.debug(f"Using sanitized host as hostname: {hostname}")
            
            # Create device-specific output folder
            device_folder = self.output_dir / hostname
            device_folder.mkdir(exist_ok=True)
            logger.debug(f"Created device folder: {device_folder}")
            
            # If we didn't auto-detect, do it now
            if device['device_type'] == 'cisco_ios':
                device_type = self.detect_device_type(connection)
                # Update connection device_type for proper command handling
                connection.device_type = device_type
            else:
                device_type = device['device_type']
            
            # Set terminal length 0 for Cisco/Arista devices
            if 'cisco' in device_type or 'arista' in device_type:
                connection.send_command("terminal length 0")
            elif 'juniper' in device_type:
                connection.send_command("set cli screen-length 0")
            
            logger.info(f"Connected to {hostname} ({device_type})")
            return connection, hostname, device_type
            
        except Exception as e:
            logger.error(f"Failed to connect to {host}: {e}")
            return None, None, None
    
    def collect_and_parse(self, connection, command, hostname, device_type):
        """
        Send command and parse with NTC templates.
        Saves raw output and JSON in device-specific folder.
        
        Returns:
            List of dictionaries ready for CSV
        """
        try:
            # Send command
            logger.info(f"Sending '{command}' to {hostname}")
            raw_output = connection.send_command(command)
            
            # Create timestamp for this collection
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            cmd_safe = command.replace(" ", "_").replace("/", "-")
            
            # Device-specific folder
            device_folder = self.output_dir / hostname
            device_folder.mkdir(exist_ok=True)
            
            # Save raw output to device folder
            raw_file = device_folder / f"{cmd_safe}_{timestamp}.txt"
            raw_file.write_text(raw_output)
            logger.debug(f"Saved raw output to {raw_file}")
            
            # Parse with NTC templates
            try:
                parsed = parse_output(
                    platform=device_type,
                    command=command,
                    data=raw_output
                )
                
                # Add hostname and device type to each entry
                for entry in parsed:
                    entry['_hostname'] = hostname
                    entry['_device_type'] = device_type
                
                # Save parsed JSON to device folder
                json_file = device_folder / f"{cmd_safe}_{timestamp}.json"
                with open(json_file, 'w') as f:
                    json.dump({
                        'hostname': hostname,
                        'device_type': device_type,
                        'command': command,
                        'timestamp': timestamp,
                        'parsed_entries': len(parsed),
                        'data': parsed
                    }, f, indent=2, default=str)
                logger.debug(f"Saved JSON output to {json_file}")
                
                logger.info(f"Parsed {len(parsed)} entries from {hostname}")
                return parsed
                
            except Exception as e:
                logger.warning(f"NTC parsing failed for {hostname}: {e}")
                
                # Still save JSON with raw output for debugging
                json_file = device_folder / f"{cmd_safe}_{timestamp}_unparsed.json"
                fallback_data = [{
                    '_hostname': hostname,
                    '_device_type': device_type,
                    'raw_output': raw_output[:500] + '...' if len(raw_output) > 500 else raw_output,
                    'parse_error': str(e)
                }]
                
                with open(json_file, 'w') as f:
                    json.dump({
                        'hostname': hostname,
                        'device_type': device_type,
                        'command': command,
                        'timestamp': timestamp,
                        'parse_status': 'failed',
                        'error': str(e),
                        'data': fallback_data
                    }, f, indent=2, default=str)
                
                return fallback_data
                
        except Exception as e:
            logger.error(f"Error collecting from {hostname}: {e}")
            return []
    
    def save_to_csv(self, data, filename):
        """Save data to CSV file in consolidated folder."""
        if not data:
            logger.warning("No data to save to CSV")
            return None
        
        filepath = self.output_dir / "consolidated" / filename
        
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
        
        logger.info(f"Saved {len(data)} rows to CSV: {filepath}")
        return filepath
    
    def save_to_json(self, data, filename, metadata=None):
        """
        Save data to JSON file in consolidated folder.
        Includes summary information for debugging.
        """
        if not data and not metadata:
            logger.warning("No data to save to JSON")
            return None
        
        filepath = self.output_dir / "consolidated" / filename
        
        output = {
            'collection_timestamp': datetime.now().isoformat(),
            'total_entries': len(data) if data else 0
        }
        
        if metadata:
            output.update(metadata)
        
        output['data'] = data
        
        with open(filepath, 'w') as f:
            json.dump(output, f, indent=2, default=str)
        
        logger.info(f"Saved JSON with {len(data) if data else 0} entries: {filepath}")
        return filepath
    
    def process_devices(self, command="show version"):
        """
        Main processing function.
        Connects to all devices, runs command, saves to CSV/JSON/RAW.
        """
        # Load devices
        devices = self.load_devices()
        if not devices:
            return
        
        print(f"\nProcessing {len(devices)} devices with command: {command}")
        print("="*60)
        
        all_data = []
        device_results = []  # For detailed JSON output
        success_count = 0
        failed_devices = []
        
        # Process each device
        for i, host in enumerate(devices, 1):
            print(f"\n[{i}/{len(devices)}] Processing {host}")
            
            # Connect and detect type
            connection, hostname, device_type = self.connect_to_device(host)
            
            if not connection:
                failed_devices.append(host)
                device_results.append({
                    'host': host,
                    'status': 'failed',
                    'error': 'Connection failed'
                })
                continue
            
            # Collect and parse data
            data = self.collect_and_parse(connection, command, hostname, device_type)
            
            if data:
                all_data.extend(data)
                success_count += 1
                device_results.append({
                    'host': host,
                    'hostname': hostname,
                    'device_type': device_type,
                    'status': 'success',
                    'entries_collected': len(data)
                })
            else:
                device_results.append({
                    'host': host,
                    'hostname': hostname,
                    'device_type': device_type,
                    'status': 'no_data',
                    'entries_collected': 0
                })
            
            # Disconnect
            connection.disconnect()
            logger.info(f"Disconnected from {hostname}")
        
        # Save consolidated results
        print("\n" + "="*60)
        print("SUMMARY")
        print("="*60)
        print(f"Successful: {success_count}/{len(devices)}")
        
        if failed_devices:
            print(f"Failed: {', '.join(failed_devices)}")
        
        if all_data:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            cmd_safe = command.replace(" ", "_").replace("/", "-")
            
            # Save CSV (primary output)
            csv_file = f"consolidated_{cmd_safe}_{timestamp}.csv"
            csv_path = self.save_to_csv(all_data, csv_file)
            
            # Save JSON (for debugging/validation)
            json_file = f"consolidated_{cmd_safe}_{timestamp}.json"
            json_metadata = {
                'command': command,
                'devices_processed': len(devices),
                'devices_successful': success_count,
                'devices_failed': len(failed_devices),
                'failed_devices': failed_devices,
                'device_results': device_results,
                'unique_device_types': list(set(d.get('_device_type', 'unknown') for d in all_data))
            }
            json_path = self.save_to_json(all_data, json_file, metadata=json_metadata)
            
            print(f"\nOutputs saved:")
            print(f"  Consolidated CSV:  {csv_path}")
            print(f"  Consolidated JSON: {json_path}")
            print(f"  Device folders:    {self.output_dir}/<hostname>/")
            print(f"\nTotal entries collected: {len(all_data)}")
            
            # Show columns
            if all_data[0]:
                cols = [c for c in all_data[0].keys() if not c.startswith('_')]
                print(f"Data columns: {', '.join(cols[:10])}")
                if len(cols) > 10:
                    print(f"              ... and {len(cols)-10} more columns")
        else:
            print("\nNo data collected from any device")
            
            # Still save summary JSON even if no data
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            json_file = f"failed_collection_{timestamp}.json"
            json_metadata = {
                'command': command,
                'devices_processed': len(devices),
                'devices_successful': 0,
                'devices_failed': len(failed_devices),
                'failed_devices': failed_devices,
                'device_results': device_results
            }
            json_path = self.save_to_json([], json_file, metadata=json_metadata)
            print(f"Summary saved to: {json_path}")


def main():
    """Main entry point with argument parsing."""
    parser = argparse.ArgumentParser(
        description='Simple network data collector - KISS approach with CSV/JSON/RAW output',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u admin -p password
  %(prog)s -u admin -p password -c "show interfaces status"
  %(prog)s -u admin -p password -c "show cdp neighbors detail"
  %(prog)s -u admin -p password -e enablepass -c "show vlan"
  %(prog)s -u admin -p password --debug  # Enable debug logging
  
Create devices.txt with one IP/hostname per line:
  192.168.1.1
  192.168.1.2
  switch1.domain.com
  # Comments start with #
  
Output: CSV (primary), JSON (debugging), RAW (validation)
        """
    )
    
    parser.add_argument('-u', '--username', required=True, help='Username for devices')
    parser.add_argument('-p', '--password', required=True, help='Password for devices')
    parser.add_argument('-e', '--enable', help='Enable password (defaults to login password)')
    parser.add_argument('-c', '--command', default='show version', 
                       help='Command to run (default: "show version")')
    parser.add_argument('-f', '--file', default='devices.txt',
                       help='Device file (default: devices.txt)')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug logging (shows all file operations)')
    
    args = parser.parse_args()
    
    # Set logging level
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    # Create collector
    collector = SimpleNetworkCollector(
        username=args.username,
        password=args.password,
        enable_password=args.enable
    )
    
    # Override device file if specified
    if args.file != 'devices.txt':
        collector.load_devices = lambda: collector.load_devices(args.file)
    
    # Process devices
    collector.process_devices(args.command)


if __name__ == "__main__":
    main()


"""
SAMPLE devices.txt:
===================
# Core Switches
192.168.1.1
192.168.1.2

# Distribution
192.168.10.1
192.168.10.2

# Access Layer
switch-access-01.domain.com
switch-access-02.domain.com

# WAN Routers
10.0.0.1
10.0.0.2


USAGE EXAMPLES:
===============

1. Basic inventory collection:
   python kiss_network.py -u admin -p cisco123

2. Collect CDP neighbors:
   python kiss_network.py -u admin -p cisco123 -c "show cdp neighbors detail"

3. Collect interface status:
   python kiss_network.py -u admin -p cisco123 -c "show interfaces status"

4. Collect VLANs with enable password:
   python kiss_network.py -u admin -p cisco123 -e enablepass -c "show vlan"

5. Use different device file:
   python kiss_network.py -u admin -p cisco123 -f routers.txt -c "show ip route"


AUTO-DETECTION:
===============
The script automatically detects:
- Cisco IOS
- Cisco IOS-XE  
- Cisco NX-OS
- Cisco IOS-XR
- Arista EOS
- Juniper Junos

And uses the appropriate NTC templates for each platform!


OUTPUT STRUCTURE (ORGANIZED BY DEVICE):
=========================================

Each device gets its own folder with all its outputs:

outputs/
├── switch1/                              # Device-specific folder
│   ├── show_version_20231025_143022.txt           # Raw output
│   ├── show_version_20231025_143022.json          # Parsed JSON
│   ├── show_cdp_neighbors_detail_20231025_143023.txt
│   ├── show_cdp_neighbors_detail_20231025_143023.json
│   └── show_interfaces_status_20231025_143024.txt
├── switch2/
│   ├── show_version_20231025_143030.txt
│   ├── show_version_20231025_143030.json
│   └── show_cdp_neighbors_detail_20231025_143031.txt
├── router1/
│   ├── show_version_20231025_143040.txt
│   └── show_ip_route_20231025_143041.txt
└── consolidated/                         # Combined results from all devices
    ├── consolidated_show_cdp_neighbors_detail_20231025_143100.csv
    └── consolidated_show_cdp_neighbors_detail_20231025_143100.json


BENEFITS OF PER-DEVICE FOLDERS:
================================
1. Easy to find all data for a specific device
2. Compare commands run at different times
3. Keep history per device
4. Troubleshoot specific devices
5. Archive or delete device data independently


OUTPUT FORMATS:
===============

Per-Device Folders:
- RAW (.txt): Complete unmodified command output
- JSON (.json): Parsed data with metadata for that device

Consolidated Folder:
- CSV: All devices combined, ready for Excel/reports
- JSON: All devices with summary statistics

Example: After running CDP discovery on 3 devices:
- outputs/switch1/show_cdp_neighbors_detail_*.txt (raw)
- outputs/switch1/show_cdp_neighbors_detail_*.json (parsed)
- outputs/switch2/show_cdp_neighbors_detail_*.txt
- outputs/switch2/show_cdp_neighbors_detail_*.json  
- outputs/router1/show_cdp_neighbors_detail_*.txt
- outputs/router1/show_cdp_neighbors_detail_*.json
- outputs/consolidated/consolidated_show_cdp_neighbors_detail_*.csv (all combined)
- outputs/consolidated/consolidated_show_cdp_neighbors_detail_*.json (all with stats)


WHY THIS ORGANIZATION?
======================
- Device-Centric: All data for a device in one place
- Easy Troubleshooting: "What did switch1 say about CDP?"
- Historical Tracking: See all commands ever run on a device
- Clean Organization: No mixing of different devices' outputs
- Selective Archiving: Archive/delete specific device data

The hostname is discovered automatically via:
1. Device prompt (most reliable)
2. 'show run | include hostname' (config check)  
3. 'show version' output (fallback)
4. Sanitized IP address (last resort)

This ensures consistent folder naming even if devices have long prompts or domain names.
"""
