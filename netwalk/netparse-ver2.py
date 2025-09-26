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
import re
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
        
        # DEBUG: Print what credentials we're storing
        print("\n" + "="*60)
        print("DEBUG: Credentials initialized in SimpleNetworkCollector")
        print(f"  Username: '{self.username}'")
        print(f"  Password: '{self.password[:2]}...{self.password[-2:]}' (length: {len(self.password)})")
        print(f"  Enable: {'Same as password' if self.enable_password == self.password else 'Different from password'}")
        print("="*60 + "\n")
        
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
        Connect to device and detect type from show version.
        No redundant auto-detection - just connect and check.
        
        Returns:
            tuple: (connection, hostname, device_type) or (None, None, None) if failed
        """
        try:
            # DEBUG: Show what we're about to use for connection
            print(f"\nDEBUG: Attempting connection to {host}")
            print(f"  Using username: '{self.username}'")
            print(f"  Using password: '{self.password[:2]}...{self.password[-2:]}' (length: {len(self.password)})")
            
            # Just connect as cisco_ios initially - it works for basic commands on most devices
            device = {
                'device_type': 'cisco_ios',  # Start with cisco_ios - works for most devices
                'host': host,
                'username': self.username,
                'password': self.password,
                'secret': self.enable_password,
                'timeout': 30,
                'global_delay_factor': 2,  # Helps with slower devices
            }
            
            # DEBUG: Show the complete device dictionary (with password masked)
            print(f"  Device dict being passed to Netmiko:")
            print(f"    device_type: '{device['device_type']}'")
            print(f"    host: '{device['host']}'")
            print(f"    username: '{device['username']}'")
            print(f"    password: <masked> (length: {len(device['password'])})")
            print(f"    secret: {'<same as password>' if device['secret'] == device['password'] else '<different>'}")
            print(f"    timeout: {device['timeout']}")
            print(f"    global_delay_factor: {device['global_delay_factor']}")
            
            logger.info(f"Connecting to {host}...")
            
            # Simple connection - no autodetect
            connection = ConnectHandler(**device)
            
            print(f"  SUCCESS: Connected to {host}")
            logger.info(f"Connected to {host}")
            
            # Now detect the actual device type from show version
            actual_device_type = self.detect_device_type(connection)
            
            # Update the connection's device type for proper command handling
            if actual_device_type != 'cisco_ios':
                connection.device_type = actual_device_type
                logger.info(f"Updated device type to: {actual_device_type}")
            
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
            
            # Method 3: Get from 'show version' (we already have this output)
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
            
            # Create device-specific output folder with hostname_IP format
            # Sanitize the host/IP for use in folder name
            sanitized_host = host.replace(':', '_')  # For IPv6 addresses
            folder_name = f"{hostname}_{sanitized_host}"
            
            device_folder = self.output_dir / folder_name
            device_folder.mkdir(exist_ok=True)
            logger.debug(f"Created device folder: {device_folder}")
            
            # Store the folder name for later use
            self.device_folder = device_folder
            
            # Set terminal length 0 for Cisco/Arista devices
            if 'cisco' in actual_device_type or 'arista' in actual_device_type:
                connection.send_command("terminal length 0")
            elif 'juniper' in actual_device_type:
                connection.send_command("set cli screen-length 0")
            
            logger.info(f"Connected to {hostname} ({actual_device_type})")
            # Return the folder name as hostname for consistency
            return connection, folder_name, actual_device_type
            
        except Exception as e:
            print(f"  FAILED: Connection to {host} failed")
            print(f"  Error: {e}")
            print(f"  Credentials used:")
            print(f"    Username: '{self.username}'")
            print(f"    Password length: {len(self.password)}")
            logger.error(f"Failed to connect to {host}: {e}")
            return None, None, None
    
    def collect_and_parse(self, connection, command, hostname, device_type):
        """
        Send command and parse with NTC templates.
        Saves raw output, JSON, and CSV in device-specific folder.
        Note: hostname parameter now contains "hostname_IP" format.
        
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
            
            # Device-specific folder (hostname already includes IP)
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
                # Extract just the hostname part (before the underscore and IP)
                actual_hostname = hostname.split('_')[0] if '_' in hostname else hostname
                for entry in parsed:
                    entry['_hostname'] = actual_hostname
                    entry['_device_type'] = device_type
                
                # Save parsed JSON to device folder
                json_file = device_folder / f"{cmd_safe}_{timestamp}.json"
                with open(json_file, 'w') as f:
                    json.dump({
                        'hostname': actual_hostname,
                        'folder': hostname,  # This includes hostname_IP
                        'device_type': device_type,
                        'command': command,
                        'timestamp': timestamp,
                        'parsed_entries': len(parsed),
                        'data': parsed
                    }, f, indent=2, default=str)
                logger.debug(f"Saved JSON output to {json_file}")
                
                # Save individual CSV to device folder
                if parsed and len(parsed) > 0:
                    csv_file = device_folder / f"{cmd_safe}_{timestamp}.csv"
                    with open(csv_file, 'w', newline='') as f:
                        writer = csv.DictWriter(f, fieldnames=parsed[0].keys())
                        writer.writeheader()
                        writer.writerows(parsed)
                    logger.debug(f"Saved CSV output to {csv_file}")
                
                logger.info(f"Parsed {len(parsed)} entries from {hostname}")
                return parsed
                
            except Exception as e:
                logger.warning(f"NTC parsing failed for {hostname}: {e}")
                
                # Still save JSON with raw output for debugging
                json_file = device_folder / f"{cmd_safe}_{timestamp}_unparsed.json"
                actual_hostname = hostname.split('_')[0] if '_' in hostname else hostname
                fallback_data = [{
                    '_hostname': actual_hostname,
                    '_device_type': device_type,
                    'raw_output': raw_output[:500] + '...' if len(raw_output) > 500 else raw_output,
                    'parse_error': str(e)
                }]
                
                with open(json_file, 'w') as f:
                    json.dump({
                        'hostname': actual_hostname,
                        'folder': hostname,
                        'device_type': device_type,
                        'command': command,
                        'timestamp': timestamp,
                        'parse_status': 'failed',
                        'error': str(e),
                        'data': fallback_data
                    }, f, indent=2, default=str)
                
                # Save CSV even for unparsed data
                csv_file = device_folder / f"{cmd_safe}_{timestamp}_unparsed.csv"
                with open(csv_file, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=fallback_data[0].keys())
                    writer.writeheader()
                    writer.writerows(fallback_data)
                
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
    
    def process_devices(self):
        """
        Main processing function.
        Connects to all devices, determines type, runs appropriate commands.
        """
        # Load devices
        devices = self.load_devices()
        if not devices:
            return
        
        print(f"\nProcessing {len(devices)} devices")
        print("="*60)
        
        all_collected_data = {}  # Store all data by command
        device_results = []
        success_count = 0
        failed_devices = []
        
        # Process each device
        for i, host in enumerate(devices, 1):
            print(f"\n[{i}/{len(devices)}] Processing {host}")
            
            # Connect and detect type
            connection, hostname_folder, device_type = self.connect_to_device(host)
            
            if not connection:
                failed_devices.append(host)
                device_results.append({
                    'host': host,
                    'status': 'failed',
                    'error': 'Connection failed'
                })
                continue
            
            # Load commands for this device type
            commands = self.load_command_list(device_type)
            
            if not commands:
                logger.warning(f"No commands to run for {hostname_folder}")
                connection.disconnect()
                continue
            
            # Extract just hostname for display (before underscore)
            display_hostname = hostname_folder.split('_')[0] if '_' in hostname_folder else hostname_folder
            
            print(f"  Hostname: {display_hostname}")
            print(f"  IP Address: {host}")
            print(f"  Device type: {device_type}")
            print(f"  Running {len(commands)} commands")
            
            device_command_count = 0
            
            # Run each command from the list
            for cmd_num, command in enumerate(commands, 1):
                print(f"    [{cmd_num}/{len(commands)}] {command}")
                
                # Collect and parse data - pass the folder name
                data = self.collect_and_parse(connection, command, hostname_folder, device_type)
                
                if data:
                    # Store data by command for consolidated output
                    if command not in all_collected_data:
                        all_collected_data[command] = []
                    all_collected_data[command].extend(data)
                    device_command_count += 1
            
            success_count += 1
            device_results.append({
                'host': host,
                'hostname': hostname_folder,  # This now includes hostname_IP
                'device_type': device_type,
                'status': 'success',
                'commands_run': device_command_count,
                'total_commands': len(commands)
            })
            
            # Disconnect
            connection.disconnect()
            logger.info(f"Disconnected from {hostname_folder}")
        
        # Save consolidated results for each command
        print("\n" + "="*60)
        print("SUMMARY")
        print("="*60)
        print(f"Devices successful: {success_count}/{len(devices)}")
        
        if failed_devices:
            print(f"Failed devices: {', '.join(failed_devices)}")
        
        # Save consolidated output for each command type
        if all_collected_data:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            print(f"\nConsolidated outputs saved:")
            for command, data in all_collected_data.items():
                if data:
                    cmd_safe = command.replace(" ", "_").replace("/", "-")
                    
                    # Save CSV
                    csv_file = f"consolidated_{cmd_safe}_{timestamp}.csv"
                    csv_path = self.save_to_csv(data, csv_file)
                    
                    # Save JSON with metadata
                    json_file = f"consolidated_{cmd_safe}_{timestamp}.json"
                    json_metadata = {
                        'command': command,
                        'devices_processed': len(devices),
                        'devices_successful': success_count,
                        'devices_failed': len(failed_devices),
                        'failed_devices': failed_devices,
                        'device_results': device_results,
                        'unique_device_types': list(set(d.get('_device_type', 'unknown') for d in data))
                    }
                    json_path = self.save_to_json(data, json_file, metadata=json_metadata)
                    
                    print(f"  {command}:")
                    print(f"    CSV:  {csv_path}")
                    print(f"    JSON: {json_path}")
                    print(f"    Entries: {len(data)}")
            
            print(f"\nDevice folders: {self.output_dir}/<hostname>_<IP>/")
            print(f"  (Contains raw, JSON, and CSV output for each command)")
            print(f"\nExample folders:")
            for device in device_results[:3]:  # Show first 3 as examples
                if device['status'] == 'success':
                    print(f"  {self.output_dir}/{device['hostname']}/")
        else:
            print("\nNo data collected from any device")
            
            # Still save summary JSON even if no data
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            json_file = f"failed_collection_{timestamp}.json"
            json_metadata = {
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
        description='Smart network data collector with device-specific command lists',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Setup:
  1. Create devices.txt with one IP/hostname per line:
     192.168.1.1
     192.168.1.2
     switch1.domain.com
     
  2. Create command lists for your device types:
     cisco_ios_commands.txt:
       show version
       show inventory
       show cdp neighbors detail
       show interfaces status
       
     arista_eos_commands.txt:
       show version
       show inventory
       show lldp neighbors detail
       show interfaces status
       
Examples:
  %(prog)s -u admin -p password
  %(prog)s -u admin -p password -e enablepass
  %(prog)s -u admin -p password --debug
  %(prog)s -u admin -p password -f routers.txt
  
The script will:
  1. Connect to each device
  2. Auto-detect device type
  3. Run commands from appropriate command list
  4. Parse output with NTC templates
  5. Save to device folders and consolidated files
        """
    )
    
    parser.add_argument('-u', '--username', required=True, help='Username for devices')
    parser.add_argument('-p', '--password', required=True, help='Password for devices')
    parser.add_argument('-e', '--enable', help='Enable password (defaults to login password)')
    parser.add_argument('-f', '--file', default='devices.txt',
                       help='Device file (default: devices.txt)')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug logging')
    
    args = parser.parse_args()
    
    # DEBUG: Show what was captured from command line
    print("\n" + "="*60)
    print("DEBUG: Command line arguments captured")
    print(f"  Username from args: '{args.username}'")
    print(f"  Password from args: '{args.password[:2] if len(args.password) > 2 else args.password}...' (length: {len(args.password)})")
    print(f"  Enable from args: '{args.enable}' (None = use login password)")
    print(f"  Device file: '{args.file}'")
    print("="*60 + "\n")
    
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
    
    # Process devices using command lists
    collector.process_devices()


if __name__ == "__main__":
    main()


"""
SETUP FILES NEEDED:
===================

1. devices.txt - List of devices (one per line):
   192.168.1.1
   192.168.1.2
   10.0.0.1
   switch1.domain.com
   # Comments start with #

2. Command lists by device type:

   cisco_ios_commands.txt:
   ========================
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
   
   cisco_nxos_commands.txt:
   =========================
   show version
   show inventory
   show cdp neighbors detail
   show interface status
   show ip interface brief vrf all
   show vlan brief
   show mac address-table
   show ip arp vrf all
   show spanning-tree summary
   show ip route summary vrf all
   
   arista_eos_commands.txt:
   =========================
   show version
   show inventory
   show lldp neighbors detail
   show interfaces status
   show ip interface brief
   show vlan
   show mac address-table
   show ip arp
   show spanning-tree summary
   show ip route summary
"""
