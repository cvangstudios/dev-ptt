#!/usr/bin/env python3
"""
netparse-ver2.py

Smart network automation with parallel processing that:
- Reads devices from simple text file (one IP per line)
- Auto-detects device type from "show version"
- Runs commands from device-specific command lists
- Uses appropriate NTC templates automatically
- Processes multiple devices in parallel for speed
- Organizes output by device hostname

Command lists:
- cisco_ios_commands.txt
- cisco_nxos_commands.txt
- cisco_xr_commands.txt
- arista_eos_commands.txt
- juniper_junos_commands.txt

Usage:
    python netparse-ver2.py -u admin -p password
    python netparse-ver2.py -u admin -p password -w 10
    python netparse-ver2.py -u admin -p password --debug
"""

import sys
import csv
import json
import argparse
import logging
import re
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

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
    Simple network data collector with parallel processing.
    Reads devices.txt, auto-detects device type, outputs CSV.
    """
    
    def __init__(self, username, password, enable_password=None, max_workers=5):
        """Initialize with credentials and parallel settings."""
        self.username = username
        self.password = password
        self.enable_password = enable_password or password
        self.max_workers = max_workers
        self.lock = threading.Lock()  # For thread-safe operations
        
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
        Simplified connection method - matches standard Netmiko usage.
        Connects as cisco_ios and detects actual type for reference only.
        
        Returns:
            tuple: (connection, hostname, device_type) or (None, None, None) if failed
        """
        try:
            # Connection parameters - using 'ip' instead of 'host' for compatibility
            device = {
                'device_type': 'cisco_ios',  # Standard cisco_ios for all devices
                'ip': host,  # Using 'ip' for better compatibility
                'username': self.username,
                'password': self.password,
                'secret': self.enable_password,
                'timeout': 30,
            }
            
            logger.info(f"Connecting to {host}...")
            
            # Standard Netmiko connection
            connection = ConnectHandler(**device)
            logger.info(f"Connected to {host}")
            
            # Detect actual device type for reference (but don't modify connection)
            actual_device_type = self.detect_device_type(connection)
            logger.info(f"Detected device type: {actual_device_type}")
            
            # Get hostname from prompt
            hostname = None
            try:
                prompt = connection.find_prompt()
                # Remove prompt characters and clean up
                hostname = prompt.replace('#', '').replace('>', '').replace('(config)', '').strip()
                logger.debug(f"Got hostname from prompt: {hostname}")
            except:
                pass
            
            # Fallback: use sanitized IP as hostname
            if not hostname:
                hostname = host.replace('.', '_').replace(':', '_')
                logger.debug(f"Using sanitized host as hostname: {hostname}")
            
            # Create device-specific output folder with hostname_IP format
            sanitized_host = host.replace(':', '_')  # For IPv6 addresses
            folder_name = f"{hostname}_{sanitized_host}"
            
            device_folder = self.output_dir / folder_name
            device_folder.mkdir(exist_ok=True)
            logger.debug(f"Created device folder: {device_folder}")
            
            # Set terminal length for complete output
            try:
                if 'cisco' in actual_device_type or 'arista' in actual_device_type:
                    connection.send_command("terminal length 0")
                elif 'juniper' in actual_device_type:
                    connection.send_command("set cli screen-length 0")
                else:
                    # Default cisco command since we connected as cisco_ios
                    connection.send_command("terminal length 0")
            except:
                # If terminal length fails, continue anyway
                pass
            
            logger.info(f"Connected to {hostname} (detected as {actual_device_type})")
            
            # Return connection with detected type (but connection stays as cisco_ios)
            return connection, folder_name, actual_device_type
            
        except Exception as e:
            logger.error(f"Failed to connect to {host}: {e}")
            return None, None, None
            
            logger.info(f"Connecting to {host}...")
            
            # Standard Netmiko connection
            connection = ConnectHandler(**device)
            logger.info(f"Connected to {host}")
            
            # Detect actual device type for reference (but don't modify connection)
            actual_device_type = self.detect_device_type(connection)
            logger.info(f"Detected device type: {actual_device_type}")
            
            # Get hostname from prompt
            hostname = None
            try:
                prompt = connection.find_prompt()
                # Remove prompt characters and clean up
                hostname = prompt.replace('#', '').replace('>', '').replace('(config)', '').strip()
                logger.debug(f"Got hostname from prompt: {hostname}")
            except:
                pass
            
            # Fallback: use sanitized IP as hostname
            if not hostname:
                hostname = host.replace('.', '_').replace(':', '_')
                logger.debug(f"Using sanitized host as hostname: {hostname}")
            
            # Create device-specific output folder with hostname_IP format
            sanitized_host = host.replace(':', '_')  # For IPv6 addresses
            folder_name = f"{hostname}_{sanitized_host}"
            
            device_folder = self.output_dir / folder_name
            device_folder.mkdir(exist_ok=True)
            logger.debug(f"Created device folder: {device_folder}")
            
            # Set terminal length for complete output
            try:
                if 'cisco' in actual_device_type or 'arista' in actual_device_type:
                    connection.send_command("terminal length 0")
                elif 'juniper' in actual_device_type:
                    connection.send_command("set cli screen-length 0")
                else:
                    # Default cisco command since we connected as cisco_ios
                    connection.send_command("terminal length 0")
            except:
                # If terminal length fails, continue anyway
                pass
            
            logger.info(f"Connected to {hostname} (detected as {actual_device_type})")
            
            # Return connection with detected type (but connection stays as cisco_ios)
            return connection, folder_name, actual_device_type
            
        except Exception as e:
            logger.error(f"Failed to connect to {host}: {e}")
            logger.error(f"[DEBUG] Failed with username: '{self.username}'")
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
    
    def process_single_device(self, host):
        """
        Process a single device - extracted for parallel execution.
        Returns a dict with results.
        """
        print(f"[Thread-{threading.current_thread().name}] Starting: {host}")
        
        result = {
            'host': host,
            'status': 'failed',
            'hostname': None,
            'device_type': None,
            'commands_run': 0,
            'data': {}
        }
        
        try:
            # Connect and detect type
            connection, hostname_folder, device_type = self.connect_to_device(host)
            
            if not connection:
                print(f"  ✗ Failed to connect: {host}")
                return result
            
            # Update result
            result['hostname'] = hostname_folder
            result['device_type'] = device_type
            
            # Load commands for this device type
            commands = self.load_command_list(device_type)
            
            if not commands:
                logger.warning(f"No commands to run for {hostname_folder}")
                connection.disconnect()
                result['status'] = 'no_commands'
                return result
            
            # Extract display hostname
            display_hostname = hostname_folder.split('_')[0] if '_' in hostname_folder else hostname_folder
            
            print(f"  → {display_hostname} ({host}): Running {len(commands)} commands on {device_type}")
            
            # Run each command
            command_data = {}
            for command in commands:
                data = self.collect_and_parse(connection, command, hostname_folder, device_type)
                if data:
                    command_data[command] = data
                    result['commands_run'] += 1
            
            # Disconnect
            connection.disconnect()
            logger.info(f"Disconnected from {hostname_folder}")
            
            # Update result
            result['status'] = 'success'
            result['data'] = command_data
            result['total_commands'] = len(commands)
            
            print(f"  ✓ Completed: {display_hostname} ({result['commands_run']}/{len(commands)} commands)")
            
        except Exception as e:
            logger.error(f"Error processing {host}: {e}")
            print(f"  ✗ Error: {host} - {str(e)[:50]}")
            result['error'] = str(e)
        
        return result
    
    def process_devices(self):
        """
        Main processing function with parallel execution.
        Connects to devices concurrently for faster processing.
        """
        # Load devices
        devices = self.load_devices()
        if not devices:
            return
        
        # Determine optimal worker count
        worker_count = min(self.max_workers, len(devices))
        
        print(f"\nProcessing {len(devices)} devices")
        print(f"Parallel mode: {worker_count} workers")
        print("="*60)
        
        all_collected_data = {}
        device_results = []
        success_count = 0
        failed_devices = []
        
        # Process devices in parallel
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            # Submit all devices for processing
            future_to_device = {
                executor.submit(self.process_single_device, device): device 
                for device in devices
            }
            
            # Process results as devices complete
            completed = 0
            for future in as_completed(future_to_device):
                device = future_to_device[future]
                completed += 1
                
                try:
                    result = future.result(timeout=300)  # 5 minute timeout per device
                    
                    # Thread-safe update of results
                    with self.lock:
                        device_results.append(result)
                        
                        if result['status'] == 'success':
                            success_count += 1
                            
                            # Merge command data
                            for command, data in result['data'].items():
                                if command not in all_collected_data:
                                    all_collected_data[command] = []
                                all_collected_data[command].extend(data)
                        else:
                            failed_devices.append(device)
                    
                    # Simple progress indicator
                    print(f"Progress: {completed}/{len(devices)} devices completed")
                    
                except Exception as e:
                    logger.error(f"Device {device} processing failed: {e}")
                    with self.lock:
                        failed_devices.append(device)
                        device_results.append({
                            'host': device,
                            'status': 'failed',
                            'error': str(e)
                        })
        
        # Save consolidated results
        print("\n" + "="*60)
        print("SUMMARY")
        print("="*60)
        print(f"Devices successful: {success_count}/{len(devices)}")
        print(f"Parallel workers used: {worker_count}")
        
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
                        'parallel_workers': worker_count,
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
                'parallel_workers': worker_count,
                'device_results': device_results
            }
            json_path = self.save_to_json([], json_file, metadata=json_metadata)
            print(f"Summary saved to: {json_path}")


def main():
    """Main entry point with argument parsing."""
    parser = argparse.ArgumentParser(
        description='Smart network data collector with parallel processing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Setup:
  1. Create devices.txt with one IP/hostname per line
  2. Create command lists for your device types (e.g., cisco_ios_commands.txt)
  
See usage examples at the end of this script for details.
        """
    )
    
    parser.add_argument('-u', '--username', required=True, help='Username for devices')
    parser.add_argument('-p', '--password', required=True, help='Password for devices')
    parser.add_argument('-e', '--enable', help='Enable password (defaults to login password)')
    parser.add_argument('-f', '--file', default='devices.txt',
                       help='Device file (default: devices.txt)')
    parser.add_argument('-w', '--workers', type=int, default=5,
                       help='Max parallel workers (default: 5, recommended: 5-10)')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug logging')
    
    args = parser.parse_args()
    
    # Validate worker count
    if args.workers < 1:
        print("Error: Workers must be at least 1")
        sys.exit(1)
    elif args.workers > 20:
        print("Warning: Using more than 20 workers may overwhelm devices")
        response = input("Continue anyway? (y/N): ")
        if response.lower() != 'y':
            sys.exit(0)
    
    # Set logging level
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    # Create collector with parallel settings
    collector = SimpleNetworkCollector(
        username=args.username,
        password=args.password,
        enable_password=args.enable,
        max_workers=args.workers
    )
    
    # Override device file if specified
    if args.file != 'devices.txt':
        collector.load_devices = lambda: collector.load_devices(args.file)
    
    print(f"Starting collection with {args.workers} parallel workers")
    
    # Process devices in parallel
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


USAGE EXAMPLES:
===============

# Basic usage (5 parallel workers by default):
python netparse-ver2.py -u admin -p password

# Specify enable password if different from login:
python netparse-ver2.py -u admin -p password -e enablepass

# Custom device file (instead of devices.txt):
python netparse-ver2.py -u admin -p password -f routers.txt
python netparse-ver2.py -u admin -p password -f lab_devices.txt

# Control parallel workers (default: 5, recommended: 5-10):
python netparse-ver2.py -u admin -p password -w 10      # Faster processing
python netparse-ver2.py -u admin -p password -w 3       # Conservative/production
python netparse-ver2.py -u admin -p password -w 1       # Serial processing (safest)

# Enable debug logging for troubleshooting:
python netparse-ver2.py -u admin -p password --debug
python netparse-ver2.py -u admin -p password -w 10 --debug

# Combined options:
python netparse-ver2.py -u admin -p password -e enablepass -f core_switches.txt -w 8
python netparse-ver2.py -u netadmin -p secret123 -f datacenter.txt -w 10 --debug

# Environment examples by use case:
# Lab/Testing (aggressive):
python netparse-ver2.py -u admin -p password -w 15

# Production (conservative):
python netparse-ver2.py -u admin -p password -w 3

# Large deployment (balanced):
python netparse-ver2.py -u admin -p password -w 10 -f all_devices.txt

# Troubleshooting slow device:
python netparse-ver2.py -u admin -p password -w 1 --debug


PARALLEL WORKERS GUIDE:
=======================
Workers | Use Case                        | Notes
--------|--------------------------------|----------------------------------
1       | Troubleshooting/Serial         | Same as original script
3       | Production/Sensitive           | Very safe, minimal load
5       | Default/Recommended            | Good balance for most environments
10      | Lab/Known Environment          | Faster, still safe
15-20   | Large deployments              | Only if devices can handle it

Rule of thumb: Start with 5, increase if no errors, decrease if connection issues


OUTPUT STRUCTURE:
=================
outputs/
├── consolidated/                       # Merged data from all devices
│   ├── consolidated_show_version_*.csv
│   ├── consolidated_show_version_*.json
│   ├── consolidated_show_inventory_*.csv
│   └── consolidated_show_inventory_*.json
│
└── <hostname>_<IP>/                    # Per-device outputs
    ├── show_version_*.txt              # Raw output
    ├── show_version_*.json             # Parsed JSON
    ├── show_version_*.csv              # Parsed CSV
    └── ...


PERFORMANCE EXPECTATIONS:
=========================
Devices | Serial    | 5 Workers | 10 Workers
--------|-----------|-----------|------------
10      | ~5 min    | ~1 min    | ~1 min
50      | ~25 min   | ~5 min    | ~3 min
100     | ~50 min   | ~10 min   | ~5 min
500     | ~4 hours  | ~50 min   | ~25 min

* Times are estimates, actual performance depends on:
  - Network latency
  - Device response time
  - Number of commands per device
  - Command complexity


TROUBLESHOOTING:
================
Issue: "Connection refused" or "Too many connections"
Fix:   Reduce workers: -w 3

Issue: Script running too slow
Fix:   Increase workers: -w 10

Issue: Can't connect to devices
Fix:   Use -w 1 --debug to troubleshoot serially

Issue: Some devices fail in parallel but work serially
Fix:   Device may have SSH connection limit, use -w 3

Issue: Want to see what's happening
Fix:   Add --debug flag for detailed logging
"""
