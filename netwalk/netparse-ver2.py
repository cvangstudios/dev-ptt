#!/usr/bin/env python3
"""
netparse_parallel.py

Simple parallel network automation that:
- Connects and immediately sets terminal length 0
- Detects device type from "show version" 
- Runs appropriate commands for each device type
- Processes devices in parallel for speed
- Retries only on authentication failure with new credentials
- Keeps everything simple and reliable

Usage:
    python netparse_parallel.py -u admin -p password
    python netparse_parallel.py -u admin -p password --workers 10
    python netparse_parallel.py -u admin -p password --sequential  # disable parallel
"""

import sys
import csv
import json
import argparse
import logging
import re
import getpass
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from netmiko import ConnectHandler
from netmiko.exceptions import AuthenticationException, NetmikoAuthenticationException
from ntc_templates.parse import parse_output

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SimpleParallelCollector:
    """
    Simple parallel network collector with smart device detection.
    """
    
    def __init__(self, username, password, enable_password=None, max_workers=5):
        """Initialize with credentials."""
        self.username = username
        self.password = password
        self.enable_password = enable_password or password
        self.max_workers = max_workers
        
        # Thread-safe storage
        self.all_collected_data = {}
        self.device_results = []
        self.failed_devices = []
        self.data_lock = Lock()
        
        # Track if we've already prompted for new credentials
        self.credentials_updated = False
        self.cred_lock = Lock()
        
        # Create output directories
        self.output_dir = Path("outputs")
        self.output_dir.mkdir(exist_ok=True)
        (self.output_dir / "consolidated").mkdir(exist_ok=True)
        
        # Device type patterns for detection
        self.device_type_patterns = [
            # Check NX-OS first (before generic IOS)
            (r'NX-OS|Nexus', 'cisco_nxos'),
            # IOS-XR
            (r'IOS[\s-]XR|IOS-XR', 'cisco_xr'),
            # IOS-XE (uses cisco_ios driver)
            (r'IOS[\s-]XE|IOS-XE|Cisco IOS XE', 'cisco_ios'),
            # Arista
            (r'Arista|EOS|vEOS', 'arista_eos'),
            # Juniper
            (r'JUNOS|Junos|junos', 'juniper_junos'),
            # Generic IOS (check last)
            (r'Cisco IOS|IOS', 'cisco_ios'),
        ]
    
    def load_devices(self, filename="devices.txt"):
        """Load devices from simple text file."""
        devices = []
        
        try:
            with open(filename, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        devices.append(line)
            
            logger.info(f"Loaded {len(devices)} devices from {filename}")
            return devices
            
        except FileNotFoundError:
            logger.error(f"File not found: {filename}")
            print(f"\nPlease create {filename} with one IP/hostname per line")
            return []
    
    def load_command_list(self, device_type):
        """Load command list for specific device type."""
        command_files = {
            'cisco_ios': 'cisco_ios_commands.txt',
            'cisco_nxos': 'cisco_nxos_commands.txt',
            'cisco_xr': 'cisco_xr_commands.txt',
            'arista_eos': 'arista_eos_commands.txt',
            'juniper_junos': 'juniper_junos_commands.txt',
        }
        
        command_file = command_files.get(device_type, f'{device_type}_commands.txt')
        
        # Look for command file
        search_paths = [
            Path(command_file),
            Path('commands') / command_file,
        ]
        
        for filepath in search_paths:
            if filepath.exists():
                commands = []
                with open(filepath, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            commands.append(line)
                logger.info(f"Loaded {len(commands)} commands for {device_type}")
                return commands
        
        # Default commands if no file found
        logger.warning(f"No command list found for {device_type}, using defaults")
        return ['show version', 'show inventory']
    
    def prompt_for_credentials(self):
        """Prompt user for new credentials."""
        print("\n⚠️  Authentication failed. Please enter new credentials:")
        new_username = input("Username: ")
        new_password = getpass.getpass("Password: ")
        new_enable = getpass.getpass("Enable password (press Enter to use same as login): ")
        
        if not new_enable:
            new_enable = new_password
        
        return new_username, new_password, new_enable
    
    def connect_to_device(self, host):
        """
        Connect to device with proper sequence:
        1. Connect
        2. Set terminal length 0 (FIRST THING)
        3. Run show version to detect type
        4. Get hostname
        """
        try:
            # Start with generic cisco_ios for initial connection
            device = {
                'device_type': 'cisco_ios',
                'host': host,
                'username': self.username,
                'password': self.password,
                'secret': self.enable_password,
                'timeout': 30,
                'global_delay_factor': 2,
            }
            
            logger.info(f"Connecting to {host}...")
            
            try:
                connection = ConnectHandler(**device)
            except (AuthenticationException, NetmikoAuthenticationException) as auth_error:
                logger.error(f"Authentication failed for {host}: {auth_error}")
                
                # Check if we should prompt for new credentials
                with self.cred_lock:
                    if not self.credentials_updated:
                        # Prompt for new credentials
                        new_user, new_pass, new_enable = self.prompt_for_credentials()
                        
                        # Update credentials for all future connections
                        self.username = new_user
                        self.password = new_pass
                        self.enable_password = new_enable
                        self.credentials_updated = True
                        
                        print("Retrying with new credentials...")
                        
                        # Try again with new credentials
                        device['username'] = self.username
                        device['password'] = self.password
                        device['secret'] = self.enable_password
                        
                        try:
                            connection = ConnectHandler(**device)
                        except Exception as retry_error:
                            logger.error(f"Authentication still failed for {host}: {retry_error}")
                            return None, None, None
                    else:
                        # Already tried new credentials, just fail this device
                        return None, None, None
            
            # STEP 1: Set terminal length 0 (FIRST THING WE DO)
            try:
                connection.send_command("terminal length 0")
                logger.debug(f"Set terminal length 0 for {host}")
            except:
                # Some devices might not support it, continue anyway
                logger.debug(f"Could not set terminal length for {host}")
            
            # STEP 2: Get show version to detect device type
            try:
                show_version_output = connection.send_command("show version")
            except Exception as e:
                logger.error(f"Failed to get show version from {host}: {e}")
                connection.disconnect()
                return None, None, None
            
            # STEP 3: Detect device type from show version
            device_type = 'cisco_ios'  # default
            for pattern, detected_type in self.device_type_patterns:
                if re.search(pattern, show_version_output, re.IGNORECASE):
                    device_type = detected_type
                    logger.info(f"Detected {host} as {detected_type}")
                    break
            
            # Update connection with correct device type
            connection.device_type = device_type
            
            # For Juniper, set screen length after detection
            if 'juniper' in device_type:
                try:
                    connection.send_command("set cli screen-length 0")
                    logger.debug(f"Set screen length 0 for Juniper {host}")
                except:
                    pass
            
            # STEP 4: Get hostname
            hostname = None
            try:
                prompt = connection.find_prompt()
                hostname = prompt.replace('#', '').replace('>', '').replace('(config)', '').strip()
                hostname = hostname.strip('[]')  # Remove brackets if present
            except:
                pass
            
            # Try to get hostname from config if prompt didn't work
            if not hostname or hostname == host:
                try:
                    output = connection.send_command("show run | include hostname")
                    match = re.search(r'hostname\s+(\S+)', output)
                    if match:
                        hostname = match.group(1)
                except:
                    pass
            
            # Fallback hostname
            if not hostname:
                hostname = host.replace('.', '_').replace(':', '_')
            
            # Create device folder
            device_folder = self.output_dir / hostname
            device_folder.mkdir(exist_ok=True)
            
            logger.info(f"Connected to {hostname} ({device_type})")
            
            # Save the show version output we already collected
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            version_file = device_folder / f"show_version_{timestamp}.txt"
            version_file.write_text(show_version_output)
            
            return connection, hostname, device_type
            
        except Exception as e:
            logger.error(f"Failed to connect to {host}: {e}")
            return None, None, None
    
    def collect_and_parse(self, connection, command, hostname, device_type):
        """Send command and parse with NTC templates."""
        try:
            logger.info(f"Sending '{command}' to {hostname}")
            raw_output = connection.send_command(command, delay_factor=2)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            cmd_safe = command.replace(" ", "_").replace("/", "-")
            
            device_folder = self.output_dir / hostname
            
            # Save raw output
            raw_file = device_folder / f"{cmd_safe}_{timestamp}.txt"
            raw_file.write_text(raw_output)
            logger.debug(f"Saved raw output to {raw_file}")
            
            # Try to parse with NTC templates
            try:
                parsed = parse_output(
                    platform=device_type,
                    command=command,
                    data=raw_output
                )
                
                # Add metadata to each entry
                for entry in parsed:
                    entry['_hostname'] = hostname
                    entry['_device_type'] = device_type
                
                # Save parsed JSON
                if parsed:
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
                    
                    # Save CSV
                    csv_file = device_folder / f"{cmd_safe}_{timestamp}.csv"
                    with open(csv_file, 'w', newline='') as f:
                        writer = csv.DictWriter(f, fieldnames=parsed[0].keys())
                        writer.writeheader()
                        writer.writerows(parsed)
                
                logger.info(f"Parsed {len(parsed)} entries from {hostname}")
                return parsed
                
            except Exception as e:
                logger.debug(f"NTC parsing not available for {command} on {device_type}")
                # Return unparsed data
                return [{'_hostname': hostname, '_device_type': device_type, 
                        '_command': command, '_timestamp': timestamp}]
                
        except Exception as e:
            logger.error(f"Error collecting '{command}' from {hostname}: {e}")
            return []
    
    def process_single_device(self, host):
        """Process a single device."""
        # Connect to device
        connection, hostname, device_type = self.connect_to_device(host)
        
        if not connection:
            with self.data_lock:
                self.failed_devices.append(host)
                self.device_results.append({
                    'host': host,
                    'status': 'failed',
                    'error': 'Connection failed'
                })
            return False
        
        try:
            # Load commands for this device type
            commands = self.load_command_list(device_type)
            
            device_command_count = 0
            
            # Run each command
            for command in commands:
                # Skip "show version" since we already ran it
                if command.strip().lower() == 'show version':
                    continue
                    
                data = self.collect_and_parse(connection, command, hostname, device_type)
                
                if data:
                    # Thread-safe data storage
                    with self.data_lock:
                        if command not in self.all_collected_data:
                            self.all_collected_data[command] = []
                        self.all_collected_data[command].extend(data)
                    device_command_count += 1
            
            # Store results
            with self.data_lock:
                self.device_results.append({
                    'host': host,
                    'hostname': hostname,
                    'device_type': device_type,
                    'status': 'success',
                    'commands_run': device_command_count
                })
            
            logger.info(f"Successfully processed {hostname}")
            return True
            
        except Exception as e:
            logger.error(f"Error processing {hostname}: {e}")
            with self.data_lock:
                self.failed_devices.append(host)
            return False
            
        finally:
            try:
                connection.disconnect()
                logger.info(f"Disconnected from {hostname}")
            except:
                pass
    
    def save_consolidated_output(self):
        """Save all collected data to consolidated files."""
        if not self.all_collected_data:
            print("\nNo data collected from any device")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        print(f"\nConsolidated outputs:")
        for command, data in self.all_collected_data.items():
            if data:
                cmd_safe = command.replace(" ", "_").replace("/", "-")
                
                # Save CSV
                csv_file = self.output_dir / "consolidated" / f"{cmd_safe}_{timestamp}.csv"
                try:
                    with open(csv_file, 'w', newline='') as f:
                        writer = csv.DictWriter(f, fieldnames=data[0].keys())
                        writer.writeheader()
                        writer.writerows(data)
                    print(f"  {command}: {csv_file} ({len(data)} entries)")
                except Exception as e:
                    logger.error(f"Failed to save CSV for {command}: {e}")
                
                # Save JSON with metadata
                json_file = self.output_dir / "consolidated" / f"{cmd_safe}_{timestamp}.json"
                try:
                    with open(json_file, 'w') as f:
                        json.dump({
                            'command': command,
                            'timestamp': timestamp,
                            'total_entries': len(data),
                            'devices': list(set(d.get('_hostname', 'unknown') for d in data)),
                            'data': data
                        }, f, indent=2, default=str)
                except Exception as e:
                    logger.error(f"Failed to save JSON for {command}: {e}")
    
    def process_devices_parallel(self, devices):
        """Process devices in parallel."""
        print(f"\nProcessing {len(devices)} devices in parallel (workers: {self.max_workers})")
        print("="*60)
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            futures = {executor.submit(self.process_single_device, host): host 
                      for host in devices}
            
            # Wait for completion
            completed = 0
            for future in as_completed(futures):
                completed += 1
                host = futures[future]
                try:
                    success = future.result(timeout=300)
                    status = "✓" if success else "✗"
                    print(f"[{completed}/{len(devices)}] {status} {host}")
                except Exception as e:
                    print(f"[{completed}/{len(devices)}] ✗ {host} - {str(e)[:50]}")
    
    def process_devices_sequential(self, devices):
        """Process devices one by one."""
        print(f"\nProcessing {len(devices)} devices sequentially")
        print("="*60)
        
        for i, host in enumerate(devices, 1):
            print(f"[{i}/{len(devices)}] Processing {host}...")
            success = self.process_single_device(host)
            status = "✓" if success else "✗"
            print(f"[{i}/{len(devices)}] {status} {host}")
    
    def process(self, parallel=True):
        """Main processing function."""
        # Load devices
        devices = self.load_devices()
        if not devices:
            return
        
        # Clear any previous data
        self.all_collected_data = {}
        self.device_results = []
        self.failed_devices = []
        self.credentials_updated = False
        
        # Process devices
        if parallel:
            self.process_devices_parallel(devices)
        else:
            self.process_devices_sequential(devices)
        
        # Print summary
        print("\n" + "="*60)
        print("SUMMARY")
        print("="*60)
        
        success_count = len([r for r in self.device_results if r['status'] == 'success'])
        print(f"Successful: {success_count}/{len(devices)}")
        
        if self.failed_devices:
            print(f"Failed: {len(self.failed_devices)}")
            for device in self.failed_devices:
                print(f"  - {device}")
        
        # Save consolidated output
        self.save_consolidated_output()
        
        print(f"\nDevice outputs: {self.output_dir}/<hostname>/")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Simple parallel network collector with device auto-detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Setup:
  1. Create devices.txt:
     192.168.1.1
     192.168.1.2
     
  2. Create command lists:
     cisco_ios_commands.txt
     cisco_nxos_commands.txt
     arista_eos_commands.txt
     
Examples:
  %(prog)s -u admin -p password                    # Parallel (default)
  %(prog)s -u admin -p password --workers 10       # More parallel workers
  %(prog)s -u admin -p password --sequential       # Disable parallel
        """
    )
    
    parser.add_argument('-u', '--username', required=True, help='Username')
    parser.add_argument('-p', '--password', required=True, help='Password')
    parser.add_argument('-e', '--enable', help='Enable password (defaults to login password)')
    parser.add_argument('-f', '--file', default='devices.txt', help='Device file')
    parser.add_argument('--workers', type=int, default=5, help='Parallel workers (default: 5)')
    parser.add_argument('--sequential', action='store_true', help='Disable parallel processing')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create collector
    collector = SimpleParallelCollector(
        username=args.username,
        password=args.password,
        enable_password=args.enable,
        max_workers=args.workers
    )
    
    # Override device file if specified
    if args.file != 'devices.txt':
        collector.load_devices = lambda: collector.load_devices(args.file)
    
    # Process devices
    collector.process(parallel=not args.sequential)


if __name__ == "__main__":
    main()
