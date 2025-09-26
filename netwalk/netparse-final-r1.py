#!/usr/bin/env python3
"""
netparse_parallel.py

Simple parallel network automation that:
- Connects and immediately sets terminal length 0
- Detects device type from "show version" 
- Runs appropriate commands for each device type
- Processes devices in parallel for speed
- Automatically tries backup credentials if primary fails
- Keeps everything simple and reliable

Usage:
    python netparse_parallel.py                      # Uses embedded credentials
    python netparse_parallel.py --workers 10         # More parallel workers
    python netparse_parallel.py --sequential         # Disable parallel
    python netparse_parallel.py -u admin -p password # Override embedded credentials
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
from threading import Lock
from netmiko import ConnectHandler
from netmiko.exceptions import AuthenticationException, NetmikoAuthenticationException
from ntc_templates.parse import parse_output

# =============================================================================
# EMBEDDED CREDENTIALS CONFIGURATION
# =============================================================================
# Primary credentials (tried first)
PRIMARY_USERNAME = "admin"
PRIMARY_PASSWORD = "cisco123"
PRIMARY_ENABLE = "cisco123"  # Enable password (same as login if not specified)

# Backup credentials (tried if primary fails)
BACKUP_USERNAME = "netadmin"
BACKUP_PASSWORD = "backup123"
BACKUP_ENABLE = "backup123"

# =============================================================================

# Setup logging to both console and file
log_dir = Path("logs")
log_dir.mkdir(exist_ok=True)
log_filename = log_dir / f"netparse_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

# Configure logging with both handlers
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)  # Capture all levels

# Console handler (INFO and above)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(console_formatter)

# File handler (DEBUG and above - captures everything)
file_handler = logging.FileHandler(log_filename, mode='w', encoding='utf-8')
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter('%(asctime)s - [%(levelname)8s] - %(funcName)20s() - %(message)s')
file_handler.setFormatter(file_formatter)

# Add both handlers
logger.addHandler(console_handler)
logger.addHandler(file_handler)

# Log the startup
logger.info(f"Starting netparse_parallel.py - Log file: {log_filename}")
logger.info(f"Python version: {sys.version}")
logger.info("="*70)


class SimpleParallelCollector:
    """
    Simple parallel network collector with smart device detection.
    """
    
    def __init__(self, username=None, password=None, enable_password=None, max_workers=5):
        """Initialize with credentials."""
        # Use provided credentials or fall back to embedded ones
        self.primary_username = username or PRIMARY_USERNAME
        self.primary_password = password or PRIMARY_PASSWORD
        self.primary_enable = enable_password or (password if password else PRIMARY_ENABLE)
        
        # Backup credentials always use embedded values
        self.backup_username = BACKUP_USERNAME
        self.backup_password = BACKUP_PASSWORD
        self.backup_enable = BACKUP_ENABLE
        
        self.max_workers = max_workers
        
        # Thread-safe storage
        self.all_collected_data = {}
        self.device_results = []
        self.failed_devices = []
        self.data_lock = Lock()
        
        # Track which credentials worked for each device
        self.device_credentials = {}
        
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
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        devices.append(line)
                        logger.debug(f"Loaded device from line {line_num}: {line}")
            
            logger.info(f"Loaded {len(devices)} devices from {filename}")
            if devices:
                logger.debug(f"Device list: {', '.join(devices)}")
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
                logger.info(f"Loading commands from {filepath}")
                with open(filepath, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            commands.append(line)
                            logger.debug(f"  Command {line_num}: {line}")
                logger.info(f"Loaded {len(commands)} commands for {device_type}")
                return commands
        
        # Default commands if no file found
        logger.warning(f"No command list found for {device_type} in {[str(p) for p in search_paths]}")
        logger.warning(f"Using default commands: show version, show inventory")
        return ['show version', 'show inventory']
    
    def connect_to_device(self, host):
        """
        Connect to device with proper sequence:
        1. Connect (try primary credentials, then backup if needed)
        2. Set terminal length 0 (FIRST THING)
        3. Run show version to detect type
        4. Get hostname
        5. Create folder with hostname_IP format
        """
        # Try primary credentials first
        credentials_to_try = [
            ('primary', self.primary_username, self.primary_password, self.primary_enable),
            ('backup', self.backup_username, self.backup_password, self.backup_enable)
        ]
        
        connection = None
        successful_creds = None
        
        for cred_type, username, password, enable in credentials_to_try:
            try:
                # Start with generic cisco_ios for initial connection
                device = {
                    'device_type': 'cisco_ios',
                    'host': host,
                    'username': username,
                    'password': password,
                    'secret': enable,
                    'timeout': 30,
                    'global_delay_factor': 2,
                }
                
                logger.info(f"Connecting to {host} with {cred_type} credentials...")
                
                try:
                    connection = ConnectHandler(**device)
                    successful_creds = cred_type
                    logger.info(f"Successfully connected to {host} using {cred_type} credentials")
                    
                    # Store which credentials worked
                    self.device_credentials[host] = cred_type
                    break  # Success, exit the credential loop
                    
                except (AuthenticationException, NetmikoAuthenticationException) as auth_error:
                    logger.warning(f"Authentication failed for {host} with {cred_type} credentials: {auth_error}")
                    if cred_type == 'backup':
                        # Both primary and backup failed
                        logger.error(f"All credential sets failed for {host}")
                        return None, None, None, None
                    # Try backup credentials next
                    continue
                    
            except Exception as e:
                logger.error(f"Failed to connect to {host} with {cred_type} credentials: {e}")
                if cred_type == 'backup':
                    # Both attempts failed
                    return None, None, None, None
                continue
        
        if not connection:
            logger.error(f"Could not establish connection to {host}")
            return None, None, None, None
        
        try:
            # STEP 1: Set terminal length 0 (FIRST THING WE DO)
            try:
                output = connection.send_command("terminal length 0")
                logger.debug(f"Set terminal length 0 for {host}: {output[:100] if output else 'OK'}")
            except Exception as e:
                # Some devices might not support it, continue anyway
                logger.debug(f"Could not set terminal length for {host}: {e}")
            
            # STEP 2: Get show version to detect device type
            try:
                show_version_output = connection.send_command("show version")
            except Exception as e:
                logger.error(f"Failed to get show version from {host}: {e}")
                connection.disconnect()
                return None, None, None, None
            
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
            
            # Create device folder with hostname and IP
            # Format: hostname_IP (e.g., router1_192.168.1.1)
            safe_host = host.replace(':', '-')  # For IPv6 addresses
            folder_name = f"{hostname}_{safe_host}"
            device_folder = self.output_dir / folder_name
            device_folder.mkdir(exist_ok=True)
            
            logger.info(f"Connected to {hostname} ({device_type}) at {host}")
            
            # Save the show version output we already collected
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            version_file = device_folder / f"show_version_{timestamp}.txt"
            version_file.write_text(show_version_output)
            
            # Return connection, hostname, device_type, and folder_name for consistency
            return connection, hostname, device_type, folder_name
            
        except Exception as e:
            logger.error(f"Failed to connect to {host}: {e}")
            return None, None, None, None
    
    def collect_and_parse(self, connection, command, hostname, device_type, folder_name):
        """Send command and parse with NTC templates."""
        try:
            logger.info(f"Sending '{command}' to {hostname}")
            raw_output = connection.send_command(command, delay_factor=2)
            
            # Log output size for debugging
            logger.debug(f"Received {len(raw_output)} bytes from '{command}' on {hostname}")
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            cmd_safe = command.replace(" ", "_").replace("/", "-")
            
            device_folder = self.output_dir / folder_name
            
            # Save raw output
            raw_file = device_folder / f"{cmd_safe}_{timestamp}.txt"
            raw_file.write_text(raw_output)
            logger.debug(f"Saved raw output to {raw_file} ({len(raw_output)} bytes)")
            
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
                    logger.debug(f"Saved parsed JSON to {json_file}")
                    
                    # Save CSV
                    csv_file = device_folder / f"{cmd_safe}_{timestamp}.csv"
                    with open(csv_file, 'w', newline='') as f:
                        writer = csv.DictWriter(f, fieldnames=parsed[0].keys())
                        writer.writeheader()
                        writer.writerows(parsed)
                    logger.debug(f"Saved CSV to {csv_file}")
                
                logger.info(f"Parsed {len(parsed)} entries from '{command}' on {hostname}")
                return parsed
                
            except Exception as e:
                logger.debug(f"NTC parsing not available for '{command}' on {device_type} ({hostname}): {e}")
                # Return unparsed data
                return [{'_hostname': hostname, '_device_type': device_type, 
                        '_command': command, '_timestamp': timestamp}]
                
        except Exception as e:
            logger.error(f"Error collecting '{command}' from {hostname} ({device_type}): {e}")
            return []
    
    def process_single_device(self, host):
        """Process a single device."""
        # Connect to device
        connection, hostname, device_type, folder_name = self.connect_to_device(host)
        
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
                    
                data = self.collect_and_parse(connection, command, hostname, device_type, folder_name)
                
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
                    'commands_run': device_command_count,
                    'folder': folder_name,
                    'credentials_used': self.device_credentials.get(host, 'unknown')
                })
            
            logger.info(f"Successfully processed {hostname} at {host} (used {self.device_credentials.get(host, 'unknown')} credentials)")
            return True
            
        except Exception as e:
            logger.error(f"Error processing {hostname} ({device_type}) at {host}: {e}")
            with self.data_lock:
                self.failed_devices.append(f"{hostname}_{host} ({device_type})")
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
            logger.warning("No data collected from any device to consolidate")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        print(f"\nConsolidated outputs:")
        logger.info("Saving consolidated outputs...")
        
        for command, data in self.all_collected_data.items():
            if data:
                cmd_safe = command.replace(" ", "_").replace("/", "-")
                
                # Save CSV - handle different field names from different device types
                csv_file = self.output_dir / "consolidated" / f"{cmd_safe}_{timestamp}.csv"
                try:
                    # Collect all unique fieldnames across all entries
                    all_fieldnames = set()
                    for entry in data:
                        all_fieldnames.update(entry.keys())
                    
                    # Sort fieldnames for consistent column order
                    # Put metadata fields first
                    fieldnames = []
                    for field in ['_hostname', '_device_type', '_command', '_timestamp']:
                        if field in all_fieldnames:
                            fieldnames.append(field)
                            all_fieldnames.remove(field)
                    # Add remaining fields alphabetically
                    fieldnames.extend(sorted(all_fieldnames))
                    
                    with open(csv_file, 'w', newline='') as f:
                        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                        writer.writeheader()
                        writer.writerows(data)
                    
                    # Get device type breakdown for reporting
                    device_types = {}
                    for entry in data:
                        dt = entry.get('_device_type', 'unknown')
                        device_types[dt] = device_types.get(dt, 0) + 1
                    
                    type_summary = ', '.join([f"{dt}:{cnt}" for dt, cnt in device_types.items()])
                    print(f"  {command}: {csv_file} ({len(data)} entries) [{type_summary}]")
                    logger.info(f"Saved consolidated CSV for '{command}': {csv_file} - {len(data)} entries from {type_summary}")
                    
                except Exception as e:
                    # Enhanced error message with device details
                    problem_devices = []
                    for entry in data[:5]:  # Check first 5 entries for debugging
                        hostname = entry.get('_hostname', 'unknown')
                        device_type = entry.get('_device_type', 'unknown')
                        problem_devices.append(f"{hostname}({device_type})")
                    
                    devices_str = ', '.join(problem_devices)
                    logger.error(f"Failed to save CSV for '{command}': {e}")
                    logger.error(f"  Problem may be from devices: {devices_str}")
                    logger.error(f"  Unique field names found: {list(all_fieldnames)[:10]}...")
                    print(f"  ⚠️  {command}: CSV save failed - check log for details")
                
                # Save JSON with metadata
                json_file = self.output_dir / "consolidated" / f"{cmd_safe}_{timestamp}.json"
                try:
                    # Group by device type for better analysis
                    devices_by_type = {}
                    for entry in data:
                        dt = entry.get('_device_type', 'unknown')
                        hn = entry.get('_hostname', 'unknown')
                        if dt not in devices_by_type:
                            devices_by_type[dt] = []
                        if hn not in devices_by_type[dt]:
                            devices_by_type[dt].append(hn)
                    
                    # Count credential usage
                    cred_stats = {
                        'primary': sum(1 for d in self.device_results if d.get('credentials_used') == 'primary'),
                        'backup': sum(1 for d in self.device_results if d.get('credentials_used') == 'backup'),
                        'failed': sum(1 for d in self.device_results if d['status'] == 'failed')
                    }
                    
                    with open(json_file, 'w') as f:
                        json.dump({
                            'command': command,
                            'timestamp': timestamp,
                            'total_entries': len(data),
                            'devices_by_type': devices_by_type,
                            'credential_stats': cred_stats,
                            'all_devices': list(set(d.get('_hostname', 'unknown') for d in data)),
                            'data': data
                        }, f, indent=2, default=str)
                    logger.info(f"Saved consolidated JSON for '{command}': {json_file}")
                except Exception as e:
                    # Enhanced error for JSON too
                    problem_devices = []
                    for entry in data[:3]:
                        hostname = entry.get('_hostname', 'unknown')
                        device_type = entry.get('_device_type', 'unknown')
                        problem_devices.append(f"{hostname}({device_type})")
                    
                    devices_str = ', '.join(problem_devices)
                    logger.error(f"Failed to save JSON for '{command}': {e}")
                    logger.error(f"  Devices involved: {devices_str}")
    
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
            logger.error("No devices to process - exiting")
            return
        
        # Clear any previous data
        self.all_collected_data = {}
        self.device_results = []
        self.failed_devices = []
        self.device_credentials = {}
        
        logger.info(f"Starting device processing - Mode: {'PARALLEL' if parallel else 'SEQUENTIAL'}")
        
        # Process devices
        if parallel:
            self.process_devices_parallel(devices)
        else:
            self.process_devices_sequential(devices)
        
        # Print and log summary
        print("\n" + "="*60)
        print("SUMMARY")
        print("="*60)
        
        logger.info("="*70)
        logger.info("FINAL SUMMARY")
        logger.info("="*70)
        
        success_count = len([r for r in self.device_results if r['status'] == 'success'])
        print(f"Successful: {success_count}/{len(devices)}")
        logger.info(f"Devices processed successfully: {success_count}/{len(devices)}")
        
        # Show credential usage
        if self.device_credentials:
            primary_count = sum(1 for c in self.device_credentials.values() if c == 'primary')
            backup_count = sum(1 for c in self.device_credentials.values() if c == 'backup')
            print(f"Credentials: Primary={primary_count}, Backup={backup_count}")
            logger.info(f"Credential usage - Primary: {primary_count}, Backup: {backup_count}")
            
            # Log which devices used backup credentials
            backup_devices = [host for host, cred in self.device_credentials.items() if cred == 'backup']
            if backup_devices:
                logger.info(f"Devices that required backup credentials: {', '.join(backup_devices)}")
        
        if self.failed_devices:
            print(f"Failed: {len(self.failed_devices)}")
            logger.warning(f"Failed devices: {len(self.failed_devices)}")
            for device in self.failed_devices:
                print(f"  - {device}")
                logger.warning(f"  Failed device: {device}")
        
        # Save consolidated output
        self.save_consolidated_output()
        
        print(f"\nDevice outputs: {self.output_dir}/<hostname>_<IP>/")
        print(f"Example: {self.output_dir}/router1_192.168.1.1/")
        
        logger.info(f"Device outputs saved to: {self.output_dir}")
        logger.info("Processing complete")


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
     
  3. Update embedded credentials in the script:
     PRIMARY_USERNAME = "admin"
     PRIMARY_PASSWORD = "cisco123"
     BACKUP_USERNAME = "netadmin"
     BACKUP_PASSWORD = "backup123"
     
Examples:
  %(prog)s                                  # Use embedded credentials
  %(prog)s --workers 10                     # More parallel workers
  %(prog)s --sequential                     # Disable parallel
  %(prog)s -u admin -p custom_pass         # Override primary credentials
  %(prog)s --debug                          # Enable debug logging
        """
    )
    
    parser.add_argument('-u', '--username', help='Override primary username')
    parser.add_argument('-p', '--password', help='Override primary password')
    parser.add_argument('-e', '--enable', help='Override enable password')
    parser.add_argument('-f', '--file', default='devices.txt', help='Device file (default: devices.txt)')
    parser.add_argument('--workers', type=int, default=5, help='Parallel workers (default: 5)')
    parser.add_argument('--sequential', action='store_true', help='Disable parallel processing')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging to console')
    
    args = parser.parse_args()
    
    # Adjust console logging level if debug flag is set
    if args.debug:
        console_handler.setLevel(logging.DEBUG)
        logger.info("Debug mode enabled - verbose console output active")
    
    # Log the configuration
    logger.info(f"Configuration: workers={args.workers}, mode={'sequential' if args.sequential else 'parallel'}")
    logger.info(f"Device file: {args.file}")
    
    # Show which credentials will be used
    if args.username or args.password:
        print(f"Using override credentials: username={args.username or 'not specified'}")
        logger.info(f"Using override credentials: username={args.username or 'not specified'}")
    else:
        print(f"Using embedded credentials (Primary: {PRIMARY_USERNAME}, Backup: {BACKUP_USERNAME})")
        logger.info(f"Using embedded credentials (Primary: {PRIMARY_USERNAME}, Backup: {BACKUP_USERNAME})")
    
    print(f"📝 Log file: {log_filename}")
    
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
    start_time = datetime.now()
    collector.process(parallel=not args.sequential)
    end_time = datetime.now()
    
    # Log final summary
    duration = (end_time - start_time).total_seconds()
    logger.info("="*70)
    logger.info(f"Script completed in {duration:.2f} seconds")
    logger.info(f"Log file saved: {log_filename}")
    print(f"\n📁 Complete log saved: {log_filename}")
    print(f"   Tip: Use 'grep ERROR {log_filename}' to find all errors")
    print(f"   Tip: Use 'grep \"Authentication failed\" {log_filename}' to find auth issues")


if __name__ == "__main__":
    main()
