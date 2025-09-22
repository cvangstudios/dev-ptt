#!/usr/bin/env python3
"""
Network Device Collector - Optimized Single Connection Version
Removes double login by eliminating unnecessary autodetect
"""

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
from ntc_templates.parse import parse_output
import csv
from datetime import datetime
from pathlib import Path
import re
import json
import socket

# EDIT THESE
USERNAME = "admin"
PASSWORD = "your_password"
ENABLE_PASSWORD = ""  # Leave empty if same as PASSWORD or not needed
DEVICE_LIST = "devices.txt"  # One IP per line

# Global CSV file creation
CREATE_GLOBAL_CSV = True

def collect_from_device(ip, username, password, enable_password=None):
    """Collect data from one device - OPTIMIZED VERSION"""
    print(f"\nConnecting to {ip}...")
    
    # OPTIMIZATION: Connect directly with cisco_ios as default
    # We'll determine the actual platform from "show version" anyway
    device = {
        'device_type': 'cisco_ios',  # Default type - works for initial connection
        'ip': ip,
        'username': username,
        'password': password,
        'timeout': 30,
    }
    
    if enable_password:
        device['secret'] = enable_password
    elif password:
        device['secret'] = password
    
    conn = None
    try:
        # SINGLE CONNECTION - no autodetect!
        print(f"  Connecting with default type (cisco_ios)...")
        conn = ConnectHandler(**device)
        
        # Enter enable mode if needed
        if not conn.check_enable_mode():
            try:
                conn.enable()
            except:
                pass
        
        hostname = conn.find_prompt().strip('#>')
        print(f"  Connected to {hostname}")
        
        # Create output folder
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_hostname = re.sub(r'[^\w\-_]', '_', hostname)
        output_dir = Path(f"network_data/{safe_hostname}_{ip}_{timestamp}")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"  Output directory: {output_dir}")
        print(f"  Absolute path: {output_dir.absolute()}")
        
        # Pre-create all JSON files to ensure they exist
        json_files_to_create = [
            'version_data.json',
            'cdp_data.json', 
            'lldp_data.json',
            'mac_data.json',
            'arp_data.json',
            'vlan_data.json',
            'commands_used.json',
            'collection_summary.json'
        ]
        
        print(f"  Creating JSON files...")
        for jf in json_files_to_create:
            json_path = output_dir / jf
            try:
                with open(str(json_path), 'w') as f:
                    json.dump([], f)  # Start with empty array
            except Exception as e:
                print(f"    FAILED to create {jf}: {e}")
        
        # Get version to determine platform (this is our ONLY platform detection)
        print("  Collecting version info to determine platform...")
        version_output = conn.send_command('show version')
        with open(str(output_dir / 'version_raw.txt'), 'w') as f:
            f.write(version_output)
        
        # Determine NTC platform from version output
        if 'Arista' in version_output or 'EOS' in version_output:
            platform = 'arista_eos'
            # For Arista, we might need to update the connection type
            # But often cisco_ios commands work fine
        elif 'NX-OS' in version_output or 'Nexus' in version_output:
            platform = 'cisco_nxos'
            # NX-OS is similar enough to IOS that basic commands work
        else:
            platform = 'cisco_ios'
            # Already using cisco_ios, so no change needed
        
        print(f"  Platform detected: {platform}")
        
        # Parse version with NTC and save JSON
        version_data = []
        version_json_file = str(output_dir / 'version_data.json')
        
        try:
            parsed = parse_output(platform=platform, command='show version', data=version_output)
        except Exception as e:
            print(f"    Version parsing error: {e}")
            parsed = None
        
        # Always write version JSON
        with open(version_json_file, 'w') as f:
            if parsed:
                json.dump(parsed, f, indent=2, default=str)
                version_data = parsed
                print(f"    Version info parsed - saved to version_data.json")
            else:
                json.dump([], f)
                print(f"    No version data parsed - empty JSON saved")
        
        # Define commands based on platform (from NTC template filenames)
        if platform == 'arista_eos':
            commands = {
                'version': 'show version',
                'cdp': None,  # Arista doesn't have CDP template
                'lldp': 'show lldp neighbors detail',
                'mac': 'show mac address-table',
                'arp': 'show arp',
                'vlan': 'show vlan',
                'management': 'show interfaces management 1'
            }
        elif platform == 'cisco_nxos':
            commands = {
                'version': 'show version',
                'cdp': 'show cdp neighbors detail',
                'lldp': 'show lldp neighbors detail',
                'mac': 'show mac address-table',
                'arp': 'show ip arp',
                'vlan': 'show vlan',
                'management': 'show interfaces mgmt0'
            }
        else:  # cisco_ios
            commands = {
                'version': 'show version',
                'cdp': 'show cdp neighbors detail',
                'lldp': 'show lldp neighbors detail',
                'mac': 'show mac-address-table',  # Note the dash!
                'arp': 'show ip arp',
                'vlan': 'show vlan',
                'management': 'show interfaces vlan1'  # IOS often uses Vlan1 for mgmt
            }
        
        # All data collections
        all_data = {
            'hostname': hostname,
            'ip': ip,
            'platform': platform,
            'version_data': version_data,
            'cdp_data': [],
            'lldp_data': [],
            'mac_data': [],
            'arp_data': [],
            'vlan_data': [],
            'management_data': [],
            'correlated_data': []  # Will hold MAC-ARP correlations
        }
        
        # Save commands used for debugging (overwrite the pre-created empty file)
        commands_used = {
            'platform': platform,
            'commands': commands
        }
        with open(str(output_dir / 'commands_used.json'), 'w') as f:
            json.dump(commands_used, f, indent=2, default=str)
            print(f"  Commands saved to commands_used.json")
        
        # ========== CDP ==========
        print(f"  Collecting CDP neighbors...")
        
        # Always create the JSON file first
        cdp_json_file = str(output_dir / 'cdp_data.json')
        
        if commands['cdp']:
            try:
                cdp_output = conn.send_command(commands['cdp'])
                with open(str(output_dir / 'cdp_raw.txt'), 'w') as f:
                    f.write(cdp_output)
                
                # Try parsing
                parsed = None
                try:
                    parsed = parse_output(platform=platform, command=commands['cdp'], data=cdp_output)
                except Exception as e:
                    print(f"    CDP parsing error: {e}")
                    parsed = None
                
                # Always write JSON
                with open(cdp_json_file, 'w') as f:
                    if parsed:
                        json.dump(parsed, f, indent=2, default=str)
                        all_data['cdp_data'] = parsed
                        print(f"    Found {len(parsed)} CDP neighbors - saved to cdp_data.json")
                    else:
                        json.dump([], f)
                        print(f"    No CDP data parsed - empty JSON saved")
                        
            except Exception as e:
                print(f"    CDP command failed: {e}")
                # Still write empty JSON
                with open(cdp_json_file, 'w') as f:
                    json.dump([], f)
        else:
            print(f"  CDP not supported on {platform}")
            with open(cdp_json_file, 'w') as f:
                json.dump([], f)
        
        # ========== LLDP ==========
        print(f"  Collecting LLDP neighbors...")
        
        # Always create the JSON file first
        lldp_json_file = str(output_dir / 'lldp_data.json')
        
        if commands['lldp']:
            try:
                lldp_output = conn.send_command(commands['lldp'])
                with open(str(output_dir / 'lldp_raw.txt'), 'w') as f:
                    f.write(lldp_output)
                
                # Try parsing
                parsed = None
                try:
                    parsed = parse_output(platform=platform, command=commands['lldp'], data=lldp_output)
                except Exception as e:
                    print(f"    LLDP parsing error: {e}")
                    parsed = None
                
                # Always write JSON
                with open(lldp_json_file, 'w') as f:
                    if parsed:
                        json.dump(parsed, f, indent=2, default=str)
                        all_data['lldp_data'] = parsed
                        print(f"    Found {len(parsed)} LLDP neighbors - saved to lldp_data.json")
                    else:
                        json.dump([], f)
                        print(f"    No LLDP data parsed - empty JSON saved")
                        
            except Exception as e:
                print(f"    LLDP command failed: {e}")
                # Still write empty JSON
                with open(lldp_json_file, 'w') as f:
                    json.dump([], f)
        else:
            print(f"  LLDP not supported on {platform}")
            with open(lldp_json_file, 'w') as f:
                json.dump([], f)
        
        # ========== MAC TABLE ==========
        print(f"  Collecting MAC address table...")
        mac_json_file = str(output_dir / 'mac_data.json')
        
        if commands['mac']:
            try:
                mac_output = conn.send_command(commands['mac'])
                with open(str(output_dir / 'mac_raw.txt'), 'w') as f:
                    f.write(mac_output)
                
                # Try parsing
                parsed = None
                try:
                    parsed = parse_output(platform=platform, command=commands['mac'], data=mac_output)
                except Exception as e:
                    print(f"    MAC parsing error: {e}")
                    parsed = None
                
                # Always write JSON
                with open(mac_json_file, 'w') as f:
                    if parsed:
                        json.dump(parsed, f, indent=2, default=str)
                        all_data['mac_data'] = parsed
                        print(f"    Found {len(parsed)} MAC entries - saved to mac_data.json")
                    else:
                        json.dump([], f)
                        print(f"    No MAC data parsed - empty JSON saved")
                        
            except Exception as e:
                print(f"    MAC command failed: {e}")
                with open(mac_json_file, 'w') as f:
                    json.dump([], f)
        
        # ========== ARP TABLE ==========
        print(f"  Collecting ARP table...")
        arp_json_file = str(output_dir / 'arp_data.json')
        
        if commands['arp']:
            try:
                arp_output = conn.send_command(commands['arp'])
                with open(str(output_dir / 'arp_raw.txt'), 'w') as f:
                    f.write(arp_output)
                
                # Try parsing
                parsed = None
                try:
                    parsed = parse_output(platform=platform, command=commands['arp'], data=arp_output)
                except Exception as e:
                    print(f"    ARP parsing error: {e}")
                    parsed = None
                
                # Always write JSON
                with open(arp_json_file, 'w') as f:
                    if parsed:
                        json.dump(parsed, f, indent=2, default=str)
                        all_data['arp_data'] = parsed
                        print(f"    Found {len(parsed)} ARP entries - saved to arp_data.json")
                    else:
                        json.dump([], f)
                        print(f"    No ARP data parsed - empty JSON saved")
                        
            except Exception as e:
                print(f"    ARP command failed: {e}")
                with open(arp_json_file, 'w') as f:
                    json.dump([], f)
        
        # ========== VLANs ==========
        print(f"  Collecting VLANs...")
        vlan_json_file = str(output_dir / 'vlan_data.json')
        
        if commands['vlan']:
            try:
                vlan_output = conn.send_command(commands['vlan'])
                with open(str(output_dir / 'vlan_raw.txt'), 'w') as f:
                    f.write(vlan_output)
                
                # Try parsing
                parsed = None
                try:
                    parsed = parse_output(platform=platform, command=commands['vlan'], data=vlan_output)
                except Exception as e:
                    print(f"    VLAN parsing error: {e}")
                    parsed = None
                
                # Always write JSON
                with open(vlan_json_file, 'w') as f:
                    if parsed:
                        json.dump(parsed, f, indent=2, default=str)
                        all_data['vlan_data'] = parsed
                        print(f"    Found {len(parsed)} VLANs - saved to vlan_data.json")
                    else:
                        json.dump([], f)
                        print(f"    No VLAN data parsed - empty JSON saved")
                        
            except Exception as e:
                print(f"    VLAN command failed: {e}")
                with open(vlan_json_file, 'w') as f:
                    json.dump([], f)
        
        # ========== MANAGEMENT INTERFACE ==========
        print(f"  Collecting management interface...")
        mgmt_json_file = str(output_dir / 'management_data.json')
        
        if commands.get('management'):
            print(f"    Command: {commands['management']}")
            try:
                mgmt_output = conn.send_command(commands['management'])
                with open(str(output_dir / 'management_raw.txt'), 'w') as f:
                    f.write(mgmt_output)
                
                # Try parsing with show interfaces template
                parsed = None
                try:
                    # Use "show interfaces" template (plural)
                    parsed = parse_output(platform=platform, command='show interfaces', data=mgmt_output)
                except Exception as e:
                    print(f"    Management parsing error: {e}")
                    parsed = None
                
                # Always write JSON
                with open(mgmt_json_file, 'w') as f:
                    if parsed:
                        json.dump(parsed, f, indent=2, default=str)
                        all_data['management_data'] = parsed
                        print(f"    Found {len(parsed) if isinstance(parsed, list) else 1} management interface(s) - saved to management_data.json")
                    else:
                        json.dump([], f)
                        print(f"    No management data parsed - empty JSON saved")
                        
            except Exception as e:
                print(f"    Management command failed: {e}")
                with open(mgmt_json_file, 'w') as f:
                    json.dump([], f)
        else:
            print(f"    Management interface command not defined for {platform}")
            with open(mgmt_json_file, 'w') as f:
                json.dump([], f)
        
        # ========== CORRELATE MAC AND ARP ==========
        print("  Correlating MAC and ARP tables...")
        correlated_data = []
        
        # Debug: Show what fields we have
        if all_data['mac_data']:
            print(f"    MAC data sample fields: {list(all_data['mac_data'][0].keys()) if all_data['mac_data'] else 'None'}")
        if all_data['arp_data']:
            print(f"    ARP data sample fields: {list(all_data['arp_data'][0].keys()) if all_data['arp_data'] else 'None'}")
        
        if all_data['mac_data'] and all_data['arp_data']:
            # Create ARP lookup dictionary (MAC -> IP)
            arp_lookup = {}
            for arp_entry in all_data['arp_data']:
                # Try multiple field names for MAC and IP
                mac = (arp_entry.get('mac_address') or 
                       arp_entry.get('mac') or 
                       arp_entry.get('hardware_address') or 
                       arp_entry.get('hw_address', ''))
                       
                ip = (arp_entry.get('ip_address') or 
                      arp_entry.get('address') or 
                      arp_entry.get('ip') or 
                      arp_entry.get('network_address', ''))
                
                if mac and ip:
                    # Normalize MAC for comparison (remove . : -)
                    norm_mac = mac.lower().replace(':', '').replace('.', '').replace('-', '')
                    arp_lookup[norm_mac] = {
                        'ip_address': ip,
                        'arp_interface': arp_entry.get('interface', arp_entry.get('port', ''))
                    }
            
            print(f"    Built ARP lookup with {len(arp_lookup)} entries")
            
            # Match MAC entries with ARP
            for mac_entry in all_data['mac_data']:
                # Try multiple field names for MAC address
                mac = (mac_entry.get('mac_address') or 
                       mac_entry.get('destination_address') or 
                       mac_entry.get('mac') or 
                       mac_entry.get('hw_address', ''))
                
                if mac:
                    # Normalize MAC for comparison
                    norm_mac = mac.lower().replace(':', '').replace('.', '').replace('-', '')
                    
                    # Look up IP from ARP table
                    arp_info = arp_lookup.get(norm_mac, {})
                    
                    # Create correlated entry - handle various field names
                    correlated_entry = {
                        'local_device': hostname,
                        'ip_address': arp_info.get('ip_address', ''),
                        'mac_address': mac,
                        'vlan': (mac_entry.get('vlan') or 
                                mac_entry.get('vlan_id') or 
                                mac_entry.get('vlan_number', '')),
                        'mac_interface': (mac_entry.get('ports') or 
                                         mac_entry.get('destination_port') or 
                                         mac_entry.get('interface') or 
                                         mac_entry.get('port', '')),
                        'arp_interface': arp_info.get('arp_interface', ''),
                        'type': mac_entry.get('type', mac_entry.get('mac_type', ''))
                    }
                    
                    correlated_data.append(correlated_entry)
            
            print(f"    Correlated {len(correlated_data)} MAC entries with ARP")
            all_data['correlated_data'] = correlated_data
        else:
            if not all_data['mac_data']:
                print(f"    No MAC data available for correlation")
            if not all_data['arp_data']:
                print(f"    No ARP data available for correlation")
            print(f"    No correlation possible - need both MAC and ARP data")
        
        # ALWAYS save correlation data to JSON (even if empty)
        with open(str(output_dir / 'mac_arp_correlation.json'), 'w') as f:
            json.dump(correlated_data, f, indent=2, default=str)
        
        # ALWAYS save correlation CSV (even if empty)
        with open(str(output_dir / 'mac_arp_correlation.csv'), 'w', newline='') as f:
            fieldnames = ['local_device', 'ip_address', 'mac_address', 'vlan', 'mac_interface', 'arp_interface', 'type']
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            if correlated_data:
                writer.writerows(correlated_data)
                print(f"    Saved {len(correlated_data)} correlations to CSV")
            else:
                print(f"    Saved empty correlation CSV")
        
        # ========== CREATE CSV FILES ==========
        # Version CSV
        if version_data:
            with open(str(output_dir / 'version_info.csv'), 'w', newline='') as f:
                # Handle both list and dict returns from NTC
                if isinstance(version_data, list):
                    data = version_data.copy()
                else:
                    data = [version_data]
                
                # Add local_device field
                for item in data:
                    item['local_device'] = hostname
                
                # Get all keys from first item
                fieldnames = ['local_device'] + [k for k in data[0].keys() if k != 'local_device']
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(data)
                print(f"    Version CSV created")
        
        # CDP CSV
        if all_data['cdp_data']:
            with open(str(output_dir / 'cdp_neighbors.csv'), 'w', newline='') as f:
                data = all_data['cdp_data'].copy()
                # Add local_device field
                for item in data:
                    item['local_device'] = hostname
                
                # Get all keys from first item
                fieldnames = ['local_device'] + [k for k in data[0].keys() if k != 'local_device']
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(data)
        
        # LLDP CSV
        if all_data['lldp_data']:
            with open(str(output_dir / 'lldp_neighbors.csv'), 'w', newline='') as f:
                data = all_data['lldp_data'].copy()
                for item in data:
                    item['local_device'] = hostname
                
                fieldnames = ['local_device'] + [k for k in data[0].keys() if k != 'local_device']
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(data)
        
        # MAC CSV
        if all_data['mac_data']:
            with open(str(output_dir / 'mac_table.csv'), 'w', newline='') as f:
                data = all_data['mac_data'].copy()
                for item in data:
                    item['local_device'] = hostname
                
                fieldnames = ['local_device'] + [k for k in data[0].keys() if k != 'local_device']
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(data)
        
        # ARP CSV
        if all_data['arp_data']:
            with open(str(output_dir / 'arp_table.csv'), 'w', newline='') as f:
                data = all_data['arp_data'].copy()
                for item in data:
                    item['local_device'] = hostname
                
                fieldnames = ['local_device'] + [k for k in data[0].keys() if k != 'local_device']
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(data)
        
        # VLAN CSV
        if all_data['vlan_data']:
            with open(str(output_dir / 'vlan_table.csv'), 'w', newline='') as f:
                data = all_data['vlan_data'].copy()
                for item in data:
                    item['local_device'] = hostname
                
                fieldnames = ['local_device'] + [k for k in data[0].keys() if k != 'local_device']
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(data)
        
        # Management Interface CSV
        if all_data['management_data']:
            with open(str(output_dir / 'management_interface.csv'), 'w', newline='') as f:
                # Handle both list and dict returns
                if isinstance(all_data['management_data'], list):
                    data = all_data['management_data'].copy()
                else:
                    data = [all_data['management_data']]
                
                for item in data:
                    item['local_device'] = hostname
                
                fieldnames = ['local_device'] + [k for k in data[0].keys() if k != 'local_device']
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(data)
                print(f"    Management interface CSV created")
        
        # ========== HELPER FUNCTIONS FOR NEIGHBOR PROCESSING ==========
        def normalize_interface(interface_name):
            """Normalize interface names - convert Eth to Ethernet"""
            if interface_name:
                # Check if it starts with "Eth" but NOT "Ethernet"
                if interface_name.lower().startswith('eth') and not interface_name.lower().startswith('ethernet'):
                    # Replace "Eth" with "Ethernet" (case-insensitive)
                    return 'Ethernet' + interface_name[3:]
            return interface_name
        
        def clean_hostname(hostname_to_clean):
            """Remove domain names from hostname to get just the base hostname"""
            if not hostname_to_clean:
                return hostname_to_clean
            
            # CONFIGURE YOUR DOMAINS HERE
            # Add or remove domain patterns as needed for your environment
            # Examples shown below - uncomment and modify as needed
            
            domains_to_remove = [
                # '.example.com',
                # '.lab.local', 
                # '.corp.company.net',
                # '.internal.org',
                # '.mydomain.com',
            ]
            
            # Remove any of the configured domains
            cleaned = hostname_to_clean
            for domain in domains_to_remove:
                if domain in cleaned.lower():
                    # Case-insensitive removal
                    idx = cleaned.lower().find(domain)
                    if idx > 0:
                        cleaned = cleaned[:idx]
                        break
            
            # Alternative method: Just take everything before the first dot
            # Uncomment the line below if you prefer this simpler approach
            # cleaned = hostname_to_clean.split('.')[0] if '.' in hostname_to_clean else hostname_to_clean
            
            return cleaned
        
        # ========== Combined neighbors CSV (CDP + LLDP) ==========
        # Define standard fieldnames for all_neighbors.csv
        NEIGHBOR_FIELDNAMES = ['local_device', 'protocol', 'capabilities', 'chassis_id', 
                              'interface_ip', 'local_interface', 'mgmt_address', 
                              'neighbor_description', 'neighbor_interface', 'neighbor_name', 
                              'platform', 'vlan_id', 'unique_id']
        
        all_neighbors = []
        unique_ids_seen = set()
        duplicate_entries = []  # Track duplicates for logging
        
        # Process CDP data - explicit field mapping for each platform
        for item in all_data['cdp_data']:
            # CDP field mapping (same for IOS and NXOS)
            # CDP fields: neighbor_name, local_interface, neighbor_interface, chassis_id, 
            #             mgmt_address, neighbor_description, capabilities, vlan_id
            standardized_item = {
                'local_device': hostname,
                'protocol': 'CDP',
                'capabilities': item.get('capabilities', ''),
                'chassis_id': item.get('chassis_id', ''),
                'interface_ip': '',  # CDP doesn't have interface_ip
                'local_interface': normalize_interface(item.get('local_interface', '')),
                'mgmt_address': item.get('mgmt_address', ''),
                'neighbor_description': item.get('neighbor_description', ''),
                'neighbor_interface': normalize_interface(item.get('neighbor_interface', '')),
                'neighbor_name': clean_hostname(item.get('neighbor_name', '')),
                'platform': item.get('platform', ''),  # May or may not exist in CDP
                'vlan_id': item.get('vlan_id', ''),
                'unique_id': ''  # Will be set below
            }
            
            # Create unique_id
            unique_id = f"{hostname}_{standardized_item['local_interface']}_{standardized_item['neighbor_name']}_{standardized_item['neighbor_interface']}"
            standardized_item['unique_id'] = unique_id
            
            # Only add if we haven't seen this unique_id before
            if unique_id not in unique_ids_seen:
                unique_ids_seen.add(unique_id)
                all_neighbors.append(standardized_item)
            else:
                print(f"    Skipping duplicate CDP entry: {unique_id}")
                duplicate_entries.append({
                    'protocol': 'CDP',
                    'unique_id': unique_id,
                    'local_interface': standardized_item['local_interface'],
                    'neighbor_name': standardized_item['neighbor_name'],
                    'neighbor_interface': standardized_item['neighbor_interface']
                })
        
        # Process LLDP data - explicit field mapping based on platform
        for item in all_data['lldp_data']:
            if platform == 'arista_eos':
                # Arista LLDP field mapping
                # Arista LLDP fields: neighbor_name, chassis_id, mgmt_address, neighbor_description,
                #                     neighbor_interface, local_interface, neighbor_count, age
                standardized_item = {
                    'local_device': hostname,
                    'protocol': 'LLDP',
                    'capabilities': '',  # Arista LLDP doesn't have capabilities
                    'chassis_id': item.get('chassis_id', ''),
                    'interface_ip': '',  # Arista LLDP doesn't have interface_ip
                    'local_interface': normalize_interface(item.get('local_interface', '')),
                    'mgmt_address': item.get('mgmt_address', ''),
                    'neighbor_description': item.get('neighbor_description', ''),
                    'neighbor_interface': normalize_interface(item.get('neighbor_interface', '')),
                    'neighbor_name': clean_hostname(item.get('neighbor_name', '')),
                    'platform': '',  # Arista LLDP doesn't have platform
                    'vlan_id': '',  # Arista LLDP doesn't have vlan_id
                    'unique_id': ''  # Will be set below
                }
            elif platform == 'cisco_nxos':
                # NXOS LLDP field mapping
                # NXOS LLDP fields: chassis_id, neighbor_name, mgmt_address, platform, 
                #                   neighbor_interface, local_interface, neighbor_description, 
                #                   interface_ip, capabilities
                standardized_item = {
                    'local_device': hostname,
                    'protocol': 'LLDP',
                    'capabilities': item.get('capabilities', ''),
                    'chassis_id': item.get('chassis_id', ''),
                    'interface_ip': item.get('interface_ip', ''),
                    'local_interface': normalize_interface(item.get('local_interface', '')),
                    'mgmt_address': item.get('mgmt_address', ''),
                    'neighbor_description': item.get('neighbor_description', ''),
                    'neighbor_interface': normalize_interface(item.get('neighbor_interface', '')),
                    'neighbor_name': clean_hostname(item.get('neighbor_name', '')),
                    'platform': item.get('platform', ''),
                    'vlan_id': '',  # NXOS LLDP doesn't have vlan_id
                    'unique_id': ''  # Will be set below
                }
            else:
                # Default/Cisco IOS LLDP field mapping
                # Assuming similar to NXOS but may vary
                standardized_item = {
                    'local_device': hostname,
                    'protocol': 'LLDP',
                    'capabilities': item.get('capabilities', ''),
                    'chassis_id': item.get('chassis_id', ''),
                    'interface_ip': item.get('interface_ip', ''),
                    'local_interface': normalize_interface(item.get('local_interface', '')),
                    'mgmt_address': item.get('mgmt_address', ''),
                    'neighbor_description': item.get('neighbor_description', ''),
                    'neighbor_interface': normalize_interface(item.get('neighbor_interface', '')),
                    'neighbor_name': clean_hostname(item.get('neighbor_name', '')),
                    'platform': item.get('platform', ''),
                    'vlan_id': item.get('vlan_id', ''),
                    'unique_id': ''  # Will be set below
                }
            
            # Create unique_id
            unique_id = f"{hostname}_{standardized_item['local_interface']}_{standardized_item['neighbor_name']}_{standardized_item['neighbor_interface']}"
            standardized_item['unique_id'] = unique_id
            
            # Only add if we haven't seen this unique_id before
            if unique_id not in unique_ids_seen:
                unique_ids_seen.add(unique_id)
                all_neighbors.append(standardized_item)
            else:
                print(f"    Skipping duplicate LLDP entry: {unique_id}")
                duplicate_entries.append({
                    'protocol': 'LLDP',
                    'unique_id': unique_id,
                    'local_interface': standardized_item['local_interface'],
                    'neighbor_name': standardized_item['neighbor_name'],
                    'neighbor_interface': standardized_item['neighbor_interface']
                })
        
        # Write duplicate log file
        duplicate_log_file = output_dir / 'duplicate_neighbors.txt'
        with open(str(duplicate_log_file), 'w') as f:
            f.write(f"Duplicate Neighbors Log\n")
            f.write(f"Device: {hostname} ({ip})\n")
            f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*80 + "\n\n")
            
            if duplicate_entries:
                f.write(f"Found {len(duplicate_entries)} duplicate neighbor entries:\n\n")
                for dup in duplicate_entries:
                    f.write(f"Protocol: {dup['protocol']}\n")
                    f.write(f"Local Interface: {dup['local_interface']}\n")
                    f.write(f"Neighbor Name: {dup['neighbor_name']}\n")
                    f.write(f"Neighbor Interface: {dup['neighbor_interface']}\n")
                    f.write(f"Unique ID: {dup['unique_id']}\n")
                    f.write("-"*40 + "\n")
                f.write(f"\nSummary: Removed {len(duplicate_entries)} duplicates from all_neighbors.csv\n")
            else:
                f.write("No duplicate neighbors found.\n")
        
        print(f"    Duplicate log saved to duplicate_neighbors.txt")
        
        # Write all_neighbors.csv with fixed fieldnames
        with open(str(output_dir / 'all_neighbors.csv'), 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=NEIGHBOR_FIELDNAMES, extrasaction='ignore')
            writer.writeheader()
            if all_neighbors:
                writer.writerows(all_neighbors)
                print(f"    Created all_neighbors.csv with {len(all_neighbors)} entries (removed {len(duplicate_entries)} duplicates)")
            else:
                print(f"    Created empty all_neighbors.csv with headers")
        
        # ========== APPEND TO GLOBAL FILES ==========
        if CREATE_GLOBAL_CSV:
            print("  Updating global CSV files...")
            
            # Global Version table
            if version_data:
                global_version_file = Path('network_data/global_version_table.csv')
                global_version_file.parent.mkdir(exist_ok=True)
                file_exists = global_version_file.exists()
                
                # Handle both list and dict returns from NTC
                if isinstance(version_data, list):
                    version_global = version_data.copy()
                else:
                    version_global = [version_data]
                
                # Add local_device to each entry
                for item in version_global:
                    item['local_device'] = hostname
                
                with open(global_version_file, 'a', newline='') as f:
                    if file_exists:
                        # File exists, just append (no header)
                        fieldnames = ['local_device'] + [k for k in version_global[0].keys() if k != 'local_device']
                        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                    else:
                        # New file, write header
                        fieldnames = ['local_device'] + [k for k in version_global[0].keys() if k != 'local_device']
                        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                        writer.writeheader()
                    writer.writerows(version_global)
                print(f"    Added {len(version_global)} version entries to global")
            
            # Global MAC
            if all_data['mac_data']:
                global_mac_file = Path('network_data/global_mac_table.csv')
                global_mac_file.parent.mkdir(exist_ok=True)
                file_exists = global_mac_file.exists()
                
                # Copy data and add local_device
                mac_global = []
                for item in all_data['mac_data']:
                    new_item = item.copy()
                    new_item['local_device'] = hostname
                    mac_global.append(new_item)
                
                with open(global_mac_file, 'a', newline='') as f:
                    if file_exists:
                        # File exists, just append (no header)
                        fieldnames = ['local_device'] + list(mac_global[0].keys())
                        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                    else:
                        # New file, write header
                        fieldnames = ['local_device'] + [k for k in mac_global[0].keys() if k != 'local_device']
                        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                        writer.writeheader()
                    writer.writerows(mac_global)
                print(f"    Added {len(mac_global)} MAC entries to global")
            
            # Global ARP
            if all_data['arp_data']:
                global_arp_file = Path('network_data/global_arp_table.csv')
                file_exists = global_arp_file.exists()
                
                # Copy data and add local_device
                arp_global = []
                for item in all_data['arp_data']:
                    new_item = item.copy()
                    new_item['local_device'] = hostname
                    arp_global.append(new_item)
                
                with open(global_arp_file, 'a', newline='') as f:
                    if file_exists:
                        fieldnames = ['local_device'] + list(arp_global[0].keys())
                        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                    else:
                        fieldnames = ['local_device'] + [k for k in arp_global[0].keys() if k != 'local_device']
                        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                        writer.writeheader()
                    writer.writerows(arp_global)
                print(f"    Added {len(arp_global)} ARP entries to global")
            
            # Global Neighbors - use fixed fieldnames like all_neighbors.csv
            if all_neighbors:
                global_neighbor_file = Path('network_data/global_neighbor_table.csv')
                file_exists = global_neighbor_file.exists()
                
                with open(global_neighbor_file, 'a', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=NEIGHBOR_FIELDNAMES, extrasaction='ignore')
                    if not file_exists:
                        # New file, write header
                        writer.writeheader()
                    writer.writerows(all_neighbors)
                print(f"    Added {len(all_neighbors)} neighbor entries to global")
        
        # ========== SAVE COLLECTION SUMMARY ==========
        # Count version entries properly
        version_count = 0
        if version_data:
            if isinstance(version_data, list):
                version_count = len(version_data)
            else:
                version_count = 1
        
        # Count management entries
        mgmt_count = 0
        if all_data['management_data']:
            if isinstance(all_data['management_data'], list):
                mgmt_count = len(all_data['management_data'])
            else:
                mgmt_count = 1
        
        summary = {
            'device': ip,
            'hostname': hostname,
            'platform': platform,
            'timestamp': datetime.now().isoformat(),
            'commands_run': commands,
            'data_collected': {
                'version_entries': version_count,
                'cdp_entries': len(all_data['cdp_data']),
                'lldp_entries': len(all_data['lldp_data']),
                'mac_entries': len(all_data['mac_data']),
                'arp_entries': len(all_data['arp_data']),
                'vlan_entries': len(all_data['vlan_data']),
                'management_entries': mgmt_count,
                'correlated_entries': len(all_data['correlated_data']),
                'total_neighbors': len(all_neighbors),
                'duplicates_removed': len(duplicate_entries)
            },
            'files_created': {
                'json_files': 10,  # Added management JSON
                'csv_files': sum([
                    1 if version_data else 0,
                    1 if all_data['cdp_data'] else 0,
                    1 if all_data['lldp_data'] else 0,
                    1 if all_data['mac_data'] else 0,
                    1 if all_data['arp_data'] else 0,
                    1 if all_data['vlan_data'] else 0,
                    1 if all_data['management_data'] else 0,
                    1 if all_data['correlated_data'] else 0,
                    1 if all_neighbors else 0
                ])
            }
        }
        with open(str(output_dir / 'collection_summary.json'), 'w') as f:
            json.dump(summary, f, indent=2, default=str)
            print(f"  Collection summary saved")
        
        # List all JSON files created
        print("\n  Verifying files:")
        
        # Check JSON files
        expected_json = [
            'version_data.json',
            'cdp_data.json',
            'lldp_data.json', 
            'mac_data.json',
            'arp_data.json',
            'vlan_data.json',
            'management_data.json',
            'mac_arp_correlation.json',
            'commands_used.json',
            'collection_summary.json'
        ]
        
        json_count = 0
        for expected_file in expected_json:
            json_path = output_dir / expected_file
            if json_path.exists():
                json_count += 1
        
        print(f"    JSON files: {json_count}/{len(expected_json)}")
        
        # Check CSV files
        csv_files = list(output_dir.glob('*.csv'))
        print(f"    CSV files: {len(csv_files)}")
        
        # Check raw text files
        txt_files = list(output_dir.glob('*_raw.txt'))
        print(f"    Raw text files: {len(txt_files)}")
        
        conn.disconnect()
        print(f"\n  ✓ SUCCESS - Data saved to {output_dir}")
        return True
        
    except NetmikoAuthenticationException:
        print(f"  ✗ AUTHENTICATION FAILED")
        return False
    except NetmikoTimeoutException:
        print(f"  ✗ CONNECTION TIMEOUT")
        return False
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        return False
    finally:
        if conn:
            try:
                conn.disconnect()
            except:
                pass

def main():
    print("="*60)
    print("Network Device Collector - OPTIMIZED (Single Connection)")
    print("="*60)
    
    # Check credentials
    if PASSWORD == "your_password" or not USERNAME or not PASSWORD:
        print("ERROR: Update USERNAME and PASSWORD in script")
        return
    
    # Load device list
    devices = []
    try:
        with open(DEVICE_LIST, 'r') as f:
            devices = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print(f"ERROR: Create '{DEVICE_LIST}' with one IP per line")
        return
    
    if not devices:
        print(f"ERROR: No devices in {DEVICE_LIST}")
        return
    
    print(f"Found {len(devices)} devices")
    print("NOTE: Using optimized single-connection approach")
    print("      (no autodetect, ~50% faster connection time)")
    
    # Ask about clearing global files
    if CREATE_GLOBAL_CSV:
        global_files = [
            'network_data/global_version_table.csv',
            'network_data/global_mac_table.csv',
            'network_data/global_arp_table.csv',
            'network_data/global_neighbor_table.csv',
            'network_data/global_mac_arp_correlation.csv',
            'network_data/global_show_interfaces.csv'
        ]
        
        existing = [f for f in global_files if Path(f).exists()]
        if existing:
            print("\nExisting global files found:")
            for f in existing:
                print(f"  - {f}")
            response = input("Clear existing global files? (y/n): ")
            if response.lower() == 'y':
                for f in existing:
                    Path(f).unlink()
                print("Cleared.")
    
    print("\nProcessing devices...\n")
    
    success = 0
    failed = []
    
    for idx, ip in enumerate(devices, 1):
        print(f"[{idx}/{len(devices)}] {ip}")
        if collect_from_device(ip, USERNAME, PASSWORD, ENABLE_PASSWORD):
            success += 1
        else:
            failed.append(ip)
    
    print("\n" + "="*60)
    print(f"Complete! {success}/{len(devices)} successful")
    
    # Report on global files created
    if CREATE_GLOBAL_CSV:
        global_files = [
            'network_data/global_version_table.csv',
            'network_data/global_mac_table.csv',
            'network_data/global_arp_table.csv',
            'network_data/global_neighbor_table.csv',
            'network_data/global_mac_arp_correlation.csv',
            'network_data/global_show_interfaces.csv'
        ]
        
        print("\nGlobal CSV files:")
        for gf in global_files:
            gf_path = Path(gf)
            if gf_path.exists():
                # Count rows (subtract header)
                with open(gf_path, 'r') as f:
                    row_count = sum(1 for line in f) - 1
                print(f"  - {gf_path.name} ({row_count} total entries)")
            else:
                print(f"  - {gf_path.name} (not created)")
    
    if failed:
        print(f"\nFailed devices:")
        for ip in failed:
            print(f"  - {ip}")

if __name__ == "__main__":
    main()
