#!/usr/bin/env python3
"""
Network Device Collector - Simplified NTC Version
Uses NTC templates for parsing based on device type
"""

from netmiko import ConnectHandler, SSHDetect
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
    """Collect data from one device"""
    print(f"\nConnecting to {ip}...")
    
    # Start with autodetect
    device = {
        'device_type': 'autodetect',
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
        # Autodetect device type
        guesser = SSHDetect(**device)
        best_match = guesser.autodetect()
        
        if best_match:
            device['device_type'] = best_match
            print(f"  Autodetected: {best_match}")
        else:
            device['device_type'] = 'cisco_ios'
            print(f"  Using default: cisco_ios")
        
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
        
        # Get version to determine platform
        print("  Collecting version info...")
        version_output = conn.send_command('show version')
        with open(output_dir / 'version_raw.txt', 'w') as f:
            f.write(version_output)
        
        # Determine NTC platform
        if 'Arista' in version_output or 'EOS' in version_output:
            platform = 'arista_eos'
        elif 'NX-OS' in version_output or 'Nexus' in version_output:
            platform = 'cisco_nxos'
        else:
            platform = 'cisco_ios'
        
        print(f"  Platform: {platform}")
        
        # Parse version with NTC and save JSON
        version_data = []
        try:
            parsed = parse_output(platform=platform, command='show version', data=version_output)
            with open(output_dir / 'version_data.json', 'w') as f:
                json.dump(parsed if parsed else [], f, indent=2, default=str)
            
            if parsed:
                version_data = parsed
                print(f"    Version info parsed - saved to version_data.json")
            else:
                print(f"    No version data parsed - empty JSON saved")
        except Exception as e:
            print(f"    Version parsing error: {e}")
            with open(output_dir / 'version_data.json', 'w') as f:
                json.dump([], f)
        
        # Define commands based on platform (from NTC template filenames)
        if platform == 'arista_eos':
            commands = {
                'version': 'show version',
                'cdp': None,  # Arista doesn't have CDP template
                'lldp': 'show lldp neighbors detail',
                'mac': 'show mac address-table',
                'arp': 'show arp',
                'vlan': 'show vlan'
            }
        elif platform == 'cisco_nxos':
            commands = {
                'version': 'show version',
                'cdp': 'show cdp neighbors detail',
                'lldp': 'show lldp neighbors detail',
                'mac': 'show mac address-table',
                'arp': 'show ip arp',
                'vlan': 'show vlan'
            }
        else:  # cisco_ios
            commands = {
                'version': 'show version',
                'cdp': 'show cdp neighbors detail',
                'lldp': 'show lldp neighbors detail',
                'mac': 'show mac-address-table',  # Note the dash!
                'arp': 'show ip arp',
                'vlan': 'show vlan'
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
            'vlan_data': []
        }
        
        # Save commands used for debugging
        commands_used = {
            'platform': platform,
            'commands': commands
        }
        with open(output_dir / 'commands_used.json', 'w') as f:
            json.dump(commands_used, f, indent=2, default=str)
        
        # ========== CDP ==========
        if commands['cdp']:
            print(f"  Collecting CDP neighbors...")
            try:
                cdp_output = conn.send_command(commands['cdp'])
                with open(output_dir / 'cdp_raw.txt', 'w') as f:
                    f.write(cdp_output)
                
                # Check if CDP is enabled
                if 'CDP is not enabled' in cdp_output or '% Invalid' in cdp_output:
                    print(f"    CDP not enabled or not supported")
                    with open(output_dir / 'cdp_data.json', 'w') as f:
                        json.dump([], f)
                else:
                    try:
                        parsed = parse_output(platform=platform, command=commands['cdp'], data=cdp_output)
                        with open(output_dir / 'cdp_data.json', 'w') as f:
                            json.dump(parsed if parsed else [], f, indent=2, default=str)
                        
                        if parsed:
                            all_data['cdp_data'] = parsed
                            print(f"    Found {len(parsed)} CDP neighbors")
                        else:
                            print(f"    No CDP data parsed")
                    except Exception as e:
                        print(f"    CDP parsing error: {e}")
                        with open(output_dir / 'cdp_data.json', 'w') as f:
                            json.dump([], f)
            except Exception as e:
                print(f"    CDP command failed: {e}")
                with open(output_dir / 'cdp_data.json', 'w') as f:
                    json.dump([], f)
        else:
            print(f"  CDP not supported on {platform}")
            with open(output_dir / 'cdp_data.json', 'w') as f:
                json.dump([], f)
        
        # ========== LLDP ==========
        if commands['lldp']:
            print(f"  Collecting LLDP neighbors...")
            try:
                lldp_output = conn.send_command(commands['lldp'])
                with open(output_dir / 'lldp_raw.txt', 'w') as f:
                    f.write(lldp_output)
                
                # Check if LLDP is enabled
                if 'LLDP is not enabled' in lldp_output or '% Invalid' in lldp_output:
                    print(f"    LLDP not enabled or not supported")
                    with open(output_dir / 'lldp_data.json', 'w') as f:
                        json.dump([], f)
                else:
                    try:
                        parsed = parse_output(platform=platform, command=commands['lldp'], data=lldp_output)
                        with open(output_dir / 'lldp_data.json', 'w') as f:
                            json.dump(parsed if parsed else [], f, indent=2, default=str)
                        
                        if parsed:
                            all_data['lldp_data'] = parsed
                            print(f"    Found {len(parsed)} LLDP neighbors")
                        else:
                            print(f"    No LLDP data parsed")
                    except Exception as e:
                        print(f"    LLDP parsing error: {e}")
                        with open(output_dir / 'lldp_data.json', 'w') as f:
                            json.dump([], f)
            except Exception as e:
                print(f"    LLDP command failed: {e}")
                with open(output_dir / 'lldp_data.json', 'w') as f:
                    json.dump([], f)
        else:
            print(f"  LLDP not supported on {platform}")
            with open(output_dir / 'lldp_data.json', 'w') as f:
                json.dump([], f)
        
        # ========== MAC TABLE ==========
        if commands['mac']:
            print(f"  Collecting MAC address table...")
            try:
                mac_output = conn.send_command(commands['mac'])
                with open(output_dir / 'mac_raw.txt', 'w') as f:
                    f.write(mac_output)
                
                if '% Invalid' in mac_output or 'Error' in mac_output:
                    print(f"    MAC command not recognized")
                    with open(output_dir / 'mac_data.json', 'w') as f:
                        json.dump([], f)
                else:
                    try:
                        parsed = parse_output(platform=platform, command=commands['mac'], data=mac_output)
                        with open(output_dir / 'mac_data.json', 'w') as f:
                            json.dump(parsed if parsed else [], f, indent=2, default=str)
                        
                        if parsed:
                            all_data['mac_data'] = parsed
                            print(f"    Found {len(parsed)} MAC entries")
                        else:
                            print(f"    No MAC data parsed")
                    except Exception as e:
                        print(f"    MAC parsing error: {e}")
                        with open(output_dir / 'mac_data.json', 'w') as f:
                            json.dump([], f)
            except Exception as e:
                print(f"    MAC command failed: {e}")
                with open(output_dir / 'mac_data.json', 'w') as f:
                    json.dump([], f)
        
        # ========== ARP TABLE ==========
        if commands['arp']:
            print(f"  Collecting ARP table...")
            try:
                arp_output = conn.send_command(commands['arp'])
                with open(output_dir / 'arp_raw.txt', 'w') as f:
                    f.write(arp_output)
                
                try:
                    parsed = parse_output(platform=platform, command=commands['arp'], data=arp_output)
                    with open(output_dir / 'arp_data.json', 'w') as f:
                        json.dump(parsed if parsed else [], f, indent=2, default=str)
                    
                    if parsed:
                        all_data['arp_data'] = parsed
                        print(f"    Found {len(parsed)} ARP entries")
                    else:
                        print(f"    No ARP data parsed")
                except Exception as e:
                    print(f"    ARP parsing error: {e}")
                    with open(output_dir / 'arp_data.json', 'w') as f:
                        json.dump([], f)
            except Exception as e:
                print(f"    ARP command failed: {e}")
                with open(output_dir / 'arp_data.json', 'w') as f:
                    json.dump([], f)
        
        # ========== VLANs ==========
        if commands['vlan']:
            print(f"  Collecting VLANs...")
            try:
                vlan_output = conn.send_command(commands['vlan'])
                with open(output_dir / 'vlan_raw.txt', 'w') as f:
                    f.write(vlan_output)
                
                try:
                    parsed = parse_output(platform=platform, command=commands['vlan'], data=vlan_output)
                    with open(output_dir / 'vlan_data.json', 'w') as f:
                        json.dump(parsed if parsed else [], f, indent=2, default=str)
                    
                    if parsed:
                        all_data['vlan_data'] = parsed
                        print(f"    Found {len(parsed)} VLANs")
                    else:
                        print(f"    No VLAN data parsed")
                except Exception as e:
                    print(f"    VLAN parsing error: {e}")
                    with open(output_dir / 'vlan_data.json', 'w') as f:
                        json.dump([], f)
            except Exception as e:
                print(f"    VLAN command failed: {e}")
                with open(output_dir / 'vlan_data.json', 'w') as f:
                    json.dump([], f)
        
        # ========== CREATE CSV FILES ==========
        # CDP CSV
        if all_data['cdp_data']:
            with open(output_dir / 'cdp_neighbors.csv', 'w', newline='') as f:
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
            with open(output_dir / 'lldp_neighbors.csv', 'w', newline='') as f:
                data = all_data['lldp_data'].copy()
                for item in data:
                    item['local_device'] = hostname
                
                fieldnames = ['local_device'] + [k for k in data[0].keys() if k != 'local_device']
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(data)
        
        # MAC CSV
        if all_data['mac_data']:
            with open(output_dir / 'mac_table.csv', 'w', newline='') as f:
                data = all_data['mac_data'].copy()
                for item in data:
                    item['local_device'] = hostname
                
                fieldnames = ['local_device'] + [k for k in data[0].keys() if k != 'local_device']
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(data)
        
        # ARP CSV
        if all_data['arp_data']:
            with open(output_dir / 'arp_table.csv', 'w', newline='') as f:
                data = all_data['arp_data'].copy()
                for item in data:
                    item['local_device'] = hostname
                
                fieldnames = ['local_device'] + [k for k in data[0].keys() if k != 'local_device']
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(data)
        
        # VLAN CSV
        if all_data['vlan_data']:
            with open(output_dir / 'vlan_table.csv', 'w', newline='') as f:
                data = all_data['vlan_data'].copy()
                for item in data:
                    item['local_device'] = hostname
                
                fieldnames = ['local_device'] + [k for k in data[0].keys() if k != 'local_device']
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(data)
        
        # Combined neighbors CSV (CDP + LLDP)
        all_neighbors = []
        for item in all_data['cdp_data']:
            new_item = item.copy()
            new_item['protocol'] = 'CDP'
            new_item['local_device'] = hostname
            all_neighbors.append(new_item)
        for item in all_data['lldp_data']:
            new_item = item.copy()
            new_item['protocol'] = 'LLDP'
            new_item['local_device'] = hostname
            all_neighbors.append(new_item)
        
        if all_neighbors:
            with open(output_dir / 'all_neighbors.csv', 'w', newline='') as f:
                # Get all unique keys
                all_keys = set()
                for item in all_neighbors:
                    all_keys.update(item.keys())
                
                fieldnames = ['local_device', 'protocol'] + sorted([k for k in all_keys if k not in ['local_device', 'protocol']])
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(all_neighbors)
        
        # ========== APPEND TO GLOBAL FILES ==========
        if CREATE_GLOBAL_CSV:
            print("  Updating global CSV files...")
            
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
            
            # Global Neighbors (already has local_device from above)
            if all_neighbors:
                global_neighbor_file = Path('network_data/global_neighbor_table.csv')
                file_exists = global_neighbor_file.exists()
                
                with open(global_neighbor_file, 'a', newline='') as f:
                    if file_exists:
                        # Just append with same field structure
                        all_keys = set()
                        for item in all_neighbors:
                            all_keys.update(item.keys())
                        fieldnames = ['local_device', 'protocol'] + sorted([k for k in all_keys if k not in ['local_device', 'protocol']])
                        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                    else:
                        # New file, write header
                        all_keys = set()
                        for item in all_neighbors:
                            all_keys.update(item.keys())
                        fieldnames = ['local_device', 'protocol'] + sorted([k for k in all_keys if k not in ['local_device', 'protocol']])
                        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                        writer.writeheader()
                    writer.writerows(all_neighbors)
                print(f"    Added {len(all_neighbors)} neighbor entries to global")
        
        # ========== SAVE COLLECTION SUMMARY ==========
        summary = {
            'device': ip,
            'hostname': hostname,
            'platform': platform,
            'timestamp': datetime.now().isoformat(),
            'commands_run': commands,
            'data_collected': {
                'version_entries': len(version_data) if isinstance(version_data, list) else 1 if version_data else 0,
                'cdp_entries': len(all_data['cdp_data']),
                'lldp_entries': len(all_data['lldp_data']),
                'mac_entries': len(all_data['mac_data']),
                'arp_entries': len(all_data['arp_data']),
                'vlan_entries': len(all_data['vlan_data']),
                'total_neighbors': len(all_neighbors)
            }
        }
        with open(output_dir / 'collection_summary.json', 'w') as f:
            json.dump(summary, f, indent=2, default=str)
        
        conn.disconnect()
        print(f"  ✓ SUCCESS - Data saved to {output_dir}")
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
    print("Network Device Collector - NTC Templates")
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
    
    # Ask about clearing global files
    if CREATE_GLOBAL_CSV:
        global_files = [
            'network_data/global_mac_table.csv',
            'network_data/global_arp_table.csv',
            'network_data/global_neighbor_table.csv'
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
    
    if failed:
        print(f"\nFailed devices:")
        for ip in failed:
            print(f"  - {ip}")

if __name__ == "__main__":
    main()
