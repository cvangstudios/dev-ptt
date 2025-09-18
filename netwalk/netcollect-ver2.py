#!/usr/bin/env python3
"""
Network Device Collector - WORKING VERSION
This one actually parses CDP, MAC, ARP, and VLAN data correctly
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
SSH_KEY_FILE = ""  # Optional: Path to SSH private key file
USE_SSH_KEY = False  # Set to True to use SSH key authentication

# Global CSV file creation - concatenates all device data
CREATE_GLOBAL_CSV = True  # Set to False to disable global CSV creation

def parse_cdp_manual(output):
    """Manual CDP parsing when NTC fails"""
    neighbors = []
    
    # Split into individual entries (separated by ---------)
    entries = re.split(r'-{3,}', output)
    
    for entry in entries:
        if 'Device ID:' not in entry:
            continue
            
        neighbor = {}
        
        # Device ID / Neighbor Name
        device_match = re.search(r'Device ID:\s*(.+)', entry)
        if device_match:
            neighbor['neighbor_name'] = device_match.group(1).strip()
            # Also use as chassis_id if not found separately
            neighbor['chassis_id'] = device_match.group(1).strip()
        
        # Management IP address
        ip_match = re.search(r'IP address:\s*(\d+\.\d+\.\d+\.\d+)', entry)
        if ip_match:
            neighbor['mgmt_address'] = ip_match.group(1)
        
        # Local and Remote interfaces
        intf_match = re.search(r'Interface:\s*([^,]+),\s*Port ID \(outgoing port\):\s*(.+)', entry)
        if intf_match:
            neighbor['local_interface'] = intf_match.group(1).strip()
            neighbor['neighbor_interface'] = intf_match.group(2).strip()
        
        # Interface IP (if exists)
        neighbor['interface_ip'] = ''
        neighbor['neighbor_description'] = ''
        neighbor['vlan_id'] = ''
        
        if neighbor.get('neighbor_name'):
            neighbors.append(neighbor)
    
    return neighbors

def collect_from_device(ip, username, password, enable_password=None, use_ssh_key=False, ssh_key_file=None):
    """Collect data from one device"""
    print(f"\nConnecting to {ip}...")
    
    # Start with autodetect to properly identify device type
    device = {
        'device_type': 'autodetect',
        'ip': ip,
        'username': username,
        'timeout': 30,
    }
    
    # Configure authentication method
    if use_ssh_key and ssh_key_file:
        device['use_keys'] = True
        device['key_file'] = ssh_key_file
        device['password'] = password  # Still needed for enable mode
    else:
        device['password'] = password
    
    # Add enable password if different
    if enable_password:
        device['secret'] = enable_password
    elif password:
        device['secret'] = password  # Use same password for enable if not specified
    
    conn = None
    try:
        # Try to autodetect device type
        guesser = SSHDetect(**device)
        best_match = guesser.autodetect()
        
        if best_match:
            device['device_type'] = best_match
            print(f"  Autodetected device type: {best_match}")
        else:
            # Default to cisco_ios if autodetect fails
            device['device_type'] = 'cisco_ios'
            print(f"  Autodetect failed, using default: cisco_ios")
        
        # Now connect with the detected device type
        conn = ConnectHandler(**device)
        
        # Enter enable mode if needed
        if not conn.check_enable_mode():
            try:
                conn.enable()
            except Exception as e:
                print(f"  Warning: Could not enter enable mode: {e}")
        
        hostname = conn.find_prompt().strip('#>')
        print(f"  Connected to {hostname}")
        
        # Create output folder
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_hostname = re.sub(r'[^\w\-_]', '_', hostname)
        output_dir = Path(f"network_data/{safe_hostname}_{ip}_{timestamp}")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # ========== DEVICE VERSION INFO ==========
        print("  Collecting version information...")
        version_output = conn.send_command('show version')
        
        # Save raw output
        with open(output_dir / 'version_raw.txt', 'w') as f:
            f.write(version_output)
        
        # Detect device type and platform
        if 'Arista' in version_output or 'EOS' in version_output:
            device_type = 'arista_eos'
            platform = 'arista_eos'
        elif 'NX-OS' in version_output or 'Nexus' in version_output:
            device_type = 'cisco_nxos'
            platform = 'cisco_nxos'
        elif 'IOS-XE' in version_output:
            device_type = 'cisco_ios'
            platform = 'cisco_xe'
        elif 'IOS' in version_output or 'Cisco' in version_output:
            device_type = 'cisco_ios'
            platform = 'cisco_ios'
        else:
            # Try to detect from netmiko device type
            if hasattr(conn, 'device_type'):
                if 'arista' in conn.device_type.lower():
                    device_type = 'arista_eos'
                    platform = 'arista_eos'
                elif 'nxos' in conn.device_type.lower():
                    device_type = 'cisco_nxos'
                    platform = 'cisco_nxos'
                else:
                    device_type = 'cisco_ios'
                    platform = 'cisco_ios'
            else:
                device_type = 'cisco_ios'  # Default fallback
                platform = 'cisco_ios'
        
        print(f"  Device type: {device_type}")
        print(f"  NTC platform: {platform}")
        
        # Parse version info with NTC templates
        version_data = {}
        try:
            parsed = parse_output(platform=platform, command='show version', data=version_output)
            if parsed:
                print(f"    NTC parsed version info")
                # Save what NTC returns
                with open(output_dir / 'version_ntc_output.json', 'w') as f:
                    json.dump(parsed, f, indent=2, default=str)
                
                # Extract key information (format varies by platform)
                if isinstance(parsed, list) and len(parsed) > 0:
                    v = parsed[0]
                    version_data = {
                        'hostname': v.get('hostname', hostname),
                        'version': v.get('version', v.get('software', '')),
                        'serial': v.get('serial', v.get('serial_number', '')),
                        'hardware': v.get('hardware', v.get('platform', v.get('model', ''))),
                        'uptime': v.get('uptime', ''),
                        'platform': platform
                    }
                elif isinstance(parsed, dict):
                    version_data = {
                        'hostname': parsed.get('hostname', hostname),
                        'version': parsed.get('version', parsed.get('software', '')),
                        'serial': parsed.get('serial', parsed.get('serial_number', '')),
                        'hardware': parsed.get('hardware', parsed.get('platform', parsed.get('model', ''))),
                        'uptime': parsed.get('uptime', ''),
                        'platform': platform
                    }
            else:
                print("    NTC version parsing returned no data")
                # Save empty result for debugging
                with open(output_dir / 'version_ntc_output.json', 'w') as f:
                    json.dump([], f)
                    
        except Exception as e:
            print(f"    Version parsing failed: {e}")
            # Save error info for debugging
            with open(output_dir / 'version_ntc_error.txt', 'w') as f:
                f.write(f"Error: {e}\n")
                f.write(f"Platform tried: {platform}\n")
        
        # Save parsed version data
        if version_data:
            with open(output_dir / 'version_info.json', 'w') as f:
                json.dump(version_data, f, indent=2, default=str)
            print(f"    Version: {version_data.get('version', 'N/A')}")
            print(f"    Serial: {version_data.get('serial', 'N/A')}")
        
        # Save debug info about platform detection
        debug_info = {
            'netmiko_device_type': device.get('device_type', 'unknown'),
            'detected_device_type': device_type,
            'ntc_platform': platform,
            'version_snippet': version_output[:500] if version_output else '',
        }
        with open(output_dir / 'platform_debug.json', 'w') as f:
            json.dump(debug_info, f, indent=2, default=str)
        
        # ========== CDP NEIGHBORS ==========
        print("  Collecting CDP neighbors...")
        cdp_output = conn.send_command('show cdp neighbors detail')
        
        # Save raw output
        with open(output_dir / 'cdp_raw.txt', 'w') as f:
            f.write(cdp_output)
        
        cdp_data = []
        
        # Try NTC templates first
        try:
            parsed = parse_output(platform=platform, command='show cdp neighbors detail', data=cdp_output)
            if parsed:
                print(f"    NTC parsed {len(parsed)} CDP entries")
                # Save what NTC actually returns
                with open(output_dir / 'cdp_ntc_output.json', 'w') as f:
                    json.dump(parsed, f, indent=2, default=str)
                
                for entry in parsed:
                    cdp_data.append({
                        'local_interface': entry.get('local_interface', ''),
                        'neighbor_name': entry.get('neighbor_name', ''),
                        'mgmt_address': entry.get('mgmt_address', ''),
                        'neighbor_interface': entry.get('neighbor_interface', ''),
                        'interface_ip': entry.get('interface_ip', ''),
                        'chassis_id': entry.get('chassis_id', ''),
                        'neighbor_description': entry.get('neighbor_description', ''),
                        'vlan_id': entry.get('vlan_id', '')
                    })
            else:
                print("    NTC CDP parsing returned no data")
                # Save empty result for debugging
                with open(output_dir / 'cdp_ntc_output.json', 'w') as f:
                    json.dump([], f)
        except Exception as e:
            print(f"    NTC parsing failed: {e}")
            # Save error info for debugging
            with open(output_dir / 'cdp_ntc_error.txt', 'w') as f:
                f.write(f"Error: {e}\n")
                f.write(f"Platform tried: {platform}\n")
        
        # If NTC failed or returned nothing, use manual parsing
        if not cdp_data:
            print("    Using manual CDP parsing...")
            parsed_manual = parse_cdp_manual(cdp_output)
            # Map manual parse fields to expected field names
            for entry in parsed_manual:
                cdp_data.append({
                    'local_interface': entry.get('local_interface', ''),
                    'neighbor_name': entry.get('neighbor_name', ''),
                    'mgmt_address': entry.get('mgmt_address', ''),
                    'neighbor_interface': entry.get('neighbor_interface', ''),
                    'interface_ip': entry.get('interface_ip', ''),
                    'chassis_id': entry.get('chassis_id', ''),
                    'neighbor_description': entry.get('neighbor_description', ''),
                    'vlan_id': entry.get('vlan_id', '')
                })
            print(f"    Manual parsed {len(cdp_data)} CDP entries")
        
        # Save CDP data
        if cdp_data:
            # Add local_device column to each entry
            for entry in cdp_data:
                entry['local_device'] = hostname
            
            with open(output_dir / 'cdp_neighbors.csv', 'w', newline='') as f:
                fieldnames = ['local_device', 'local_interface', 'neighbor_name', 'neighbor_interface', 'mgmt_address', 'interface_ip', 'chassis_id', 'neighbor_description', 'vlan_id']
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(cdp_data)
            
            print(f"    Saved {len(cdp_data)} CDP neighbors")
            for n in cdp_data[:3]:  # Show first 3
                print(f"      {n.get('local_interface', 'N/A')} -> {n.get('neighbor_name', 'N/A')} ({n.get('neighbor_interface', 'N/A')})")
        else:
            # Ensure we have an empty JSON file for consistency
            if not (output_dir / 'cdp_ntc_output.json').exists():
                with open(output_dir / 'cdp_ntc_output.json', 'w') as f:
                    json.dump([], f)
        
        # ========== MAC ADDRESS TABLE ==========
        print("  Collecting MAC address table...")
        
        mac_data = []
        mac_parsed = False
        
        # Try different commands - Arista uses "show mac address-table"
        if platform == 'arista_eos':
            mac_commands = ['show mac address-table']
        else:
            mac_commands = ['show mac address-table', 'show mac-address-table']
        
        for cmd in mac_commands:
            mac_output = conn.send_command(cmd)
            if 'Invalid' not in mac_output and 'Error' not in mac_output and '%' not in mac_output[:50]:
                # Save raw output
                with open(output_dir / 'mac_raw.txt', 'w') as f:
                    f.write(mac_output)
                
                try:
                    parsed = parse_output(platform=platform, command=cmd, data=mac_output)
                    if parsed:
                        print(f"    NTC parsed {len(parsed)} MAC entries")
                        # Save what NTC returns
                        with open(output_dir / 'mac_ntc_output.json', 'w') as f:
                            json.dump(parsed, f, indent=2, default=str)
                        
                        for entry in parsed:
                            mac_data.append({
                                'vlan_id': entry.get('vlan_id', entry.get('vlan', '')),
                                'mac_address': entry.get('mac_address', entry.get('destination_address', '')),
                                'type': entry.get('type', ''),
                                'ports': entry.get('ports', entry.get('destination_port', '')),
                                'age': entry.get('age', ''),
                                'secure': entry.get('secure', ''),
                                'ntfy': entry.get('ntfy', '')
                            })
                        mac_parsed = True
                        break
                    else:
                        print(f"    NTC MAC parsing returned no data for command: {cmd}")
                        # Save empty result for debugging
                        with open(output_dir / 'mac_ntc_output.json', 'w') as f:
                            json.dump([], f)
                except Exception as e:
                    print(f"    NTC MAC parsing failed for {cmd}: {e}")
                    # Save error info for debugging
                    with open(output_dir / 'mac_ntc_error.txt', 'w') as f:
                        f.write(f"Error: {e}\n")
                        f.write(f"Platform: {platform}\n")
                        f.write(f"Command: {cmd}\n")
        
        # Manual MAC parsing if NTC failed
        if not mac_data and 'mac_output' in locals():
            print("    Using manual MAC parsing...")
            for line in mac_output.split('\n'):
                # Look for MAC address pattern
                match = re.search(r'(\d+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+(\w+)\s+(\S+)', line, re.I)
                if match:
                    mac_data.append({
                        'vlan_id': match.group(1),
                        'mac_address': match.group(2),
                        'type': match.group(3),
                        'ports': match.group(4),
                        'age': '',
                        'secure': '',
                        'ntfy': ''
                    })
            
            if not mac_data:
                # If still no data, save empty json for debugging
                with open(output_dir / 'mac_ntc_output.json', 'w') as f:
                    json.dump([], f)
        
        # Save MAC data
        if mac_data:
            # Add local_device column to each entry
            for entry in mac_data:
                entry['local_device'] = hostname
            
            with open(output_dir / 'mac_table.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['local_device', 'vlan_id', 'mac_address', 'type', 'ports', 'age', 'secure', 'ntfy'])
                writer.writeheader()
                writer.writerows(mac_data)
            print(f"    Saved {len(mac_data)} MAC entries")
        else:
            # Ensure we have an empty JSON file for consistency
            if not (output_dir / 'mac_ntc_output.json').exists():
                with open(output_dir / 'mac_ntc_output.json', 'w') as f:
                    json.dump([], f)
        
        # ========== ARP TABLE ==========
        print("  Collecting ARP table...")
        
        # Arista uses "show arp", Cisco uses "show ip arp"
        if platform == 'arista_eos':
            arp_command = 'show arp'
        else:
            arp_command = 'show ip arp'
        
        arp_output = conn.send_command(arp_command)
        
        # Save raw output
        with open(output_dir / 'arp_raw.txt', 'w') as f:
            f.write(arp_output)
        
        arp_data = []
        
        try:
            parsed = parse_output(platform=platform, command=arp_command, data=arp_output)
            if parsed:
                print(f"    NTC parsed {len(parsed)} ARP entries")
                # Save what NTC returns
                with open(output_dir / 'arp_ntc_output.json', 'w') as f:
                    json.dump(parsed, f, indent=2, default=str)
                
                for entry in parsed:
                    arp_data.append({
                        'ip_address': entry.get('ip_address', entry.get('address', '')),
                        'mac_address': entry.get('mac_address', entry.get('mac', '')),
                        'interface': entry.get('interface', ''),
                        'age': entry.get('age', '')
                    })
            else:
                print("    NTC ARP parsing returned no data")
                # Save empty result for debugging
                with open(output_dir / 'arp_ntc_output.json', 'w') as f:
                    json.dump([], f)
        except Exception as e:
            print(f"    NTC ARP parsing failed: {e}")
            # Save error info for debugging
            with open(output_dir / 'arp_ntc_error.txt', 'w') as f:
                f.write(f"Error: {e}\n")
                f.write(f"Platform: {platform}\n")
                f.write(f"Command: {arp_command}\n")
        
        # Manual ARP parsing if NTC failed
        if not arp_data:
            print("    Using manual ARP parsing...")
            for line in arp_output.split('\n'):
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+\S+\s+(\S+)', line, re.I)
                if match:
                    arp_data.append({
                        'ip_address': match.group(1),
                        'mac_address': match.group(2),
                        'interface': match.group(3),
                        'age': ''
                    })
        
        # Save ARP data
        if arp_data:
            # Add local_device column to each entry
            for entry in arp_data:
                entry['local_device'] = hostname
            
            with open(output_dir / 'arp_table.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['local_device', 'ip_address', 'mac_address', 'interface', 'age'])
                writer.writeheader()
                writer.writerows(arp_data)
            print(f"    Saved {len(arp_data)} ARP entries")
        else:
            # Ensure we have an empty JSON file for consistency
            if not (output_dir / 'arp_ntc_output.json').exists():
                with open(output_dir / 'arp_ntc_output.json', 'w') as f:
                    json.dump([], f)
        
        # ========== LLDP NEIGHBORS (if no CDP or in addition) ==========
        print("  Collecting LLDP neighbors...")
        lldp_output = conn.send_command('show lldp neighbors detail')
        
        # Save raw output
        with open(output_dir / 'lldp_raw.txt', 'w') as f:
            f.write(lldp_output)
        
        lldp_data = []
        
        if 'LLDP is not enabled' not in lldp_output:
            try:
                parsed = parse_output(platform=platform, command='show lldp neighbors detail', data=lldp_output)
                if parsed:
                    print(f"    NTC parsed {len(parsed)} LLDP entries")
                    # Save what NTC actually returns
                    with open(output_dir / 'lldp_ntc_output.json', 'w') as f:
                        json.dump(parsed, f, indent=2, default=str)
                    
                    # Use the correct LLDP field names from NTC output
                    for entry in parsed:
                        lldp_data.append({
                            'local_interface': entry.get('local_interface', ''),
                            'neighbor_name': entry.get('neighbor_name', ''),
                            'neighbor_interface': entry.get('neighbor_interface', ''),
                            'mgmt_address': entry.get('mgmt_address', ''),
                            'chassis_id': entry.get('chassis_id', ''),
                            'neighbor_description': entry.get('neighbor_description', ''),
                            'vlan_id': entry.get('vlan_id', '')
                        })
                else:
                    print("    NTC LLDP parsing returned no data")
                    # Save empty result for debugging
                    with open(output_dir / 'lldp_ntc_output.json', 'w') as f:
                        json.dump([], f)
            except Exception as e:
                print(f"    LLDP parsing failed: {e}")
                # Save error info for debugging
                with open(output_dir / 'lldp_ntc_error.txt', 'w') as f:
                    f.write(f"Error: {e}\n")
                    f.write(f"Platform: {platform}\n")
        else:
            print("    LLDP is not enabled on this device")
        
        # Save LLDP data
        if lldp_data:
            # Add local_device column to each entry
            for entry in lldp_data:
                entry['local_device'] = hostname
            
            with open(output_dir / 'lldp_neighbors.csv', 'w', newline='') as f:
                fieldnames = ['local_device', 'local_interface', 'neighbor_name', 'neighbor_interface', 'mgmt_address', 'chassis_id', 'neighbor_description', 'vlan_id']
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(lldp_data)
            
            print(f"    Saved {len(lldp_data)} LLDP neighbors")
        else:
            # Ensure we have an empty JSON file for consistency
            if not (output_dir / 'lldp_ntc_output.json').exists():
                with open(output_dir / 'lldp_ntc_output.json', 'w') as f:
                    json.dump([], f)
        
        # Combine CDP and LLDP neighbors
        all_neighbors = []
        for n in cdp_data:
            n['protocol'] = 'CDP'
            n['local_device'] = hostname  # Ensure it's set
            all_neighbors.append(n)
        for n in lldp_data:
            n['protocol'] = 'LLDP'
            n['local_device'] = hostname  # Ensure it's set
            all_neighbors.append(n)
        
        if all_neighbors:
            with open(output_dir / 'all_neighbors.csv', 'w', newline='') as f:
                fieldnames = ['local_device', 'protocol', 'local_interface', 'neighbor_name', 'neighbor_interface', 'mgmt_address', 'chassis_id', 'neighbor_description', 'vlan_id']
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(all_neighbors)
            print(f"    Saved {len(all_neighbors)} total neighbors (CDP + LLDP)")
        # ========== VLANs ==========
        print("  Collecting VLANs...")
        
        # Arista uses "show vlan", Cisco uses "show vlan brief" or "show vlan"
        if platform == 'arista_eos':
            vlan_commands = ['show vlan']
        else:
            vlan_commands = ['show vlan brief', 'show vlan']
        
        vlan_data = []
        for cmd in vlan_commands:
            vlan_output = conn.send_command(cmd)
            
            # Save raw output
            if cmd == vlan_commands[0]:
                with open(output_dir / 'vlan_raw.txt', 'w') as f:
                    f.write(vlan_output)
            else:
                with open(output_dir / f'vlan_{cmd.replace(" ", "_")}_raw.txt', 'w') as f:
                    f.write(vlan_output)
            
            try:
                parsed = parse_output(platform=platform, command=cmd, data=vlan_output)
                
                if parsed:
                    print(f"    NTC parsed {len(parsed)} VLANs using '{cmd}'")
                    # Save what NTC returns
                    with open(output_dir / 'vlan_ntc_output.json', 'w') as f:
                        json.dump(parsed, f, indent=2, default=str)
                    
                    for entry in parsed:
                        interfaces = entry.get('interfaces', [])
                        if isinstance(interfaces, list):
                            interfaces = ', '.join(interfaces)
                        
                        vlan_data.append({
                            'vlan_id': entry.get('vlan_id', ''),
                            'vlan_name': entry.get('vlan_name', entry.get('name', '')),
                            'status': entry.get('status', ''),
                            'interfaces': interfaces
                        })
                    break  # Stop if we got data
                else:
                    print(f"    NTC VLAN parsing returned no data for '{cmd}'")
                    if cmd == vlan_commands[-1]:  # Last command tried
                        # Save empty result for debugging
                        with open(output_dir / 'vlan_ntc_output.json', 'w') as f:
                            json.dump([], f)
            except Exception as e:
                print(f"    NTC VLAN parsing failed for '{cmd}': {e}")
                if cmd == vlan_commands[-1]:  # Last command tried
                    # Save error info for debugging
                    with open(output_dir / 'vlan_ntc_error.txt', 'w') as f:
                        f.write(f"Error: {e}\n")
                        f.write(f"Platform: {platform}\n")
                        f.write(f"Commands tried: {vlan_commands}\n")
        
        # Save VLAN data
        if vlan_data:
            with open(output_dir / 'vlan_table.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['vlan_id', 'vlan_name', 'status', 'interfaces'])
                writer.writeheader()
                writer.writerows(vlan_data)
            print(f"    Saved {len(vlan_data)} VLANs")
        else:
            # Ensure we have an empty JSON file for consistency
            if not (output_dir / 'vlan_ntc_output.json').exists():
                with open(output_dir / 'vlan_ntc_output.json', 'w') as f:
                    json.dump([], f)
        
        # ========== CORRELATE MAC/ARP ==========
        if mac_data and arp_data:
            print("  Correlating MAC and ARP...")
            
            # Create lookup
            arp_lookup = {}
            for arp in arp_data:
                if arp['mac_address']:
                    # Normalize MAC
                    norm_mac = arp['mac_address'].lower().replace(':', '').replace('.', '').replace('-', '')
                    arp_lookup[norm_mac] = arp['ip_address']
            
            correlated = []
            for mac in mac_data:
                if mac['mac_address']:
                    norm_mac = mac['mac_address'].lower().replace(':', '').replace('.', '').replace('-', '')
                    ip = arp_lookup.get(norm_mac, '')
                    
                    correlated.append({
                        'local_device': hostname,
                        'vlan_id': mac['vlan_id'],
                        'mac_address': mac['mac_address'],
                        'type': mac['type'],
                        'ports': mac['ports'],
                        'ip_address': ip
                    })
            
            if correlated:
                with open(output_dir / 'mac_arp_correlated.csv', 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=['local_device', 'vlan_id', 'mac_address', 'type', 'ports', 'ip_address'])
                    writer.writeheader()
                    writer.writerows(correlated)
                print(f"    Saved {len(correlated)} correlated entries")
        
        # ========== APPEND TO GLOBAL CSV FILES ==========
        if CREATE_GLOBAL_CSV:
            print("  Updating global CSV files...")
            
            # Global MAC table
            if mac_data:
                global_mac_file = Path('network_data/global_mac_table.csv')
                global_mac_file.parent.mkdir(exist_ok=True)
                
                # Check if file exists to determine if we need headers
                file_exists = global_mac_file.exists()
                
                with open(global_mac_file, 'a', newline='') as f:
                    fieldnames = ['local_device', 'vlan_id', 'mac_address', 'type', 'ports', 'age', 'secure', 'ntfy']
                    writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                    
                    if not file_exists:
                        writer.writeheader()
                    
                    writer.writerows(mac_data)
                print(f"    Added {len(mac_data)} entries to global MAC table")
            
            # Global ARP table
            if arp_data:
                global_arp_file = Path('network_data/global_arp_table.csv')
                file_exists = global_arp_file.exists()
                
                with open(global_arp_file, 'a', newline='') as f:
                    fieldnames = ['local_device', 'ip_address', 'mac_address', 'interface', 'age']
                    writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                    
                    if not file_exists:
                        writer.writeheader()
                    
                    writer.writerows(arp_data)
                print(f"    Added {len(arp_data)} entries to global ARP table")
            
            # Global neighbor table (CDP + LLDP combined)
            if all_neighbors:
                global_neighbor_file = Path('network_data/global_neighbor_table.csv')
                file_exists = global_neighbor_file.exists()
                
                with open(global_neighbor_file, 'a', newline='') as f:
                    fieldnames = ['local_device', 'protocol', 'local_interface', 'neighbor_name', 'neighbor_interface', 'mgmt_address', 'chassis_id', 'neighbor_description', 'vlan_id']
                    writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                    
                    if not file_exists:
                        writer.writeheader()
                    
                    writer.writerows(all_neighbors)
                print(f"    Added {len(all_neighbors)} entries to global neighbor table")
        
        conn.disconnect()
        print(f"  ✓ SUCCESS - Data saved to {output_dir}")
        
        # Save collection summary
        summary = {
            'device': ip,
            'hostname': hostname,
            'platform': platform,
            'device_type': device_type,
            'cdp_count': len(cdp_data),
            'lldp_count': len(lldp_data),
            'mac_count': len(mac_data),
            'arp_count': len(arp_data),
            'vlan_count': len(vlan_data),
            'timestamp': datetime.now().isoformat()
        }
        with open(output_dir / 'collection_summary.json', 'w') as f:
            json.dump(summary, f, indent=2, default=str)
        
        return True
        
    except NetmikoAuthenticationException:
        print(f"  ✗ AUTHENTICATION FAILED: Check username/password for {ip}")
        return False
    except NetmikoTimeoutException:
        print(f"  ✗ CONNECTION TIMEOUT: Device {ip} is not reachable or not responding")
        return False
    except socket.timeout:
        print(f"  ✗ SOCKET TIMEOUT: Device {ip} took too long to respond")
        return False
    except socket.gaierror:
        print(f"  ✗ DNS ERROR: Cannot resolve {ip}")
        return False
    except ConnectionRefusedError:
        print(f"  ✗ CONNECTION REFUSED: SSH may not be enabled on {ip}")
        return False
    except Exception as e:
        print(f"  ✗ UNEXPECTED ERROR: {e}")
        return False
    finally:
        if conn:
            try:
                conn.disconnect()
            except:
                pass

def validate_connectivity(ip, timeout=2):
    """Quick check if device is reachable"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, 22))  # Check SSH port
        sock.close()
        return result == 0
    except:
        return False

def main():
    print("="*60)
    print("Network Device Collector")
    print("="*60)
    
    # Check credentials
    if not USE_SSH_KEY:
        if PASSWORD == "your_password" or not USERNAME or not PASSWORD:
            print("ERROR: Please update USERNAME and PASSWORD variables in the script")
            return
    else:
        if not SSH_KEY_FILE or not Path(SSH_KEY_FILE).exists():
            print(f"ERROR: SSH key file '{SSH_KEY_FILE}' not found")
            return
        if not USERNAME:
            print("ERROR: USERNAME is required even with SSH key authentication")
            return
    
    devices = []
    try:
        with open(DEVICE_LIST, 'r') as f:
            devices = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print(f"ERROR: Create '{DEVICE_LIST}' with one IP per line")
        return
    
    if not devices:
        print(f"ERROR: No devices found in {DEVICE_LIST}")
        return
    
    print(f"Found {len(devices)} devices")
    
    # Check if global files exist and ask about clearing them
    if CREATE_GLOBAL_CSV:
        global_files = [
            'network_data/global_mac_table.csv',
            'network_data/global_arp_table.csv',
            'network_data/global_neighbor_table.csv'
        ]
        
        existing_globals = [f for f in global_files if Path(f).exists()]
        if existing_globals:
            print("\nExisting global CSV files found:")
            for f in existing_globals:
                print(f"  - {f}")
            response = input("Clear existing global CSV files? (y/n): ")
            if response.lower() == 'y':
                for f in existing_globals:
                    Path(f).unlink()
                print("Global CSV files cleared.")
    
    # Optional: Quick connectivity check
    print("\nPerforming connectivity check...")
    reachable = []
    unreachable = []
    for ip in devices:
        if validate_connectivity(ip):
            reachable.append(ip)
            print(f"  ✓ {ip} is reachable")
        else:
            unreachable.append(ip)
            print(f"  ✗ {ip} is NOT reachable on SSH port 22")
    
    if unreachable:
        print(f"\nWarning: {len(unreachable)} device(s) appear unreachable")
        response = input("Continue with reachable devices only? (y/n): ")
        if response.lower() != 'y':
            print("Exiting...")
            return
        devices = reachable
    
    if not devices:
        print("No reachable devices to process")
        return
    
    print(f"\nProcessing {len(devices)} reachable device(s)\n")
    
    success = 0
    failed = []
    for idx, ip in enumerate(devices, 1):
        print(f"[{idx}/{len(devices)}] Processing {ip}")
        if collect_from_device(ip, USERNAME, PASSWORD, ENABLE_PASSWORD, USE_SSH_KEY, SSH_KEY_FILE):
            success += 1
        else:
            failed.append(ip)
    
    print("\n" + "="*60)
    print(f"Complete! {success}/{len(devices)} successful")
    
    # Report on global files created
    if CREATE_GLOBAL_CSV:
        global_files = [
            'network_data/global_mac_table.csv',
            'network_data/global_arp_table.csv',
            'network_data/global_neighbor_table.csv'
        ]
        
        print("\nGlobal CSV files created:")
        for gf in global_files:
            if Path(gf).exists():
                row_count = sum(1 for line in open(gf)) - 1  # Subtract header row
                print(f"  - {gf} ({row_count} total entries)")
    
    if failed:
        print(f"\nFailed devices:")
        for ip in failed:
            print(f"  - {ip}")
        
        # Optionally save failed devices to a file for retry
        with open('failed_devices.txt', 'w') as f:
            for ip in failed:
                f.write(f"{ip}\n")
        print(f"\nFailed devices saved to 'failed_devices.txt' for retry")

if __name__ == "__main__":
    main()
