#!/usr/bin/env python3
"""
Network Device Collector - WORKING VERSION
This one actually parses CDP, MAC, ARP, and VLAN data correctly
"""

from netmiko import ConnectHandler
from ntc_templates.parse import parse_output
import csv
from datetime import datetime
from pathlib import Path
import re
import json

# EDIT THESE
USERNAME = "admin"
PASSWORD = "your_password"
DEVICE_LIST = "devices.txt"  # One IP per line

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
        
        if neighbor.get('neighbor_name'):
            neighbors.append(neighbor)
    
    return neighbors

def collect_from_device(ip, username, password):
    """Collect data from one device"""
    print(f"\nConnecting to {ip}...")
    
    device = {
        'device_type': 'cisco_ios',
        'ip': ip,
        'username': username,
        'password': password,
        'timeout': 30,
    }
    
    try:
        conn = ConnectHandler(**device)
        hostname = conn.find_prompt().strip('#>')
        print(f"  Connected to {hostname}")
        
        # Create output folder
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_hostname = re.sub(r'[^\w\-_]', '_', hostname)
        output_dir = Path(f"network_data/{safe_hostname}_{ip}_{timestamp}")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Detect device type
        version = conn.send_command('show version')
        if 'NX-OS' in version:
            device_type = 'cisco_nxos'
        elif 'IOS' in version:
            device_type = 'cisco_ios'
        else:
            device_type = 'cisco_ios'
        
        print(f"  Device type: {device_type}")
        
        # ========== CDP NEIGHBORS ==========
        print("  Collecting CDP neighbors...")
        cdp_output = conn.send_command('show cdp neighbors detail')
        
        # Save raw output
        with open(output_dir / 'cdp_raw.txt', 'w') as f:
            f.write(cdp_output)
        
        cdp_data = []
        
        # Try NTC templates first
        try:
            parsed = parse_output(platform=device_type, command='show cdp neighbors detail', data=cdp_output)
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
                        'neighbor_description': entry.get('neighbor_description', '')
                    })
        except Exception as e:
            print(f"    NTC parsing failed: {e}")
        
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
                    'neighbor_description': entry.get('neighbor_description', '')
                })
            print(f"    Manual parsed {len(cdp_data)} CDP entries")
        
        # Save CDP data
        if cdp_data:
            with open(output_dir / 'cdp_neighbors.csv', 'w', newline='') as f:
                fieldnames = ['local_interface', 'neighbor_name', 'neighbor_interface', 'mgmt_address', 'interface_ip', 'chassis_id', 'neighbor_description']
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(cdp_data)
            
            print(f"    Saved {len(cdp_data)} CDP neighbors")
            for n in cdp_data[:3]:  # Show first 3
                print(f"      {n.get('local_interface', 'N/A')} -> {n.get('neighbor_name', 'N/A')} ({n.get('neighbor_interface', 'N/A')})")
        
        # ========== MAC ADDRESS TABLE ==========
        print("  Collecting MAC address table...")
        
        mac_data = []
        # Try different commands
        for cmd in ['show mac address-table', 'show mac-address-table']:
            mac_output = conn.send_command(cmd)
            if 'Invalid' not in mac_output and 'Error' not in mac_output:
                # Save raw output
                with open(output_dir / 'mac_raw.txt', 'w') as f:
                    f.write(mac_output)
                
                try:
                    parsed = parse_output(platform=device_type, command=cmd, data=mac_output)
                    if parsed:
                        print(f"    NTC parsed {len(parsed)} MAC entries")
                        # Save what NTC returns
                        with open(output_dir / 'mac_ntc_output.json', 'w') as f:
                            json.dump(parsed, f, indent=2, default=str)
                        
                        for entry in parsed:
                            mac_data.append({
                                'vlan_id': entry.get('vlan_id', ''),
                                'mac_address': entry.get('mac_address', ''),
                                'type': entry.get('type', ''),
                                'ports': entry.get('ports', ''),
                                'age': entry.get('age', ''),
                                'secure': entry.get('secure', ''),
                                'ntfy': entry.get('ntfy', '')
                            })
                        break
                except:
                    pass
        
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
        
        # Save MAC data
        if mac_data:
            with open(output_dir / 'mac_table.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['vlan_id', 'mac_address', 'type', 'ports', 'age', 'secure', 'ntfy'])
                writer.writeheader()
                writer.writerows(mac_data)
            print(f"    Saved {len(mac_data)} MAC entries")
        
        # ========== ARP TABLE ==========
        print("  Collecting ARP table...")
        arp_output = conn.send_command('show ip arp')
        
        # Save raw output
        with open(output_dir / 'arp_raw.txt', 'w') as f:
            f.write(arp_output)
        
        arp_data = []
        
        try:
            parsed = parse_output(platform=device_type, command='show ip arp', data=arp_output)
            if parsed:
                print(f"    NTC parsed {len(parsed)} ARP entries")
                # Save what NTC returns
                with open(output_dir / 'arp_ntc_output.json', 'w') as f:
                    json.dump(parsed, f, indent=2, default=str)
                
                for entry in parsed:
                    arp_data.append({
                        'ip_address': entry.get('ip_address', ''),
                        'mac_address': entry.get('mac_address', ''),
                        'interface': entry.get('interface', ''),
                        'age': entry.get('age', '')
                    })
        except:
            pass
        
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
            with open(output_dir / 'arp_table.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['ip_address', 'mac_address', 'interface', 'age'])
                writer.writeheader()
                writer.writerows(arp_data)
            print(f"    Saved {len(arp_data)} ARP entries")
        
        # ========== LLDP NEIGHBORS (if no CDP or in addition) ==========
        print("  Collecting LLDP neighbors...")
        lldp_output = conn.send_command('show lldp neighbors detail')
        
        # Save raw output
        with open(output_dir / 'lldp_raw.txt', 'w') as f:
            f.write(lldp_output)
        
        lldp_data = []
        
        if 'LLDP is not enabled' not in lldp_output:
            try:
                parsed = parse_output(platform=device_type, command='show lldp neighbors detail', data=lldp_output)
                if parsed:
                    print(f"    NTC parsed {len(parsed)} LLDP entries")
                    # Save what NTC actually returns
                    with open(output_dir / 'lldp_ntc_output.json', 'w') as f:
                        json.dump(parsed, f, indent=2, default=str)
                    
                    # Map LLDP fields - they might be different from CDP
                    for entry in parsed:
                        lldp_data.append({
                            'local_interface': entry.get('local_interface', entry.get('local_port', '')),
                            'neighbor_name': entry.get('neighbor', entry.get('system_name', '')),
                            'mgmt_address': entry.get('management_address', entry.get('mgmt_address', '')),
                            'neighbor_interface': entry.get('neighbor_port_id', entry.get('remote_port', '')),
                            'chassis_id': entry.get('chassis_id', ''),
                        })
            except Exception as e:
                print(f"    LLDP parsing failed: {e}")
        
        # Save LLDP data
        if lldp_data:
            with open(output_dir / 'lldp_neighbors.csv', 'w', newline='') as f:
                fieldnames = ['local_interface', 'neighbor_name', 'neighbor_interface', 'mgmt_address', 'chassis_id']
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(lldp_data)
            
            print(f"    Saved {len(lldp_data)} LLDP neighbors")
        
        # Combine CDP and LLDP neighbors
        all_neighbors = []
        for n in cdp_data:
            n['protocol'] = 'CDP'
            all_neighbors.append(n)
        for n in lldp_data:
            n['protocol'] = 'LLDP'
            all_neighbors.append(n)
        
        if all_neighbors:
            with open(output_dir / 'all_neighbors.csv', 'w', newline='') as f:
                fieldnames = ['protocol', 'local_interface', 'neighbor_name', 'neighbor_interface', 'mgmt_address']
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(all_neighbors)
            print(f"    Saved {len(all_neighbors)} total neighbors (CDP + LLDP)")
        print("  Collecting VLANs...")
        vlan_output = conn.send_command('show vlan brief')
        
        # Save raw output
        with open(output_dir / 'vlan_raw.txt', 'w') as f:
            f.write(vlan_output)
        
        vlan_data = []
        
        try:
            parsed = parse_output(platform=device_type, command='show vlan brief', data=vlan_output)
            if not parsed:
                vlan_output = conn.send_command('show vlan')
                parsed = parse_output(platform=device_type, command='show vlan', data=vlan_output)
            
            if parsed:
                print(f"    NTC parsed {len(parsed)} VLANs")
                # Save what NTC returns
                with open(output_dir / 'vlan_ntc_output.json', 'w') as f:
                    json.dump(parsed, f, indent=2, default=str)
                
                for entry in parsed:
                    interfaces = entry.get('interfaces', [])
                    if isinstance(interfaces, list):
                        interfaces = ', '.join(interfaces)
                    
                    vlan_data.append({
                        'vlan_id': entry.get('vlan_id', ''),
                        'vlan_name': entry.get('vlan_name', ''),
                        'status': entry.get('status', ''),
                        'interfaces': interfaces
                    })
        except:
            pass
        
        # Save VLAN data
        if vlan_data:
            with open(output_dir / 'vlan_table.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['vlan_id', 'vlan_name', 'status', 'interfaces'])
                writer.writeheader()
                writer.writerows(vlan_data)
            print(f"    Saved {len(vlan_data)} VLANs")
        
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
                        'vlan_id': mac['vlan_id'],
                        'mac_address': mac['mac_address'],
                        'type': mac['type'],
                        'ports': mac['ports'],
                        'ip_address': ip
                    })
            
            if correlated:
                with open(output_dir / 'mac_arp_correlated.csv', 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=['vlan_id', 'mac_address', 'type', 'ports', 'ip_address'])
                    writer.writeheader()
                    writer.writerows(correlated)
                print(f"    Saved {len(correlated)} correlated entries")
        
        conn.disconnect()
        print(f"  ✓ SUCCESS - Data saved to {output_dir}")
        return True
        
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        return False

def main():
    print("="*60)
    print("Network Device Collector")
    print("="*60)
    
    devices = []
    try:
        with open(DEVICE_LIST, 'r') as f:
            devices = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print(f"ERROR: Create '{DEVICE_LIST}' with one IP per line")
        return
    
    print(f"Found {len(devices)} devices\n")
    
    success = 0
    for idx, ip in enumerate(devices, 1):
        print(f"[{idx}/{len(devices)}] Processing {ip}")
        if collect_from_device(ip, USERNAME, PASSWORD):
            success += 1
    
    print("\n" + "="*60)
    print(f"Complete! {success}/{len(devices)} successful")

if __name__ == "__main__":
    main()
