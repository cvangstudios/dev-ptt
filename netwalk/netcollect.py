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
        
        # Device ID
        device_match = re.search(r'Device ID:\s*(.+)', entry)
        if device_match:
            neighbor['device_id'] = device_match.group(1).strip()
        
        # IP address
        ip_match = re.search(r'IP address:\s*(\d+\.\d+\.\d+\.\d+)', entry)
        if ip_match:
            neighbor['ip_address'] = ip_match.group(1)
        
        # Platform
        platform_match = re.search(r'Platform:\s*([^,]+)', entry)
        if platform_match:
            neighbor['platform'] = platform_match.group(1).strip()
        
        # Local and Remote interfaces
        intf_match = re.search(r'Interface:\s*([^,]+),\s*Port ID \(outgoing port\):\s*(.+)', entry)
        if intf_match:
            neighbor['local_port'] = intf_match.group(1).strip()
            neighbor['remote_port'] = intf_match.group(2).strip()
        
        # Native VLAN
        vlan_match = re.search(r'Native VLAN:\s*(\d+)', entry)
        if vlan_match:
            neighbor['native_vlan'] = vlan_match.group(1)
        
        # Duplex
        duplex_match = re.search(r'Duplex:\s*(\w+)', entry)
        if duplex_match:
            neighbor['duplex'] = duplex_match.group(1)
        
        if neighbor.get('device_id'):
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
                        'local_port': entry.get('local_port', ''),
                        'device_id': entry.get('destination_host', entry.get('device_id', '')),
                        'ip_address': entry.get('management_ip', ''),
                        'platform': entry.get('platform', ''),
                        'remote_port': entry.get('remote_port', ''),
                        'native_vlan': entry.get('native_vlan', ''),
                        'duplex': entry.get('duplex', '')
                    })
        except Exception as e:
            print(f"    NTC parsing failed: {e}")
        
        # If NTC failed or returned nothing, use manual parsing
        if not cdp_data:
            print("    Using manual CDP parsing...")
            cdp_data = parse_cdp_manual(cdp_output)
            print(f"    Manual parsed {len(cdp_data)} CDP entries")
        
        # Save CDP data
        if cdp_data:
            with open(output_dir / 'cdp_neighbors.csv', 'w', newline='') as f:
                fieldnames = ['local_port', 'device_id', 'remote_port', 'ip_address', 'platform', 'native_vlan', 'duplex']
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(cdp_data)
            
            print(f"    Saved {len(cdp_data)} CDP neighbors")
            for n in cdp_data[:3]:  # Show first 3
                print(f"      {n.get('local_port', 'N/A')} -> {n.get('device_id', 'N/A')}")
        
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
                                'vlan': entry.get('vlan', ''),
                                'mac': entry.get('destination_address', entry.get('mac', '')),
                                'type': entry.get('type', ''),
                                'ports': entry.get('destination_port', entry.get('ports', ''))
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
                        'vlan': match.group(1),
                        'mac': match.group(2),
                        'type': match.group(3),
                        'ports': match.group(4)
                    })
        
        # Save MAC data
        if mac_data:
            with open(output_dir / 'mac_table.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['vlan', 'mac', 'type', 'ports'])
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
                        'ip': entry.get('address', entry.get('ip', '')),
                        'mac': entry.get('mac', ''),
                        'interface': entry.get('interface', '')
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
                        'ip': match.group(1),
                        'mac': match.group(2),
                        'interface': match.group(3)
                    })
        
        # Save ARP data
        if arp_data:
            with open(output_dir / 'arp_table.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['ip', 'mac', 'interface'])
                writer.writeheader()
                writer.writerows(arp_data)
            print(f"    Saved {len(arp_data)} ARP entries")
        
        # ========== VLAN ==========
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
                        'name': entry.get('name', ''),
                        'status': entry.get('status', ''),
                        'interfaces': interfaces
                    })
        except:
            pass
        
        # Save VLAN data
        if vlan_data:
            with open(output_dir / 'vlan_table.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['vlan_id', 'name', 'status', 'interfaces'])
                writer.writeheader()
                writer.writerows(vlan_data)
            print(f"    Saved {len(vlan_data)} VLANs")
        
        # ========== CORRELATE MAC/ARP ==========
        if mac_data and arp_data:
            print("  Correlating MAC and ARP...")
            
            # Create lookup
            arp_lookup = {}
            for arp in arp_data:
                if arp['mac']:
                    # Normalize MAC
                    norm_mac = arp['mac'].lower().replace(':', '').replace('.', '').replace('-', '')
                    arp_lookup[norm_mac] = arp['ip']
            
            correlated = []
            for mac in mac_data:
                if mac['mac']:
                    norm_mac = mac['mac'].lower().replace(':', '').replace('.', '').replace('-', '')
                    ip = arp_lookup.get(norm_mac, '')
                    
                    correlated.append({
                        'vlan': mac['vlan'],
                        'mac': mac['mac'],
                        'type': mac['type'],
                        'ports': mac['ports'],
                        'ip': ip
                    })
            
            if correlated:
                with open(output_dir / 'mac_arp_correlated.csv', 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=['vlan', 'mac', 'type', 'ports', 'ip'])
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
