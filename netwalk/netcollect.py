#!/usr/bin/env python3
"""
Network Device Collector using NTC Templates (Simplified and Working)
Uses the actual field names from NTC templates
"""

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException
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

def collect_from_device(ip, username, password):
    """Collect data from one device"""
    print(f"\nConnecting to {ip}...")
    
    # Connection parameters
    device = {
        'device_type': 'cisco_ios',  # Start with cisco_ios
        'ip': ip,
        'username': username,
        'password': password,
        'timeout': 30,
    }
    
    try:
        # Connect
        conn = ConnectHandler(**device)
        hostname = conn.find_prompt().strip('#>')
        
        # Detect device type from version
        version_output = conn.send_command('show version')
        if 'NX-OS' in version_output or 'Nexus' in version_output:
            device_type = 'cisco_nxos'
        elif 'Arista' in version_output:
            device_type = 'arista_eos'
        else:
            device_type = 'cisco_ios'
        
        conn.device_type = device_type
        print(f"  Connected to {hostname} (type: {device_type})")
        
        # Create output folder
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_hostname = re.sub(r'[^\w\-_]', '_', hostname)
        output_dir = Path(f"network_data/{safe_hostname}_{ip}_{timestamp}")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # ========== CDP NEIGHBORS ==========
        print("  Getting CDP neighbors detail...")
        cdp_output = conn.send_command('show cdp neighbors detail')
        
        with open(output_dir / 'cdp_raw.txt', 'w') as f:
            f.write(cdp_output)
        
        cdp_neighbors = []
        if 'CDP is not enabled' not in cdp_output:
            try:
                # Parse with NTC templates
                parsed = parse_output(platform=device_type, command='show cdp neighbors detail', data=cdp_output)
                
                # Debug: Save what NTC actually returns
                with open(output_dir / 'cdp_parsed.json', 'w') as f:
                    json.dump(parsed, f, indent=2, default=str)
                
                if parsed:
                    print(f"    NTC returned {len(parsed)} CDP entries")
                    
                    # Map the actual NTC fields to our CSV fields
                    for entry in parsed:
                        # NTC template fields for CDP (based on actual templates):
                        # - destination_host or device_id: Remote device name
                        # - management_ip: Management IP address
                        # - platform: Platform/model
                        # - remote_port: Remote interface
                        # - local_port: Local interface
                        # - software_version: Version info
                        
                        neighbor = {
                            'protocol': 'CDP',
                            'local_port': entry.get('local_port', ''),
                            'device_id': entry.get('destination_host', entry.get('device_id', '')),
                            'platform': entry.get('platform', ''),
                            'remote_port': entry.get('remote_port', ''),
                            'ip_address': entry.get('management_ip', ''),
                            'version': entry.get('software_version', ''),
                        }
                        
                        cdp_neighbors.append(neighbor)
                        
                        # Debug print
                        print(f"      {neighbor['local_port']} -> {neighbor['device_id']} ({neighbor['remote_port']})")
                
            except Exception as e:
                print(f"    CDP parsing error: {e}")
        
        # Save CDP to CSV
        if cdp_neighbors:
            with open(output_dir / 'cdp_neighbors.csv', 'w', newline='') as f:
                fieldnames = ['protocol', 'local_port', 'device_id', 'remote_port', 'ip_address', 'platform', 'version']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(cdp_neighbors)
            print(f"    Saved {len(cdp_neighbors)} CDP neighbors to CSV")
        
        # ========== LLDP NEIGHBORS ==========
        print("  Getting LLDP neighbors detail...")
        lldp_output = conn.send_command('show lldp neighbors detail')
        
        with open(output_dir / 'lldp_raw.txt', 'w') as f:
            f.write(lldp_output)
        
        lldp_neighbors = []
        if 'LLDP is not enabled' not in lldp_output:
            try:
                parsed = parse_output(platform=device_type, command='show lldp neighbors detail', data=lldp_output)
                
                # Debug: Save what NTC actually returns
                with open(output_dir / 'lldp_parsed.json', 'w') as f:
                    json.dump(parsed, f, indent=2, default=str)
                
                if parsed:
                    print(f"    NTC returned {len(parsed)} LLDP entries")
                    
                    for entry in parsed:
                        neighbor = {
                            'protocol': 'LLDP',
                            'local_port': entry.get('local_interface', entry.get('local_port', '')),
                            'device_id': entry.get('neighbor', entry.get('system_name', '')),
                            'platform': entry.get('system_description', ''),
                            'remote_port': entry.get('neighbor_port_id', entry.get('remote_port', '')),
                            'ip_address': entry.get('management_address', ''),
                            'version': '',
                        }
                        
                        lldp_neighbors.append(neighbor)
                        print(f"      {neighbor['local_port']} -> {neighbor['device_id']} ({neighbor['remote_port']})")
                
            except Exception as e:
                print(f"    LLDP parsing error: {e}")
        
        # Save LLDP to CSV
        if lldp_neighbors:
            with open(output_dir / 'lldp_neighbors.csv', 'w', newline='') as f:
                fieldnames = ['protocol', 'local_port', 'device_id', 'remote_port', 'ip_address', 'platform', 'version']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(lldp_neighbors)
            print(f"    Saved {len(lldp_neighbors)} LLDP neighbors to CSV")
        
        # ========== MAC ADDRESS TABLE ==========
        print("  Getting MAC address table...")
        
        # Try different commands
        mac_data = []
        for cmd in ['show mac address-table', 'show mac-address-table']:
            mac_output = conn.send_command(cmd)
            if 'Invalid' not in mac_output:
                with open(output_dir / 'mac_raw.txt', 'w') as f:
                    f.write(mac_output)
                
                try:
                    parsed = parse_output(platform=device_type, command=cmd, data=mac_output)
                    
                    # Debug: Save what NTC actually returns
                    with open(output_dir / 'mac_parsed.json', 'w') as f:
                        json.dump(parsed, f, indent=2, default=str)
                    
                    if parsed:
                        print(f"    NTC returned {len(parsed)} MAC entries")
                        
                        for entry in parsed:
                            # NTC fields: destination_address (MAC), destination_port (interface), vlan, type
                            mac_entry = {
                                'vlan': entry.get('vlan', ''),
                                'mac_address': entry.get('destination_address', entry.get('mac', '')),
                                'type': entry.get('type', 'dynamic'),
                                'ports': entry.get('destination_port', entry.get('ports', ''))
                            }
                            mac_data.append(mac_entry)
                        break
                        
                except Exception as e:
                    print(f"    MAC parsing error with {cmd}: {e}")
        
        # Save MAC table
        if mac_data:
            with open(output_dir / 'mac_table.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['vlan', 'mac_address', 'type', 'ports'])
                writer.writeheader()
                writer.writerows(mac_data)
            print(f"    Saved {len(mac_data)} MAC entries to CSV")
        
        # ========== ARP TABLE ==========
        print("  Getting ARP table...")
        arp_output = conn.send_command('show ip arp')
        
        with open(output_dir / 'arp_raw.txt', 'w') as f:
            f.write(arp_output)
        
        arp_data = []
        try:
            parsed = parse_output(platform=device_type, command='show ip arp', data=arp_output)
            
            # Debug: Save what NTC actually returns
            with open(output_dir / 'arp_parsed.json', 'w') as f:
                json.dump(parsed, f, indent=2, default=str)
            
            if parsed:
                print(f"    NTC returned {len(parsed)} ARP entries")
                
                for entry in parsed:
                    # NTC fields: address (IP), mac, interface
                    arp_entry = {
                        'address': entry.get('address', entry.get('ip', '')),
                        'mac': entry.get('mac', ''),
                        'interface': entry.get('interface', '')
                    }
                    arp_data.append(arp_entry)
        
        except Exception as e:
            print(f"    ARP parsing error: {e}")
        
        # Save ARP table
        if arp_data:
            with open(output_dir / 'arp_table.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['address', 'mac', 'interface'])
                writer.writeheader()
                writer.writerows(arp_data)
            print(f"    Saved {len(arp_data)} ARP entries to CSV")
        
        # ========== VLANs ==========
        print("  Getting VLANs...")
        vlan_output = conn.send_command('show vlan brief')
        
        with open(output_dir / 'vlan_raw.txt', 'w') as f:
            f.write(vlan_output)
        
        vlan_data = []
        try:
            parsed = parse_output(platform=device_type, command='show vlan brief', data=vlan_output)
            if not parsed:
                # Try without 'brief'
                vlan_output = conn.send_command('show vlan')
                parsed = parse_output(platform=device_type, command='show vlan', data=vlan_output)
            
            # Debug: Save what NTC actually returns
            with open(output_dir / 'vlan_parsed.json', 'w') as f:
                json.dump(parsed, f, indent=2, default=str)
            
            if parsed:
                print(f"    NTC returned {len(parsed)} VLAN entries")
                
                for entry in parsed:
                    # Handle interfaces as list
                    interfaces = entry.get('interfaces', [])
                    if isinstance(interfaces, list):
                        interfaces = ', '.join(interfaces)
                    
                    vlan_entry = {
                        'vlan_id': entry.get('vlan_id', ''),
                        'name': entry.get('name', ''),
                        'status': entry.get('status', ''),
                        'interfaces': interfaces
                    }
                    vlan_data.append(vlan_entry)
        
        except Exception as e:
            print(f"    VLAN parsing error: {e}")
        
        # Save VLAN table
        if vlan_data:
            with open(output_dir / 'vlan_table.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['vlan_id', 'name', 'status', 'interfaces'])
                writer.writeheader()
                writer.writerows(vlan_data)
            print(f"    Saved {len(vlan_data)} VLAN entries to CSV")
        
        # ========== COMBINED NEIGHBORS ==========
        all_neighbors = cdp_neighbors + lldp_neighbors
        if all_neighbors:
            with open(output_dir / 'all_neighbors.csv', 'w', newline='') as f:
                fieldnames = ['protocol', 'local_port', 'device_id', 'remote_port', 'ip_address', 'platform', 'version']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(all_neighbors)
        
        # ========== CORRELATE MAC AND ARP ==========
        print("  Correlating MAC and ARP...")
        correlated = []
        
        # Create ARP lookup by MAC
        arp_by_mac = {}
        for arp in arp_data:
            if arp['mac']:
                # Normalize MAC for comparison
                norm_mac = arp['mac'].lower().replace(':', '').replace('.', '').replace('-', '')
                arp_by_mac[norm_mac] = arp
        
        # Process each MAC entry
        for mac in mac_data:
            if mac['mac_address']:
                # Normalize MAC for comparison
                norm_mac = mac['mac_address'].lower().replace(':', '').replace('.', '').replace('-', '')
                
                # Look for ARP entry
                if norm_mac in arp_by_mac:
                    arp = arp_by_mac[norm_mac]
                    correlated.append({
                        'vlan': mac['vlan'],
                        'mac_address': mac['mac_address'],
                        'type': mac['type'],
                        'ports': mac['ports'],
                        'ip_address': arp['address'],
                        'arp_interface': arp['interface']
                    })
                else:
                    correlated.append({
                        'vlan': mac['vlan'],
                        'mac_address': mac['mac_address'],
                        'type': mac['type'],
                        'ports': mac['ports'],
                        'ip_address': '',
                        'arp_interface': ''
                    })
        
        # Save correlated data
        if correlated:
            with open(output_dir / 'mac_arp_correlated.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['vlan', 'mac_address', 'type', 'ports', 'ip_address', 'arp_interface'])
                writer.writeheader()
                writer.writerows(correlated)
            print(f"    Saved {len(correlated)} correlated MAC/ARP entries")
        
        conn.disconnect()
        print(f"  [SUCCESS] Data saved to {output_dir}")
        return True
        
    except Exception as e:
        print(f"  [FAILED] {e}")
        return False

def main():
    """Main function"""
    print("="*60)
    print("Network Device Collector (NTC Templates)")
    print("="*60)
    
    # Read device list
    devices = []
    try:
        with open(DEVICE_LIST, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    devices.append(line)
    except FileNotFoundError:
        print(f"ERROR: Create '{DEVICE_LIST}' with one IP per line")
        return
    
    if not devices:
        print(f"No devices found in {DEVICE_LIST}")
        return
    
    print(f"Found {len(devices)} devices")
    
    # Process each device
    success = 0
    failed = 0
    
    for idx, ip in enumerate(devices, 1):
        print(f"\n[{idx}/{len(devices)}] Device: {ip}")
        if collect_from_device(ip, USERNAME, PASSWORD):
            success += 1
        else:
            failed += 1
    
    print("\n" + "="*60)
    print(f"Complete! Success: {success}, Failed: {failed}")
    print(f"Check 'network_data/' folder for results")
    print("\nDebug files (*_parsed.json) show actual NTC template output")

if __name__ == "__main__":
    main()
