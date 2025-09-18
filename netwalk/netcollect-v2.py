#!/usr/bin/env python3
"""
Network Device Collector with TextFSM CDP/LLDP Parsing
Collects and parses MAC tables, ARP tables, CDP/LLDP neighbors, and VLANs
"""

from netmiko import ConnectHandler
from ntc_templates.parse import parse_output
import csv
from datetime import datetime
from pathlib import Path
import re

# EDIT THESE
USERNAME = "admin"
PASSWORD = "your_password"
DEVICE_LIST = "devices.txt"  # One IP per line

def parse_cdp_neighbors(cdp_output, device_type):
    """Parse CDP neighbors using TextFSM"""
    try:
        # Use NTC templates to parse CDP output
        parsed = parse_output(platform=device_type, command='show cdp neighbors detail', data=cdp_output)
        
        # Format the parsed data
        neighbors = []
        for entry in parsed:
            neighbor = {
                'local_interface': entry.get('local_port', ''),
                'neighbor_device': entry.get('destination_host', entry.get('device_id', '')),
                'neighbor_interface': entry.get('remote_port', ''),
                'neighbor_ip': entry.get('management_ip', ''),
                'platform': entry.get('platform', ''),
                'capabilities': entry.get('capabilities', ''),
                'software_version': entry.get('software_version', '')
            }
            neighbors.append(neighbor)
        return neighbors
    except:
        # Fallback to basic parsing if TextFSM fails
        return parse_cdp_basic(cdp_output)

def parse_cdp_basic(output):
    """Basic CDP parsing as fallback"""
    neighbors = []
    current = {}
    
    for line in output.split('\n'):
        if 'Device ID' in line and ':' in line:
            if current:
                neighbors.append(current)
            current = {'neighbor_device': line.split(':')[1].strip()}
        elif 'IP address' in line and current:
            current['neighbor_ip'] = line.split(':')[1].strip()
        elif 'Platform' in line and current:
            current['platform'] = line.split(':')[1].strip().split(',')[0]
        elif 'Interface' in line and current:
            parts = line.split(':')[1].strip().split(',')
            current['local_interface'] = parts[0].strip()
            if len(parts) > 1:
                port_part = parts[1].replace('Port ID (outgoing port)', '').strip()
                current['neighbor_interface'] = port_part.strip(':').strip()
        elif 'Capabilities' in line and current:
            current['capabilities'] = line.split(':')[1].strip()
    
    if current:
        neighbors.append(current)
    
    return neighbors

def parse_lldp_neighbors(lldp_output, device_type):
    """Parse LLDP neighbors using TextFSM"""
    try:
        # Use NTC templates to parse LLDP output
        parsed = parse_output(platform=device_type, command='show lldp neighbors detail', data=lldp_output)
        
        neighbors = []
        for entry in parsed:
            neighbor = {
                'local_interface': entry.get('local_interface', entry.get('local_port', '')),
                'neighbor_device': entry.get('neighbor', entry.get('system_name', '')),
                'neighbor_interface': entry.get('neighbor_port_id', entry.get('remote_port', '')),
                'neighbor_ip': entry.get('management_address', ''),
                'platform': entry.get('system_description', ''),
                'capabilities': entry.get('capabilities', ''),
                'protocol': 'LLDP'
            }
            neighbors.append(neighbor)
        return neighbors
    except:
        # Fallback to basic parsing
        return parse_lldp_basic(lldp_output)

def parse_lldp_basic(output):
    """Basic LLDP parsing as fallback"""
    neighbors = []
    current = {}
    
    for line in output.split('\n'):
        if 'Local Intf' in line and ':' in line:
            if current:
                neighbors.append(current)
            current = {'local_interface': line.split(':')[1].strip(), 'protocol': 'LLDP'}
        elif 'System Name' in line and current:
            current['neighbor_device'] = line.split(':')[1].strip()
        elif 'Port id' in line and current:
            current['neighbor_interface'] = line.split(':')[1].strip()
        elif 'Management Addresses' in line and current:
            # Next line usually has the IP
            current['neighbor_ip'] = line.split(':')[1].strip() if ':' in line else ''
        elif 'System Description' in line and current:
            current['platform'] = line.split(':')[1].strip()
    
    if current:
        neighbors.append(current)
    
    return neighbors

def collect_from_device(ip, username, password):
    """Collect data from one device"""
    print(f"Connecting to {ip}...")
    
    # Try to connect
    device = {
        'device_type': 'cisco_ios',  # Will try to auto-detect
        'ip': ip,
        'username': username,
        'password': password,
        'timeout': 30,
    }
    
    try:
        # Connect
        conn = ConnectHandler(**device)
        hostname = conn.find_prompt().strip('#>')
        device_type = conn.device_type
        print(f"  Connected to {hostname} (type: {device_type})")
        
        # Create output folder
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_hostname = re.sub(r'[^\w\-_]', '_', hostname)
        output_dir = Path(f"network_data/{safe_hostname}_{ip}_{timestamp}")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Collect MAC table
        print("  Getting MAC table...")
        mac_output = conn.send_command('show mac address-table')
        with open(output_dir / 'mac_table_raw.txt', 'w') as f:
            f.write(mac_output)
        
        # Parse MAC table
        mac_data = []
        try:
            parsed_mac = parse_output(platform=device_type, command='show mac address-table', data=mac_output)
            for entry in parsed_mac:
                mac_data.append({
                    'vlan': entry.get('vlan', ''),
                    'mac': entry.get('destination_address', entry.get('mac', '')),
                    'type': entry.get('type', 'dynamic'),
                    'interface': entry.get('destination_port', entry.get('ports', ''))
                })
        except:
            # Fallback to regex parsing
            for line in mac_output.split('\n'):
                match = re.search(r'(\d+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+(\w+)\s+(\S+)', line, re.I)
                if match:
                    mac_data.append({
                        'vlan': match.group(1),
                        'mac': match.group(2),
                        'type': match.group(3),
                        'interface': match.group(4)
                    })
        
        if mac_data:
            with open(output_dir / 'mac_table.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['vlan', 'mac', 'type', 'interface'])
                writer.writeheader()
                writer.writerows(mac_data)
        
        # Collect ARP table
        print("  Getting ARP table...")
        arp_output = conn.send_command('show ip arp')
        with open(output_dir / 'arp_table_raw.txt', 'w') as f:
            f.write(arp_output)
        
        # Parse ARP
        arp_data = []
        try:
            parsed_arp = parse_output(platform=device_type, command='show ip arp', data=arp_output)
            for entry in parsed_arp:
                arp_data.append({
                    'ip': entry.get('address', entry.get('ip', '')),
                    'mac': entry.get('mac', ''),
                    'interface': entry.get('interface', '')
                })
        except:
            # Fallback to regex
            for line in arp_output.split('\n'):
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+\S+\s+(\S+)', line, re.I)
                if match:
                    arp_data.append({
                        'ip': match.group(1),
                        'mac': match.group(2),
                        'interface': match.group(3)
                    })
        
        if arp_data:
            with open(output_dir / 'arp_table.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['ip', 'mac', 'interface'])
                writer.writeheader()
                writer.writerows(arp_data)
        
        # Collect CDP neighbors
        print("  Getting CDP neighbors...")
        cdp_output = conn.send_command('show cdp neighbors detail')
        with open(output_dir / 'cdp_neighbors_raw.txt', 'w') as f:
            f.write(cdp_output)
        
        # Parse CDP with TextFSM
        cdp_neighbors = []
        if 'CDP is not enabled' not in cdp_output:
            cdp_neighbors = parse_cdp_neighbors(cdp_output, device_type)
        
        # Try LLDP if no CDP or if Arista
        if not cdp_neighbors or device_type == 'arista_eos':
            print("  Getting LLDP neighbors...")
            lldp_output = conn.send_command('show lldp neighbors detail')
            with open(output_dir / 'lldp_neighbors_raw.txt', 'w') as f:
                f.write(lldp_output)
            
            if 'LLDP is not enabled' not in lldp_output:
                lldp_neighbors = parse_lldp_neighbors(lldp_output, device_type)
                cdp_neighbors.extend(lldp_neighbors)
        
        # Save parsed neighbors to CSV
        if cdp_neighbors:
            fieldnames = set()
            for neighbor in cdp_neighbors:
                fieldnames.update(neighbor.keys())
            
            with open(output_dir / 'neighbors.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=sorted(list(fieldnames)))
                writer.writeheader()
                writer.writerows(cdp_neighbors)
            
            print(f"    Found {len(cdp_neighbors)} neighbors")
        
        # Collect VLANs
        print("  Getting VLANs...")
        vlan_output = conn.send_command('show vlan')
        with open(output_dir / 'vlans_raw.txt', 'w') as f:
            f.write(vlan_output)
        
        # Parse VLANs
        vlan_data = []
        try:
            parsed_vlans = parse_output(platform=device_type, command='show vlan', data=vlan_output)
            for entry in parsed_vlans:
                vlan_data.append({
                    'vlan_id': entry.get('vlan_id', ''),
                    'name': entry.get('name', ''),
                    'status': entry.get('status', 'active'),
                    'interfaces': ', '.join(entry.get('interfaces', []))
                })
        except:
            # Basic parsing
            for line in vlan_output.split('\n'):
                match = re.search(r'^(\d+)\s+(\S+)\s+(\w+)', line)
                if match:
                    vlan_data.append({
                        'vlan_id': match.group(1),
                        'name': match.group(2),
                        'status': match.group(3),
                        'interfaces': ''
                    })
        
        if vlan_data:
            with open(output_dir / 'vlans.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['vlan_id', 'name', 'status', 'interfaces'])
                writer.writeheader()
                writer.writerows(vlan_data)
        
        # Create connectivity report
        with open(output_dir / 'connectivity_report.txt', 'w') as f:
            f.write(f"Device Connectivity Report\n")
            f.write(f"="*60 + "\n")
            f.write(f"Device: {hostname}\n")
            f.write(f"IP: {ip}\n")
            f.write(f"Type: {device_type}\n")
            f.write(f"Collected: {timestamp}\n\n")
            
            f.write("Connected Devices:\n")
            f.write("-"*40 + "\n")
            for n in cdp_neighbors:
                f.write(f"Local Port: {n.get('local_interface', 'Unknown')}\n")
                f.write(f"  -> Neighbor: {n.get('neighbor_device', 'Unknown')}\n")
                f.write(f"  -> Neighbor Port: {n.get('neighbor_interface', 'Unknown')}\n")
                f.write(f"  -> Neighbor IP: {n.get('neighbor_ip', 'Unknown')}\n")
                f.write(f"  -> Platform: {n.get('platform', 'Unknown')}\n")
                f.write("\n")
            
            f.write(f"\nTotal Neighbors: {len(cdp_neighbors)}\n")
            f.write(f"MAC Entries: {len(mac_data)}\n")
            f.write(f"ARP Entries: {len(arp_data)}\n")
            f.write(f"VLANs: {len(vlan_data)}\n")
        
        conn.disconnect()
        print(f"  [SUCCESS] Data saved to {output_dir}")
        return True
        
    except Exception as e:
        print(f"  [FAILED] {e}")
        return False

def main():
    """Main function"""
    print("="*60)
    print("Network Device Collector with TextFSM Parsing")
    print("="*60)
    
    # Check if TextFSM is installed
    try:
        from ntc_templates.parse import parse_output
        print("TextFSM parsing enabled")
    except ImportError:
        print("WARNING: Install textfsm and ntc-templates for better parsing")
        print("Run: pip install textfsm ntc-templates")
    
    # Read device list
    devices = []
    try:
        with open(DEVICE_LIST, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    devices.append(line)
    except FileNotFoundError:
        print(f"ERROR: {DEVICE_LIST} not found!")
        print("Create a file with one IP per line")
        return
    
    if not devices:
        print(f"No devices found in {DEVICE_LIST}")
        return
    
    print(f"Found {len(devices)} devices\n")
    
    # Process each device
    success = 0
    failed = 0
    
    for ip in devices:
        if collect_from_device(ip, USERNAME, PASSWORD):
            success += 1
        else:
            failed += 1
    
    # Summary
    print("\n" + "="*60)
    print(f"Complete! Success: {success}, Failed: {failed}")
    print(f"Check network_data/ folder for results")
    print("\nKey files created per device:")
    print("  - neighbors.csv: Device connectivity with ports and IPs")
    print("  - connectivity_report.txt: Human-readable connectivity")
    print("  - mac_table.csv: MAC addresses")
    print("  - arp_table.csv: IP to MAC mappings")

if __name__ == "__main__":
    main()
