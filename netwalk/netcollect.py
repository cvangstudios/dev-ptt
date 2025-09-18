#!/usr/bin/env python3
"""
Network Device Collector - Simple Netmiko Version
Collects MAC tables, ARP tables, neighbors, and VLANs from network devices
"""

from netmiko import ConnectHandler
import csv
from datetime import datetime
from pathlib import Path
import re

# EDIT THESE
USERNAME = "admin"
PASSWORD = "your_password"
DEVICE_LIST = "devices.txt"  # One IP per line

def collect_from_device(ip, username, password):
    """Collect data from one device"""
    print(f"Connecting to {ip}...")
    
    # Try to connect
    device = {
        'device_type': 'cisco_ios',  # Will auto-detect
        'ip': ip,
        'username': username,
        'password': password,
        'timeout': 30,
    }
    
    try:
        # Connect
        conn = ConnectHandler(**device)
        hostname = conn.find_prompt().strip('#>')
        print(f"  Connected to {hostname}")
        
        # Create output folder
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_hostname = re.sub(r'[^\w\-_]', '_', hostname)
        output_dir = Path(f"network_data/{safe_hostname}_{ip}_{timestamp}")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Collect MAC table
        print("  Getting MAC table...")
        mac_output = conn.send_command('show mac address-table')
        with open(output_dir / 'mac_table.txt', 'w') as f:
            f.write(mac_output)
        
        # Parse MAC table to CSV
        mac_data = []
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
        with open(output_dir / 'arp_table.txt', 'w') as f:
            f.write(arp_output)
        
        # Parse ARP to CSV
        arp_data = []
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
        print("  Getting CDP/LLDP neighbors...")
        cdp_output = conn.send_command('show cdp neighbors detail')
        with open(output_dir / 'cdp_neighbors.txt', 'w') as f:
            f.write(cdp_output)
        
        # Collect VLANs
        print("  Getting VLANs...")
        vlan_output = conn.send_command('show vlan')
        with open(output_dir / 'vlans.txt', 'w') as f:
            f.write(vlan_output)
        
        # Create summary
        with open(output_dir / 'summary.txt', 'w') as f:
            f.write(f"Device: {hostname}\n")
            f.write(f"IP: {ip}\n")
            f.write(f"Collected: {timestamp}\n")
            f.write(f"MAC entries: {len(mac_data)}\n")
            f.write(f"ARP entries: {len(arp_data)}\n")
        
        conn.disconnect()
        print(f"  [SUCCESS] Data saved to {output_dir}")
        return True
        
    except Exception as e:
        print(f"  [FAILED] {e}")
        return False

def main():
    """Main function"""
    print("="*60)
    print("Network Device Collector")
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

if __name__ == "__main__":
    main()
