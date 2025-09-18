#!/usr/bin/env python3
"""
Network Device Collector using NTC Templates
Collects and parses MAC tables, ARP tables, CDP/LLDP neighbors, and VLANs
Uses NTC-templates for parsing, which are well-tested TextFSM templates

Required packages:
- pip install netmiko
- pip install ntc-templates
- pip install textfsm
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

def detect_device_type(conn):
    """Detect if device is IOS, NX-OS, or EOS"""
    print("  Detecting device type...")
    
    # Get version information
    version_output = ""
    device_type = conn.device_type  # Start with what Netmiko detected
    
    try:
        version_output = conn.send_command('show version', delay_factor=2)
    except:
        pass
    
    version_upper = version_output.upper()
    
    # Check for NX-OS (highest priority as it's often misdetected)
    if 'NX-OS' in version_upper or 'NEXUS' in version_upper:
        device_type = 'cisco_nxos'
        print("    Detected: Cisco NX-OS")
    # Check for Arista EOS
    elif 'ARISTA' in version_upper or 'EOS' in version_output:
        device_type = 'arista_eos'
        print("    Detected: Arista EOS")
    # Check for IOS-XE
    elif 'IOS-XE' in version_upper or 'IOS XE' in version_upper:
        device_type = 'cisco_ios'
        print("    Detected: Cisco IOS-XE")
    # Check for IOS-XR
    elif 'IOS-XR' in version_upper or 'IOS XR' in version_upper:
        device_type = 'cisco_xr'
        print("    Detected: Cisco IOS-XR")
    # Default to IOS for other Cisco devices
    elif 'CISCO IOS' in version_upper or 'CISCO' in version_upper:
        device_type = 'cisco_ios'
        print("    Detected: Cisco IOS")
    else:
        print(f"    Using default: {device_type}")
    
    # Update the connection's device type
    conn.device_type = device_type
    return device_type, version_output

def extract_system_name(device_id, strip_domains=[]):
    """
    Extract hostname from CDP Device ID field
    Handles formats like:
    - Hostname
    - Hostname.domain.com
    - Hostname(SerialNumber)
    - SerialNumber(Hostname)
    """
    if not device_id:
        return device_id
    
    hostname = device_id
    
    # Handle Hostname(Serial) format
    if '(' in hostname:
        hostname = hostname.split('(')[0].strip()
    
    # Strip configured domains
    for domain in strip_domains:
        if hostname.endswith(domain):
            hostname = hostname[:-(len(domain))].rstrip('.')
    
    # Also remove any .local, .lan, etc if not in strip list
    if '.' in hostname and not re.match(r'^\d+\.\d+\.\d+\.\d+', hostname):
        # It's not an IP, so remove domain
        hostname = hostname.split('.')[0]
    
    return hostname.strip()

def correlate_mac_arp(mac_data, arp_data):
    """Correlate MAC and ARP tables to create unified view"""
    correlated = []
    
    # Create lookup dictionary
    arp_by_mac = {}
    for arp in arp_data:
        mac = arp.get('mac', '').lower().replace(':', '').replace('.', '').replace('-', '')
        if mac:
            arp_by_mac[mac] = arp
    
    # Process MAC entries
    for mac_entry in mac_data:
        mac_addr = mac_entry.get('mac', '').lower().replace(':', '').replace('.', '').replace('-', '')
        
        entry = {
            'vlan': mac_entry.get('vlan', ''),
            'mac': mac_entry.get('mac', ''),
            'type': mac_entry.get('type', ''),
            'interface': mac_entry.get('interface', ''),
            'ip': '',
            'arp_interface': ''
        }
        
        # Look for matching ARP entry
        if mac_addr in arp_by_mac:
            arp_entry = arp_by_mac[mac_addr]
            entry['ip'] = arp_entry.get('ip', '')
            entry['arp_interface'] = arp_entry.get('interface', '')
        
        correlated.append(entry)
    
    # Add ARP entries without matching MAC
    processed_macs = set(m.get('mac', '').lower().replace(':', '').replace('.', '').replace('-', '') 
                        for m in mac_data if m.get('mac'))
    
    for arp_entry in arp_data:
        mac_addr = arp_entry.get('mac', '').lower().replace(':', '').replace('.', '').replace('-', '')
        if mac_addr and mac_addr not in processed_macs:
            entry = {
                'vlan': '',
                'mac': arp_entry.get('mac', ''),
                'type': 'ARP-only',
                'interface': '',
                'ip': arp_entry.get('ip', ''),
                'arp_interface': arp_entry.get('interface', '')
            }
            correlated.append(entry)
    
    return correlated

def collect_from_device(ip, username, password):
    """Collect data from one device"""
    print(f"\nConnecting to {ip}...")
    
    # Initial connection parameters
    device = {
        'device_type': 'autodetect',
        'ip': ip,
        'username': username,
        'password': password,
        'timeout': 30,
        'global_delay_factor': 2,
    }
    
    try:
        # Try autodetect first
        try:
            from netmiko import SSHDetect
            guesser = SSHDetect(**device)
            best_match = guesser.autodetect()
            device['device_type'] = best_match
            print(f"  Auto-detected: {best_match}")
        except:
            device['device_type'] = 'cisco_ios'
            print("  Auto-detect failed, using cisco_ios")
        
        # Connect
        conn = ConnectHandler(**device)
        hostname = conn.find_prompt().strip('#>')
        
        # Detect specific device type
        device_type, version_output = detect_device_type(conn)
        
        print(f"  Connected to {hostname} (type: {device_type})")
        
        # Create output folder
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_hostname = re.sub(r'[^\w\-_]', '_', hostname)
        output_dir = Path(f"network_data/{safe_hostname}_{ip}_{timestamp}")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Save version info
        with open(output_dir / 'version.txt', 'w') as f:
            f.write(version_output)
        
        # ========== MAC TABLE ==========
        print("  Getting MAC table...")
        mac_commands = [
            'show mac address-table',
            'show mac-address-table',
            'show mac address-table dynamic'
        ]
        
        mac_data = []
        for cmd in mac_commands:
            try:
                mac_output = conn.send_command(cmd, delay_factor=2)
                if 'Invalid' not in mac_output and 'Error' not in mac_output:
                    with open(output_dir / 'mac_table_raw.txt', 'w') as f:
                        f.write(mac_output)
                    
                    # Parse with NTC templates
                    parsed = parse_output(platform=device_type, command=cmd, data=mac_output)
                    if parsed:
                        for entry in parsed:
                            mac_data.append({
                                'vlan': entry.get('vlan', ''),
                                'mac': entry.get('destination_address', entry.get('mac', '')),
                                'type': entry.get('type', 'dynamic'),
                                'interface': entry.get('destination_port', entry.get('interface', ''))
                            })
                        print(f"    Parsed {len(mac_data)} MAC entries")
                        break
            except:
                continue
        
        if mac_data:
            with open(output_dir / 'mac_table.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['vlan', 'mac', 'type', 'interface'])
                writer.writeheader()
                writer.writerows(mac_data)
        
        # ========== ARP TABLE ==========
        print("  Getting ARP table...")
        arp_output = conn.send_command('show ip arp', delay_factor=2)
        with open(output_dir / 'arp_table_raw.txt', 'w') as f:
            f.write(arp_output)
        
        arp_data = []
        try:
            parsed = parse_output(platform=device_type, command='show ip arp', data=arp_output)
            if parsed:
                for entry in parsed:
                    arp_data.append({
                        'ip': entry.get('address', entry.get('ip', '')),
                        'mac': entry.get('mac', ''),
                        'interface': entry.get('interface', '')
                    })
                print(f"    Parsed {len(arp_data)} ARP entries")
        except:
            print("    ARP parsing failed")
        
        if arp_data:
            with open(output_dir / 'arp_table.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['ip', 'mac', 'interface'])
                writer.writeheader()
                writer.writerows(arp_data)
        
        # ========== CORRELATE MAC/ARP ==========
        if mac_data and arp_data:
            print("  Correlating MAC and ARP tables...")
            correlated_data = correlate_mac_arp(mac_data, arp_data)
            
            with open(output_dir / 'mac_arp_correlated.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['vlan', 'mac', 'type', 'interface', 'ip', 'arp_interface'])
                writer.writeheader()
                writer.writerows(correlated_data)
            print(f"    Created correlated table with {len(correlated_data)} entries")
        
        # ========== CDP NEIGHBORS ==========
        all_neighbors = []
        print("  Getting CDP neighbors...")
        
        cdp_output = conn.send_command('show cdp neighbors detail', delay_factor=3)
        with open(output_dir / 'cdp_neighbors_raw.txt', 'w') as f:
            f.write(cdp_output)
        
        if 'CDP is not enabled' not in cdp_output:
            try:
                parsed = parse_output(platform=device_type, command='show cdp neighbors detail', data=cdp_output)
                if parsed:
                    for entry in parsed:
                        neighbor = {
                            'protocol': 'CDP',
                            'local_interface': entry.get('local_port', ''),
                            'neighbor_device': extract_system_name(entry.get('device_id', '')),
                            'neighbor_interface': entry.get('remote_port', ''),
                            'neighbor_ip': entry.get('management_ip', ''),
                            'platform': entry.get('platform', ''),
                            'software_version': entry.get('software_version', ''),
                            'capabilities': entry.get('capabilities', ''),
                            'vtp_domain': entry.get('vtp_domain', ''),
                            'native_vlan': entry.get('native_vlan', ''),
                            'duplex': entry.get('duplex', '')
                        }
                        
                        # Handle IP lists (some templates return lists)
                        if isinstance(neighbor['neighbor_ip'], list):
                            neighbor['neighbor_ip'] = ', '.join(neighbor['neighbor_ip'])
                        
                        all_neighbors.append(neighbor)
                    
                    print(f"    Parsed {len(parsed)} CDP neighbors")
            except Exception as e:
                print(f"    CDP parsing failed: {e}")
        
        # ========== LLDP NEIGHBORS ==========
        print("  Getting LLDP neighbors...")
        
        lldp_output = conn.send_command('show lldp neighbors detail', delay_factor=3)
        with open(output_dir / 'lldp_neighbors_raw.txt', 'w') as f:
            f.write(lldp_output)
        
        if 'LLDP is not enabled' not in lldp_output:
            try:
                parsed = parse_output(platform=device_type, command='show lldp neighbors detail', data=lldp_output)
                if parsed:
                    # Check if we already have CDP data for these interfaces
                    cdp_interfaces = set(n['local_interface'] for n in all_neighbors if n.get('protocol') == 'CDP')
                    
                    for entry in parsed:
                        local_int = entry.get('local_interface', entry.get('local_port', ''))
                        
                        # Skip if we already have CDP data for this interface
                        if local_int not in cdp_interfaces:
                            neighbor = {
                                'protocol': 'LLDP',
                                'local_interface': local_int,
                                'neighbor_device': entry.get('neighbor', entry.get('system_name', '')),
                                'neighbor_interface': entry.get('neighbor_port_id', entry.get('remote_port', '')),
                                'neighbor_ip': entry.get('management_address', ''),
                                'platform': entry.get('system_description', ''),
                                'software_version': '',
                                'capabilities': entry.get('capabilities', ''),
                                'vtp_domain': '',
                                'native_vlan': '',
                                'duplex': ''
                            }
                            
                            # Handle IP lists
                            if isinstance(neighbor['neighbor_ip'], list):
                                neighbor['neighbor_ip'] = ', '.join(neighbor['neighbor_ip'])
                            
                            all_neighbors.append(neighbor)
                    
                    print(f"    Parsed {len(parsed)} LLDP neighbors")
            except Exception as e:
                print(f"    LLDP parsing failed: {e}")
        
        # Save neighbors to CSV
        if all_neighbors:
            fieldnames = ['protocol', 'local_interface', 'neighbor_device', 'neighbor_interface', 
                         'neighbor_ip', 'platform', 'software_version', 'capabilities',
                         'vtp_domain', 'native_vlan', 'duplex']
            
            with open(output_dir / 'neighbors.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(all_neighbors)
            
            print(f"    Found {len(all_neighbors)} total neighbors")
            
            # Also save as JSON
            with open(output_dir / 'neighbors.json', 'w') as f:
                json.dump(all_neighbors, f, indent=2)
        
        # ========== VLANs ==========
        print("  Getting VLANs...")
        vlan_commands = ['show vlan', 'show vlan brief']
        
        vlan_data = []
        for cmd in vlan_commands:
            try:
                vlan_output = conn.send_command(cmd, delay_factor=2)
                if 'Invalid' not in vlan_output and 'Error' not in vlan_output:
                    with open(output_dir / 'vlans_raw.txt', 'w') as f:
                        f.write(vlan_output)
                    
                    parsed = parse_output(platform=device_type, command=cmd, data=vlan_output)
                    if parsed:
                        for entry in parsed:
                            # Handle interfaces as list
                            interfaces = entry.get('interfaces', [])
                            if isinstance(interfaces, list):
                                interfaces = ', '.join(interfaces)
                            
                            vlan_data.append({
                                'vlan_id': entry.get('vlan_id', ''),
                                'name': entry.get('name', ''),
                                'status': entry.get('status', 'active'),
                                'interfaces': interfaces
                            })
                        print(f"    Parsed {len(vlan_data)} VLANs")
                        break
            except:
                continue
        
        if vlan_data:
            with open(output_dir / 'vlans.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['vlan_id', 'name', 'status', 'interfaces'])
                writer.writeheader()
                writer.writerows(vlan_data)
        
        # ========== SUMMARY REPORT ==========
        with open(output_dir / 'connectivity_report.txt', 'w') as f:
            f.write(f"Device Connectivity Report\n")
            f.write(f"="*60 + "\n")
            f.write(f"Device: {hostname}\n")
            f.write(f"IP: {ip}\n")
            f.write(f"Type: {device_type}\n")
            f.write(f"Collected: {timestamp}\n\n")
            
            f.write("Summary:\n")
            f.write(f"  Total Neighbors: {len(all_neighbors)}\n")
            f.write(f"  - CDP: {sum(1 for n in all_neighbors if n.get('protocol') == 'CDP')}\n")
            f.write(f"  - LLDP: {sum(1 for n in all_neighbors if n.get('protocol') == 'LLDP')}\n")
            f.write(f"  MAC Entries: {len(mac_data)}\n")
            f.write(f"  ARP Entries: {len(arp_data)}\n")
            f.write(f"  VLANs: {len(vlan_data)}\n\n")
            
            f.write("Connected Devices:\n")
            f.write("-"*40 + "\n")
            
            for n in all_neighbors:
                f.write(f"\n[{n.get('protocol', 'Unknown')}] {n.get('local_interface', 'Unknown')}\n")
                f.write(f"  Device: {n.get('neighbor_device', 'Unknown')}\n")
                f.write(f"  Remote Port: {n.get('neighbor_interface', 'Unknown')}\n")
                if n.get('neighbor_ip'):
                    f.write(f"  IP: {n.get('neighbor_ip')}\n")
                if n.get('platform'):
                    f.write(f"  Platform: {n.get('platform')}\n")
                if n.get('native_vlan'):
                    f.write(f"  Native VLAN: {n.get('native_vlan')}\n")
        
        conn.disconnect()
        print(f"  [SUCCESS] Data saved to {output_dir}")
        return True
        
    except NetmikoAuthenticationException:
        print(f"  [FAILED] Authentication failed for {ip}")
        return False
    except NetmikoTimeoutException:
        print(f"  [FAILED] Connection timeout for {ip}")
        return False
    except Exception as e:
        print(f"  [FAILED] {e}")
        return False

def main():
    """Main function"""
    print("="*60)
    print("Network Device Collector with NTC Templates")
    print("="*60)
    
    # Check required modules
    try:
        from ntc_templates.parse import parse_output
        print("✓ NTC Templates installed")
    except ImportError:
        print("✗ ERROR: NTC Templates not installed")
        print("  Run: pip install ntc-templates")
        return
    
    try:
        from netmiko import ConnectHandler
        print("✓ Netmiko installed")
    except ImportError:
        print("✗ ERROR: Netmiko not installed")
        print("  Run: pip install netmiko")
        return
    
    # Read device list
    devices = []
    try:
        with open(DEVICE_LIST, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    devices.append(line)
    except FileNotFoundError:
        print(f"\n✗ ERROR: {DEVICE_LIST} not found!")
        print(f"  Create '{DEVICE_LIST}' with one IP per line")
        print("  Example:")
        print("    192.168.1.1")
        print("    192.168.1.2")
        print("    # 192.168.1.3  (commented out)")
        return
    
    if not devices:
        print(f"No devices found in {DEVICE_LIST}")
        return
    
    print(f"\nFound {len(devices)} devices to process")
    print("-"*60)
    
    # Process each device
    success = 0
    failed = 0
    
    for idx, ip in enumerate(devices, 1):
        print(f"\n[{idx}/{len(devices)}] Processing {ip}")
        if collect_from_device(ip, USERNAME, PASSWORD):
            success += 1
        else:
            failed += 1
    
    # Summary
    print("\n" + "="*60)
    print(f"Collection Complete!")
    print(f"✓ Success: {success} devices")
    if failed > 0:
        print(f"✗ Failed: {failed} devices")
    
    print(f"\n📁 Check 'network_data/' folder for results")
    print("\nFiles created per device:")
    print("  ├── neighbors.csv          - CDP/LLDP neighbors")
    print("  ├── mac_arp_correlated.csv - Correlated MAC+ARP")
    print("  ├── mac_table.csv          - MAC address table")
    print("  ├── arp_table.csv          - ARP table")
    print("  ├── vlans.csv              - VLAN information")
    print("  └── connectivity_report.txt - Summary report")

if __name__ == "__main__":
    main()
