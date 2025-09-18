#!/usr/bin/env python3
"""
Network Device Collector with TextFSM CDP/LLDP Parsing
Collects and parses MAC tables, ARP tables, CDP/LLDP neighbors, and VLANs
Correlates MAC and ARP data for complete visibility

TROUBLESHOOTING CDP/LLDP PARSING:
- Check the *_raw.txt files to see actual command output
- Check *_textfsm_debug.json to see what fields TextFSM returns
- Common issues:
  * CDP/LLDP not enabled on device (check raw output)
  * TextFSM templates not matching device output format
  * Field names varying between device types/versions
- The script has fallback regex parsers if TextFSM fails
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
    """Detect if device is IOS, NX-OS, or EOS with enhanced detection"""
    print("  Detecting device type...")
    
    # Get version information
    version_output = ""
    device_type = conn.device_type  # Start with what Netmiko detected
    
    # Try 'show version' command
    try:
        version_output = conn.send_command('show version', delay_factor=2)
    except:
        pass
    
    # Convert to uppercase for case-insensitive matching
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
        # Try to detect based on prompt format if version didn't help
        prompt = conn.find_prompt()
        if '#' in prompt:
            if '%' in prompt or 'nexus' in prompt.lower():
                device_type = 'cisco_nxos'
                print("    Detected: Cisco NX-OS (based on prompt)")
            else:
                device_type = 'cisco_ios'
                print("    Detected: Cisco IOS (based on prompt)")
        else:
            print(f"    Using default: {device_type}")
    
    # Update the connection's device type
    conn.device_type = device_type
    return device_type, version_output

def get_mac_table_command(device_type):
    """Get the appropriate MAC table command for device type"""
    if device_type == 'cisco_nxos':
        # NX-OS uses 'show mac address-table'
        return 'show mac address-table'
    elif device_type == 'arista_eos':
        # Arista uses 'show mac address-table'
        return 'show mac address-table'
    elif device_type == 'cisco_xr':
        # IOS-XR might use different command
        return 'show mac address-table'
    else:  # cisco_ios and others
        # IOS can use either, but this is most common
        return 'show mac address-table'

def parse_cdp_neighbors(cdp_output, device_type):
    """Parse CDP neighbors using TextFSM with improved fallback"""
    neighbors = []
    
    if not cdp_output or 'CDP is not enabled' in cdp_output:
        return neighbors
    
    try:
        # Use NTC templates to parse CDP output
        parsed = parse_output(platform=device_type, command='show cdp neighbors detail', data=cdp_output)
        
        if parsed and isinstance(parsed, list):
            for entry in parsed:
                # Handle different field names from different templates
                neighbor = {
                    'protocol': 'CDP',
                    'local_interface': entry.get('local_port', entry.get('local_interface', '')),
                    'neighbor_device': entry.get('destination_host', entry.get('device_id', entry.get('neighbor', ''))),
                    'neighbor_interface': entry.get('remote_port', entry.get('neighbor_interface', entry.get('port_id', ''))),
                    'neighbor_ip': entry.get('management_ip', entry.get('ip_address', entry.get('ip', ''))),
                    'platform': entry.get('platform', entry.get('system_name', '')),
                    'capabilities': entry.get('capabilities', ''),
                    'software_version': entry.get('software_version', entry.get('version', ''))
                }
                
                # Clean up device name (remove domain if present)
                if neighbor['neighbor_device']:
                    if '(' in neighbor['neighbor_device']:
                        neighbor['neighbor_device'] = neighbor['neighbor_device'].split('(')[0].strip()
                    elif '.' in neighbor['neighbor_device'] and not re.match(r'^\d+\.\d+\.\d+\.\d+', neighbor['neighbor_device']):
                        # Remove domain but not if it's an IP
                        neighbor['neighbor_device'] = neighbor['neighbor_device'].split('.')[0]
                
                # Only add if we have at least a device name or IP
                if neighbor['neighbor_device'] or neighbor['neighbor_ip']:
                    neighbors.append(neighbor)
            
            if neighbors:
                print(f"      Parsed {len(neighbors)} CDP neighbors with TextFSM")
            else:
                print(f"      TextFSM returned empty results, trying fallback parser")
                neighbors = parse_cdp_basic(cdp_output)
        else:
            print(f"      TextFSM parsing returned no data, trying fallback parser")
            neighbors = parse_cdp_basic(cdp_output)
            
    except Exception as e:
        print(f"      TextFSM parsing failed: {str(e)[:100]}, trying fallback parser")
        neighbors = parse_cdp_basic(cdp_output)
    
    return neighbors

def parse_cdp_basic(output):
    """Basic CDP parsing as fallback - handles multiple formats"""
    neighbors = []
    current = {}
    
    for line in output.split('\n'):
        # Check for Device ID in various formats
        if 'Device ID' in line:
            # Save previous entry if exists
            if current and 'neighbor_device' in current:
                neighbors.append(current)
            
            # Extract device name - handle different formats
            device_name = ''
            if ':' in line:
                device_name = line.split(':', 1)[1].strip()
            elif 'Device ID' in line:
                # Sometimes it's "Device ID: hostname" or "Device ID:hostname"
                parts = line.split('Device ID')
                if len(parts) > 1:
                    device_name = parts[1].strip().lstrip(':').strip()
            
            # Clean up device name (remove domain/serial)
            if device_name:
                if '(' in device_name:
                    device_name = device_name.split('(')[0].strip()
                if '.' in device_name and not re.match(r'^\d+\.\d+\.\d+\.\d+', device_name):
                    # Remove domain but not if it's an IP
                    device_name = device_name.split('.')[0]
                
                current = {
                    'protocol': 'CDP',
                    'neighbor_device': device_name,
                    'neighbor_ip': '',
                    'neighbor_interface': '',
                    'local_interface': '',
                    'platform': '',
                    'capabilities': '',
                    'software_version': ''
                }
        
        # Parse other fields only if we have a current device
        elif current:
            if 'IP address' in line or 'IPv4 Address' in line:
                # Handle "IP address: x.x.x.x" or "IPv4 Address: x.x.x.x"
                if ':' in line:
                    ip = line.split(':', 1)[1].strip()
                    if re.match(r'\d+\.\d+\.\d+\.\d+', ip):
                        current['neighbor_ip'] = ip
            
            elif 'Platform' in line:
                # Parse platform and capabilities
                if ':' in line:
                    platform_info = line.split(':', 1)[1].strip()
                    # Split by comma to separate platform from capabilities
                    parts = platform_info.split(',')
                    if parts:
                        current['platform'] = parts[0].strip()
                    # Look for Capabilities
                    if 'Capabilities' in platform_info:
                        cap_parts = platform_info.split('Capabilities')
                        if len(cap_parts) > 1:
                            current['capabilities'] = cap_parts[1].strip().lstrip(':').strip()
            
            elif 'Interface' in line:
                # Parse local and remote interfaces
                # Format: "Interface: GigabitEthernet0/0,  Port ID (outgoing port): GigabitEthernet0/0"
                if ':' in line:
                    int_info = line.split(':', 1)[1].strip()
                    
                    # Get local interface (before comma)
                    if ',' in int_info:
                        local_int = int_info.split(',')[0].strip()
                        current['local_interface'] = local_int
                        
                        # Get remote interface (after "Port ID")
                        if 'Port ID' in int_info:
                            port_parts = int_info.split('Port ID')
                            if len(port_parts) > 1:
                                remote_int = port_parts[1].strip()
                                # Remove "(outgoing port)" and colons
                                remote_int = remote_int.replace('(outgoing port)', '')
                                remote_int = remote_int.replace(':', '').strip()
                                current['neighbor_interface'] = remote_int
                    else:
                        # No comma, just local interface
                        current['local_interface'] = int_info.strip()
            
            elif 'Version' in line and ':' in line:
                # Get software version
                version = line.split(':', 1)[1].strip()
                # Take first line of version if multiline
                if version:
                    current['software_version'] = version.split('\n')[0].strip()
    
    # Don't forget the last entry
    if current and 'neighbor_device' in current:
        neighbors.append(current)
    
    # Clean up empty entries
    neighbors = [n for n in neighbors if n.get('neighbor_device')]
    
    if neighbors:
        print(f"      Parsed {len(neighbors)} CDP neighbors with basic parser")
    else:
        print("      No CDP neighbors found in output")
    
    return neighbors

def parse_lldp_neighbors(lldp_output, device_type):
    """Parse LLDP neighbors using TextFSM with improved fallback"""
    neighbors = []
    
    if not lldp_output or 'LLDP is not enabled' in lldp_output:
        return neighbors
    
    try:
        # Use NTC templates to parse LLDP output
        parsed = parse_output(platform=device_type, command='show lldp neighbors detail', data=lldp_output)
        
        if parsed and isinstance(parsed, list):
            for entry in parsed:
                # Handle different field names from different templates
                neighbor = {
                    'protocol': 'LLDP',
                    'local_interface': entry.get('local_interface', entry.get('local_port', entry.get('local_intf', ''))),
                    'neighbor_device': entry.get('neighbor', entry.get('system_name', entry.get('device_id', ''))),
                    'neighbor_interface': entry.get('neighbor_port_id', entry.get('remote_port', entry.get('port_id', ''))),
                    'neighbor_ip': entry.get('management_address', entry.get('management_ip', entry.get('mgmt_address', ''))),
                    'platform': entry.get('system_description', entry.get('platform', entry.get('description', ''))),
                    'capabilities': entry.get('capabilities', entry.get('system_capabilities', '')),
                    'software_version': entry.get('software_version', '')
                }
                
                # Clean up device name
                if neighbor['neighbor_device']:
                    if '.' in neighbor['neighbor_device'] and not re.match(r'^\d+\.\d+\.\d+\.\d+', neighbor['neighbor_device']):
                        neighbor['neighbor_device'] = neighbor['neighbor_device'].split('.')[0]
                
                # Only add if we have at least a device name or IP
                if neighbor['neighbor_device'] or neighbor['neighbor_ip']:
                    neighbors.append(neighbor)
            
            if neighbors:
                print(f"      Parsed {len(neighbors)} LLDP neighbors with TextFSM")
            else:
                print(f"      TextFSM returned empty results, trying fallback parser")
                neighbors = parse_lldp_basic(lldp_output)
        else:
            print(f"      TextFSM parsing returned no data, trying fallback parser")
            neighbors = parse_lldp_basic(lldp_output)
            
    except Exception as e:
        print(f"      TextFSM parsing failed: {str(e)[:100]}, trying fallback parser")
        neighbors = parse_lldp_basic(lldp_output)
    
    return neighbors

def parse_lldp_basic(output):
    """Basic LLDP parsing as fallback - handles multiple formats"""
    neighbors = []
    current = {}
    
    for line in output.split('\n'):
        # Check for start of new neighbor - various formats
        if 'Local Intf' in line or 'Local Interface' in line:
            # Save previous entry if exists
            if current and 'neighbor_device' in current:
                neighbors.append(current)
            
            # Extract local interface
            local_int = ''
            if ':' in line:
                local_int = line.split(':', 1)[1].strip()
            else:
                # Sometimes format is "Local Intf: Gi0/0" or just has the interface after
                parts = re.split(r'Local Intf(?:erface)?[:\s]+', line)
                if len(parts) > 1:
                    local_int = parts[1].strip()
            
            if local_int:
                current = {
                    'protocol': 'LLDP',
                    'local_interface': local_int,
                    'neighbor_device': '',
                    'neighbor_interface': '',
                    'neighbor_ip': '',
                    'platform': '',
                    'capabilities': '',
                    'software_version': ''
                }
        
        # Parse other fields
        elif current:
            # System Name (neighbor hostname)
            if 'System Name' in line or 'SysName' in line:
                if ':' in line:
                    name = line.split(':', 1)[1].strip()
                    # Clean up the name
                    if '.' in name and not re.match(r'^\d+\.\d+\.\d+\.\d+', name):
                        name = name.split('.')[0]  # Remove domain
                    current['neighbor_device'] = name
            
            # Port ID (neighbor interface)
            elif 'Port id' in line or 'PortId' in line or 'Port ID' in line:
                if ':' in line:
                    port = line.split(':', 1)[1].strip()
                    # Clean up port name
                    port = port.replace('"', '').strip()
                    current['neighbor_interface'] = port
            
            # Port Description
            elif 'Port Description' in line or 'PortDescr' in line:
                if ':' in line and not current['neighbor_interface']:
                    # Sometimes port description has the actual port
                    port_desc = line.split(':', 1)[1].strip()
                    if port_desc and len(port_desc) < 50:  # Reasonable length for interface name
                        current['neighbor_interface'] = port_desc
            
            # Management Address (IP)
            elif 'Management Address' in line or 'MgmtAddress' in line:
                # IP might be on same line or next line
                if ':' in line:
                    addr_part = line.split(':', 1)[1].strip()
                    # Look for IP pattern
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', addr_part)
                    if ip_match:
                        current['neighbor_ip'] = ip_match.group(1)
                    elif not addr_part or addr_part == 'not advertised':
                        current['neighbor_ip'] = ''
            
            # Also check for standalone IP line (sometimes IP is on next line)
            elif re.match(r'^\s*\d+\.\d+\.\d+\.\d+\s*

def correlate_mac_arp(mac_data, arp_data):
    """Correlate MAC and ARP tables to create unified view"""
    correlated = []
    
    # Create lookup dictionaries
    arp_by_mac = {}
    for arp in arp_data:
        mac = arp.get('mac', '').lower()
        if mac:
            arp_by_mac[mac] = arp
    
    # Correlate MAC entries with ARP
    for mac_entry in mac_data:
        mac_addr = mac_entry.get('mac', '').lower()
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
    processed_macs = set(m.get('mac', '').lower() for m in mac_data)
    for arp_entry in arp_data:
        mac_addr = arp_entry.get('mac', '').lower()
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
        'device_type': 'autodetect',  # Let Netmiko auto-detect
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
            # Fallback to cisco_ios if autodetect fails
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
        
        # Collect MAC table
        print("  Getting MAC table...")
        mac_command = get_mac_table_command(device_type)
        mac_output = conn.send_command(mac_command)
        with open(output_dir / 'mac_table_raw.txt', 'w') as f:
            f.write(mac_output)
        
        # Parse MAC table
        mac_data = []
        try:
            parsed_mac = parse_output(platform=device_type, command=mac_command, data=mac_output)
            if parsed_mac:
                for entry in parsed_mac:
                    mac_data.append({
                        'vlan': entry.get('vlan', ''),
                        'mac': entry.get('destination_address', entry.get('mac', '')),
                        'type': entry.get('type', 'dynamic'),
                        'interface': entry.get('destination_port', entry.get('ports', ''))
                    })
                print(f"    Parsed {len(mac_data)} MAC entries with TextFSM")
        except Exception as e:
            print(f"    TextFSM MAC parsing failed: {e}, using regex")
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
        
        # Collect ARP table
        print("  Getting ARP table...")
        arp_output = conn.send_command('show ip arp')
        with open(output_dir / 'arp_table_raw.txt', 'w') as f:
            f.write(arp_output)
        
        # Parse ARP
        arp_data = []
        try:
            parsed_arp = parse_output(platform=device_type, command='show ip arp', data=arp_output)
            if parsed_arp:
                for entry in parsed_arp:
                    arp_data.append({
                        'ip': entry.get('address', entry.get('ip', '')),
                        'mac': entry.get('mac', ''),
                        'interface': entry.get('interface', '')
                    })
                print(f"    Parsed {len(arp_data)} ARP entries with TextFSM")
        except Exception as e:
            print(f"    TextFSM ARP parsing failed: {e}, using regex")
            # Fallback to regex
            for line in arp_output.split('\n'):
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+\S+\s+(\S+)', line, re.I)
                if match:
                    arp_data.append({
                        'ip': match.group(1),
                        'mac': match.group(2),
                        'interface': match.group(3)
                    })
        
        # Save individual MAC and ARP tables
        if mac_data:
            with open(output_dir / 'mac_table.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['vlan', 'mac', 'type', 'interface'])
                writer.writeheader()
                writer.writerows(mac_data)
        
        if arp_data:
            with open(output_dir / 'arp_table.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['ip', 'mac', 'interface'])
                writer.writeheader()
                writer.writerows(arp_data)
        
        # Correlate MAC and ARP tables
        correlated_data = []  # Initialize
        print("  Correlating MAC and ARP tables...")
        correlated_data = correlate_mac_arp(mac_data, arp_data)
        if correlated_data:
            with open(output_dir / 'mac_arp_correlated.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['vlan', 'mac', 'type', 'interface', 'ip', 'arp_interface'])
                writer.writeheader()
                writer.writerows(correlated_data)
            print(f"    Created correlated table with {len(correlated_data)} entries")
        
        # Collect CDP neighbors
        all_neighbors = []
        cdp_neighbors = []  # Initialize to empty list
        print("  Getting CDP neighbors...")
        try:
            cdp_output = conn.send_command('show cdp neighbors detail', delay_factor=2)
            with open(output_dir / 'cdp_neighbors_raw.txt', 'w') as f:
                f.write(cdp_output)
            
            # Debug: save TextFSM parsed output to see what fields we get
            try:
                debug_parsed = parse_output(platform=device_type, command='show cdp neighbors detail', data=cdp_output)
                if debug_parsed:
                    with open(output_dir / 'cdp_textfsm_debug.json', 'w') as f:
                        json.dump(debug_parsed, f, indent=2)
                    print(f"    DEBUG: TextFSM CDP fields saved to cdp_textfsm_debug.json")
            except:
                pass
            
            cdp_neighbors = parse_cdp_neighbors(cdp_output, device_type)
            all_neighbors.extend(cdp_neighbors)
        except Exception as e:
            print(f"    CDP collection failed: {e}")
        
        # Collect LLDP neighbors
        print("  Getting LLDP neighbors...")
        try:
            lldp_output = conn.send_command('show lldp neighbors detail', delay_factor=2)
            with open(output_dir / 'lldp_neighbors_raw.txt', 'w') as f:
                f.write(lldp_output)
            
            # Debug: save TextFSM parsed output to see what fields we get
            try:
                debug_parsed = parse_output(platform=device_type, command='show lldp neighbors detail', data=lldp_output)
                if debug_parsed:
                    with open(output_dir / 'lldp_textfsm_debug.json', 'w') as f:
                        json.dump(debug_parsed, f, indent=2)
                    print(f"    DEBUG: TextFSM LLDP fields saved to lldp_textfsm_debug.json")
            except:
                pass
            
            lldp_neighbors = parse_lldp_neighbors(lldp_output, device_type)
            
            # Deduplicate - only add LLDP entries that don't exist in CDP
            cdp_interfaces = set(n.get('local_interface') for n in cdp_neighbors if n.get('local_interface'))
            for lldp in lldp_neighbors:
                if lldp.get('local_interface') not in cdp_interfaces:
                    all_neighbors.append(lldp)
        except Exception as e:
            print(f"    LLDP collection failed: {e}")
        
        # Save all neighbors to CSV
        if all_neighbors:
            # Get all unique fields from neighbors
            all_fields = set()
            for neighbor in all_neighbors:
                all_fields.update(neighbor.keys())
            
            fieldnames = sorted(list(all_fields))
            
            with open(output_dir / 'neighbors.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(all_neighbors)
            
            print(f"    Found {len(all_neighbors)} total neighbors (CDP+LLDP)")
            
            # Also save as JSON for easier processing
            with open(output_dir / 'neighbors.json', 'w') as f:
                json.dump(all_neighbors, f, indent=2)
        else:
            print("    WARNING: No neighbors found!")
        
        # Collect VLANs
        print("  Getting VLANs...")
        vlan_output = conn.send_command('show vlan')
        with open(output_dir / 'vlans_raw.txt', 'w') as f:
            f.write(vlan_output)
        
        # Parse VLANs
        vlan_data = []
        try:
            parsed_vlans = parse_output(platform=device_type, command='show vlan', data=vlan_output)
            if parsed_vlans:
                for entry in parsed_vlans:
                    interfaces = entry.get('interfaces', [])
                    if isinstance(interfaces, list):
                        interfaces = ', '.join(interfaces)
                    vlan_data.append({
                        'vlan_id': entry.get('vlan_id', ''),
                        'name': entry.get('name', ''),
                        'status': entry.get('status', 'active'),
                        'interfaces': interfaces
                    })
                print(f"    Parsed {len(vlan_data)} VLANs with TextFSM")
        except Exception as e:
            print(f"    TextFSM VLAN parsing failed: {e}, using regex")
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
        
        # Create comprehensive connectivity report
        with open(output_dir / 'connectivity_report.txt', 'w') as f:
            f.write(f"Device Connectivity Report\n")
            f.write(f"="*60 + "\n")
            f.write(f"Device: {hostname}\n")
            f.write(f"IP: {ip}\n")
            f.write(f"Type: {device_type}\n")
            f.write(f"Collected: {timestamp}\n\n")
            
            f.write("Connected Devices:\n")
            f.write("-"*40 + "\n")
            
            # Group neighbors by protocol
            cdp_count = sum(1 for n in all_neighbors if n.get('protocol') == 'CDP')
            lldp_count = sum(1 for n in all_neighbors if n.get('protocol') == 'LLDP')
            
            f.write(f"Total CDP Neighbors: {cdp_count}\n")
            f.write(f"Total LLDP Neighbors: {lldp_count}\n\n")
            
            for n in all_neighbors:
                f.write(f"[{n.get('protocol', 'Unknown')}] Local Port: {n.get('local_interface', 'Unknown')}\n")
                f.write(f"  -> Neighbor: {n.get('neighbor_device', 'Unknown')}\n")
                f.write(f"  -> Neighbor Port: {n.get('neighbor_interface', 'Unknown')}\n")
                f.write(f"  -> Neighbor IP: {n.get('neighbor_ip', 'Unknown')}\n")
                f.write(f"  -> Platform: {n.get('platform', 'Unknown')}\n")
                if n.get('capabilities'):
                    f.write(f"  -> Capabilities: {n.get('capabilities')}\n")
                f.write("\n")
            
            f.write(f"\n" + "="*60 + "\n")
            f.write(f"Summary Statistics:\n")
            f.write(f"Total Neighbors: {len(all_neighbors)}\n")
            f.write(f"MAC Entries: {len(mac_data)}\n")
            f.write(f"ARP Entries: {len(arp_data)}\n")
            f.write(f"Correlated MAC/ARP: {len(correlated_data)}\n")
            f.write(f"VLANs: {len(vlan_data)}\n")
        
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
    print("Network Device Collector with TextFSM Parsing")
    print("="*60)
    
    # Check if required modules are installed
    try:
        from ntc_templates.parse import parse_output
        print("✓ TextFSM parsing enabled")
    except ImportError:
        print("✗ WARNING: Install textfsm and ntc-templates for better parsing")
        print("  Run: pip install textfsm ntc-templates")
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
    print("\nKey files created per device:")
    print("  ├── neighbors.csv         - CDP/LLDP neighbors (MAIN OUTPUT)")
    print("  ├── neighbors.json        - Neighbors in JSON format")
    print("  ├── mac_arp_correlated.csv - MAC+ARP correlation table")
    print("  ├── mac_table.csv         - MAC address table")
    print("  ├── arp_table.csv         - ARP table")
    print("  ├── vlans.csv            - VLAN information")
    print("  ├── connectivity_report.txt - Human-readable report")
    print("  └── *_raw.txt files      - Raw command outputs")

if __name__ == "__main__":
    main(), line) and not current['neighbor_ip']:
                current['neighbor_ip'] = line.strip()
            
            # System Description (platform info)
            elif 'System Description' in line or 'SysDesc' in line:
                if ':' in line:
                    desc = line.split(':', 1)[1].strip()
                    # Take first line if multiline
                    if desc:
                        current['platform'] = desc.split('\n')[0].strip()
            
            # System Capabilities
            elif 'System Capabilities' in line or 'SysCap' in line:
                if ':' in line:
                    caps = line.split(':', 1)[1].strip()
                    # Sometimes format is "supported: B,R enabled: B,R"
                    if 'enabled' in caps:
                        enabled_part = caps.split('enabled')[1].strip().lstrip(':').strip()
                        current['capabilities'] = enabled_part
                    else:
                        current['capabilities'] = caps
    
    # Don't forget the last entry
    if current and current.get('neighbor_device'):
        neighbors.append(current)
    
    # For Cisco format where System Name might be in different format
    if not neighbors:
        current = {}
        for line in output.split('\n'):
            # Alternative Cisco LLDP format
            if 'Device ID' in line:
                if current and 'neighbor_device' in current:
                    neighbors.append(current)
                if ':' in line:
                    device = line.split(':', 1)[1].strip()
                    current = {
                        'protocol': 'LLDP',
                        'neighbor_device': device,
                        'neighbor_ip': '',
                        'neighbor_interface': '',
                        'local_interface': '',
                        'platform': '',
                        'capabilities': '',
                        'software_version': ''
                    }
            elif current:
                if 'Local Intf' in line and ':' in line:
                    current['local_interface'] = line.split(':', 1)[1].strip()
                elif 'Port id' in line and ':' in line:
                    current['neighbor_interface'] = line.split(':', 1)[1].strip()
                elif 'System Name' in line and ':' in line:
                    name = line.split(':', 1)[1].strip()
                    if not current.get('neighbor_device'):
                        current['neighbor_device'] = name
        
        if current and current.get('neighbor_device'):
            neighbors.append(current)
    
    # Clean up empty entries
    neighbors = [n for n in neighbors if n.get('neighbor_device') or n.get('neighbor_ip')]
    
    if neighbors:
        print(f"      Parsed {len(neighbors)} LLDP neighbors with basic parser")
    else:
        print("      No LLDP neighbors found in output")
    
    return neighbors

def correlate_mac_arp(mac_data, arp_data):
    """Correlate MAC and ARP tables to create unified view"""
    correlated = []
    
    # Create lookup dictionaries
    arp_by_mac = {}
    for arp in arp_data:
        mac = arp.get('mac', '').lower()
        if mac:
            arp_by_mac[mac] = arp
    
    # Correlate MAC entries with ARP
    for mac_entry in mac_data:
        mac_addr = mac_entry.get('mac', '').lower()
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
    processed_macs = set(m.get('mac', '').lower() for m in mac_data)
    for arp_entry in arp_data:
        mac_addr = arp_entry.get('mac', '').lower()
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
        'device_type': 'autodetect',  # Let Netmiko auto-detect
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
            # Fallback to cisco_ios if autodetect fails
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
        
        # Collect MAC table
        print("  Getting MAC table...")
        mac_command = get_mac_table_command(device_type)
        mac_output = conn.send_command(mac_command)
        with open(output_dir / 'mac_table_raw.txt', 'w') as f:
            f.write(mac_output)
        
        # Parse MAC table
        mac_data = []
        try:
            parsed_mac = parse_output(platform=device_type, command=mac_command, data=mac_output)
            if parsed_mac:
                for entry in parsed_mac:
                    mac_data.append({
                        'vlan': entry.get('vlan', ''),
                        'mac': entry.get('destination_address', entry.get('mac', '')),
                        'type': entry.get('type', 'dynamic'),
                        'interface': entry.get('destination_port', entry.get('ports', ''))
                    })
                print(f"    Parsed {len(mac_data)} MAC entries with TextFSM")
        except Exception as e:
            print(f"    TextFSM MAC parsing failed: {e}, using regex")
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
        
        # Collect ARP table
        print("  Getting ARP table...")
        arp_output = conn.send_command('show ip arp')
        with open(output_dir / 'arp_table_raw.txt', 'w') as f:
            f.write(arp_output)
        
        # Parse ARP
        arp_data = []
        try:
            parsed_arp = parse_output(platform=device_type, command='show ip arp', data=arp_output)
            if parsed_arp:
                for entry in parsed_arp:
                    arp_data.append({
                        'ip': entry.get('address', entry.get('ip', '')),
                        'mac': entry.get('mac', ''),
                        'interface': entry.get('interface', '')
                    })
                print(f"    Parsed {len(arp_data)} ARP entries with TextFSM")
        except Exception as e:
            print(f"    TextFSM ARP parsing failed: {e}, using regex")
            # Fallback to regex
            for line in arp_output.split('\n'):
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+\S+\s+(\S+)', line, re.I)
                if match:
                    arp_data.append({
                        'ip': match.group(1),
                        'mac': match.group(2),
                        'interface': match.group(3)
                    })
        
        # Save individual MAC and ARP tables
        if mac_data:
            with open(output_dir / 'mac_table.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['vlan', 'mac', 'type', 'interface'])
                writer.writeheader()
                writer.writerows(mac_data)
        
        if arp_data:
            with open(output_dir / 'arp_table.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['ip', 'mac', 'interface'])
                writer.writeheader()
                writer.writerows(arp_data)
        
        # Correlate MAC and ARP tables
        print("  Correlating MAC and ARP tables...")
        correlated_data = correlate_mac_arp(mac_data, arp_data)
        if correlated_data:
            with open(output_dir / 'mac_arp_correlated.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['vlan', 'mac', 'type', 'interface', 'ip', 'arp_interface'])
                writer.writeheader()
                writer.writerows(correlated_data)
            print(f"    Created correlated table with {len(correlated_data)} entries")
        
        # Collect CDP neighbors
        all_neighbors = []
        print("  Getting CDP neighbors...")
        try:
            cdp_output = conn.send_command('show cdp neighbors detail', delay_factor=2)
            with open(output_dir / 'cdp_neighbors_raw.txt', 'w') as f:
                f.write(cdp_output)
            
            cdp_neighbors = parse_cdp_neighbors(cdp_output, device_type)
            all_neighbors.extend(cdp_neighbors)
        except Exception as e:
            print(f"    CDP collection failed: {e}")
        
        # Collect LLDP neighbors
        print("  Getting LLDP neighbors...")
        try:
            lldp_output = conn.send_command('show lldp neighbors detail', delay_factor=2)
            with open(output_dir / 'lldp_neighbors_raw.txt', 'w') as f:
                f.write(lldp_output)
            
            lldp_neighbors = parse_lldp_neighbors(lldp_output, device_type)
            
            # Deduplicate - only add LLDP entries that don't exist in CDP
            cdp_interfaces = set(n.get('local_interface') for n in cdp_neighbors)
            for lldp in lldp_neighbors:
                if lldp.get('local_interface') not in cdp_interfaces:
                    all_neighbors.append(lldp)
        except Exception as e:
            print(f"    LLDP collection failed: {e}")
        
        # Save all neighbors to CSV
        if all_neighbors:
            # Get all unique fields from neighbors
            all_fields = set()
            for neighbor in all_neighbors:
                all_fields.update(neighbor.keys())
            
            fieldnames = sorted(list(all_fields))
            
            with open(output_dir / 'neighbors.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(all_neighbors)
            
            print(f"    Found {len(all_neighbors)} total neighbors (CDP+LLDP)")
            
            # Also save as JSON for easier processing
            with open(output_dir / 'neighbors.json', 'w') as f:
                json.dump(all_neighbors, f, indent=2)
        else:
            print("    WARNING: No neighbors found!")
        
        # Collect VLANs
        print("  Getting VLANs...")
        vlan_output = conn.send_command('show vlan')
        with open(output_dir / 'vlans_raw.txt', 'w') as f:
            f.write(vlan_output)
        
        # Parse VLANs
        vlan_data = []
        try:
            parsed_vlans = parse_output(platform=device_type, command='show vlan', data=vlan_output)
            if parsed_vlans:
                for entry in parsed_vlans:
                    interfaces = entry.get('interfaces', [])
                    if isinstance(interfaces, list):
                        interfaces = ', '.join(interfaces)
                    vlan_data.append({
                        'vlan_id': entry.get('vlan_id', ''),
                        'name': entry.get('name', ''),
                        'status': entry.get('status', 'active'),
                        'interfaces': interfaces
                    })
                print(f"    Parsed {len(vlan_data)} VLANs with TextFSM")
        except Exception as e:
            print(f"    TextFSM VLAN parsing failed: {e}, using regex")
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
        
        # Create comprehensive connectivity report
        with open(output_dir / 'connectivity_report.txt', 'w') as f:
            f.write(f"Device Connectivity Report\n")
            f.write(f"="*60 + "\n")
            f.write(f"Device: {hostname}\n")
            f.write(f"IP: {ip}\n")
            f.write(f"Type: {device_type}\n")
            f.write(f"Collected: {timestamp}\n\n")
            
            f.write("Connected Devices:\n")
            f.write("-"*40 + "\n")
            
            # Group neighbors by protocol
            cdp_count = sum(1 for n in all_neighbors if n.get('protocol') == 'CDP')
            lldp_count = sum(1 for n in all_neighbors if n.get('protocol') == 'LLDP')
            
            f.write(f"Total CDP Neighbors: {cdp_count}\n")
            f.write(f"Total LLDP Neighbors: {lldp_count}\n\n")
            
            for n in all_neighbors:
                f.write(f"[{n.get('protocol', 'Unknown')}] Local Port: {n.get('local_interface', 'Unknown')}\n")
                f.write(f"  -> Neighbor: {n.get('neighbor_device', 'Unknown')}\n")
                f.write(f"  -> Neighbor Port: {n.get('neighbor_interface', 'Unknown')}\n")
                f.write(f"  -> Neighbor IP: {n.get('neighbor_ip', 'Unknown')}\n")
                f.write(f"  -> Platform: {n.get('platform', 'Unknown')}\n")
                if n.get('capabilities'):
                    f.write(f"  -> Capabilities: {n.get('capabilities')}\n")
                f.write("\n")
            
            f.write(f"\n" + "="*60 + "\n")
            f.write(f"Summary Statistics:\n")
            f.write(f"Total Neighbors: {len(all_neighbors)}\n")
            f.write(f"MAC Entries: {len(mac_data)}\n")
            f.write(f"ARP Entries: {len(arp_data)}\n")
            f.write(f"Correlated MAC/ARP: {len(correlated_data)}\n")
            f.write(f"VLANs: {len(vlan_data)}\n")
        
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
    print("Network Device Collector with TextFSM Parsing")
    print("="*60)
    
    # Check if required modules are installed
    try:
        from ntc_templates.parse import parse_output
        print("✓ TextFSM parsing enabled")
    except ImportError:
        print("✗ WARNING: Install textfsm and ntc-templates for better parsing")
        print("  Run: pip install textfsm ntc-templates")
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
    print("\nKey files created per device:")
    print("  ├── neighbors.csv         - CDP/LLDP neighbors (MAIN OUTPUT)")
    print("  ├── neighbors.json        - Neighbors in JSON format")
    print("  ├── mac_arp_correlated.csv - MAC+ARP correlation table")
    print("  ├── mac_table.csv         - MAC address table")
    print("  ├── arp_table.csv         - ARP table")
    print("  ├── vlans.csv            - VLAN information")
    print("  ├── connectivity_report.txt - Human-readable report")
    print("  └── *_raw.txt files      - Raw command outputs")

if __name__ == "__main__":
    main()
