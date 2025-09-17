#!/usr/bin/env python3
"""
Network Device Information Collector with Auto-Detection
Asynchronously collects MAC, ARP, and CDP/LLDP information from network devices
Uses TextFSM for robust parsing and auto-detects device types
"""

import asyncio
import csv
import json
import re
import textfsm
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import logging
from io import StringIO

# Required libraries
try:
    import netdev
    from ntc_templates.parse import parse_output
except ImportError:
    print("Please install required packages:")
    print("pip install netdev textfsm ntc-templates")
    exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class NetworkDeviceCollector:
    """Collects information from network devices with auto-detection"""
    
    # Device detection patterns
    DEVICE_PATTERNS = {
        'cisco_ios': [
            r'Cisco IOS Software',
            r'Cisco Internetwork Operating System Software',
            r'IOS \(tm\)',
            r'IOS-XE'
        ],
        'cisco_nxos': [
            r'Cisco Nexus Operating System',
            r'NX-OS',
            r'system:\s+version\s+\d+\.\d+\(\d+\)',
            r'cisco Nexus\d+ \w+'
        ],
        'arista_eos': [
            r'Arista',
            r'EOS',
            r'Software image version:'
        ]
    }
    
    def __init__(self, username: str, password: str, output_dir: str = "network_data"):
        self.username = username
        self.password = password
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.devices_info = {}
        self.cdp_lldp_data = {}
        self.connection_stats = {
            'successful': 0,
            'failed': 0,
            'in_progress': 0,
            'total': 0
        }
        
    async def detect_device_type(self, ip: str, timeout: int = 30) -> Optional[str]:
        """Auto-detect device type by connecting and checking version"""
        # Try generic SSH first
        device_params = {
            'device_type': 'cisco_ios',  # Start with IOS as it's most common
            'host': ip,
            'username': self.username,
            'password': self.password,
            'timeout': timeout,
            'conn_timeout': 20,  # Connection timeout
        }
        
        try:
            logger.info(f"Auto-detecting device type for {ip}")
            connection = netdev.create(**device_params)
            await connection.connect()
            
            # Try getting version information
            version_cmds = [
                'show version',
                'show version | include Software',
                'show version | include system'
            ]
            
            version_output = ""
            for cmd in version_cmds:
                try:
                    version_output = await connection.send_command(cmd, strip_command=False)
                    if version_output:
                        break
                except:
                    continue
            
            await connection.disconnect()
            
            # Detect device type from version output
            for device_type, patterns in self.DEVICE_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, version_output, re.IGNORECASE):
                        logger.info(f"Detected {ip} as {device_type}")
                        return device_type
            
            # Default to cisco_ios if can't determine
            logger.warning(f"Could not determine device type for {ip}, defaulting to cisco_ios")
            return 'cisco_ios'
            
        except Exception as e:
            logger.error(f"Failed to detect device type for {ip}: {e}")
            return None
    
    async def connect_device(self, ip: str, device_type: str, timeout: int = 30) -> Optional[netdev.AsyncSSH]:
        """Establish SSH connection to device with retry logic"""
        device_params = {
            'device_type': device_type,
            'host': ip,
            'username': self.username,
            'password': self.password,
            'timeout': timeout,
            'conn_timeout': 20,  # Connection timeout
        }
        
        max_retries = 2
        for attempt in range(max_retries):
            try:
                logger.info(f"Connecting to {ip} as {device_type} (attempt {attempt + 1}/{max_retries})")
                connection = netdev.create(**device_params)
                await connection.connect()
                logger.info(f"Successfully connected to {ip}")
                return connection
            except Exception as e:
                if attempt < max_retries - 1:
                    wait_time = (attempt + 1) * 2  # Exponential backoff
                    logger.warning(f"Connection attempt {attempt + 1} failed for {ip}: {e}. Retrying in {wait_time}s...")
                    await asyncio.sleep(wait_time)
                else:
                    logger.error(f"Failed to connect to {ip} after {max_retries} attempts: {e}")
                    return None
    
    async def parse_with_textfsm(self, output: str, platform: str, command: str) -> List[Dict]:
        """Parse command output using TextFSM/NTC-templates"""
        try:
            # Use NTC-templates for parsing
            parsed = parse_output(platform=platform, command=command, data=output)
            if isinstance(parsed, list):
                return parsed
            elif isinstance(parsed, dict):
                return [parsed]
            else:
                return []
        except Exception as e:
            logger.warning(f"TextFSM parsing failed for {command}: {e}, falling back to raw parsing")
            return []
    
    async def get_mac_table(self, connection, device_type: str) -> List[Dict]:
        """Get MAC address table using TextFSM parsing"""
        try:
            if device_type == 'arista_eos':
                output = await connection.send_command('show mac address-table')
                parsed = await self.parse_with_textfsm(output, 'arista_eos', 'show mac address-table')
            else:
                output = await connection.send_command('show mac address-table')
                parsed = await self.parse_with_textfsm(output, device_type, 'show mac address-table')
            
            # Normalize the parsed data
            mac_data = []
            for entry in parsed:
                mac_data.append({
                    'vlan': entry.get('vlan', 'N/A'),
                    'mac': entry.get('destination_address', entry.get('mac', 'N/A')),
                    'type': entry.get('type', 'dynamic'),
                    'interface': entry.get('destination_port', entry.get('interface', 'N/A'))
                })
            
            return mac_data
            
        except Exception as e:
            logger.error(f"Error getting MAC table: {e}")
            return []
    
    async def get_arp_table(self, connection, device_type: str) -> List[Dict]:
        """Get ARP table using TextFSM parsing"""
        try:
            output = await connection.send_command('show ip arp')
            parsed = await self.parse_with_textfsm(output, device_type, 'show ip arp')
            
            # Normalize the parsed data
            arp_data = []
            for entry in parsed:
                arp_data.append({
                    'ip': entry.get('address', entry.get('ip', 'N/A')),
                    'mac': entry.get('mac', 'N/A'),
                    'type': entry.get('type', entry.get('protocol', 'N/A')),
                    'interface': entry.get('interface', 'N/A')
                })
            
            return arp_data
            
        except Exception as e:
            logger.error(f"Error getting ARP table: {e}")
            return []
    
    async def get_cdp_lldp_neighbors(self, connection, device_type: str) -> List[Dict]:
        """Get CDP/LLDP neighbor information using TextFSM"""
        neighbors_data = []
        
        try:
            if device_type == 'arista_eos':
                # Arista primarily uses LLDP
                commands = [
                    ('show lldp neighbors detail', 'show lldp neighbors detail'),
                    ('show cdp neighbors detail', 'show cdp neighbors detail')
                ]
            else:
                # Cisco primarily uses CDP but may have LLDP
                commands = [
                    ('show cdp neighbors detail', 'show cdp neighbors detail'),
                    ('show lldp neighbors detail', 'show lldp neighbors detail')
                ]
            
            for cmd, parse_cmd in commands:
                try:
                    output = await connection.send_command(cmd)
                    if "Invalid" not in output and "Ambiguous" not in output:
                        parsed = await self.parse_with_textfsm(output, device_type, parse_cmd)
                        
                        # Normalize neighbor data
                        for entry in parsed:
                            neighbor = {
                                'local_interface': entry.get('local_interface', 'N/A'),
                                'neighbor_name': entry.get('neighbor', entry.get('device_id', entry.get('system_name', 'N/A'))),
                                'neighbor_interface': entry.get('neighbor_interface', entry.get('remote_port', entry.get('port_id', 'N/A'))),
                                'neighbor_ip': entry.get('management_ip', entry.get('ip', 'N/A')),
                                'platform': entry.get('platform', entry.get('capabilities', 'N/A')),
                                'protocol': 'CDP' if 'cdp' in cmd else 'LLDP'
                            }
                            neighbors_data.append(neighbor)
                except:
                    continue
            
            return neighbors_data
            
        except Exception as e:
            logger.error(f"Error getting CDP/LLDP neighbors: {e}")
            return []
    
    async def get_interface_descriptions(self, connection, device_type: str) -> Dict[str, str]:
        """Get interface descriptions for additional context"""
        try:
            output = await connection.send_command('show interface description')
            parsed = await self.parse_with_textfsm(output, device_type, 'show interface description')
            
            # Create interface to description mapping
            desc_map = {}
            for entry in parsed:
                interface = entry.get('interface', entry.get('port', ''))
                description = entry.get('description', entry.get('descrip', ''))
                if interface and description:
                    desc_map[interface] = description
            
            return desc_map
        except:
            return {}
    
    async def get_vlan_information(self, connection, device_type: str) -> List[Dict]:
        """Get VLAN information"""
        try:
            if device_type == 'cisco_nxos':
                output = await connection.send_command('show vlan brief')
            else:
                output = await connection.send_command('show vlan')
            
            parsed = await self.parse_with_textfsm(output, device_type, 'show vlan')
            
            vlan_data = []
            for entry in parsed:
                vlan_data.append({
                    'vlan_id': entry.get('vlan_id', 'N/A'),
                    'name': entry.get('name', 'N/A'),
                    'status': entry.get('status', 'active'),
                    'interfaces': entry.get('interfaces', [])
                })
            
            return vlan_data
        except:
            return []
    
    async def create_mac_arp_binding(self, mac_data: List[Dict], arp_data: List[Dict], 
                                   interface_desc: Dict[str, str]) -> List[Dict]:
        """Enhanced MAC-ARP binding with interface descriptions"""
        binding_data = []
        
        # Create MAC lookup dictionary
        mac_dict = {}
        for entry in mac_data:
            mac_address = entry['mac'].lower().replace(':', '').replace('.', '')
            mac_dict[mac_address] = entry
        
        for arp_entry in arp_data:
            # Normalize MAC address format
            arp_mac = arp_entry['mac'].lower().replace(':', '').replace('.', '')
            
            if arp_mac in mac_dict:
                mac_entry = mac_dict[arp_mac]
                interface = mac_entry['interface']
                binding_data.append({
                    'ip': arp_entry['ip'],
                    'mac': arp_entry['mac'],
                    'interface': interface,
                    'interface_description': interface_desc.get(interface, ''),
                    'vlan': mac_entry.get('vlan', 'N/A'),
                    'mac_type': mac_entry.get('type', 'N/A'),
                    'arp_interface': arp_entry['interface']
                })
            else:
                binding_data.append({
                    'ip': arp_entry['ip'],
                    'mac': arp_entry['mac'],
                    'interface': 'Not in MAC table',
                    'interface_description': '',
                    'vlan': 'N/A',
                    'mac_type': 'N/A',
                    'arp_interface': arp_entry['interface']
                })
        
        return binding_data
    
    async def process_device(self, ip: str):
        """Process a single device with auto-detection"""
        self.connection_stats['in_progress'] += 1
        logger.info(f"[Progress: {self.connection_stats['in_progress']}/{self.connection_stats['total']}] Starting processing of {ip}")
        
        # Auto-detect device type
        device_type = await self.detect_device_type(ip)
        if not device_type:
            logger.error(f"Could not detect device type for {ip}, skipping")
            self.connection_stats['in_progress'] -= 1
            self.connection_stats['failed'] += 1
            return
        
        connection = await self.connect_device(ip, device_type, timeout=30)
        if not connection:
            self.connection_stats['in_progress'] -= 1
            self.connection_stats['failed'] += 1
            return
        
        try:
            # Get device hostname and version info
            if device_type == 'arista_eos':
                hostname_cmd = 'show hostname'
                hostname_output = await connection.send_command(hostname_cmd)
                hostname = hostname_output.strip().split('\n')[0]
            else:
                hostname_cmd = 'show running-config | include hostname'
                hostname_output = await connection.send_command(hostname_cmd)
                hostname = hostname_output.split()[-1] if hostname_output and 'hostname' in hostname_output else ip
            
            logger.info(f"Processing device {hostname} ({ip}) - Type: {device_type}")
            
            # Collect all data
            logger.info(f"  Collecting MAC table...")
            mac_data = await self.get_mac_table(connection, device_type)
            
            logger.info(f"  Collecting ARP table...")
            arp_data = await self.get_arp_table(connection, device_type)
            
            logger.info(f"  Collecting CDP/LLDP neighbors...")
            cdp_lldp_data = await self.get_cdp_lldp_neighbors(connection, device_type)
            
            logger.info(f"  Collecting interface descriptions...")
            interface_desc = await self.get_interface_descriptions(connection, device_type)
            
            logger.info(f"  Collecting VLAN information...")
            vlan_data = await self.get_vlan_information(connection, device_type)
            
            logger.info(f"  Creating MAC-ARP bindings...")
            binding_data = await self.create_mac_arp_binding(mac_data, arp_data, interface_desc)
            
            # Store device information
            self.devices_info[ip] = {
                'hostname': hostname,
                'device_type': device_type,
                'mac_table': mac_data,
                'arp_table': arp_data,
                'cdp_lldp_neighbors': cdp_lldp_data,
                'mac_arp_binding': binding_data,
                'vlan_info': vlan_data,
                'interface_descriptions': interface_desc
            }
            
            # Store neighbor data for correlation
            self.cdp_lldp_data[ip] = cdp_lldp_data
            
            # Save to CSV files
            await self.save_to_csv(ip, hostname, mac_data, arp_data, cdp_lldp_data, 
                                 binding_data, vlan_data, interface_desc)
            
            logger.info(f"Successfully processed {hostname} ({ip})")
            self.connection_stats['successful'] += 1
            
        except Exception as e:
            logger.error(f"Error processing device {ip}: {e}")
            self.connection_stats['failed'] += 1
        finally:
            self.connection_stats['in_progress'] -= 1
            await connection.disconnect()
            logger.info(f"[Progress: Completed {self.connection_stats['successful'] + self.connection_stats['failed']}/{self.connection_stats['total']}] Finished {ip}")
    
    async def save_to_csv(self, ip: str, hostname: str, mac_data: List[Dict], 
                         arp_data: List[Dict], cdp_lldp_data: List[Dict], 
                         binding_data: List[Dict], vlan_data: List[Dict],
                         interface_desc: Dict[str, str]):
        """Save all collected data to CSV files"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_hostname = re.sub(r'[^\w\-_]', '_', hostname)
        device_dir = self.output_dir / f"{safe_hostname}_{ip}_{timestamp}"
        device_dir.mkdir(exist_ok=True, parents=True)
        
        # Save MAC table
        if mac_data:
            with open(device_dir / 'mac_table.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['vlan', 'mac', 'type', 'interface'])
                writer.writeheader()
                writer.writerows(mac_data)
        
        # Save ARP table
        if arp_data:
            with open(device_dir / 'arp_table.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['ip', 'mac', 'type', 'interface'])
                writer.writeheader()
                writer.writerows(arp_data)
        
        # Save CDP/LLDP neighbors
        if cdp_lldp_data:
            fieldnames = set()
            for entry in cdp_lldp_data:
                fieldnames.update(entry.keys())
            with open(device_dir / 'cdp_lldp_neighbors.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=sorted(list(fieldnames)))
                writer.writeheader()
                writer.writerows(cdp_lldp_data)
        
        # Save MAC-ARP binding
        if binding_data:
            with open(device_dir / 'mac_arp_binding.csv', 'w', newline='') as f:
                fieldnames = ['ip', 'mac', 'interface', 'interface_description', 
                            'vlan', 'mac_type', 'arp_interface']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(binding_data)
        
        # Save VLAN information
        if vlan_data:
            with open(device_dir / 'vlan_info.csv', 'w', newline='') as f:
                # Flatten interfaces list for CSV
                flat_vlan_data = []
                for vlan in vlan_data:
                    vlan_copy = vlan.copy()
                    if isinstance(vlan_copy.get('interfaces'), list):
                        vlan_copy['interfaces'] = ', '.join(vlan_copy['interfaces'])
                    flat_vlan_data.append(vlan_copy)
                
                if flat_vlan_data:
                    writer = csv.DictWriter(f, fieldnames=['vlan_id', 'name', 'status', 'interfaces'])
                    writer.writeheader()
                    writer.writerows(flat_vlan_data)
        
        # Save interface descriptions
        if interface_desc:
            with open(device_dir / 'interface_descriptions.csv', 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['interface', 'description'])
                for intf, desc in interface_desc.items():
                    writer.writerow([intf, desc])
        
        # Save device summary
        with open(device_dir / 'device_summary.txt', 'w') as f:
            f.write(f"Device: {hostname}\n")
            f.write(f"IP Address: {ip}\n")
            f.write(f"Device Type: {self.devices_info[ip]['device_type']}\n")
            f.write(f"Collection Time: {timestamp}\n")
            f.write(f"\nStatistics:\n")
            f.write(f"  MAC Entries: {len(mac_data)}\n")
            f.write(f"  ARP Entries: {len(arp_data)}\n")
            f.write(f"  Neighbors: {len(cdp_lldp_data)}\n")
            f.write(f"  VLANs: {len(vlan_data)}\n")
        
        logger.info(f"Data saved for {hostname} ({ip}) in {device_dir}")
    
    def correlate_connections(self):
        """Correlate device connections and create network topology with hierarchy detection"""
        connections = []
        bidirectional_links = {}
        device_connection_count = {}  # Track connection density
        device_neighbors = {}  # Track all neighbors for each device
        
        # First pass: collect all connections
        for local_ip, neighbors in self.cdp_lldp_data.items():
            local_hostname = self.devices_info[local_ip]['hostname']
            
            # Initialize neighbor tracking
            if local_hostname not in device_neighbors:
                device_neighbors[local_hostname] = {
                    'ip': local_ip,
                    'neighbors': [],
                    'neighbor_count': 0,
                    'is_in_seed': True
                }
            
            for neighbor in neighbors:
                neighbor_ip = neighbor.get('neighbor_ip', 'Unknown')
                neighbor_name = neighbor.get('neighbor_name', 'Unknown')
                
                # Check if neighbor is in our device list
                neighbor_in_list = False
                neighbor_hostname = neighbor_name
                
                for device_ip in self.devices_info:
                    if (neighbor_ip == device_ip or 
                        neighbor_name == self.devices_info[device_ip]['hostname']):
                        neighbor_in_list = True
                        neighbor_hostname = self.devices_info[device_ip]['hostname']
                        break
                
                # Track neighbor relationships
                device_neighbors[local_hostname]['neighbors'].append({
                    'name': neighbor_hostname,
                    'ip': neighbor_ip,
                    'interface': neighbor.get('neighbor_interface', 'Unknown'),
                    'in_seed_list': neighbor_in_list
                })
                device_neighbors[local_hostname]['neighbor_count'] += 1
                
                # Track connection density
                if neighbor_in_list:
                    # Count connections for devices in our list
                    if local_hostname not in device_connection_count:
                        device_connection_count[local_hostname] = 0
                    device_connection_count[local_hostname] += 1
                    
                    if neighbor_hostname not in device_connection_count:
                        device_connection_count[neighbor_hostname] = 0
                    device_connection_count[neighbor_hostname] += 1
                    
                    # Initialize neighbor tracking for discovered devices
                    if neighbor_hostname not in device_neighbors:
                        device_neighbors[neighbor_hostname] = {
                            'ip': neighbor_ip,
                            'neighbors': [],
                            'neighbor_count': 0,
                            'is_in_seed': True
                        }
                
                connection = {
                    'local_device': local_hostname,
                    'local_ip': local_ip,
                    'local_interface': neighbor.get('local_interface', 'Unknown'),
                    'neighbor_device': neighbor_hostname,
                    'neighbor_ip': neighbor_ip,
                    'neighbor_interface': neighbor.get('neighbor_interface', 'Unknown'),
                    'platform': neighbor.get('platform', 'Unknown'),
                    'protocol': neighbor.get('protocol', 'Unknown'),
                    'in_device_list': 'Yes' if neighbor_in_list else 'No'
                }
                
                connections.append(connection)
                
                # Track bidirectional links
                link_key = tuple(sorted([local_hostname, neighbor_hostname]))
                if link_key not in bidirectional_links:
                    bidirectional_links[link_key] = []
                bidirectional_links[link_key].append(connection)
        
        # Build network hierarchy
        hierarchy = self.build_network_hierarchy(device_neighbors, device_connection_count)
        
        # Detect network clusters/pods
        clusters = self.detect_network_clusters(device_neighbors, hierarchy)
        
        # Save all correlation data
        if connections:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            
            # Save detailed connections
            correlation_file = self.output_dir / f'device_connections_{timestamp}.csv'
            with open(correlation_file, 'w', newline='') as f:
                fieldnames = ['local_device', 'local_ip', 'local_interface',
                            'neighbor_device', 'neighbor_ip', 'neighbor_interface',
                            'platform', 'protocol', 'in_device_list']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(connections)
            
            # Save topology summary
            topology_file = self.output_dir / f'network_topology_{timestamp}.csv'
            with open(topology_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Device A', 'Device B', 'Connection Count', 'Bidirectional'])
                
                for link, conns in bidirectional_links.items():
                    is_bidirectional = len(conns) >= 2
                    writer.writerow([link[0], link[1], len(conns), 
                                   'Yes' if is_bidirectional else 'No'])
            
            # Save hierarchy analysis
            self.save_hierarchy_analysis(hierarchy, clusters, timestamp)
            
            logger.info(f"Device correlation saved to {correlation_file}")
            logger.info(f"Network topology saved to {topology_file}")
            logger.info(f"Hierarchy analysis saved")
        
        return connections
    
    async def process_all_devices(self, device_ips: List[str], max_concurrent: int = 10):
        """Process all devices asynchronously with controlled concurrency
        
        Args:
            device_ips: List of device IP addresses
            max_concurrent: Maximum number of concurrent SSH sessions (default: 10)
        """
        # Set total count for progress tracking
        self.connection_stats['total'] = len(device_ips)
        
        # Create semaphore to limit concurrent connections
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def process_with_semaphore(ip):
            """Process device with semaphore to limit concurrency"""
            async with semaphore:
                logger.info(f"Acquiring connection slot for {ip} (max concurrent: {max_concurrent})")
                await self.process_device(ip)
                logger.info(f"Released connection slot for {ip}")
        
        # Create tasks with semaphore control
        tasks = [process_with_semaphore(ip) for ip in device_ips]
        
        logger.info(f"Starting processing of {len(device_ips)} devices with max {max_concurrent} concurrent connections")
        logger.info("=" * 60)
        
        # Process all devices with controlled concurrency
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Log any exceptions that occurred (these are unexpected exceptions not handled in process_device)
        for ip, result in zip(device_ips, results):
            if isinstance(result, Exception):
                logger.error(f"Unexpected error processing {ip}: {result}")
        
        # Log final statistics
        logger.info("=" * 60)
        logger.info(f"Processing complete: {self.connection_stats['successful']} successful, {self.connection_stats['failed']} failed")
        
        # Correlate connections after all devices are processed
        logger.info("Creating network topology correlation...")
        self.correlate_connections()
        
        # Generate final summary report
        self.generate_summary_report()
    
    def generate_summary_report(self):
        """Generate a summary report of all collected data"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        summary_file = self.output_dir / f'collection_summary_{timestamp}.txt'
        
        with open(summary_file, 'w') as f:
            f.write("="*60 + "\n")
            f.write("Network Device Collection Summary\n")
            f.write("="*60 + "\n\n")
            f.write(f"Collection Time: {timestamp}\n")
            f.write(f"Total Devices Attempted: {self.connection_stats['total']}\n")
            f.write(f"Successful: {self.connection_stats['successful']}\n")
            f.write(f"Failed: {self.connection_stats['failed']}\n\n")
            
            f.write("Device Summary:\n")
            f.write("-"*40 + "\n")
            
            for ip, info in self.devices_info.items():
                f.write(f"\n{info['hostname']} ({ip}):\n")
                f.write(f"  Type: {info['device_type']}\n")
                f.write(f"  MAC Entries: {len(info['mac_table'])}\n")
                f.write(f"  ARP Entries: {len(info['arp_table'])}\n")
                f.write(f"  Neighbors: {len(info['cdp_lldp_neighbors'])}\n")
                f.write(f"  VLANs: {len(info.get('vlan_info', []))}\n")
                
                # List neighbors
                if info['cdp_lldp_neighbors']:
                    f.write(f"  Connected to:\n")
                    for neighbor in info['cdp_lldp_neighbors'][:5]:  # Show first 5
                        f.write(f"    - {neighbor.get('neighbor_name')} via {neighbor.get('local_interface')}\n")
                    if len(info['cdp_lldp_neighbors']) > 5:
                        f.write(f"    ... and {len(info['cdp_lldp_neighbors']) - 5} more\n")
        
        logger.info(f"Summary report saved to {summary_file}")
    
    def build_network_hierarchy(self, device_neighbors: Dict, connection_count: Dict) -> Dict:
        """Build network hierarchy tree based on connection density
        
        Devices with more connections are likely higher in the hierarchy:
        - Core/Distribution switches have many connections
        - Access switches have fewer connections
        - End devices have the least connections
        """
        hierarchy = {
            'core': [],      # Devices with highest connection count
            'distribution': [],  # Mid-level connection count
            'access': [],    # Lower connection count
            'edge': [],      # Minimal connections
            'unknown': [],    # Devices not in seed list
            'topology_type': 'unknown',  # Will detect: spine-leaf, 3-tier, or mesh
            'statistics': {}
        }
        
        # Calculate statistics for tier detection
        if connection_count:
            counts = list(connection_count.values())
            avg_connections = sum(counts) / len(counts)
            max_connections = max(counts)
            min_connections = min(counts)
            std_dev = (sum((x - avg_connections) ** 2 for x in counts) / len(counts)) ** 0.5
            
            hierarchy['statistics'] = {
                'avg_connections': avg_connections,
                'max_connections': max_connections,
                'min_connections': min_connections,
                'std_deviation': std_dev,
                'total_devices': len(connection_count)
            }
            
            # Detect topology type based on connection patterns
            if std_dev < avg_connections * 0.3 and avg_connections > 5:
                # Low variation with high connectivity suggests spine-leaf
                hierarchy['topology_type'] = 'spine-leaf'
                core_threshold = avg_connections * 1.5
                dist_threshold = avg_connections * 0.8
                access_threshold = avg_connections * 0.4
            elif max_connections > avg_connections * 3:
                # High variation suggests traditional 3-tier
                hierarchy['topology_type'] = '3-tier'
                core_threshold = max(avg_connections * 2, max_connections * 0.6)
                dist_threshold = avg_connections * 1.2
                access_threshold = avg_connections * 0.7
            else:
                # Mixed or mesh topology
                hierarchy['topology_type'] = 'hybrid/mesh'
                core_threshold = max(avg_connections * 1.8, max_connections * 0.5)
                dist_threshold = avg_connections
                access_threshold = avg_connections * 0.6
            
            logger.info(f"Network topology detected: {hierarchy['topology_type']}")
            logger.info(f"Network statistics - Devices: {len(counts)}, Avg connections: {avg_connections:.1f}, "
                       f"Max: {max_connections}, StdDev: {std_dev:.1f}")
            logger.info(f"Tier thresholds - Core: >{core_threshold:.1f}, Dist: >{dist_threshold:.1f}, "
                       f"Access: >{access_threshold:.1f}")
            
            # Classify devices by connection density
            for device, count in sorted(connection_count.items(), key=lambda x: x[1], reverse=True):
                device_info = {
                    'name': device,
                    'connection_count': count,
                    'neighbors': device_neighbors.get(device, {}).get('neighbors', []),
                    'ip': device_neighbors.get(device, {}).get('ip', 'Unknown'),
                    'connection_ratio': count / max_connections  # Relative connectivity
                }
                
                # Adjust classification based on topology type
                if hierarchy['topology_type'] == 'spine-leaf':
                    # In spine-leaf, high connection devices are spines
                    if count >= core_threshold:
                        device_info['role'] = 'spine'
                        hierarchy['core'].append(device_info)
                    elif count >= dist_threshold:
                        device_info['role'] = 'leaf'
                        hierarchy['distribution'].append(device_info)
                    else:
                        device_info['role'] = 'tor/access'
                        hierarchy['access'].append(device_info)
                else:
                    # Traditional 3-tier classification
                    if count >= core_threshold:
                        device_info['role'] = 'core'
                        hierarchy['core'].append(device_info)
                    elif count >= dist_threshold:
                        device_info['role'] = 'distribution'
                        hierarchy['distribution'].append(device_info)
                    elif count >= access_threshold:
                        device_info['role'] = 'access'
                        hierarchy['access'].append(device_info)
                    else:
                        device_info['role'] = 'edge'
                        hierarchy['edge'].append(device_info)
        
        # Add devices not in connection count (isolated or external)
        for device, info in device_neighbors.items():
            if device not in connection_count:
                hierarchy['unknown'].append({
                    'name': device,
                    'connection_count': 0,
                    'neighbors': info.get('neighbors', []),
                    'ip': info.get('ip', 'Unknown'),
                    'connection_ratio': 0,
                    'role': 'isolated/external'
                })
        
        return hierarchy
    
    def detect_network_clusters(self, device_neighbors: Dict, hierarchy: Dict) -> List[Dict]:
        """Detect network clusters/pods based on connectivity patterns
        
        Clusters are groups of devices that share common uplinks (distribution/core devices)
        This helps identify datacenter pods, building sections, or network zones
        """
        clusters = []
        
        # Find devices connected to each core/distribution device
        uplink_devices = hierarchy['core'] + hierarchy['distribution']
        
        for uplink in uplink_devices:
            cluster_devices = []
            uplink_name = uplink['name']
            
            # Find all devices connected to this uplink
            for device_name, device_info in device_neighbors.items():
                for neighbor in device_info.get('neighbors', []):
                    if neighbor['name'] == uplink_name and device_name != uplink_name:
                        cluster_devices.append({
                            'device': device_name,
                            'ip': device_info.get('ip', 'Unknown'),
                            'connection_interface': neighbor.get('interface', 'Unknown')
                        })
                        break
            
            if cluster_devices:
                clusters.append({
                    'uplink_device': uplink_name,
                    'uplink_ip': uplink.get('ip', 'Unknown'),
                    'uplink_tier': 'core' if uplink in hierarchy['core'] else 'distribution',
                    'connected_devices': cluster_devices,
                    'cluster_size': len(cluster_devices)
                })
        
        # Sort clusters by size (largest first)
        clusters.sort(key=lambda x: x['cluster_size'], reverse=True)
        
        return clusters
    
    def save_hierarchy_analysis(self, hierarchy: Dict, clusters: List[Dict], timestamp: str):
        """Save network hierarchy and cluster analysis"""
        
        # Save hierarchy analysis with role information
        hierarchy_file = self.output_dir / f'network_hierarchy_{timestamp}.csv'
        with open(hierarchy_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Device', 'IP', 'Tier', 'Role', 'Connection Count', 'Connection Ratio', 'Connected Devices'])
            
            for tier_name, devices in hierarchy.items():
                if tier_name not in ['unknown', 'topology_type', 'statistics']:  # Skip metadata
                    for device in devices:
                        neighbor_names = [n['name'] for n in device['neighbors'] if n.get('in_seed_list', False)]
                        writer.writerow([
                            device['name'],
                            device['ip'],
                            tier_name.upper(),
                            device.get('role', tier_name).upper(),
                            device['connection_count'],
                            f"{device.get('connection_ratio', 0):.2%}",
                            ', '.join(neighbor_names[:5]) + ('...' if len(neighbor_names) > 5 else '')
                        ])
        
        # Save cluster analysis
        cluster_file = self.output_dir / f'network_clusters_{timestamp}.csv'
        with open(cluster_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Cluster Uplink', 'Uplink IP', 'Uplink Tier', 'Cluster Size', 'Connected Devices'])
            
            for cluster in clusters:
                device_list = [d['device'] for d in cluster['connected_devices']]
                writer.writerow([
                    cluster['uplink_device'],
                    cluster['uplink_ip'],
                    cluster['uplink_tier'].upper(),
                    cluster['cluster_size'],
                    ', '.join(device_list[:10]) + ('...' if len(device_list) > 10 else '')
                ])
        
        # Save detailed cluster membership
        cluster_detail_file = self.output_dir / f'cluster_membership_{timestamp}.csv'
        with open(cluster_detail_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Device', 'Device IP', 'Uplink Device', 'Uplink IP', 'Uplink Tier', 'Interface'])
            
            for cluster in clusters:
                for device in cluster['connected_devices']:
                    writer.writerow([
                        device['device'],
                        device['ip'],
                        cluster['uplink_device'],
                        cluster['uplink_ip'],
                        cluster['uplink_tier'].upper(),
                        device['connection_interface']
                    ])
        
        # Generate network topology tree visualization (text format)
        tree_file = self.output_dir / f'network_tree_{timestamp}.txt'
        with open(tree_file, 'w') as f:
            f.write("="*60 + "\n")
            f.write("Network Topology Tree Structure\n")
            f.write("="*60 + "\n\n")
            
            # Topology type and statistics
            f.write(f"DETECTED TOPOLOGY TYPE: {hierarchy.get('topology_type', 'unknown').upper()}\n")
            f.write("-"*40 + "\n")
            
            if 'statistics' in hierarchy and hierarchy['statistics']:
                stats = hierarchy['statistics']
                f.write(f"Network Statistics:\n")
                f.write(f"  Total Devices: {stats.get('total_devices', 0)}\n")
                f.write(f"  Average Connections: {stats.get('avg_connections', 0):.1f}\n")
                f.write(f"  Maximum Connections: {stats.get('max_connections', 0)}\n")
                f.write(f"  Standard Deviation: {stats.get('std_deviation', 0):.1f}\n")
                f.write("\n")
            
            # Adjust display based on topology type
            if hierarchy.get('topology_type') == 'spine-leaf':
                # Spine-Leaf specific display
                if hierarchy['core']:
                    f.write("SPINE LAYER (High Connection Density)\n")
                    f.write("-"*40 + "\n")
                    for device in hierarchy['core']:
                        f.write(f"[SPINE] {device['name']} ({device['ip']}) - {device['connection_count']} connections "
                               f"({device.get('connection_ratio', 0):.1%} of max)\n")
                    f.write("\n")
                
                if hierarchy['distribution']:
                    f.write("LEAF LAYER\n")
                    f.write("-"*40 + "\n")
                    for device in hierarchy['distribution']:
                        f.write(f"  [LEAF] {device['name']} ({device['ip']}) - {device['connection_count']} connections\n")
                        
                        # Show connected devices
                        for cluster in clusters:
                            if cluster['uplink_device'] == device['name']:
                                f.write(f"    Connected devices ({cluster['cluster_size']} total):\n")
                                for connected in cluster['connected_devices'][:5]:
                                    f.write(f"      └─ {connected['device']} ({connected['ip']})\n")
                                if cluster['cluster_size'] > 5:
                                    f.write(f"      └─ ... and {cluster['cluster_size'] - 5} more\n")
                                break
                    f.write("\n")
                    
            else:
                # Traditional 3-tier display
                if hierarchy['core']:
                    f.write("CORE LAYER (Highest Connection Density)\n")
                    f.write("-"*40 + "\n")
                    for device in hierarchy['core']:
                        f.write(f"[CORE] {device['name']} ({device['ip']}) - {device['connection_count']} connections "
                               f"({device.get('connection_ratio', 0):.1%} of max)\n")
                    f.write("\n")
                
                if hierarchy['distribution']:
                    f.write("DISTRIBUTION LAYER\n")
                    f.write("-"*40 + "\n")
                    for device in hierarchy['distribution']:
                        f.write(f"  [DIST] {device['name']} ({device['ip']}) - {device['connection_count']} connections\n")
                        
                        # Show devices connected to this distribution device
                        for cluster in clusters:
                            if cluster['uplink_device'] == device['name']:
                                f.write(f"    Connected devices ({cluster['cluster_size']} total):\n")
                                for connected in cluster['connected_devices'][:5]:
                                    f.write(f"      └─ {connected['device']} ({connected['ip']})\n")
                                if cluster['cluster_size'] > 5:
                                    f.write(f"      └─ ... and {cluster['cluster_size'] - 5} more\n")
                                break
                    f.write("\n")
            
            # Access layer (common to all topologies)
            if hierarchy['access']:
                f.write("ACCESS LAYER\n")
                f.write("-"*40 + "\n")
                for device in hierarchy['access']:
                    f.write(f"    [ACCESS] {device['name']} ({device['ip']}) - {device['connection_count']} connections\n")
                f.write("\n")
            
            # Edge devices
            if hierarchy['edge']:
                f.write("EDGE DEVICES\n")
                f.write("-"*40 + "\n")
                for device in hierarchy['edge']:
                    f.write(f"      [EDGE] {device['name']} ({device['ip']}) - {device['connection_count']} connections\n")
                f.write("\n")
            
            # Cluster summary
            f.write("\n" + "="*60 + "\n")
            f.write("NETWORK CLUSTERS/PODS\n")
            f.write("="*60 + "\n\n")
            
            if clusters:
                # Group clusters by uplink tier
                core_clusters = [c for c in clusters if c['uplink_tier'] == 'core']
                dist_clusters = [c for c in clusters if c['uplink_tier'] == 'distribution']
                
                if core_clusters:
                    f.write("Core-Connected Clusters:\n")
                    f.write("-"*40 + "\n")
                    for i, cluster in enumerate(core_clusters[:5], 1):
                        f.write(f"  Cluster {i}: {cluster['uplink_device']}\n")
                        f.write(f"    Size: {cluster['cluster_size']} devices\n")
                        f.write(f"    Members: {', '.join([d['device'] for d in cluster['connected_devices'][:3]])}")
                        if cluster['cluster_size'] > 3:
                            f.write(f" +{cluster['cluster_size'] - 3} more")
                        f.write("\n")
                    f.write("\n")
                
                if dist_clusters:
                    f.write("Distribution-Connected Clusters:\n")
                    f.write("-"*40 + "\n")
                    for i, cluster in enumerate(dist_clusters[:5], 1):
                        f.write(f"  Cluster {i}: {cluster['uplink_device']}\n")
                        f.write(f"    Size: {cluster['cluster_size']} devices\n")
                        f.write(f"    Members: {', '.join([d['device'] for d in cluster['connected_devices'][:3]])}")
                        if cluster['cluster_size'] > 3:
                            f.write(f" +{cluster['cluster_size'] - 3} more")
                        f.write("\n")
                    f.write("\n")
            
            # Network statistics
            f.write("="*60 + "\n")
            f.write("NETWORK SUMMARY\n")
            f.write("="*60 + "\n")
            
            if hierarchy.get('topology_type') == 'spine-leaf':
                f.write(f"Spine switches: {len(hierarchy['core'])}\n")
                f.write(f"Leaf switches: {len(hierarchy['distribution'])}\n")
                f.write(f"ToR/Access switches: {len(hierarchy['access'])}\n")
            else:
                f.write(f"Core devices: {len(hierarchy['core'])}\n")
                f.write(f"Distribution devices: {len(hierarchy['distribution'])}\n")
                f.write(f"Access devices: {len(hierarchy['access'])}\n")
            
            f.write(f"Edge devices: {len(hierarchy['edge'])}\n")
            f.write(f"Total clusters identified: {len(clusters)}\n")
            
            if clusters:
                avg_cluster_size = sum(c['cluster_size'] for c in clusters) / len(clusters)
                f.write(f"Average cluster size: {avg_cluster_size:.1f} devices\n")
                f.write(f"Largest cluster: {clusters[0]['cluster_size']} devices (uplink: {clusters[0]['uplink_device']})\n")
                
                # Identify potential datacenter pods
                large_clusters = [c for c in clusters if c['cluster_size'] >= 5]
                if large_clusters:
                    f.write(f"\nPotential Datacenter Pods/Zones: {len(large_clusters)}\n")
                    for cluster in large_clusters[:3]:
                        f.write(f"  - {cluster['uplink_device']}: {cluster['cluster_size']} devices\n")
        
        logger.info(f"Network hierarchy saved to {hierarchy_file}")
        logger.info(f"Network clusters saved to {cluster_file}")
        logger.info(f"Network tree visualization saved to {tree_file}")

def read_device_list(filename: str) -> List[str]:
    """
    Read device list from file
    Expected format: One IP address per line
    Lines starting with # are treated as comments
    """
    devices = []
    
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Extract IP address (first item if space/comma separated)
                    ip = line.split(',')[0].split()[0].strip()
                    devices.append(ip)
    except FileNotFoundError:
        logger.error(f"Device list file {filename} not found")
    except Exception as e:
        logger.error(f"Error reading device list: {e}")
    
    return devices

async def main():
    """Main execution function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Network Device Information Collector with Auto-Detection')
    parser.add_argument('device_list', help='File containing list of device IPs (one per line)')
    parser.add_argument('-u', '--username', required=True, help='SSH username')
    parser.add_argument('-p', '--password', required=True, help='SSH password')
    parser.add_argument('-o', '--output', default='network_data', help='Output directory')
    parser.add_argument('--concurrent', type=int, default=10, help='Max concurrent connections (default: 10)')
    
    args = parser.parse_args()
    
    # Read device list
    devices = read_device_list(args.device_list)
    
    if not devices:
        logger.error("No devices found in the device list")
        return
    
    print("\n" + "="*60)
    print("Network Device Information Collector")
    print("="*60)
    print(f"Devices to process: {len(devices)}")
    print(f"Max concurrent connections: {args.concurrent}")
    print(f"Output directory: {args.output}")
    print("="*60 + "\n")
    
    # Create collector and process devices
    collector = NetworkDeviceCollector(args.username, args.password, args.output)
    await collector.process_all_devices(devices, max_concurrent=args.concurrent)
    
    # Print summary
    print("\n" + "="*60)
    print("Collection Complete!")
    print("="*60)
    print(f"Devices processed successfully: {collector.connection_stats['successful']}/{len(devices)}")
    print(f"Failed devices: {collector.connection_stats['failed']}")
    print(f"Output directory: {collector.output_dir}")
    
    print("\nDevice Summary:")
    for ip, info in collector.devices_info.items():
        hostname = info['hostname']
        device_type = info['device_type']
        neighbor_count = len(info['cdp_lldp_neighbors'])
        print(f"  {hostname} ({ip}) - {device_type}: {neighbor_count} neighbors")
    
    # Print hierarchy summary if correlation was performed
    if hasattr(collector, 'cdp_lldp_data') and collector.cdp_lldp_data:
        print("\n" + "="*60)
        print("Network Hierarchy Detected:")
        print("="*60)
        print("Check the output directory for:")
        print("  - network_hierarchy_*.csv - Device tier classification")
        print("  - network_clusters_*.csv - Identified network clusters/pods")
        print("  - network_tree_*.txt - Visual tree representation")
        print("  - cluster_membership_*.csv - Detailed cluster membership")

if __name__ == '__main__':
    # Example device list file (devices.txt):
    # 192.168.1.1
    # 192.168.1.2
    # 10.0.0.1
    # 10.0.0.2
    # # This is a comment
    # 172.16.0.1
    
    asyncio.run(main())
