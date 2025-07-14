#!/usr/bin/env python3
"""
Advanced Python Ping Script with nmap -sP like functionality
Supports: IP ranges, CIDR blocks, subnets, host files, and individual IPs
Features: Pre/Post implementation scanning with comparison and reporting
"""

import argparse
import asyncio
import ipaddress
import platform
import subprocess
import sys
import time
import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import List, Set, Union, Iterator, Dict
from datetime import datetime
import socket
import struct


class PingScanner:
    def __init__(self, timeout: float = 1.0, max_workers: int = 100):
        self.timeout = timeout
        self.max_workers = max_workers
        self.system = platform.system().lower()
        self.alive_hosts = set()
        self.dead_hosts = set()
        self.scan_results = {}
        self.scan_metadata = {}
        
    def ping_host(self, host: str) -> bool:
        """Ping a single host and return True if alive"""
        try:
            # Determine ping command based on OS
            if self.system == "windows":
                cmd = ["ping", "-n", "1", "-w", str(int(self.timeout * 1000)), host]
            else:
                cmd = ["ping", "-c", "1", "-W", str(int(self.timeout)), host]
            
            # Execute ping command
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 1
            )
            
            return result.returncode == 0
            
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            return False
    
    def parse_ip_range(self, ip_range: str) -> List[str]:
        """Parse various IP range formats"""
        ips = []
        
        try:
            # Handle CIDR notation (e.g., 192.168.1.0/24)
            if '/' in ip_range:
                network = ipaddress.ip_network(ip_range, strict=False)
                return [str(ip) for ip in network.hosts()]
            
            # Handle hyphen range (e.g., 192.168.1.1-192.168.1.50)
            elif '-' in ip_range:
                start_ip, end_ip = ip_range.split('-')
                start = ipaddress.ip_address(start_ip.strip())
                end = ipaddress.ip_address(end_ip.strip())
                
                if start.version != end.version:
                    raise ValueError("IP versions must match")
                
                current = start
                while current <= end:
                    ips.append(str(current))
                    current += 1
                
                return ips
            
            # Handle comma-separated IPs (e.g., 192.168.1.1,192.168.1.2,192.168.1.3)
            elif ',' in ip_range:
                return [ip.strip() for ip in ip_range.split(',')]
            
            # Handle range notation (e.g., 192.168.1.1-50)
            elif ip_range.count('.') == 3 and '-' in ip_range.split('.')[-1]:
                base_ip = '.'.join(ip_range.split('.')[:-1])
                last_octet_range = ip_range.split('.')[-1]
                
                if '-' in last_octet_range:
                    start, end = last_octet_range.split('-')
                    for i in range(int(start), int(end) + 1):
                        ips.append(f"{base_ip}.{i}")
                
                return ips
            
            # Handle single IP
            else:
                ipaddress.ip_address(ip_range)  # Validate IP
                return [ip_range]
                
        except (ipaddress.AddressValueError, ValueError) as e:
            print(f"Error parsing IP range '{ip_range}': {e}")
            return []
    
    def parse_subnet_range(self, subnet: str, ip_range: str) -> List[str]:
        """Parse subnet with specific IP range (e.g., 192.168.1.0/24 with range 1-50)"""
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            base_ip = str(network.network_address)
            
            # Parse the range part
            if '-' in ip_range:
                start, end = map(int, ip_range.split('-'))
                ips = []
                for i in range(start, end + 1):
                    try:
                        ip = ipaddress.ip_address(f"{'.'.join(base_ip.split('.')[:-1])}.{i}")
                        if ip in network:
                            ips.append(str(ip))
                    except ipaddress.AddressValueError:
                        continue
                return ips
            else:
                # Single IP in subnet
                try:
                    ip = ipaddress.ip_address(f"{'.'.join(base_ip.split('.')[:-1])}.{ip_range}")
                    if ip in network:
                        return [str(ip)]
                except ipaddress.AddressValueError:
                    pass
                
        except (ipaddress.AddressValueError, ValueError) as e:
            print(f"Error parsing subnet range '{subnet}' with range '{ip_range}': {e}")
        
        return []
    
    def load_hosts_from_file(self, filename: str) -> List[str]:
        """Load host list from file"""
        hosts = []
        try:
            with open(filename, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Each line can contain IP ranges, CIDR blocks, etc.
                        hosts.extend(self.parse_ip_range(line))
        except FileNotFoundError:
            print(f"Error: File '{filename}' not found")
        except Exception as e:
            print(f"Error reading file '{filename}': {e}")
        
        return hosts
    
    def scan_hosts(self, hosts: List[str], verbose: bool = False, scan_type: str = "pre", scan_name: str = "scan") -> None:
        """Scan multiple hosts concurrently"""
        if not hosts:
            print("No hosts to scan")
            return
        
        print(f"Scanning {len(hosts)} hosts...")
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all ping tasks
            future_to_host = {executor.submit(self.ping_host, host): host for host in hosts}
            
            # Process results as they complete
            for future in future_to_host:
                host = future_to_host[future]
                try:
                    is_alive = future.result()
                    if is_alive:
                        self.alive_hosts.add(host)
                        if verbose:
                            print(f"Host {host} is UP")
                    else:
                        self.dead_hosts.add(host)
                        if verbose:
                            print(f"Host {host} is DOWN")
                except Exception as e:
                    self.dead_hosts.add(host)
                    if verbose:
                        print(f"Error pinging {host}: {e}")
        
        end_time = time.time()
        elapsed_time = end_time - start_time
        
        # Store scan results
        self.scan_results = {
            'alive_hosts': sorted(list(self.alive_hosts), key=lambda x: ipaddress.ip_address(x)),
            'dead_hosts': sorted(list(self.dead_hosts), key=lambda x: ipaddress.ip_address(x)),
            'total_hosts': len(self.alive_hosts) + len(self.dead_hosts),
            'scan_time': elapsed_time
        }
        
        self.scan_metadata = {
            'scan_type': scan_type,
            'scan_name': scan_name,
            'timestamp': datetime.now().isoformat(),
            'timeout': self.timeout,
            'max_workers': self.max_workers,
            'total_scanned': len(hosts)
        }
        
        self.print_summary(elapsed_time)
        
        # Save results to file
        self.save_scan_results(scan_type, scan_name)
        
        # If this is a post-implementation scan, compare with pre-implementation
        if scan_type == "post":
            self.compare_with_pre_scan(scan_name)
    
    def print_summary(self, elapsed_time: float) -> None:
        """Print scan summary"""
        total_hosts = len(self.alive_hosts) + len(self.dead_hosts)
        
        print(f"\n--- Scan Summary ---")
        print(f"Total hosts scanned: {total_hosts}")
        print(f"Hosts up: {len(self.alive_hosts)}")
        print(f"Hosts down: {len(self.dead_hosts)}")
        print(f"Scan completed in {elapsed_time:.2f} seconds")
        
        if self.alive_hosts:
            print(f"\nAlive hosts:")
            for host in sorted(self.alive_hosts, key=lambda x: ipaddress.ip_address(x)):
                print(f"  {host}")
    
    def save_scan_results(self, scan_type: str, scan_name: str) -> None:
        """Save scan results to JSON file"""
        # Create scans directory if it doesn't exist
        scan_dir = Path("scans")
        scan_dir.mkdir(exist_ok=True)
        
        # Create filename based on scan type and name
        filename = f"{scan_type}_implementation_{scan_name}.json"
        filepath = scan_dir / filename
        
        # Prepare data to save
        save_data = {
            'metadata': self.scan_metadata,
            'results': self.scan_results
        }
        
        # Save to JSON file
        try:
            with open(filepath, 'w') as f:
                json.dump(save_data, f, indent=2)
            print(f"\n✓ Scan results saved to: {filepath}")
        except Exception as e:
            print(f"✗ Error saving scan results: {e}")
    
    def load_scan_results(self, scan_type: str, scan_name: str) -> Dict:
        """Load scan results from JSON file"""
        scan_dir = Path("scans")
        filename = f"{scan_type}_implementation_{scan_name}.json"
        filepath = scan_dir / filename
        
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return None
        except Exception as e:
            print(f"✗ Error loading scan results: {e}")
            return None
    
    def compare_with_pre_scan(self, scan_name: str) -> None:
        """Compare post-implementation scan with pre-implementation scan"""
        print(f"\n--- Comparing with Pre-Implementation Scan ---")
        
        # Load pre-implementation scan results
        pre_scan_data = self.load_scan_results("pre", scan_name)
        
        if not pre_scan_data:
            print(f"✗ No pre-implementation scan found with name '{scan_name}'")
            print(f"  Expected file: scans/pre_implementation_{scan_name}.json")
            return
        
        pre_alive = set(pre_scan_data['results']['alive_hosts'])
        pre_dead = set(pre_scan_data['results']['dead_hosts'])
        post_alive = set(self.scan_results['alive_hosts'])
        post_dead = set(self.scan_results['dead_hosts'])
        
        # Analysis
        newly_alive = post_alive - pre_alive
        newly_dead = post_dead - pre_dead
        still_alive = pre_alive & post_alive
        still_dead = pre_dead & post_dead
        
        # Hosts that were alive before but are now dead (critical finding)
        went_down = pre_alive - post_alive
        
        # Hosts that were dead before but are now alive (positive finding)
        came_up = pre_dead - post_dead
        
        # Print comparison results
        print(f"\nComparison Results:")
        print(f"Pre-implementation:  {len(pre_alive)} up, {len(pre_dead)} down")
        print(f"Post-implementation: {len(post_alive)} up, {len(post_dead)} down")
        
        print(f"\nStatus Changes:")
        print(f"  Hosts that came up: {len(came_up)}")
        print(f"  Hosts that went down: {len(went_down)}")
        print(f"  Hosts still up: {len(still_alive)}")
        print(f"  Hosts still down: {len(still_dead)}")
        
        # Critical alerts for hosts that went down
        if went_down:
            print(f"\n🚨 CRITICAL: {len(went_down)} hosts went DOWN after implementation!")
            for host in sorted(went_down, key=lambda x: ipaddress.ip_address(x)):
                print(f"  ❌ {host} (was UP, now DOWN)")
        
        # Positive alerts for hosts that came up
        if came_up:
            print(f"\n✅ POSITIVE: {len(came_up)} hosts came UP after implementation!")
            for host in sorted(came_up, key=lambda x: ipaddress.ip_address(x)):
                print(f"  ✅ {host} (was DOWN, now UP)")
        
        # Save comparison results
        self.save_comparison_results(scan_name, {
            'pre_scan': pre_scan_data,
            'post_scan': {'metadata': self.scan_metadata, 'results': self.scan_results},
            'comparison': {
                'went_down': sorted(list(went_down), key=lambda x: ipaddress.ip_address(x)),
                'came_up': sorted(list(came_up), key=lambda x: ipaddress.ip_address(x)),
                'still_alive': sorted(list(still_alive), key=lambda x: ipaddress.ip_address(x)),
                'still_dead': sorted(list(still_dead), key=lambda x: ipaddress.ip_address(x)),
                'summary': {
                    'pre_alive_count': len(pre_alive),
                    'pre_dead_count': len(pre_dead),
                    'post_alive_count': len(post_alive),
                    'post_dead_count': len(post_dead),
                    'went_down_count': len(went_down),
                    'came_up_count': len(came_up)
                }
            }
        })
    
    def save_comparison_results(self, scan_name: str, comparison_data: Dict) -> None:
        """Save comparison results to JSON and generate human-readable report"""
        scan_dir = Path("scans")
        scan_dir.mkdir(exist_ok=True)
        
        # Save JSON comparison data
        json_filename = f"comparison_{scan_name}.json"
        json_filepath = scan_dir / json_filename
        
        try:
            with open(json_filepath, 'w') as f:
                json.dump(comparison_data, f, indent=2)
            print(f"✓ Comparison data saved to: {json_filepath}")
        except Exception as e:
            print(f"✗ Error saving comparison data: {e}")
        
        # Generate human-readable report
        report_filename = f"comparison_report_{scan_name}.txt"
        report_filepath = scan_dir / report_filename
        
        try:
            with open(report_filepath, 'w') as f:
                self.write_comparison_report(f, comparison_data, scan_name)
            print(f"✓ Comparison report saved to: {report_filepath}")
        except Exception as e:
            print(f"✗ Error saving comparison report: {e}")
    
    def write_comparison_report(self, file_handle, comparison_data: Dict, scan_name: str) -> None:
        """Write human-readable comparison report"""
        comp = comparison_data['comparison']
        pre_meta = comparison_data['pre_scan']['metadata']
        post_meta = comparison_data['post_scan']['metadata']
        
        file_handle.write(f"NETWORK IMPLEMENTATION COMPARISON REPORT\n")
        file_handle.write(f"=" * 50 + "\n\n")
        
        file_handle.write(f"Scan Name: {scan_name}\n")
        file_handle.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        file_handle.write(f"PRE-IMPLEMENTATION SCAN:\n")
        file_handle.write(f"  Timestamp: {pre_meta['timestamp']}\n")
        file_handle.write(f"  Hosts Up: {comp['summary']['pre_alive_count']}\n")
        file_handle.write(f"  Hosts Down: {comp['summary']['pre_dead_count']}\n\n")
        
        file_handle.write(f"POST-IMPLEMENTATION SCAN:\n")
        file_handle.write(f"  Timestamp: {post_meta['timestamp']}\n")
        file_handle.write(f"  Hosts Up: {comp['summary']['post_alive_count']}\n")
        file_handle.write(f"  Hosts Down: {comp['summary']['post_dead_count']}\n\n")
        
        file_handle.write(f"SUMMARY OF CHANGES:\n")
        file_handle.write(f"  Hosts that went DOWN: {comp['summary']['went_down_count']}\n")
        file_handle.write(f"  Hosts that came UP: {comp['summary']['came_up_count']}\n\n")
        
        if comp['went_down']:
            file_handle.write(f"🚨 CRITICAL ALERTS - HOSTS THAT WENT DOWN:\n")
            file_handle.write(f"-" * 40 + "\n")
            for host in comp['went_down']:
                file_handle.write(f"❌ {host} (was UP, now DOWN)\n")
            file_handle.write(f"\n")
        
        if comp['came_up']:
            file_handle.write(f"✅ POSITIVE CHANGES - HOSTS THAT CAME UP:\n")
            file_handle.write(f"-" * 40 + "\n")
            for host in comp['came_up']:
                file_handle.write(f"✅ {host} (was DOWN, now UP)\n")
            file_handle.write(f"\n")
        
        if comp['still_alive']:
            file_handle.write(f"STABLE HOSTS - REMAINED UP:\n")
            file_handle.write(f"-" * 25 + "\n")
            for host in comp['still_alive']:
                file_handle.write(f"✓ {host}\n")
            file_handle.write(f"\n")
        
        if comp['still_dead']:
            file_handle.write(f"UNCHANGED HOSTS - REMAINED DOWN:\n")
            file_handle.write(f"-" * 30 + "\n")
            for host in comp['still_dead']:
                file_handle.write(f"○ {host}\n")
            file_handle.write(f"\n")
        
        file_handle.write(f"RECOMMENDATIONS:\n")
        file_handle.write(f"-" * 15 + "\n")
        if comp['went_down']:
            file_handle.write(f"• URGENT: Investigate {len(comp['went_down'])} hosts that went down\n")
            file_handle.write(f"• Check network connectivity, services, and configuration\n")
        if comp['came_up']:
            file_handle.write(f"• Verify {len(comp['came_up'])} newly available hosts are functioning correctly\n")
        if not comp['went_down'] and not comp['came_up']:
            file_handle.write(f"• No host status changes detected - implementation appears stable\n")
        
        file_handle.write(f"\nEnd of Report\n")
    
    def get_user_scan_info(self) -> tuple:
        """Get scan type and name from user input"""
        print("\n" + "="*60)
        print("NETWORK IMPLEMENTATION SCANNER")
        print("="*60)
        
        while True:
            scan_type = input("\nIs this a PRE or POST implementation scan? (pre/post): ").lower().strip()
            if scan_type in ['pre', 'post']:
                break
            print("Please enter 'pre' or 'post'")
        
        print(f"\nYou selected: {scan_type.upper()}-implementation scan")
        
        while True:
            scan_name = input("Enter a name for this scan (e.g., 'firewall_upgrade', 'network_migration'): ").strip()
            if scan_name and scan_name.replace('_', '').replace('-', '').isalnum():
                break
            print("Please enter a valid name (alphanumeric characters, underscores, and hyphens only)")
        
        return scan_type, scan_name
    
    def list_available_scans(self) -> None:
        """List available scan files"""
        scan_dir = Path("scans")
        if not scan_dir.exists():
            return
        
        pre_scans = []
        post_scans = []
        comparison_files = []
        
        for file in scan_dir.glob("*.json"):
            if file.name.startswith("pre_implementation_"):
                scan_name = file.name.replace("pre_implementation_", "").replace(".json", "")
                pre_scans.append(scan_name)
            elif file.name.startswith("post_implementation_"):
                scan_name = file.name.replace("post_implementation_", "").replace(".json", "")
                post_scans.append(scan_name)
            elif file.name.startswith("comparison_"):
                scan_name = file.name.replace("comparison_", "").replace(".json", "")
                comparison_files.append(scan_name)
        
        if pre_scans or post_scans or comparison_files:
            print(f"\n--- Available Scans ---")
            if pre_scans:
                print(f"Pre-implementation scans: {', '.join(sorted(pre_scans))}")
            if post_scans:
                print(f"Post-implementation scans: {', '.join(sorted(post_scans))}")
            if comparison_files:
                print(f"Comparison reports: {', '.join(sorted(comparison_files))}")
            print()



def main():
    parser = argparse.ArgumentParser(
        description="Advanced Python Ping Scanner with nmap -sP functionality and implementation tracking",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.1                    # Single IP
  %(prog)s 192.168.1.0/24                 # CIDR block
  %(prog)s 192.168.1.1-192.168.1.50       # IP range with hyphens
  %(prog)s 192.168.1.1-50                 # Last octet range
  %(prog)s 192.168.1.1,192.168.1.5,192.168.1.10  # Comma-separated IPs
  %(prog)s -f hosts.txt                   # Load from file
  %(prog)s -s 192.168.1.0/24 -r 1-50      # Subnet with range
  %(prog)s -t 2.0 -w 50 192.168.1.0/24    # Custom timeout and workers
  %(prog)s --list-scans                   # List available scans
        """
    )
    
    # Input options
    parser.add_argument('targets', nargs='*', help='IP addresses, ranges, or CIDR blocks to scan')
    parser.add_argument('-f', '--file', help='Read host list from file')
    parser.add_argument('-s', '--subnet', help='Subnet to scan (use with -r for range)')
    parser.add_argument('-r', '--range', help='IP range within subnet (e.g., 1-50)')
    
    # Scan options
    parser.add_argument('-t', '--timeout', type=float, default=1.0, help='Ping timeout in seconds (default: 1.0)')
    parser.add_argument('-w', '--workers', type=int, default=100, help='Max concurrent workers (default: 100)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    # New options
    parser.add_argument('--list-scans', action='store_true', help='List available scan files')
    parser.add_argument('--batch-mode', action='store_true', help='Skip user prompts (for automation)')
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = PingScanner(timeout=args.timeout, max_workers=args.workers)
    
    # Handle list scans option
    if args.list_scans:
        scanner.list_available_scans()
        return
    
    # Validate arguments
    if not args.targets and not args.file and not args.subnet:
        parser.error("Must specify targets, file, or subnet")
    
    if args.subnet and not args.range:
        parser.error("Must specify range when using subnet option")
    
    # Get scan information from user (unless in batch mode)
    if not args.batch_mode:
        scan_type, scan_name = scanner.get_user_scan_info()
        scanner.list_available_scans()
    else:
        # Default values for batch mode
        scan_type = "pre"
        scan_name = f"batch_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    # Collect all hosts to scan
    all_hosts = set()
    
    # Add targets from command line
    if args.targets:
        for target in args.targets:
            hosts = scanner.parse_ip_range(target)
            all_hosts.update(hosts)
    
    # Add hosts from file
    if args.file:
        hosts = scanner.load_hosts_from_file(args.file)
        all_hosts.update(hosts)
    
    # Add hosts from subnet range
    if args.subnet and args.range:
        hosts = scanner.parse_subnet_range(args.subnet, args.range)
        all_hosts.update(hosts)
    
    # Convert to sorted list
    hosts_list = sorted(list(all_hosts), key=lambda x: ipaddress.ip_address(x))
    
    # Perform scan
    scanner.scan_hosts(hosts_list, verbose=args.verbose, scan_type=scan_type, scan_name=scan_name)


if __name__ == "__main__":
    main()
