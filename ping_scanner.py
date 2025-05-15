#!/usr/bin/env python3
"""
Fast Ping Scanner with CIDR Support
Python 3.9.2 compatible
"""

import subprocess
import ipaddress
import socket
import csv
import sys
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import platform

# Force reload if running interactively
if __name__ == "__main__":
    import importlib
    importlib.reload(sys.modules[__name__] if __name__ in sys.modules else sys.modules[__file__.split('.')[0]])

class PingScanner:
    def __init__(self, max_workers=20, timeout=1, packet_size=32, default_domain=""):
        """
        Initialize the ping scanner
        
        Args:
            max_workers (int): Maximum number of concurrent ping operations
            timeout (int): Ping timeout in seconds
            packet_size (int): Ping packet size in bytes
            default_domain (str): Default domain to append to hostnames without FQDN
        """
        self.max_workers = max_workers
        self.timeout = timeout
        self.packet_size = packet_size
        self.default_domain = default_domain
        self.os_type = platform.system().lower()
        self.results = []
        
    def is_valid_ip(self, address):
        """
        Check if an address is a valid IP address
        
        Args:
            address (str): Address to check
            
        Returns:
            bool: True if valid IP, False otherwise
        """
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False
    
    def is_valid_cidr(self, address):
        """
        Check if an address is a valid CIDR block
        
        Args:
            address (str): Address to check
            
        Returns:
            bool: True if valid CIDR, False otherwise
        """
        return '/' in address and not self.is_valid_ip(address)
    
    def is_valid_hostname(self, hostname, with_domain=False):
        """
        Check if a hostname is valid according to RFC standards
        
        Args:
            hostname (str): Hostname to validate
            with_domain (bool): Whether to append default domain before validation
            
        Returns:
            bool: True if valid hostname, False otherwise
        """
        if not hostname:
            return False
        
        # If requested and no dot present, append default domain for validation
        if with_domain and '.' not in hostname and self.default_domain:
            test_hostname = f"{hostname}.{self.default_domain}"
        else:
            test_hostname = hostname
            
        if len(test_hostname) > 253:
            return False
        
        # Remove leading/trailing dots
        test_hostname = test_hostname.rstrip('.')
        
        # Check each label (part between dots)
        labels = test_hostname.split('.')
        for label in labels:
            # Labels must be 1-63 characters
            if not label or len(label) > 63:
                return False
            # Labels must start and end with alphanumeric
            if not label[0].isalnum() or not label[-1].isalnum():
                return False
            # Labels can contain hyphens but not at start/end
            if not all(c.isalnum() or c == '-' for c in label):
                return False
        
        return True
    
    def resolve_hostname(self, hostname):
        """
        Resolve hostname to IP address with validation
        
        Args:
            hostname (str): Hostname to resolve
            
        Returns:
            str or None: IP address if resolved, None if failed
        """
        try:
            # Clean up the hostname
            hostname = hostname.strip()
            original_hostname = hostname
            
            # If hostname doesn't contain a dot and we have a default domain, append it
            if '.' not in hostname and self.default_domain:
                hostname = f"{hostname}.{self.default_domain}"
                print(f"    Appending domain: {original_hostname} -> {hostname}")
            
            # Validate hostname format (using the final hostname with domain)
            if not self.is_valid_hostname(hostname):
                print(f"  Invalid hostname format: {hostname}")
                return None
            
            # Resolve hostname to IP
            ip = socket.gethostbyname(hostname)
            return ip
        except socket.gaierror as e:
            print(f"  DNS resolution failed for {hostname}: {e}")
            return None
        except UnicodeError as e:
            print(f"  Invalid hostname encoding for {hostname}: {e}")
            return None
        except Exception as e:
            print(f"  Unexpected error resolving {hostname}: {e}")
            return None
    
    def ping_host(self, target, original_target=None):
        """
        Ping a single host and resolve its hostname
        
        Args:
            target (str): IP address to ping
            original_target (str): Original hostname if target was resolved from hostname
            
        Returns:
            dict: Result dictionary with ip, status, hostname, response_time, and original_target
        """
        # Choose ping command based on OS
        if self.os_type == "windows":
            ping_cmd = ["ping", "-n", "1", "-w", str(self.timeout * 1000), "-l", str(self.packet_size), str(target)]
        else:
            ping_cmd = ["ping", "-c", "1", "-W", str(self.timeout), "-s", str(self.packet_size), str(target)]
        
        result = {
            'ip': str(target),
            'status': 'Down',
            'hostname': '',
            'response_time': '',
            'original_target': original_target or str(target)
        }
        
        try:
            # Execute ping command
            output = subprocess.run(
                ping_cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 1
            )
            
            if output.returncode == 0:
                result['status'] = 'Up'
                
                # Extract response time from ping output
                if self.os_type == "windows":
                    # Parse Windows ping output for response time
                    for line in output.stdout.split('\n'):
                        if 'time=' in line.lower() or 'time<' in line.lower():
                            # Extract time value
                            parts = line.split()
                            for part in parts:
                                if 'time' in part.lower():
                                    time_part = part.split('=')[-1].replace('ms', '').replace('<', '')
                                    result['response_time'] = f"{time_part}ms"
                                    break
                            break
                else:
                    # Parse Unix/Linux ping output for response time
                    for line in output.stdout.split('\n'):
                        if 'time=' in line:
                            time_part = line.split('time=')[1].split()[0]
                            result['response_time'] = time_part
                            break
                
                # Try to resolve hostname
                try:
                    hostname = socket.gethostbyaddr(str(target))[0]
                    result['hostname'] = hostname
                except socket.herror:
                    result['hostname'] = 'No PTR record'
                    
        except subprocess.TimeoutExpired:
            result['status'] = 'Timeout'
        except Exception as e:
            result['status'] = f'Error: {str(e)}'
            
        return result
    
    def get_hosts_from_cidr(self, cidr_block):
        """
        Generate list of host IPs from CIDR block, excluding network and broadcast
        
        Args:
            cidr_block (str): CIDR notation (e.g., '192.168.1.0/24')
            
        Returns:
            list: List of host IP addresses
        """
        try:
            network = ipaddress.ip_network(cidr_block, strict=False)
            hosts = []
            
            # Get all hosts, excluding network and broadcast addresses
            for ip in network.hosts():
                hosts.append(ip)
                
            return hosts
        except ValueError as e:
            print(f"Error parsing CIDR block {cidr_block}: {e}")
            return []
    
    def scan_targets(self, targets):
        """
        Scan multiple targets (IPs, hostnames, or CIDR blocks)
        
        Args:
            targets (list): List of IP addresses, hostnames, or CIDR blocks
        """
        all_ips = []
        hostname_targets = []
        failed_resolutions = []
        
        # First pass: categorize targets
        for i, target in enumerate(targets):
            print(f"Processing target {i+1}/{len(targets)}: '{target}'")
            
            try:
                if self.is_valid_cidr(target):
                    # It's a CIDR block
                    print(f"  Expanding CIDR block: {target}")
                    hosts = self.get_hosts_from_cidr(target)
                    all_ips.extend([(ip, None) for ip in hosts])
                    print(f"  Added {len(hosts)} hosts from {target}")
                elif self.is_valid_ip(target):
                    # It's a single IP
                    print(f"  Valid IP: {target}")
                    all_ips.append((ipaddress.ip_address(target), None))
                else:
                    # Assume it's a hostname
                    print(f"  Attempting to resolve hostname: {target}")
                    ip = self.resolve_hostname(target)
                    if ip:
                        all_ips.append((ipaddress.ip_address(ip), target))
                        print(f"    {target} -> {ip}")
                    else:
                        failed_resolutions.append(target)
                        print(f"    Failed to resolve: {target}")
            except Exception as e:
                print(f"  Error processing '{target}': {e}")
                failed_resolutions.append(target)
                continue
        
        # Report failed resolutions
        if failed_resolutions:
            print(f"\nFailed to resolve {len(failed_resolutions)} target(s):")
            for target in failed_resolutions:
                print(f"  - {target}")
        
        print(f"\nScanning {len(all_ips)} hosts...")
        print(f"Using {self.max_workers} concurrent workers")
        print("-" * 50)
        
        # Perform concurrent ping scans
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all ping jobs
            future_to_target = {executor.submit(self.ping_host, ip, original): (ip, original) for ip, original in all_ips}
            
            # Process completed futures
            completed = 0
            for future in as_completed(future_to_target):
                result = future.result()
                self.results.append(result)
                completed += 1
                
                # Print progress
                if completed % 10 == 0 or completed == len(all_ips):
                    print(f"Progress: {completed}/{len(all_ips)} hosts scanned")
                    
        print("-" * 50)
        
    def save_results(self, filename=None):
        """
        Save results to CSV file
        
        Args:
            filename (str): Optional custom filename
        """
        if not filename:
            timestamp = datetime.now().strftime("%d%m%y_%H%M%S")
            filename = f"ping_sweep_results_{timestamp}.csv"
        
        # Sort results by IP address
        self.results.sort(key=lambda x: ipaddress.ip_address(x['ip']))
        
        # Write to CSV
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['ip', 'status', 'hostname', 'response_time', 'original_target']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for result in self.results:
                writer.writerow(result)
        
        print(f"Results saved to: {filename}")
        
    def print_summary(self):
        """Print scan summary"""
        total = len(self.results)
        up_count = sum(1 for r in self.results if r['status'] == 'Up')
        down_count = total - up_count
        
        print(f"\nScan Summary:")
        print(f"Total hosts scanned: {total}")
        print(f"Hosts up: {up_count}")
        print(f"Hosts down: {down_count}")
        print(f"Response rate: {(up_count/total*100):.1f}%" if total > 0 else "0%")
        
        # Show first few live hosts
        live_hosts = [r for r in self.results if r['status'] == 'Up']
        if live_hosts:
            print(f"\nFirst {min(5, len(live_hosts))} live hosts:")
            for host in live_hosts[:5]:
                hostname = host['hostname'] if host['hostname'] else 'No hostname'
                response = host['response_time'] if host['response_time'] else 'N/A'
                original = f" (from {host['original_target']})" if host['original_target'] != host['ip'] else ""
                print(f"  {host['ip']} ({hostname}) - {response}{original}")

    def read_hosts_file(self, filename='hosts.txt'):
        """
        Read hosts and CIDR blocks from a file with validation
        
        Args:
            filename (str): Name of the file containing hosts/CIDR blocks
            
        Returns:
            list: List of targets (IPs and CIDR blocks)
        """
        targets = []
        
        try:
            with open(filename, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    # Strip whitespace and skip empty lines/comments
                    original_line = line
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Split on whitespace to handle multiple targets per line
                    line_targets = line.split()
                    for target in line_targets:
                        # Clean and validate target
                        target = target.strip()
                        
                        # Debug output for problematic entries
                        if not target:
                            print(f"Warning: Empty target on line {line_num}")
                            continue
                            
                        if len(target) > 253:
                            print(f"Warning: Target too long on line {line_num}: '{target}' ({len(target)} chars)")
                            continue
                        
                        # Check for common problematic characters
                        if any(ord(c) > 127 for c in target):
                            print(f"Warning: Non-ASCII characters in target on line {line_num}: '{target}'")
                            # Try to encode to ASCII to catch issues early
                            try:
                                target.encode('ascii')
                            except UnicodeEncodeError:
                                print(f"  Skipping due to encoding issues")
                                continue
                        
                        # Check for multiple consecutive dots
                        if '..' in target:
                            print(f"Warning: Multiple consecutive dots in target on line {line_num}: '{target}'")
                            continue
                            
                        # Add valid targets
                        targets.append(target)
                        
            print(f"Loaded {len(targets)} valid targets from {filename}")
            
            # Check if we have any IP addresses vs hostnames
            ip_count = sum(1 for t in targets if self.is_valid_ip(t) or self.is_valid_cidr(t))
            hostname_count = len(targets) - ip_count
            
            if hostname_count > 0:
                print(f"Found {ip_count} IP/CIDR targets and {hostname_count} hostname targets")
                if self.default_domain:
                    print(f"Default domain for hostnames: {self.default_domain}")
                else:
                    print("No default domain set - will use hostnames as-is")
            
            return targets
            
        except FileNotFoundError:
            print(f"Error: File '{filename}' not found")
            print(f"Please create a hosts.txt file with IP addresses, hostnames, or CIDR blocks")
            print("Example hosts.txt content:")
            print("  192.168.1.1")
            print("  server1")
            print("  web-server.company.com")
            print("  10.0.0.0/24")
            print("  172.16.1.0/29")
            print("  # This is a comment")
            return []
        except Exception as e:
            print(f"Error reading file '{filename}': {e}")
            return []

def main():
    parser = argparse.ArgumentParser(
        description="Fast ping scanner with CIDR support",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ping_scanner.py                              # Scan hosts from hosts.txt
  python ping_scanner.py -f myfile.txt                # Scan hosts from custom file
  python ping_scanner.py -d company.com               # Set default domain for hostnames
  python ping_scanner.py -w 100 -t 2                  # Custom workers and timeout
  python ping_scanner.py -s 64 -w 30                  # 64-byte packets with 30 workers
  python ping_scanner.py -d local.lan -f servers.txt  # Scan with domain and custom file
        """
    )
    
    parser.add_argument(
        '-f', '--file',
        type=str,
        default='hosts.txt',
        help='File containing IP addresses or CIDR blocks (default: hosts.txt)'
    )
    
    parser.add_argument(
        '-w', '--workers',
        type=int,
        default=20,
        help='Number of concurrent workers (default: 20)'
    )
    
    parser.add_argument(
        '-t', '--timeout',
        type=int,
        default=1,
        help='Ping timeout in seconds (default: 1)'
    )
    
    parser.add_argument(
        '-d', '--domain',
        type=str,
        default="",
        help='Default domain to append to hostnames without FQDN (e.g., company.com)'
    )
    
    parser.add_argument(
        '-s', '--size',
        type=int,
        default=32,
        help='Ping packet size in bytes (default: 32)'
    )
    
    parser.add_argument(
        '-o', '--output',
        type=str,
        help='Output CSV filename (default: auto-generated)'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.workers < 1 or args.workers > 1000:
        print("Error: Workers must be between 1 and 1000")
        sys.exit(1)
        
    if args.timeout < 1 or args.timeout > 30:
        print("Error: Timeout must be between 1 and 30 seconds")
        sys.exit(1)
        
    if args.size < 1 or args.size > 65507:
        print("Error: Packet size must be between 1 and 65507 bytes")
        sys.exit(1)
    
    # Create scanner and run scan
    scanner = PingScanner(max_workers=args.workers, timeout=args.timeout, packet_size=args.size, default_domain=args.domain)
    
    # Debug: Check if ping_host method exists
    print(f"DEBUG: ping_host method exists: {hasattr(scanner, 'ping_host')}")
    print(f"DEBUG: Available methods: {[method for method in dir(scanner) if not method.startswith('_')]}")
    
    # Read targets from file
    targets = scanner.read_hosts_file(args.file)
    
    if not targets:
        print("No valid targets found. Exiting.")
        sys.exit(1)
    
    try:
        # Start scan
        start_time = datetime.now()
        scanner.scan_targets(targets)
        end_time = datetime.now()
        
        # Print results
        scanner.print_summary()
        print(f"\nScan completed in {(end_time - start_time).total_seconds():.2f} seconds")
        
        # Save results
        scanner.save_results(args.output)
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        if scanner.results:
            print("Saving partial results...")
            scanner.save_results(args.output)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
