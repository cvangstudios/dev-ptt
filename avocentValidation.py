#!/usr/bin/env python3
"""
Cyclades SNMP Configuration Validator with ACL File
Reads ACL from file and validates against Cyclades SNMP config grouped by community
"""

import json
import yaml
import re
import ipaddress
import os
from typing import Dict, List, Any, Optional, Set
from collections import defaultdict

class CiscoACLParser:
    """Parse Cisco access-list to extract permitted networks"""
    
    def __init__(self):
        self.permitted_networks: Set[str] = set()
    
    def parse_acl_file(self, filename: str) -> List[str]:
        """Read and parse Cisco ACL from file"""
        try:
            with open(filename, 'r') as f:
                acl_text = f.read()
            return self.parse_acl(acl_text)
        except FileNotFoundError:
            print(f"Error: ACL file '{filename}' not found")
            return []
        except Exception as e:
            print(f"Error reading ACL file: {e}")
            return []
    
    def parse_acl(self, acl_text: str) -> List[str]:
        """Parse Cisco ACL and extract permitted networks in CIDR format"""
        print("Starting ACL parsing...")
        self.permitted_networks = set()
        
        # Split into lines and process each
        lines = acl_text.strip().split('\n')
        print(f"Found {len(lines)} lines in ACL file")
        
        for i, line in enumerate(lines):
            line = line.strip()
            if not line or line.startswith('!'):
                print(f"Line {i+1}: Skipping comment/empty line")
                continue
            
            print(f"Line {i+1}: Processing '{line[:50]}{'...' if len(line) > 50 else ''}'")
            
            # Parse different ACL formats
            network = self._parse_acl_line(line)
            if network:
                self.permitted_networks.add(network)
                print(f"Line {i+1}: Extracted network '{network}'")
            else:
                print(f"Line {i+1}: No network found")
        
        result = sorted(list(self.permitted_networks))
        print(f"ACL parsing complete. Found {len(result)} unique networks: {result}")
        return result
    
    def _parse_acl_line(self, line: str) -> Optional[str]:
        """Parse a single ACL line and extract network in CIDR format"""
        
        # NX-OS format: permit ip 1.1.1.0/24 any
        nxos_pattern = r'permit\s+ip\s+(\d+\.\d+\.\d+\.\d+/\d+)\s+'
        match = re.search(nxos_pattern, line, re.IGNORECASE)
        if match:
            return match.group(1)
        
        # NX-OS host format: permit ip host 192.168.1.100 any
        nxos_host_pattern = r'permit\s+ip\s+host\s+(\d+\.\d+\.\d+\.\d+)\s+'
        match = re.search(nxos_host_pattern, line, re.IGNORECASE)
        if match:
            host = match.group(1)
            return f"{host}/32"
        
        # IOS Standard numbered ACL: access-list 10 permit 192.168.1.0 0.0.0.255
        std_pattern = r'access-list\s+\d+\s+permit\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)'
        match = re.search(std_pattern, line, re.IGNORECASE)
        if match:
            network = match.group(1)
            wildcard = match.group(2)
            return self._wildcard_to_cidr(network, wildcard)
        
        # IOS Standard numbered ACL host: access-list 10 permit host 192.168.1.100
        host_pattern = r'access-list\s+\d+\s+permit\s+host\s+(\d+\.\d+\.\d+\.\d+)'
        match = re.search(host_pattern, line, re.IGNORECASE)
        if match:
            host = match.group(1)
            return f"{host}/32"
        
        # IOS Extended ACL: access-list 100 permit ip 192.168.1.0 0.0.0.255 any
        ext_pattern = r'access-list\s+\d+\s+permit\s+ip\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+'
        match = re.search(ext_pattern, line, re.IGNORECASE)
        if match:
            network = match.group(1)
            wildcard = match.group(2)
            return self._wildcard_to_cidr(network, wildcard)
        
        # IOS Extended ACL host: access-list 100 permit ip host 192.168.1.100 any
        ext_host_pattern = r'access-list\s+\d+\s+permit\s+ip\s+host\s+(\d+\.\d+\.\d+\.\d+)\s+'
        match = re.search(ext_host_pattern, line, re.IGNORECASE)
        if match:
            host = match.group(1)
            return f"{host}/32"
        
        # IOS Named ACL: permit 192.168.1.0 0.0.0.255
        named_pattern = r'^\s*permit\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)'
        match = re.search(named_pattern, line, re.IGNORECASE)
        if match:
            network = match.group(1)
            wildcard = match.group(2)
            return self._wildcard_to_cidr(network, wildcard)
        
        # IOS Named ACL host: permit host 192.168.1.100
        named_host_pattern = r'^\s*permit\s+host\s+(\d+\.\d+\.\d+\.\d+)'
        match = re.search(named_host_pattern, line, re.IGNORECASE)
        if match:
            host = match.group(1)
            return f"{host}/32"
        
        return None
    
    def _wildcard_to_cidr(self, network: str, wildcard: str) -> str:
        """Convert network and wildcard mask to CIDR notation"""
        try:
            # Convert wildcard mask to subnet mask
            wildcard_parts = [int(x) for x in wildcard.split('.')]
            subnet_parts = [255 - x for x in wildcard_parts]
            subnet_mask = '.'.join(str(x) for x in subnet_parts)
            
            # Create network object
            net = ipaddress.IPv4Network(f"{network}/{subnet_mask}", strict=False)
            return str(net)
        except:
            # Fallback for invalid formats
            return f"{network}/32"

class CycladesConfigParser:
    """Parse full Cyclades configuration and extract SNMP section"""
    
    def __init__(self):
        self.snmp_communities: Dict[str, Dict] = {}
    
    def parse_config_file(self, filename: str) -> Dict[str, Dict]:
        """Read and parse Cyclades configuration from file"""
        try:
            with open(filename, 'r') as f:
                config_text = f.read()
            return self.extract_snmp_config(config_text)
        except FileNotFoundError:
            print(f"Error: Configuration file '{filename}' not found")
            return {}
        except Exception as e:
            print(f"Error reading configuration file: {e}")
            return {}
    
    def extract_snmp_config(self, config_text: str) -> Dict[str, Dict]:
        """Extract and parse SNMP configuration section from full Cyclades config"""
        
        # Find the /network/snmp/ section
        snmp_section = self._extract_snmp_section(config_text)
        if not snmp_section:
            print("Warning: No /network/snmp/ section found in configuration")
            return {}
        
        # Parse the SNMP section
        return self._parse_snmp_section(snmp_section)
    
    def _extract_snmp_section(self, config_text: str) -> str:
        """Extract the /network/snmp/ section from full configuration"""
        
        # Look for the start of the SNMP section
        start_pattern = r'cd\s+/network/snmp/?'
        start_match = re.search(start_pattern, config_text, re.IGNORECASE)
        
        if not start_match:
            print("Warning: Start delimiter 'cd /network/snmp/' not found")
            return ""
        
        start_pos = start_match.end()  # Start after the cd command
        
        # Look specifically for the end delimiter
        end_pattern = r'cd\s+/network/dhcp_server/settings'
        end_match = re.search(end_pattern, config_text[start_pos:], re.IGNORECASE)
        
        if end_match:
            end_pos = start_pos + end_match.start()
            snmp_section = config_text[start_pos:end_pos]
            print(f"SNMP section extracted: {len(snmp_section)} characters")
            return snmp_section
        else:
            print("Warning: End delimiter 'cd /network/dhcp_server/settings' not found")
            # Fallback to next 'cd' command or end of file
            fallback_pattern = r'\ncd\s+/'
            fallback_match = re.search(fallback_pattern, config_text[start_pos:])
            if fallback_match:
                end_pos = start_pos + fallback_match.start()
                snmp_section = config_text[start_pos:end_pos]
                print(f"SNMP section extracted (fallback): {len(snmp_section)} characters")
                return snmp_section
            else:
                snmp_section = config_text[start_pos:]
                print(f"SNMP section extracted (to end): {len(snmp_section)} characters")
                return snmp_section
    
    def _parse_snmp_section(self, snmp_text: str) -> Dict[str, Dict]:
        """Parse SNMP section and group by community string"""
        
        print(f"Parsing SNMP section: {len(snmp_text)} characters")
        
        communities = defaultdict(lambda: {
            'sources': [],
            'version': None,
            'permission': None,
            'oid': None
        })
        
        # Clean up the text and split into blocks by 'add' statements
        # Remove the initial cd command if present
        clean_text = re.sub(r'^cd\s+/network/snmp/?.*?\n', '', snmp_text, flags=re.IGNORECASE)
        
        # Split by 'add' keywords, but keep the 'add' in each block
        blocks = re.split(r'\n(?=add\b)', clean_text, flags=re.IGNORECASE)
        
        print(f"Found {len(blocks)} potential blocks")
        
        for i, block in enumerate(blocks):
            block = block.strip()
            if not block or len(block) < 10:  # Skip very short blocks
                continue
                
            print(f"Processing block {i+1}: {block[:100]}...")
            
            # Skip blocks that don't contain 'add' (like delete statements)
            if not re.search(r'\badd\b', block, re.IGNORECASE):
                print(f"  Skipping block {i+1} - no 'add' found")
                continue
            
            entry = self._parse_block(block)
            if entry:
                community = entry['name']
                communities[community]['sources'].append(entry['source'])
                
                print(f"  Added entry: {community} -> {entry['source']}")
                
                # Store other attributes (they should be consistent within a community)
                if communities[community]['version'] is None:
                    communities[community]['version'] = entry['version']
                if communities[community]['permission'] is None:
                    communities[community]['permission'] = entry['permission']
                if entry.get('oid') and communities[community]['oid'] is None:
                    communities[community]['oid'] = entry['oid']
            else:
                print(f"  Failed to parse block {i+1}")
        
        # Convert defaultdict to regular dict and sort sources
        result = {}
        for community, data in communities.items():
            result[community] = {
                'sources': sorted(list(set(data['sources']))),  # Remove duplicates and sort
                'version': data['version'],
                'permission': data['permission']
            }
            if data['oid']:
                result[community]['oid'] = data['oid']
        
        print(f"Final result: {len(result)} communities found")
        for community, data in result.items():
            print(f"  {community}: {len(data['sources'])} sources")
        
        self.snmp_communities = result
        return result
    
    def extract_hostname(self, config_text: str) -> str:
        """Extract hostname from /network/settings section"""
        
        # Find the /network/settings section
        settings_pattern = r'cd\s+/network/settings'
        settings_match = re.search(settings_pattern, config_text, re.IGNORECASE)
        
        if not settings_match:
            return "unknown-hostname"
        
        start_pos = settings_match.start()
        
        # Find the end of the settings section (next 'cd' command or end of file)
        remaining_text = config_text[start_pos:]
        end_pattern = r'\ncd\s+/'
        end_match = re.search(end_pattern, remaining_text)
        
        if end_match:
            end_pos = start_pos + end_match.start()
            settings_section = config_text[start_pos:end_pos]
        else:
            settings_section = config_text[start_pos:]
        
        # Extract hostname
        hostname_pattern = r'set\s+hostname\s*=\s*([^\s\n]+)'
        hostname_match = re.search(hostname_pattern, settings_section, re.IGNORECASE)
        
        if hostname_match:
            return hostname_match.group(1).strip()
        
        return "unknown-hostname"
    
    def _parse_block(self, block: str) -> Optional[Dict[str, str]]:
        """Parse a single add block"""
        entry_data = {}
        
        # Extract each set command
        patterns = {
            'name': r'set\s+name\s*=\s*([^\s\n]+)',
            'version': r'set\s+version\s*=\s*([^\s\n]+)',
            'source': r'set\s+source\s*=\s*([^\s\n]+)',
            'permission': r'set\s+permission\s*=\s*([^\s\n]+)',
            'oid': r'set\s+oid\s*=\s*([^\s\n]+)'
        }
        
        for key, pattern in patterns.items():
            match = re.search(pattern, block, re.IGNORECASE)
            if match:
                entry_data[key] = match.group(1).strip()
        
        # Validate required fields
        required_fields = ['name', 'version', 'source', 'permission']
        if all(field in entry_data for field in required_fields):
            return entry_data
        
        return None
    
    def to_json(self) -> str:
        """Convert parsed SNMP communities to JSON"""
        return json.dumps(self.snmp_communities, indent=2)
    
    def to_yaml(self) -> str:
        """Convert parsed SNMP communities to YAML"""
        return yaml.dump(self.snmp_communities, default_flow_style=False, indent=2)

class SNMPACLValidator:
    """Validate Cyclades SNMP configuration against Cisco ACL"""
    
    def __init__(self):
        self.acl_parser = CiscoACLParser()
        self.config_parser = CycladesConfigParser()
    
    def validate_from_files(self, acl_file: str, config_file: str, 
                           expected_community: str = None) -> Dict[str, Any]:
        """Validate SNMP configuration against ACL using files"""
        
        print("=== Starting ACL validation phase ===")
        
        # Parse ACL file
        print(f"Reading ACL file: {acl_file}")
        try:
            acl_networks = set(self.acl_parser.parse_acl_file(acl_file))
            print(f"ACL parsing completed successfully. Found {len(acl_networks)} networks.")
        except Exception as e:
            print(f"ERROR: ACL parsing failed: {e}")
            return {}
        
        print("=== Checking ACL entries ===")
        for i, network in enumerate(sorted(acl_networks)):
            print(f"ACL entry {i+1}: {network}")
        
        # Parse Cyclades configuration
        print(f"Reading Cyclades configuration file: {config_file}")
        try:
            snmp_communities = self.config_parser.parse_config_file(config_file)
            print(f"Cyclades config parsing completed. Found {len(snmp_communities)} communities.")
        except Exception as e:
            print(f"ERROR: Cyclades config parsing failed: {e}")
            return {}
        
        print("=== Starting validation comparison ===")
        result = self._validate_communities(acl_networks, snmp_communities, expected_community)
        print("=== Validation comparison completed ===")
        
        return result
    
    def _validate_communities(self, acl_networks: Set[str], 
                             snmp_communities: Dict[str, Dict],
                             expected_community: str = None) -> Dict[str, Any]:
        """Validate ACL networks against SNMP communities"""
        
        print("=== Starting community validation ===")
        
        validation_results = {
            'acl_networks': sorted(list(acl_networks)),
            'snmp_communities': snmp_communities,
            'validation_by_community': {},
            'overall_summary': {}
        }
        
        total_communities = len(snmp_communities)
        compliant_communities = 0
        
        print(f"Validating {total_communities} communities against {len(acl_networks)} ACL networks")
        
        # Validate each community
        for community_num, (community, community_data) in enumerate(snmp_communities.items(), 1):
            print(f"=== Processing community {community_num}/{total_communities}: '{community}' ===")
            
            configured_networks = set(community_data['sources'])
            print(f"Community '{community}' has {len(configured_networks)} configured sources")
            
            print("Comparing ACL networks against community sources...")
            missing_networks = acl_networks - configured_networks
            extra_networks = configured_networks - acl_networks
            matching_networks = acl_networks & configured_networks
            
            print(f"  Matching networks: {len(matching_networks)}")
            print(f"  Missing networks: {len(missing_networks)}")
            print(f"  Extra networks: {len(extra_networks)}")
            
            is_compliant = len(missing_networks) == 0
            if is_compliant:
                compliant_communities += 1
                print(f"  Community '{community}' is COMPLIANT")
            else:
                print(f"  Community '{community}' is NON-COMPLIANT")
            
            compliance_percentage = (len(matching_networks) / len(acl_networks) * 100) if acl_networks else 0
            
            validation_results['validation_by_community'][community] = {
                'compliant': is_compliant,
                'configured_sources': sorted(list(configured_networks)),
                'matching_networks': sorted(list(matching_networks)),
                'missing_networks': sorted(list(missing_networks)),
                'extra_networks': sorted(list(extra_networks)),
                'summary': {
                    'total_acl_networks': len(acl_networks),
                    'configured_networks': len(configured_networks),
                    'matching_count': len(matching_networks),
                    'missing_count': len(missing_networks),
                    'extra_count': len(extra_networks),
                    'compliance_percentage': round(compliance_percentage, 2)
                }
            }
        
        print("=== Generating overall summary ===")
        # Overall summary
        validation_results['overall_summary'] = {
            'total_communities': total_communities,
            'compliant_communities': compliant_communities,
            'overall_compliance': compliant_communities == total_communities,
            'community_compliance_rate': round((compliant_communities / total_communities * 100), 2) if total_communities > 0 else 0
        }
        
        print(f"Overall compliance: {compliant_communities}/{total_communities} communities compliant")
        print("=== Community validation completed ===")
        
        return validation_results
    
    def get_snmp_json(self) -> str:
        """Get parsed SNMP configuration as JSON"""
        return self.config_parser.to_json()
    
    def get_snmp_yaml(self) -> str:
        """Get parsed SNMP configuration as YAML"""
        return self.config_parser.to_yaml()

    def extract_hostname(self, config_text: str) -> str:
        """Extract hostname from /network/settings section"""
        
        # Find the /network/settings section
        settings_pattern = r'cd\s+/network/settings'
        settings_match = re.search(settings_pattern, config_text, re.IGNORECASE)
        
        if not settings_match:
            return "unknown-hostname"
        
        start_pos = settings_match.start()
        
        # Find the end of the settings section (next 'cd' command or end of file)
        remaining_text = config_text[start_pos:]
        end_pattern = r'\ncd\s+/'
        end_match = re.search(end_pattern, remaining_text)
        
        if end_match:
            end_pos = start_pos + end_match.start()
            settings_section = config_text[start_pos:end_pos]
        else:
            settings_section = config_text[start_pos:]
        
        # Extract hostname
        hostname_pattern = r'set\s+hostname\s*=\s*([^\s\n]+)'
        hostname_match = re.search(hostname_pattern, settings_section, re.IGNORECASE)
        
        if hostname_match:
            return hostname_match.group(1).strip()
        
        return "unknown-hostname"

    def extract_hostname(self, config_text: str) -> str:
        """Extract hostname from /network/settings section"""
        
        # Find the /network/settings section
        settings_pattern = r'cd\s+/network/settings'
        settings_match = re.search(settings_pattern, config_text, re.IGNORECASE)
        
        if not settings_match:
            return "unknown-hostname"
        
        start_pos = settings_match.start()
        
        # Find the end of the settings section (next 'cd' command or end of file)
        remaining_text = config_text[start_pos:]
        end_pattern = r'\ncd\s+/'
        end_match = re.search(end_pattern, remaining_text)
        
        if end_match:
            end_pos = start_pos + end_match.start()
            settings_section = config_text[start_pos:end_pos]
        else:
            settings_section = config_text[start_pos:]
        
        # Extract hostname
        hostname_pattern = r'set\s+hostname\s*=\s*([^\s\n]+)'
        hostname_match = re.search(hostname_pattern, settings_section, re.IGNORECASE)
        
        if hostname_match:
            return hostname_match.group(1).strip()
        
        return "unknown-hostname"

def extract_hostname_from_config(config_text: str) -> str:
    """Extract hostname from /network/settings section"""
    
    # Find the /network/settings section
    settings_pattern = r'cd\s+/network/settings'
    settings_match = re.search(settings_pattern, config_text, re.IGNORECASE)
    
    if not settings_match:
        return "unknown-hostname"
    
    start_pos = settings_match.start()
    
    # Find the end of the settings section (next 'cd' command or end of file)
    remaining_text = config_text[start_pos:]
    end_pattern = r'\ncd\s+/'
    end_match = re.search(end_pattern, remaining_text)
    
    if end_match:
        end_pos = start_pos + end_match.start()
        settings_section = config_text[start_pos:end_pos]
    else:
        settings_section = config_text[start_pos:]
    
    # Extract hostname
    hostname_pattern = r'set\s+hostname\s*=\s*([^\s\n]+)'
    hostname_match = re.search(hostname_pattern, settings_section, re.IGNORECASE)
    
    if hostname_match:
        return hostname_match.group(1).strip()
    
    return "unknown-hostname"

def process_uot_files(folder_path: str = ".") -> None:
    """Process all .log files containing 'uot' in their name"""
    
    # ACL file should be in the same folder
    acl_file = os.path.join(folder_path, "acl-80.txt")
    
    if not os.path.exists(acl_file):
        print(f"Error: {acl_file} not found. Please ensure acl-80.txt is in the folder.")
        return
    
    # Find all .log files containing 'uot'
    log_files = []
    for filename in os.listdir(folder_path):
        if filename.endswith('.log') and 'uot' in filename.lower():
            log_files.append(filename)
    
    if not log_files:
        print(f"No .log files containing 'uot' found in {folder_path}")
        return
    
    print(f"Found {len(log_files)} files to process: {', '.join(log_files)}")
    
    # Process each file
    for log_file in log_files:
        print(f"\n=== Processing {log_file} ===")
        
        config_file_path = os.path.join(folder_path, log_file)
        
        # Create validator and parse config to get hostname
        validator = SNMPACLValidator()
        
        try:
            with open(config_file_path, 'r') as f:
                config_text = f.read()
            
            # Extract hostname
            hostname = extract_hostname_from_config(config_text)
            print(f"Extracted hostname: {hostname}")
            
            # Validate configuration
            validation = validator.validate_from_files(acl_file, config_file_path)
            
            # Generate output filename
            output_file = os.path.join(folder_path, f"config-audit-{hostname}.txt")
            
            # Write results to output file
            print(f"Writing audit report to: {output_file}")
            write_audit_report(output_file, log_file, hostname, validation, validator)
            
            print(f"✓ Avocent audit complete for {hostname} - results written to {output_file}")
            print("=" * 60)
            
        except Exception as e:
            print(f"✗ Error processing {log_file}: {e}")
            continue

def write_audit_report(output_file: str, source_file: str, hostname: str, 
                      validation: Dict, validator: SNMPACLValidator) -> None:
    """Write detailed audit report to file"""
    
    print(f"Generating audit report for {hostname}...")
    print(f"Writing to file: {output_file}")
    
    # Test if we can write to the file at all
    try:
        print("Testing file write access...")
        with open(output_file, 'w') as test_f:
            test_f.write("TEST\n")
        print("File write test successful")
    except Exception as e:
        print(f"ERROR: Cannot write to file {output_file}: {e}")
        return
    
    try:
        with open(output_file, 'w') as f:
            print("File opened successfully")
            
            print("Writing basic header line 1...")
            f.write("=" * 80 + "\n")
            f.flush()
            
            print("Writing basic header line 2...")
            f.write(f"CYCLADES SNMP CONFIGURATION AUDIT REPORT\n")
            f.flush()
            
            print("Writing basic header line 3...")
            f.write("=" * 80 + "\n")
            f.flush()
            
            print("Writing source file info...")
            f.write(f"Source File: {source_file}\n")
            f.flush()
            
            print("Writing hostname info...")
            f.write(f"Hostname: {hostname}\n")
            f.flush()
            
            print("Getting current timestamp...")
            try:
                import datetime
                current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"Timestamp generated: {current_time}")
                f.write(f"Audit Date: {current_time}\n")
                f.flush()
            except Exception as e:
                print(f"Warning: Could not get timestamp: {e}")
                f.write(f"Audit Date: Unknown\n")
                f.flush()
            
            print("Writing final header line...")
            f.write("=" * 80 + "\n\n")
            f.flush()
            
            print("Header completed successfully")
            
            print("Writing SNMP configuration section...")
            f.write("SNMP CONFIGURATION BY COMMUNITY\n")
            f.write("-" * 40 + "\n")
            f.flush()
            
            print("Getting YAML from validator...")
            try:
                print("Calling validator.get_snmp_yaml()...")
                yaml_content = validator.get_snmp_yaml()
                print(f"YAML content received, length: {len(yaml_content)} characters")
                print(f"First 100 chars of YAML: {yaml_content[:100]}")
                f.write(yaml_content)
                f.write("\n")
                f.flush()
                print("YAML written successfully")
            except Exception as e:
                print(f"Error getting YAML: {e}")
                import traceback
                print(f"YAML error traceback: {traceback.format_exc()}")
                f.write("Error generating YAML content\n\n")
                f.flush()
            
            print("Writing overall summary...")
            overall = validation.get('overall_summary', {})
            print(f"Overall summary data: {overall}")
            
            f.write("OVERALL COMPLIANCE SUMMARY\n")
            f.write("-" * 40 + "\n")
            f.write(f"Overall Compliance: {'PASS' if overall.get('overall_compliance', False) else 'FAIL'}\n")
            f.write(f"Total Communities: {overall.get('total_communities', 0)}\n")
            f.write(f"Compliant Communities: {overall.get('compliant_communities', 0)}\n")
            f.write(f"Community Compliance Rate: {overall.get('community_compliance_rate', 0)}%\n\n")
            f.flush()
            print("Overall summary written successfully")
            
            # Simplified rest of the report for now
            print("Writing simplified rest of report...")
            f.write("VALIDATION COMPLETED\n")
            f.write("See debug output for details.\n")
            f.flush()
        
        print(f"Audit report written successfully to {output_file}")
        
    except Exception as e:
        print(f"ERROR writing audit report: {e}")
        import traceback
        print(f"Full traceback: {traceback.format_exc()}")
        raise

def main():
    """Main execution function"""
    
    import sys
    
    # Check if folder path provided as argument
    folder_path = sys.argv[1] if len(sys.argv) > 1 else "."
    
    if not os.path.exists(folder_path):
        print(f"Error: Folder path '{folder_path}' does not exist")
        return
    
    # Check if ACL file exists
    acl_file = os.path.join(folder_path, "acl-80.txt")
    if not os.path.exists(acl_file):
        print(f"Creating sample {acl_file}...")
        sample_acl = """access-list 80 permit 10.1.1.0 0.0.0.255
access-list 80 permit 10.1.2.0 0.0.0.255
access-list 80 permit 10.1.3.0 0.0.0.255
access-list 80 permit 10.1.100.0 0.0.0.255"""
        
        with open(acl_file, 'w') as f:
            f.write(sample_acl)
        print(f"Sample {acl_file} created. Please edit it with your actual ACL.")
        return
    
    # Process all UOT files
    process_uot_files(folder_path)

if __name__ == "__main__":
    main()
