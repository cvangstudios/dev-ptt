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
        self.permitted_networks = set()
        
        # Split into lines and process each
        lines = acl_text.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('!'):
                continue
            
            # Parse different ACL formats
            network = self._parse_acl_line(line)
            if network:
                self.permitted_networks.add(network)
        
        return sorted(list(self.permitted_networks))
    
    def _parse_acl_line(self, line: str) -> Optional[str]:
        """Parse a single ACL line and extract network in CIDR format"""
        
        # Standard numbered ACL: access-list 10 permit 192.168.1.0 0.0.0.255
        std_pattern = r'access-list\s+\d+\s+permit\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)'
        match = re.search(std_pattern, line, re.IGNORECASE)
        if match:
            network = match.group(1)
            wildcard = match.group(2)
            return self._wildcard_to_cidr(network, wildcard)
        
        # Standard numbered ACL host: access-list 10 permit host 192.168.1.100
        host_pattern = r'access-list\s+\d+\s+permit\s+host\s+(\d+\.\d+\.\d+\.\d+)'
        match = re.search(host_pattern, line, re.IGNORECASE)
        if match:
            host = match.group(1)
            return f"{host}/32"
        
        # Extended ACL: access-list 100 permit ip 192.168.1.0 0.0.0.255 any
        ext_pattern = r'access-list\s+\d+\s+permit\s+ip\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+'
        match = re.search(ext_pattern, line, re.IGNORECASE)
        if match:
            network = match.group(1)
            wildcard = match.group(2)
            return self._wildcard_to_cidr(network, wildcard)
        
        # Extended ACL host: access-list 100 permit ip host 192.168.1.100 any
        ext_host_pattern = r'access-list\s+\d+\s+permit\s+ip\s+host\s+(\d+\.\d+\.\d+\.\d+)\s+'
        match = re.search(ext_host_pattern, line, re.IGNORECASE)
        if match:
            host = match.group(1)
            return f"{host}/32"
        
        # Named ACL: permit 192.168.1.0 0.0.0.255
        named_pattern = r'^\s*permit\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)'
        match = re.search(named_pattern, line, re.IGNORECASE)
        if match:
            network = match.group(1)
            wildcard = match.group(2)
            return self._wildcard_to_cidr(network, wildcard)
        
        # Named ACL host: permit host 192.168.1.100
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
        
        # Parse ACL file
        acl_networks = set(self.acl_parser.parse_acl_file(acl_file))
        
        # Parse Cyclades configuration
        snmp_communities = self.config_parser.parse_config_file(config_file)
        
        return self._validate_communities(acl_networks, snmp_communities, expected_community)
    
    def _validate_communities(self, acl_networks: Set[str], 
                             snmp_communities: Dict[str, Dict],
                             expected_community: str = None) -> Dict[str, Any]:
        """Validate ACL networks against SNMP communities"""
        
        validation_results = {
            'acl_networks': sorted(list(acl_networks)),
            'snmp_communities': snmp_communities,
            'validation_by_community': {},
            'overall_summary': {}
        }
        
        total_communities = len(snmp_communities)
        compliant_communities = 0
        
        # Validate each community
        for community, community_data in snmp_communities.items():
            configured_networks = set(community_data['sources'])
            
            missing_networks = acl_networks - configured_networks
            extra_networks = configured_networks - acl_networks
            matching_networks = acl_networks & configured_networks
            
            is_compliant = len(missing_networks) == 0
            if is_compliant:
                compliant_communities += 1
            
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
        
        # Overall summary
        validation_results['overall_summary'] = {
            'total_communities': total_communities,
            'compliant_communities': compliant_communities,
            'overall_compliance': compliant_communities == total_communities,
            'community_compliance_rate': round((compliant_communities / total_communities * 100), 2) if total_communities > 0 else 0
        }
        
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
            write_audit_report(output_file, log_file, hostname, validation, validator)
            
            print(f"✓ Audit complete - results written to {output_file}")
            
        except Exception as e:
            print(f"✗ Error processing {log_file}: {e}")
            continue

def write_audit_report(output_file: str, source_file: str, hostname: str, 
                      validation: Dict, validator: SNMPACLValidator) -> None:
    """Write detailed audit report to file"""
    
    with open(output_file, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write(f"CYCLADES SNMP CONFIGURATION AUDIT REPORT\n")
        f.write("=" * 80 + "\n")
        f.write(f"Source File: {source_file}\n")
        f.write(f"Hostname: {hostname}\n")
        f.write(f"Audit Date: {os.popen('date').read().strip()}\n")
        f.write("=" * 80 + "\n\n")
        
        # SNMP Configuration Summary
        f.write("SNMP CONFIGURATION BY COMMUNITY\n")
        f.write("-" * 40 + "\n")
        f.write(validator.get_yaml())
        f.write("\n")
        
        # Overall Summary
        overall = validation['overall_summary']
        f.write("OVERALL COMPLIANCE SUMMARY\n")
        f.write("-" * 40 + "\n")
        f.write(f"Overall Compliance: {'PASS' if overall['overall_compliance'] else 'FAIL'}\n")
        f.write(f"Total Communities: {overall['total_communities']}\n")
        f.write(f"Compliant Communities: {overall['compliant_communities']}\n")
        f.write(f"Community Compliance Rate: {overall['community_compliance_rate']}%\n\n")
        
        # ACL Networks
        f.write("ACL INTENT NETWORKS\n")
        f.write("-" * 40 + "\n")
        for network in validation['acl_networks']:
            f.write(f"  {network}\n")
        f.write("\n")
        
        # Per-Community Details
        f.write("DETAILED VALIDATION BY COMMUNITY\n")
        f.write("-" * 40 + "\n")
        
        for community, results in validation['validation_by_community'].items():
            f.write(f"\nCommunity: {community}\n")
            f.write(f"Status: {'COMPLIANT' if results['compliant'] else 'NON-COMPLIANT'}\n")
            f.write(f"Networks Matched: {results['summary']['matching_count']}/{results['summary']['total_acl_networks']}\n")
            f.write(f"Compliance Percentage: {results['summary']['compliance_percentage']}%\n")
            
            if results['matching_networks']:
                f.write(f"✓ Matching Networks:\n")
                for network in results['matching_networks']:
                    f.write(f"    {network}\n")
            
            if results['missing_networks']:
                f.write(f"✗ Missing Networks (in ACL but not in SNMP config):\n")
                for network in results['missing_networks']:
                    f.write(f"    {network}\n")
            
            if results['extra_networks']:
                f.write(f"⚠ Extra Networks (in SNMP config but not in ACL):\n")
                for network in results['extra_networks']:
                    f.write(f"    {network}\n")
            
            f.write("\n" + "-" * 40 + "\n")
        
        # Raw JSON Data
        f.write("\nRAW VALIDATION DATA (JSON)\n")
        f.write("-" * 40 + "\n")
        f.write(json.dumps(validation, indent=2))

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
