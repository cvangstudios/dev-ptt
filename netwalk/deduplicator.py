#!/usr/bin/env python3
"""
Network Deduplication and Hierarchy Analyzer
Removes duplicate connections from global neighbor table and creates hierarchy visualization
"""

import pandas as pd
import networkx as nx
from pyvis.network import Network
from anytree import Node, RenderTree
import re
from collections import defaultdict
import json
from datetime import datetime

class NetworkDeduplicator:
    """Handles deduplication of bidirectional network connections"""
    
    def __init__(self, csv_file):
        """Initialize with the global neighbor table CSV"""
        self.csv_file = csv_file
        self.df = None
        self.df_deduped = None
        self.log_file = f"deduplication_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        self.log_entries = []
        self.duplicate_details = []
        
    def _log(self, message):
        """Add message to log"""
        self.log_entries.append(message)
        print(message)
        
    def load_data(self):
        """Load the CSV file"""
        self._log(f"Loading data from {self.csv_file}...")
        try:
            # Try UTF-8 first (most common)
            self.df = pd.read_csv(self.csv_file, encoding='utf-8')
        except UnicodeDecodeError:
            try:
                # Try Latin-1 if UTF-8 fails
                self._log("UTF-8 decoding failed, trying Latin-1...")
                self.df = pd.read_csv(self.csv_file, encoding='latin-1')
            except:
                # Try with default encoding as last resort
                self._log("Latin-1 decoding failed, using default encoding...")
                self.df = pd.read_csv(self.csv_file)
        
        # Add row numbers for reference (1-based to match CSV viewing)
        self.df['original_row_number'] = range(2, len(self.df) + 2)  # Starting from 2 (row 1 is header)
        
        self._log(f"Loaded {len(self.df)} rows")
        self._log(f"Columns found: {', '.join([col for col in self.df.columns if col != 'original_row_number'])}")
        
    def audit_bidirectional_connections(self):
        """Audit how many neighbor_names appear as local_devices"""
        self._log("\n" + "="*60)
        self._log("AUDITING BIDIRECTIONAL CONNECTIONS")
        self._log("="*60)
        
        # Get unique local devices and neighbor names (handle NaN and convert to strings)
        local_devices = set()
        for device in self.df['local_device'].unique():
            if pd.notna(device):
                local_devices.add(str(device))
        
        neighbor_names = set()
        for device in self.df['neighbor_name'].unique():
            if pd.notna(device):
                neighbor_names.add(str(device))
        
        # Find devices that appear in both columns
        bidirectional_devices = local_devices.intersection(neighbor_names)
        
        self._log(f"Total unique local devices: {len(local_devices)}")
        self._log(f"Total unique neighbor names: {len(neighbor_names)}")
        self._log(f"Devices appearing as both local and neighbor: {len(bidirectional_devices)}")
        if len(local_devices) > 0:
            self._log(f"Percentage of bidirectional devices: {len(bidirectional_devices)/len(local_devices)*100:.1f}%")
        
        return bidirectional_devices
    
    def save_unique_id2_debug_file(self):
        """Save a debug CSV showing unique_id2 creation for verification"""
        debug_file = f"unique_id2_debug_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        self._log(f"\nSaving unique_id2 debug file to {debug_file}...")
        
        # Create a debug dataframe with only relevant columns
        debug_columns = [
            'original_row_number',
            'local_device', 
            'local_interface',
            'neighbor_name',
            'neighbor_interface',
            'unique_id',
            'unique_id2'
        ]
        
        # Filter to show all rows, but highlight those with unique_id2
        df_debug = self.df[debug_columns].copy()
        
        # Add a column to show if this row has unique_id2
        df_debug['has_unique_id2'] = df_debug['unique_id2'] != ''
        
        # Add a column showing if unique_id2 matches any unique_id
        unique_ids_set = set(self.df['unique_id'].astype(str).str.strip())
        df_debug['unique_id2_matches_a_unique_id'] = df_debug['unique_id2'].apply(
            lambda x: 'YES' if x != '' and str(x).strip() in unique_ids_set else 'NO' if x != '' else ''
        )
        
        # Sort to show rows with unique_id2 first
        df_debug = df_debug.sort_values('has_unique_id2', ascending=False)
        
        # Save the debug file
        df_debug.to_csv(debug_file, index=False)
        
        self._log(f"Debug file saved with {len(df_debug)} rows")
        self._log(f"Rows with unique_id2: {df_debug['has_unique_id2'].sum()}")
        self._log(f"Rows where unique_id2 matches a unique_id: {(df_debug['unique_id2_matches_a_unique_id'] == 'YES').sum()}")
        
        # Show first few examples in the log
        rows_with_id2 = df_debug[df_debug['has_unique_id2']]
        if not rows_with_id2.empty:
            self._log("\nFirst 5 rows with unique_id2 values:")
            for idx, row in rows_with_id2.head(5).iterrows():
                self._log(f"\nRow {row['original_row_number']}:")
                self._log(f"  unique_id:  '{row['unique_id']}'")
                self._log(f"  unique_id2: '{row['unique_id2']}'")
                self._log(f"  Matches a unique_id? {row['unique_id2_matches_a_unique_id']}")
        
        return debug_file
    
    def create_unique_id2(self):
        """Create unique_id2 field for deduplication"""
        self._log("\nCreating unique_id2 field for deduplication...")
        
        # Get set of all local devices for quick lookup (converted to strings)
        local_devices_set = set()
        for device in self.df['local_device'].unique():
            if pd.notna(device):
                local_devices_set.add(str(device).strip())
        
        # Initialize unique_id2 column
        self.df['unique_id2'] = ''
        
        # Debug: Show first few unique_id values to understand format
        self._log("\nSample unique_id values from CSV:")
        sample_ids = self.df['unique_id'].head(3)
        for i, uid in enumerate(sample_ids):
            if pd.notna(uid):
                self._log(f"  Row {i+2}: '{uid}'")
        
        # Process each row
        created_count = 0
        for idx, row in self.df.iterrows():
            # Skip if neighbor_name is NaN
            if pd.isna(row['neighbor_name']):
                continue
                
            # Check if neighbor_name exists as a local_device
            neighbor_name_stripped = str(row['neighbor_name']).strip()
            if neighbor_name_stripped in local_devices_set:
                # Create unique_id2 by concatenating in EXACT same format as unique_id
                # This should be: neighbor_name + neighbor_interface + local_device + local_interface
                # with NO spaces or separators between them
                unique_id2 = (
                    str(row['neighbor_name']).strip() + 
                    str(row['neighbor_interface']).strip() + 
                    str(row['local_device']).strip() + 
                    str(row['local_interface']).strip()
                )
                self.df.at[idx, 'unique_id2'] = unique_id2
                created_count += 1
                
                # Debug: Show first few unique_id2 creations
                if created_count <= 3:
                    self._log(f"\nCreated unique_id2 for row {row['original_row_number']}:")
                    self._log(f"  neighbor_name: '{row['neighbor_name']}' ({len(str(row['neighbor_name']).strip())} chars)")
                    self._log(f"  neighbor_interface: '{row['neighbor_interface']}' ({len(str(row['neighbor_interface']).strip())} chars)")
                    self._log(f"  local_device: '{row['local_device']}' ({len(str(row['local_device']).strip())} chars)")
                    self._log(f"  local_interface: '{row['local_interface']}' ({len(str(row['local_interface']).strip())} chars)")
                    self._log(f"  Concatenated unique_id2: '{unique_id2}' (total {len(unique_id2)} chars)")
        
        # Count how many rows have unique_id2
        rows_with_id2 = len(self.df[self.df['unique_id2'] != ''])
        self._log(f"\nCreated unique_id2 for {rows_with_id2} rows where neighbor_name exists as local_device")
        
        # Save debug file for inspection
        debug_file = self.save_unique_id2_debug_file()
        self._log(f"\n[OK] Check '{debug_file}' to verify unique_id2 values!")
        
    def find_and_remove_duplicates(self):
        """Find and remove duplicate connections with detailed logging"""
        self._log("\nFinding duplicate connections...")
        
        # Create a dictionary for quick unique_id lookup with row information
        unique_id_dict = {}
        for idx, row in self.df.iterrows():
            if pd.notna(row['unique_id']):
                # Strip whitespace from unique_id for consistent matching
                unique_id_stripped = str(row['unique_id']).strip()
                unique_id_dict[unique_id_stripped] = {
                    'row_num': row['original_row_number'],
                    'local_device': str(row['local_device']) if pd.notna(row['local_device']) else 'N/A',
                    'local_interface': str(row['local_interface']) if pd.notna(row['local_interface']) else 'N/A',
                    'neighbor_name': str(row['neighbor_name']) if pd.notna(row['neighbor_name']) else 'N/A',
                    'neighbor_interface': str(row['neighbor_interface']) if pd.notna(row['neighbor_interface']) else 'N/A'
                }
        
        self._log(f"Built unique_id dictionary with {len(unique_id_dict)} entries")
        
        # Find rows where unique_id2 matches any unique_id
        self.df['is_duplicate'] = False
        self.df['matching_row'] = ''
        
        matches_found = 0
        for idx, row in self.df.iterrows():
            if row['unique_id2'] != '':
                unique_id2_stripped = str(row['unique_id2']).strip()
                
                # Debug first few checks
                if matches_found < 3 and unique_id2_stripped in unique_id_dict:
                    self._log(f"\n  Match found for row {row['original_row_number']}:")
                    self._log(f"    unique_id2: '{unique_id2_stripped}'")
                    self._log(f"    matches unique_id of row {unique_id_dict[unique_id2_stripped]['row_num']}")
                
                if unique_id2_stripped in unique_id_dict:
                    self.df.at[idx, 'is_duplicate'] = True
                    matching_info = unique_id_dict[unique_id2_stripped]
                    self.df.at[idx, 'matching_row'] = matching_info['row_num']
                    matches_found += 1
                    
                    # Store detailed duplicate information
                    self.duplicate_details.append({
                        'deleted_row': row['original_row_number'],
                        'deleted_connection': f"{str(row['local_device']) if pd.notna(row['local_device']) else 'N/A'}:{str(row['local_interface']) if pd.notna(row['local_interface']) else 'N/A'} <-> {str(row['neighbor_name']) if pd.notna(row['neighbor_name']) else 'N/A'}:{str(row['neighbor_interface']) if pd.notna(row['neighbor_interface']) else 'N/A'}",
                        'kept_row': matching_info['row_num'],
                        'kept_connection': f"{matching_info['local_device']}:{matching_info['local_interface']} <-> {matching_info['neighbor_name']}:{matching_info['neighbor_interface']}",
                        'unique_id': str(row['unique_id']) if pd.notna(row['unique_id']) else 'N/A',
                        'unique_id2': str(row['unique_id2'])
                    })
        
        duplicates_count = self.df['is_duplicate'].sum()
        self._log(f"\nFound {duplicates_count} duplicate connections")
        
        if duplicates_count == 0:
            self._log("No duplicates found. Checking why:")
            self._log(f"  - Rows with unique_id2: {len(self.df[self.df['unique_id2'] != ''])}")
            self._log(f"  - Unique unique_id values: {len(unique_id_dict)}")
            
            # Show sample comparison
            sample_with_id2 = self.df[self.df['unique_id2'] != ''].head(1)
            if not sample_with_id2.empty:
                sample_row = sample_with_id2.iloc[0]
                self._log(f"\n  Sample row with unique_id2:")
                self._log(f"    Row {sample_row['original_row_number']}: unique_id2 = '{sample_row['unique_id2']}'")
                self._log(f"    Expected format: neighbor_name_neighbor_interface_local_device_local_interface")
                self._log(f"    Looking for match in unique_id dictionary...")
                if str(sample_row['unique_id2']).strip() in unique_id_dict:
                    self._log(f"    Found match!")
                else:
                    self._log(f"    No match found. This unique_id2 value doesn't exist in unique_id column.")
                    self._log(f"    Check if unique_id uses underscores as separators in your CSV.")
        
        # Remove duplicates
        self._log("Removing duplicate connections...")
        self.df_deduped = self.df[~self.df['is_duplicate']].copy()
        
        # Drop helper columns
        self.df_deduped = self.df_deduped.drop(columns=['unique_id2', 'is_duplicate', 'matching_row', 'original_row_number'])
        
        self._log(f"Rows after deduplication: {len(self.df_deduped)}")
        self._log(f"Removed {len(self.df) - len(self.df_deduped)} duplicate rows")
        
    def save_deduplicated_data(self, output_file='deduplicated_neighbor_table.csv'):
        """Save the deduplicated data to a new CSV"""
        self._log(f"\nSaving deduplicated data to {output_file}...")
        self.df_deduped.to_csv(output_file, index=False)
        self._log(f"Saved {len(self.df_deduped)} rows to {output_file}")
        
    def save_log_file(self):
        """Save detailed log file with duplicate information"""
        self._log(f"\nSaving detailed log to {self.log_file}...")
        
        with open(self.log_file, 'w', encoding='utf-8') as f:
            # Write header
            f.write("="*80 + "\n")
            f.write("NETWORK DEDUPLICATION LOG\n")
            f.write(f"Source File: {self.csv_file}\n")
            f.write(f"Processing Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*80 + "\n\n")
            
            # Write general log entries
            f.write("PROCESSING SUMMARY\n")
            f.write("-"*40 + "\n")
            for entry in self.log_entries:
                f.write(entry + "\n")
            
            # Add unique_id2 comparison section only if df exists
            if hasattr(self, 'df') and 'unique_id2' in self.df.columns:
                f.write("\n" + "="*80 + "\n")
                f.write("UNIQUE_ID2 VERIFICATION\n")
                f.write("="*80 + "\n")
                
                # Get all rows with unique_id2
                rows_with_id2 = self.df[self.df['unique_id2'] != '']
                if not rows_with_id2.empty:
                    f.write(f"Total rows with unique_id2: {len(rows_with_id2)}\n\n")
                    f.write("Sample comparisons (first 10):\n")
                    f.write("-"*40 + "\n")
                    
                    for idx, row in rows_with_id2.head(10).iterrows():
                        f.write(f"\nRow {row['original_row_number']}:\n")
                        f.write(f"  Local: {row['local_device']}:{row['local_interface']} -> Neighbor: {row['neighbor_name']}:{row['neighbor_interface']}\n")
                        f.write(f"  unique_id:  '{row['unique_id']}'\n")
                        f.write(f"  unique_id2: '{row['unique_id2']}'\n")
                        
                        # Check if unique_id2 matches any unique_id
                        if str(row['unique_id2']).strip() in set(self.df['unique_id'].astype(str).str.strip()):
                            f.write(f"  STATUS: [MATCH FOUND] - This is a duplicate\n")
                        else:
                            f.write(f"  STATUS: [NO MATCH] - unique_id2 doesn't match any unique_id\n")
                else:
                    f.write("No rows with unique_id2 were created.\n")
            
            # Write detailed duplicate information
            f.write("\n" + "="*80 + "\n")
            f.write("DETAILED DUPLICATE REMOVAL LOG\n")
            f.write("="*80 + "\n")
            f.write(f"Total duplicates removed: {len(self.duplicate_details)}\n")
            f.write("-"*80 + "\n\n")
            
            if self.duplicate_details:
                # Sort by deleted row number
                self.duplicate_details.sort(key=lambda x: x['deleted_row'])
                
                for i, dup in enumerate(self.duplicate_details, 1):
                    f.write(f"Duplicate #{i}:\n")
                    f.write(f"  DELETED - Row {dup['deleted_row']} from {self.csv_file}:\n")
                    f.write(f"    Connection: {dup['deleted_connection']}\n")
                    f.write(f"    unique_id:  {dup['unique_id']}\n")
                    f.write(f"    unique_id2: {dup['unique_id2']}\n")
                    f.write(f"  KEPT - Row {dup['kept_row']} from {self.csv_file}:\n")
                    f.write(f"    Connection: {dup['kept_connection']}\n")
                    f.write(f"  Reason: unique_id2 matches unique_id of kept row (bidirectional duplicate)\n")
                    f.write("-"*40 + "\n")
                
                # Summary by device
                f.write("\n" + "="*80 + "\n")
                f.write("DUPLICATES BY DEVICE\n")
                f.write("="*80 + "\n")
                
                device_duplicates = defaultdict(int)
                for dup in self.duplicate_details:
                    # Extract device from connection string (already converted to string)
                    device = dup['deleted_connection'].split(':')[0]
                    device_duplicates[device] += 1
                
                # Sort by count
                sorted_devices = sorted(device_duplicates.items(), key=lambda x: x[1], reverse=True)
                for device, count in sorted_devices:
                    f.write(f"  {device}: {count} duplicate connections removed\n")
            else:
                f.write("No duplicates found - all connections appear to be unique.\n")
                f.write("\nPossible reasons:\n")
                f.write("1. The unique_id field format doesn't match the expected concatenation\n")
                f.write("   Expected format: local_device_local_interface_neighbor_name_neighbor_interface\n")
                f.write("2. There are no bidirectional connections in the data\n")
                f.write("3. Check the unique_id2_debug_*.csv file to verify concatenation\n")
            
            f.write("\n" + "="*80 + "\n")
            f.write("END OF LOG\n")
            f.write("="*80 + "\n")
        
        print(f"Detailed log saved to: {self.log_file}")
        
    def get_connection_summary(self):
        """Generate summary of connections after deduplication"""
        self._log("\n" + "="*60)
        self._log("CONNECTION SUMMARY (After Deduplication)")
        self._log("="*60)
        
        # Unique devices (handling NaN and converting to strings)
        all_devices = set()
        for device in self.df_deduped['local_device'].unique():
            if pd.notna(device):
                all_devices.add(str(device))
        for device in self.df_deduped['neighbor_name'].unique():
            if pd.notna(device):
                all_devices.add(str(device))
        
        self._log(f"Total unique devices in network: {len(all_devices)}")
        
        # Connection types by protocol
        if 'protocol' in self.df_deduped.columns:
            protocol_counts = self.df_deduped['protocol'].value_counts()
            self._log("\nConnections by protocol:")
            for protocol, count in protocol_counts.items():
                self._log(f"  {protocol}: {count}")
        
        # Platform summary if available
        if 'platform' in self.df_deduped.columns:
            platforms = self.df_deduped['platform'].value_counts().head(10)
            self._log("\nTop 10 platforms:")
            for platform, count in platforms.items():
                self._log(f"  {platform}: {count}")
    
    def verify_unique_id_format(self):
        """Verify and display the format of unique_id field in the CSV"""
        self._log("\n" + "="*60)
        self._log("VERIFYING UNIQUE_ID FORMAT")
        self._log("="*60)
        
        # Check if unique_id column exists
        if 'unique_id' not in self.df.columns:
            self._log("ERROR: 'unique_id' column not found in CSV!")
            return
        
        # Analyze a few rows to understand the unique_id format
        sample_size = min(5, len(self.df))
        self._log(f"\nAnalyzing first {sample_size} rows to understand unique_id format:")
        
        for i in range(sample_size):
            row = self.df.iloc[i]
            self._log(f"\nRow {i+2}:")
            self._log(f"  local_device: '{row['local_device']}'")
            self._log(f"  local_interface: '{row['local_interface']}'")
            self._log(f"  neighbor_name: '{row['neighbor_name']}'")
            self._log(f"  neighbor_interface: '{row['neighbor_interface']}'")
            self._log(f"  unique_id: '{row['unique_id']}'")
            
            # Try to recreate what unique_id should be
            expected_unique_id = (
                str(row['local_device']).strip() +
                str(row['local_interface']).strip() +
                str(row['neighbor_name']).strip() +
                str(row['neighbor_interface']).strip()
            )
            
            if str(row['unique_id']).strip() == expected_unique_id:
                self._log(f"  ✓ unique_id matches expected format (local_device+local_interface+neighbor_name+neighbor_interface)")
            else:
                self._log(f"  ✗ unique_id does NOT match expected format")
                self._log(f"    Expected: '{expected_unique_id}'")
                self._log(f"    Actual:   '{row['unique_id']}'")
    
    def run_deduplication(self):
        """Run the complete deduplication process"""
        self.load_data()
        self.verify_unique_id_format()  # Add verification step
        self.audit_bidirectional_connections()
        self.create_unique_id2()
        self.find_and_remove_duplicates()
        self.save_deduplicated_data()
        self.get_connection_summary()
        self.save_log_file()  # Save the log file at the end
        
        return self.df_deduped


class NetworkHierarchyAnalyzer:
    """Analyzes network hierarchy from deduplicated neighbor data"""
    
    def __init__(self, df):
        """Initialize with deduplicated dataframe"""
        self.df = df
        self.G = nx.Graph()
        self.hierarchy_scores = {}
        self.device_tiers = {}
        
    def build_graph(self):
        """Build network graph from deduplicated data"""
        print("\n" + "="*60)
        print("BUILDING NETWORK GRAPH")
        print("="*60)
        
        # Build edges from the deduplicated data
        for _, row in self.df.iterrows():
            # Skip rows with invalid device names
            if pd.isna(row['local_device']) or pd.isna(row['neighbor_name']):
                continue
            
            # Convert device names to strings
            local_device = str(row['local_device'])
            neighbor_name = str(row['neighbor_name'])
            
            # Add edge with all available metadata
            edge_data = {
                'local_port': str(row['local_interface']),
                'remote_port': str(row['neighbor_interface']),
                'protocol': row.get('protocol', 'unknown'),
            }
            
            # Add optional fields if they exist
            if 'platform' in row and pd.notna(row['platform']):
                edge_data['platform'] = str(row['platform'])
            if 'capabilities' in row and pd.notna(row['capabilities']):
                edge_data['capabilities'] = str(row['capabilities'])
            if 'vlan_id' in row and pd.notna(row['vlan_id']):
                edge_data['vlan_id'] = str(row['vlan_id'])
                
            self.G.add_edge(
                local_device, 
                neighbor_name,
                **edge_data
            )
        
        print(f"Graph built: {self.G.number_of_nodes()} nodes, {self.G.number_of_edges()} edges")
        
    def analyze_hierarchy(self):
        """Determine network hierarchy using multiple metrics"""
        print("\nAnalyzing network hierarchy...")
        
        # 1. Calculate centrality metrics
        degree_cent = nx.degree_centrality(self.G)
        betweenness_cent = nx.betweenness_centrality(self.G)
        closeness_cent = nx.closeness_centrality(self.G)
        
        # 2. Identify leaf nodes (access layer candidates)
        leaf_nodes = [n for n in self.G.nodes() if self.G.degree(n) == 1]
        
        # 3. Calculate distance from leaves
        max_distances = {}
        for node in self.G.nodes():
            max_distances[node] = 0
            
        for leaf in leaf_nodes:
            try:
                paths = nx.single_source_shortest_path_length(self.G, leaf)
                for node, dist in paths.items():
                    max_distances[node] = max(max_distances.get(node, 0), dist)
            except:
                continue
        
        # Normalize distances
        max_dist = max(max_distances.values()) if max_distances else 1
        for node in max_distances:
            max_distances[node] = max_distances[node] / max_dist if max_dist > 0 else 0
        
        # 4. Check device naming patterns
        def get_name_tier_hint(device_name):
            # Convert to string and handle NaN/None values
            if pd.isna(device_name) or device_name is None:
                return 0.5
            
            name_lower = str(device_name).lower()
            # Core patterns
            if any(x in name_lower for x in ['core', 'backbone', 'cb', 'agg']):
                return 1.0
            # Distribution patterns
            elif any(x in name_lower for x in ['dist', 'distribution', 'dstr']):
                return 0.6
            # Access patterns
            elif any(x in name_lower for x in ['access', 'acc', 'edge', 'asw', 'sw-']):
                return 0.2
            # Router/WAN patterns (often core)
            elif any(x in name_lower for x in ['rtr', 'router', 'wan', 'fw', 'firewall']):
                return 0.9
            return 0.5
        
        # 5. Analyze port patterns and capabilities
        def analyze_device_metadata(node):
            edges = self.G.edges(node, data=True)
            score_hint = 0.5
            
            for _, _, data in edges:
                # Check for trunk/uplink port patterns
                port = str(data.get('local_port', '')).lower()
                if any(x in port for x in ['te', 'ten', 'forty', 'hundred']):
                    score_hint = max(score_hint, 0.8)  # High-speed ports suggest core/dist
                elif 'po' in port or 'port-channel' in port:
                    score_hint = max(score_hint, 0.7)  # Port channels suggest higher tier
                
                # Check capabilities if available
                caps = str(data.get('capabilities', '')).lower()
                if 'router' in caps:
                    score_hint = max(score_hint, 0.9)
                    
            return score_hint
        
        # 6. Combine all metrics
        for node in self.G.nodes():
            name_hint = get_name_tier_hint(node)
            metadata_hint = analyze_device_metadata(node)
            
            # Weighted combination of metrics
            score = (
                degree_cent.get(node, 0) * 0.25 +          # Connection count
                betweenness_cent.get(node, 0) * 0.25 +     # Traffic centrality
                closeness_cent.get(node, 0) * 0.15 +       # Network centrality
                max_distances.get(node, 0) * 0.15 +        # Distance from edge
                name_hint * 0.15 +                         # Naming convention
                metadata_hint * 0.05                       # Port/capability patterns
            )
            
            self.hierarchy_scores[node] = score
            
            # Assign tier based on score
            if score > 0.7:
                self.device_tiers[node] = 'Core'
            elif score > 0.4:
                self.device_tiers[node] = 'Distribution'
            else:
                self.device_tiers[node] = 'Access'
        
        # Summary
        tier_counts = defaultdict(int)
        for tier in self.device_tiers.values():
            tier_counts[tier] += 1
        
        print("Hierarchy analysis complete:")
        for tier in ['Core', 'Distribution', 'Access']:
            if tier in tier_counts:
                print(f"  {tier}: {tier_counts[tier]} devices")
    
    def create_interactive_viz(self, output_file='network_hierarchy.html'):
        """Create interactive HTML visualization using pyvis"""
        print(f"\nCreating interactive visualization: {output_file}")
        
        # Create network with hierarchical layout
        net = Network(
            height='900px', 
            width='100%', 
            bgcolor='#1a1a1a',
            font_color='white'
        )
        
        # Configure physics for hierarchical layout
        net.set_options("""
        {
            "nodes": {
                "borderWidth": 2,
                "shadow": true,
                "font": {
                    "size": 14,
                    "strokeWidth": 3,
                    "strokeColor": "#000000"
                }
            },
            "edges": {
                "color": {
                    "color": "#848484",
                    "highlight": "#00ff00",
                    "hover": "#00ff00"
                },
                "smooth": {
                    "type": "continuous"
                }
            },
            "physics": {
                "enabled": true,
                "hierarchicalRepulsion": {
                    "centralGravity": 0.0,
                    "springLength": 200,
                    "springConstant": 0.01,
                    "nodeDistance": 150,
                    "damping": 0.09
                },
                "solver": "hierarchicalRepulsion",
                "stabilization": {
                    "enabled": true,
                    "iterations": 1000
                }
            },
            "layout": {
                "hierarchical": {
                    "enabled": true,
                    "levelSeparation": 200,
                    "nodeSpacing": 100,
                    "treeSpacing": 200,
                    "blockShifting": true,
                    "edgeMinimization": true,
                    "parentCentralization": true,
                    "direction": "UD",
                    "sortMethod": "directed"
                }
            },
            "interaction": {
                "hover": true,
                "tooltipDelay": 100
            }
        }
        """)
        
        # Define tier properties
        tier_colors = {
            'Core': '#ff4444',         # Red
            'Distribution': '#44aaff',  # Blue
            'Access': '#44ff44'         # Green
        }
        
        tier_sizes = {
            'Core': 40,
            'Distribution': 30,
            'Access': 20
        }
        
        tier_levels = {
            'Core': 1,
            'Distribution': 2,
            'Access': 3
        }
        
        # Add nodes
        for node in self.G.nodes():
            tier = self.device_tiers[node]
            score = self.hierarchy_scores[node]
            
            # Create detailed hover information
            connections = list(self.G.neighbors(node))
            edges_data = list(self.G.edges(node, data=True))
            
            hover_text = (
                f"<b>{str(node)}</b><br>"
                f"<b>Tier:</b> {tier}<br>"
                f"<b>Hierarchy Score:</b> {score:.3f}<br>"
                f"<b>Connections:</b> {len(connections)}<br>"
                f"<b>Connected to:</b><br>"
            )
            
            # Add connection details
            for _, neighbor, data in edges_data[:5]:
                hover_text += f"  • {str(neighbor)} ({data.get('local_port', 'N/A')})<br>"
            if len(edges_data) > 5:
                hover_text += f"  ... and {len(edges_data)-5} more"
            
            net.add_node(
                str(node),  # Convert to string for pyvis
                label=str(node),
                color=tier_colors[tier],
                size=tier_sizes[tier],
                level=tier_levels[tier],
                title=hover_text,
                font={'size': 12, 'face': 'Arial'}
            )
        
        # Add edges
        for edge in self.G.edges(data=True):
            hover_text = (
                f"<b>Connection:</b><br>"
                f"{str(edge[0])}:{edge[2].get('local_port', 'N/A')}<br>"
                f"↕<br>"
                f"{str(edge[1])}:{edge[2].get('remote_port', 'N/A')}<br>"
                f"<b>Protocol:</b> {edge[2].get('protocol', 'N/A')}"
            )
            if 'vlan_id' in edge[2]:
                hover_text += f"<br><b>VLAN:</b> {edge[2]['vlan_id']}"
                
            net.add_edge(str(edge[0]), str(edge[1]), title=hover_text)
        
        # Save the visualization
        net.save_graph(output_file)
        print(f"Interactive visualization saved to: {output_file}")
    
    def create_text_hierarchy(self):
        """Create text-based hierarchical view"""
        print("\n" + "="*60)
        print("NETWORK HIERARCHY (Text View)")
        print("="*60)
        
        # Group devices by tier
        tiers = defaultdict(list)
        for node, tier in self.device_tiers.items():
            tiers[tier].append((str(node), self.hierarchy_scores[node]))
        
        # Sort within each tier by score
        for tier in tiers:
            tiers[tier].sort(key=lambda x: x[1], reverse=True)
        
        # Display hierarchy
        for tier_name in ['Core', 'Distribution', 'Access']:
            if tier_name in tiers:
                print(f"\n{tier_name.upper()} LAYER")
                print("-" * 40)
                for device, score in tiers[tier_name][:10]:  # Show top 10 per tier
                    connections = self.G.degree(device)
                    print(f"  [{score:.2f}] {device:<30} ({connections} connections)")
                if len(tiers[tier_name]) > 10:
                    print(f"  ... and {len(tiers[tier_name])-10} more devices")
        
        # Show key inter-tier connections
        print("\n" + "="*60)
        print("KEY INTER-TIER CONNECTIONS")
        print("="*60)
        
        # Find important links (between different tiers)
        inter_tier_links = []
        for edge in self.G.edges(data=True):
            node1, node2, data = edge
            tier1, tier2 = self.device_tiers[node1], self.device_tiers[node2]
            if tier1 != tier2:
                inter_tier_links.append({
                    'link': f"{str(node1)} ({tier1}) --- {str(node2)} ({tier2})",
                    'ports': f"{data.get('local_port', 'N/A')} <-> {data.get('remote_port', 'N/A')}",
                    'priority': abs(['Core', 'Distribution', 'Access'].index(tier1) - 
                                  ['Core', 'Distribution', 'Access'].index(tier2))
                })
        
        # Sort by priority
        inter_tier_links.sort(key=lambda x: x['priority'], reverse=True)
        
        # Display top important links
        for link in inter_tier_links[:15]:
            print(f"  {link['link']}")
            print(f"    Ports: {link['ports']}")
    
    def generate_network_stats(self):
        """Generate comprehensive network statistics"""
        print("\n" + "="*60)
        print("NETWORK STATISTICS")
        print("="*60)
        
        print(f"Total Devices: {self.G.number_of_nodes()}")
        print(f"Total Links: {self.G.number_of_edges()}")
        print(f"Network Density: {nx.density(self.G):.3f}")
        
        # Check connectivity
        if nx.is_connected(self.G):
            print("Network Status: Fully Connected [OK]")
            print(f"Average Path Length: {nx.average_shortest_path_length(self.G):.2f}")
            print(f"Diameter: {nx.diameter(self.G)}")
        else:
            components = list(nx.connected_components(self.G))
            print(f"Network Status: {len(components)} Separate Segments")
            for i, component in enumerate(components[:5], 1):
                print(f"  Segment {i}: {len(component)} devices")
            if len(components) > 5:
                print(f"  ... and {len(components)-5} more segments")
        
        # Find potential single points of failure
        print("\nCritical Infrastructure Analysis:")
        if nx.is_connected(self.G):
            articulation_points = list(nx.articulation_points(self.G))
            if articulation_points:
                print(f"Single Points of Failure: {len(articulation_points)} devices")
                for ap in articulation_points[:5]:
                    tier = self.device_tiers[ap]
                    print(f"  [WARNING] {str(ap)} ({tier} layer)")
                if len(articulation_points) > 5:
                    print(f"  ... and {len(articulation_points)-5} more")
            else:
                print("  [OK] No single points of failure detected")
        
        # Bridge analysis
        bridges = list(nx.bridges(self.G))
        if bridges:
            print(f"\nCritical Links: {len(bridges)} connections")
            for bridge in bridges[:5]:
                tier1 = self.device_tiers[bridge[0]]
                tier2 = self.device_tiers[bridge[1]]
                print(f"  [WARNING] {str(bridge[0])} ({tier1}) <-> {str(bridge[1])} ({tier2})")
            if len(bridges) > 5:
                print(f"  ... and {len(bridges)-5} more")
    
    def run_analysis(self, output_file='network_hierarchy.html'):
        """Run complete hierarchy analysis"""
        self.build_graph()
        self.analyze_hierarchy()
        self.create_interactive_viz(output_file)
        self.create_text_hierarchy()
        self.generate_network_stats()
        
        print("\n" + "="*60)
        print("ANALYSIS COMPLETE!")
        print(f"Open '{output_file}' in your browser to view the interactive diagram")
        print("="*60)


def main():
    """Main execution function"""
    import sys
    
    # Default file name
    csv_file = 'global_neighbor_table.csv'
    
    # Check if a different file was specified
    if len(sys.argv) > 1:
        csv_file = sys.argv[1]
    
    try:
        print("="*60)
        print("NETWORK DEDUPLICATION AND HIERARCHY ANALYZER")
        print("="*60)
        
        # Step 1: Deduplicate the data
        deduplicator = NetworkDeduplicator(csv_file)
        df_deduped = deduplicator.run_deduplication()
        
        # Step 2: Analyze hierarchy
        analyzer = NetworkHierarchyAnalyzer(df_deduped)
        analyzer.run_analysis()
        
        print("\n" + "="*60)
        print("ALL PROCESSING COMPLETE!")
        print("="*60)
        print("Generated files:")
        print("  1. deduplicated_neighbor_table.csv - Cleaned data without duplicates")
        print("  2. network_hierarchy.html - Interactive network diagram")
        print(f"  3. {deduplicator.log_file} - Detailed deduplication log")
        print("  4. unique_id2_debug_*.csv - Debug file showing all unique_id2 values")
        print("\nIMPORTANT: Open the unique_id2_debug file in Excel to verify concatenation!")
        
    except FileNotFoundError:
        print(f"\nError: File '{csv_file}' not found")
        print("Please ensure 'global_neighbor_table.csv' exists in the current directory")
        sys.exit(1)
    except KeyError as e:
        print(f"\nError: Missing expected column in CSV: {e}")
        print("Required columns: local_device, neighbor_name, local_interface, neighbor_interface, unique_id")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
