#!/usr/bin/env python3
"""
Simplified test script to verify unique_id2 creation with underscores
"""

import pandas as pd
import sys

def test_unique_id2_creation(csv_file):
    """Test creating unique_id2 with underscores"""
    
    print("="*60)
    print("TESTING UNIQUE_ID2 CREATION")
    print("="*60)
    
    # Load the CSV
    print(f"\nLoading {csv_file}...")
    df = pd.read_csv(csv_file, encoding='utf-8')
    print(f"Loaded {len(df)} rows")
    
    # Show first few unique_id values
    print("\nFirst 3 unique_id values from CSV:")
    for i in range(min(3, len(df))):
        print(f"  Row {i+2}: '{df.iloc[i]['unique_id']}'")
    
    # Get all local devices
    local_devices = set(df['local_device'].astype(str).str.strip())
    print(f"\nFound {len(local_devices)} unique local devices")
    
    # Create unique_id2
    print("\nCreating unique_id2 values...")
    df['unique_id2'] = ''
    
    count = 0
    for idx in df.index:
        neighbor_name = str(df.at[idx, 'neighbor_name']).strip()
        
        if neighbor_name in local_devices:
            # BUILD WITH UNDERSCORES - SUPER EXPLICIT
            p1 = str(df.at[idx, 'neighbor_name']).strip()
            p2 = str(df.at[idx, 'neighbor_interface']).strip()
            p3 = str(df.at[idx, 'local_device']).strip()
            p4 = str(df.at[idx, 'local_interface']).strip()
            
            # Create with underscores
            unique_id2 = p1 + "_" + p2 + "_" + p3 + "_" + p4
            
            df.at[idx, 'unique_id2'] = unique_id2
            count += 1
            
            # Show first 3
            if count <= 3:
                print(f"\nRow {idx+2}:")
                print(f"  Parts: '{p1}' + '_' + '{p2}' + '_' + '{p3}' + '_' + '{p4}'")
                print(f"  Result: '{unique_id2}'")
                print(f"  Length: {len(unique_id2)}")
                print(f"  Underscores: {unique_id2.count('_')}")
    
    print(f"\nCreated {count} unique_id2 values")
    
    # Save debug file
    debug_file = 'test_unique_id2_debug.csv'
    print(f"\nSaving to {debug_file}...")
    
    # Create debug dataframe
    debug_df = df[['local_device', 'local_interface', 'neighbor_name', 
                   'neighbor_interface', 'unique_id', 'unique_id2']].copy()
    debug_df['has_unique_id2'] = debug_df['unique_id2'] != ''
    debug_df['unique_id2_has_underscore'] = debug_df['unique_id2'].apply(
        lambda x: 'YES' if x and '_' in x else 'NO'
    )
    
    # Save
    debug_df.to_csv(debug_file, index=False, encoding='utf-8')
    print(f"Saved debug file")
    
    # Show summary
    print("\n" + "="*60)
    print("SUMMARY:")
    print(f"Total rows: {len(df)}")
    print(f"Rows with unique_id2: {count}")
    
    # Check if underscores are in the saved data
    if count > 0:
        sample = df[df['unique_id2'] != ''].iloc[0]['unique_id2']
        print(f"\nSample unique_id2 from dataframe: '{sample}'")
        print(f"Has underscores: {'YES' if '_' in sample else 'NO - THIS IS THE PROBLEM!'}")
        
        # Check how many matches we would get
        unique_ids = set(df['unique_id'].astype(str))
        matches = 0
        for uid2 in df[df['unique_id2'] != '']['unique_id2']:
            if uid2 in unique_ids:
                matches += 1
        print(f"\nMatches found: {matches} out of {count}")
    
    print("="*60)

if __name__ == "__main__":
    csv_file = 'global_neighbor_table.csv'
    if len(sys.argv) > 1:
        csv_file = sys.argv[1]
    
    test_unique_id2_creation(csv_file)
