#!/usr/bin/env python3
"""
Generic API JSON Scraper with CSV Export
Version: 1.0
Description: Fetches JSON data from API endpoints using serial numbers,
             creates pretty-printed JSON files, and consolidates data into CSV.
             
Usage: python script.py
Requirements: 'serials.txt' file in same directory as script
"""

import subprocess
import json
import csv
import os
import sys
import getpass
from datetime import datetime
from pathlib import Path

# Script Configuration
SCRIPT_VERSION = "1.0"
BASE_URL_TEMPLATE = "https://acme.com/sn="  # Modify this for your API endpoint

def read_serial_numbers(file_path):
    """
    Read serial numbers from text file.
    First line is project name, remaining lines are serial numbers.
    
    Args:
        file_path (str): Path to text file containing serial numbers
        
    Returns:
        tuple: (project_name, list_of_serial_numbers)
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]
        
        if not lines:
            raise ValueError("File is empty")
            
        project_name = lines[0]
        serial_numbers = lines[1:]
        
        print(f"Project: {project_name}")
        print(f"Found {len(serial_numbers)} serial numbers")
        
        return project_name, serial_numbers
        
    except FileNotFoundError:
        print(f"❌ Error: File '{file_path}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error reading file: {e}")
        sys.exit(1)

def fetch_json_data(serial_number, base_url):
    """
    Fetch JSON data from API using curl with system authentication.
    
    Args:
        serial_number (str): Serial number to query
        base_url (str): Base URL template for API
        
    Returns:
        dict or None: JSON data if successful, None if failed
    """
    url = f"{base_url}{serial_number}"
    
    try:
        print(f"Fetching data for SN: {serial_number}")
        
        # Execute curl command with system authentication
        result = subprocess.run([
            'curl',
            '-s',  # Silent mode
            '-L',  # Follow redirects
            '--max-time', '30',  # 30 second timeout
            '--fail',  # Fail on HTTP errors
            '--negotiate',  # Enable SPNEGO/Negotiate authentication (Kerberos/NTLM)
            '--user', ':',  # Use current user credentials (empty user:pass triggers system auth)
            '--ntlm',  # Enable NTLM authentication for Windows domains
            '--anyauth',  # Let curl pick the best auth method available
            url
        ], capture_output=True, text=True, check=True, encoding='utf-8')
        
        # Parse JSON response
        data = json.loads(result.stdout)
        return data
        
    except subprocess.CalledProcessError as e:
        print(f"❌ API request failed for {serial_number}: HTTP error (Status: {e.returncode})")
        print(f"   This might be an authentication issue. Check your domain credentials.")
        return None
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON response for {serial_number}: {e}")
        return None
    except Exception as e:
        print(f"❌ Error fetching {serial_number}: {e}")
        return None

def create_pretty_json_file(serial_number, data, project_name, output_dir):
    """
    Create a pretty-printed JSON file with header information.
    
    Args:
        serial_number (str): Serial number
        data (dict): JSON data from API
        project_name (str): Project name for header
        output_dir (Path): Output directory path
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Create header information
    header_info = {
        "metadata": {
            "project_name": project_name,
            "serial_number": serial_number,
            "timestamp": timestamp,
            "script_version": SCRIPT_VERSION,
            "data_source": f"{BASE_URL_TEMPLATE}{serial_number}"
        },
        "api_data": data
    }
    
    # Save to JSON file
    file_path = output_dir / f"{serial_number}.json"
    
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(header_info, f, indent=2, ensure_ascii=False)
        print(f"✅ Saved JSON: {file_path}")
        
    except Exception as e:
        print(f"❌ Error saving JSON for {serial_number}: {e}")

def extract_csv_data(serial_number, data):
    """
    Extract specific data fields for CSV export.
    
    CUSTOMIZE THIS FUNCTION FOR YOUR API DATA STRUCTURE
    
    Args:
        serial_number (str): Serial number
        data (dict): JSON data from API
        
    Returns:
        dict or None: Flattened data for CSV row, or None if extraction fails
    """
    
    try:
        csv_row = {
            'serial_number': serial_number
        }
        
        # =================================================================
        # CUSTOMIZE THIS SECTION FOR YOUR SPECIFIC API DATA STRUCTURE
        # =================================================================
        
        # Example 1: Direct field extraction with hyperlinks
        # Uncomment and modify these based on your JSON structure
        """
        # Regular fields (no hyperlinks)
        csv_row.update({
            'name': data.get('name', ''),
            'model': data.get('model', ''),
            'location': data.get('location', ''),
            'last_seen': data.get('last_seen', ''),
        })
        
        # Fields converted to hyperlinks (value shows, but becomes clickable)
        status_value = data.get('status', '')
        csv_row['status'] = f'=HYPERLINK("https://status-portal.com/device/{serial_number}","{status_value}")' if status_value else ''
        
        ip_value = data.get('ip_address', '')
        csv_row['ip_address'] = f'=HYPERLINK("https://{ip_value}","{ip_value}")' if ip_value else ''
        
        model_value = data.get('model', '')
        csv_row['model'] = f'=HYPERLINK("https://docs.vendor.com/{model_value}","{model_value}")' if model_value else ''
        """
        
        # Example 2: Nested field extraction with hyperlinks
        # For nested JSON like: {"device": {"info": {"model": "ABC123"}}}
        """
        device_info = data.get('device', {}).get('info', {})
        
        # Regular nested fields
        csv_row.update({
            'device_type': device_info.get('type', ''),
            'firmware_version': device_info.get('firmware', ''),
        })
        
        # Nested field as hyperlink
        model_value = device_info.get('model', '')
        csv_row['device_model'] = f'=HYPERLINK("https://support.vendor.com/model/{model_value}","{model_value}")' if model_value else ''
        
        # Using nested management IP for web interface link
        mgmt_ip = data.get('management', {}).get('ip_address', '')
        csv_row['management_ip'] = f'=HYPERLINK("https://{mgmt_ip}","{mgmt_ip}")' if mgmt_ip else ''
        """
        
        # Example 3: Array/list handling with hyperlinks
        # For JSON with arrays: {"tags": ["tag1", "tag2", "tag3"]}
        """
        # Regular array handling
        tags = data.get('tags', [])
        csv_row['tags'] = ', '.join(tags) if tags else ''
        
        # Array with hyperlinks - create clickable tag search
        if tags:
            tag_links = []
            for tag in tags:
                tag_links.append(f'=HYPERLINK("https://search.company.com/tag/{tag}","{tag}")')
            csv_row['searchable_tags'] = ' | '.join(tag_links)
        else:
            csv_row['searchable_tags'] = ''
        
        # Alternative: Single hyperlink for all tags
        tags_string = ','.join(tags) if tags else ''
        csv_row['tags_search'] = f'=HYPERLINK("https://search.company.com/tags/{tags_string}","Search All Tags")' if tags else ''
        """
        
        # Example 4: Creating hyperlinks from multiple data points
        # Combine different fields to create useful links
        """
        # Create asset management portal link
        asset_id = data.get('asset_id', '')
        location = data.get('location', '')
        csv_row['asset_portal'] = f'=HYPERLINK("https://assets.company.com/device/{asset_id}","View Asset {asset_id}")' if asset_id else ''
        
        # Create monitoring dashboard link using multiple fields
        device_type = data.get('type', '')
        site_code = data.get('site_code', '')
        if device_type and site_code:
            csv_row['monitoring'] = f'=HYPERLINK("https://monitor.com/site/{site_code}/type/{device_type}","Monitor Dashboard")'
        
        # Create support ticket link with pre-filled info
        model = data.get('model', '')
        if model:
            csv_row['create_ticket'] = f'=HYPERLINK("https://support.com/new?serial={serial_number}&model={model}","Create Support Ticket")'
        """
        
        # =================================================================
        # GENERIC FALLBACK: Extract all top-level fields
        # Remove this section once you customize the specific extractions above
        # =================================================================
        
        # This extracts ALL top-level keys from the JSON
        # Customize this by commenting out and using specific extractions above
        for key, value in data.items():
            if isinstance(value, (str, int, float, bool)):
                csv_row[key] = value
            elif isinstance(value, (list, dict)):
                # Convert complex types to string representation
                csv_row[key] = str(value)
            else:
                csv_row[key] = str(value)
        
        return csv_row
        
    except Exception as e:
        print(f"⚠️  CSV extraction failed for {serial_number}: {e}")
        print(f"   Skipping CSV data for this serial number")
        return None

def create_csv_file(project_name, all_csv_data, output_dir):
    """
    Create consolidated CSV file from all collected data.
    
    Args:
        project_name (str): Project name for filename
        all_csv_data (list): List of dictionaries containing CSV row data
        output_dir (Path): Output directory path
    """
    if not all_csv_data:
        print("❌ No data to write to CSV")
        return
    
    # Generate CSV filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_filename = f"{project_name}_{timestamp}.csv"
    csv_path = output_dir / csv_filename
    
    try:
        # Get all unique headers from all rows
        all_headers = set()
        for row in all_csv_data:
            all_headers.update(row.keys())
        
        # Sort headers for consistent column order
        headers = sorted(all_headers)
        
        # Write CSV file
        with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers)
            writer.writeheader()
            writer.writerows(all_csv_data)
        
        print(f"✅ CSV saved: {csv_path}")
        print(f"📊 Total records: {len(all_csv_data)}")
        print(f"📋 Columns: {len(headers)}")
        
    except Exception as e:
        print(f"❌ Error creating CSV: {e}")

def main():
    """Main execution function."""
    
    # Display current user information
    current_user = getpass.getuser()
    print(f"🔐 Running as user: {current_user}")
    print(f"🌐 Using system authentication for API requests")
    print()
    
    # Get script directory and serial file path
    script_dir = Path(__file__).parent
    serial_file = script_dir / "serials.txt"
    
    # Check if serials.txt exists
    if not serial_file.exists():
        print("❌ Error: 'serials.txt' not found in script directory")
        print(f"📁 Expected location: {serial_file}")
        print("💡 Create a 'serials.txt' file with:")
        print("   Line 1: Project Name")
        print("   Line 2+: Serial numbers (one per line)")
        sys.exit(1)
    
    # Read serial numbers and project name
    project_name, serial_numbers = read_serial_numbers(serial_file)
    
    # Create output directory in same folder as script
    safe_project_name = "".join(c for c in project_name if c.isalnum() or c in (' ', '-', '_')).rstrip()
    output_dir = script_dir / safe_project_name.replace(' ', '_')
    output_dir.mkdir(exist_ok=True)
    
    print(f"📁 Output directory: {output_dir}")
    print(f"🚀 Starting data collection for {len(serial_numbers)} serial numbers...\n")
    
    # Collect data for all serial numbers
    all_csv_data = []
    successful_count = 0
    
    for i, serial_number in enumerate(serial_numbers, 1):
        print(f"[{i}/{len(serial_numbers)}] Processing: {serial_number}")
        
        # Fetch JSON data
        data = fetch_json_data(serial_number, BASE_URL_TEMPLATE)
        
        if data is not None:
            # Print pretty JSON to terminal
            print("📄 JSON Response:")
            print("-" * 40)
            print(json.dumps(data, indent=2, ensure_ascii=False))
            print("-" * 40)
            
            # Create pretty JSON file
            create_pretty_json_file(serial_number, data, project_name, output_dir)
            
            # Extract data for CSV (with error handling)
            csv_row = extract_csv_data(serial_number, data)
            if csv_row is not None:
                all_csv_data.append(csv_row)
            else:
                print(f"⚠️  Skipping CSV data for {serial_number} due to extraction errors")
            
            successful_count += 1
        
        print()  # Empty line for readability
    
    # Create consolidated CSV file
    if all_csv_data:
        create_csv_file(project_name, all_csv_data, output_dir)
    else:
        print("⚠️  No CSV data collected - CSV file creation skipped")
        print("   This could be due to:")
        print("   • All API requests failed")
        print("   • CSV extraction errors (missing/mismatched keys)")
        print("   • Customization needed in extract_csv_data() function")
    
    # Summary
    print("="*50)
    print("📋 SUMMARY")
    print("="*50)
    print(f"Project: {project_name}")
    print(f"Total serial numbers: {len(serial_numbers)}")
    print(f"Successful retrievals: {successful_count}")
    print(f"Failed retrievals: {len(serial_numbers) - successful_count}")
    print(f"CSV records created: {len(all_csv_data)}")
    print(f"Output directory: {output_dir}")
    print("="*50)

if __name__ == "__main__":
    main()
