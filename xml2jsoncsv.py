import requests
import urllib3
import json
import xml.etree.ElementTree as ET
from xml.dom import minidom
import sys
import csv
from datetime import datetime
import os

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def xml_to_dict(element):
    """
    Convert XML element to dictionary
    """
    result = {}
    
    # Add attributes with @ prefix
    if element.attrib:
        for key, value in element.attrib.items():
            result[f'@{key}'] = value
    
    # Handle text content
    if element.text and element.text.strip():
        text_content = element.text.strip()
        if len(element) == 0:  # No children, just return text
            if element.attrib:
                result['#text'] = text_content
                return result
            else:
                return text_content
        else:
            result['#text'] = text_content
    
    # Handle child elements
    for child in element:
        child_data = xml_to_dict(child)
        
        if child.tag in result:
            # Convert to list if multiple elements with same tag
            if not isinstance(result[child.tag], list):
                result[child.tag] = [result[child.tag]]
            result[child.tag].append(child_data)
        else:
            result[child.tag] = child_data
    
    return result

def flatten_dict(d, parent_key='', sep='_'):
    """
    Flatten nested dictionary for CSV conversion
    """
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        elif isinstance(v, list):
            # Handle lists by creating separate columns for each item
            for i, item in enumerate(v):
                if isinstance(item, dict):
                    items.extend(flatten_dict(item, f"{new_key}_{i}", sep=sep).items())
                else:
                    items.append((f"{new_key}_{i}", str(item)))
        else:
            items.append((new_key, str(v) if v is not None else ''))
    return dict(items)

def extract_rss_items(json_data):
    """
    Extract RSS items from JSON data structure
    """
    items = []
    
    # Common RSS feed structures
    possible_paths = [
        ['rss', 'channel', 'item'],
        ['feed', 'entry'],
        ['channel', 'item'],
        ['items'],
        ['data'],
        ['results']
    ]
    
    def get_nested_value(data, path):
        current = data
        for key in path:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        return current
    
    # Try to find items using different path patterns
    for path in possible_paths:
        result = get_nested_value(json_data, path)
        if result:
            if isinstance(result, list):
                items = result
                print(f"Found {len(items)} items using path: {' -> '.join(path)}")
                break
            elif isinstance(result, dict):
                # Single item, convert to list
                items = [result]
                print(f"Found 1 item using path: {' -> '.join(path)}")
                break
    
    # If no items found with standard paths, try to find any list in the data
    if not items:
        def find_lists(obj, path="root"):
            lists_found = []
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if isinstance(value, list) and value and isinstance(value[0], dict):
                        lists_found.append((f"{path}.{key}", value))
                    elif isinstance(value, (dict, list)):
                        lists_found.extend(find_lists(value, f"{path}.{key}"))
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    if isinstance(item, (dict, list)):
                        lists_found.extend(find_lists(item, f"{path}[{i}]"))
            return lists_found
        
        potential_lists = find_lists(json_data)
        if potential_lists:
            # Use the largest list found
            largest_list = max(potential_lists, key=lambda x: len(x[1]))
            items = largest_list[1]
            print(f"Found {len(items)} items at path: {largest_list[0]}")
    
    return items

def convert_json_to_csv(json_data, filename=None):
    """
    Convert JSON data to CSV format, focusing on RSS feed items
    """
    try:
        # Extract RSS items from JSON
        items = extract_rss_items(json_data)
        
        if not items:
            print("No items found in JSON data for CSV conversion")
            return False
        
        # Flatten all items to get all possible columns
        flattened_items = []
        all_keys = set()
        
        for item in items:
            flattened = flatten_dict(item)
            flattened_items.append(flattened)
            all_keys.update(flattened.keys())
        
        # Sort keys for consistent column order
        sorted_keys = sorted(all_keys)
        
        # Prepare CSV data
        csv_data = []
        for flattened in flattened_items:
            row = [flattened.get(key, '') for key in sorted_keys]
            csv_data.append(row)
        
        # Generate filename if not provided
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            csv_filename = f"rss_feed_{timestamp}.csv"
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            csv_filename = f"{filename}_{timestamp}.csv"
        
        # Write CSV file
        with open(csv_filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(sorted_keys)  # Header row
            writer.writerows(csv_data)
        
        print(f"\n=== CSV Conversion Complete ===")
        print(f"✓ CSV file saved: {csv_filename}")
        print(f"✓ Records exported: {len(csv_data)}")
        print(f"✓ Columns: {len(sorted_keys)}")
        
        # Show first few column names
        if sorted_keys:
            print(f"✓ Sample columns: {', '.join(sorted_keys[:5])}")
            if len(sorted_keys) > 5:
                print(f"  ... and {len(sorted_keys) - 5} more columns")
        
        return True
        
    except Exception as e:
        print(f"Error converting JSON to CSV: {e}")
        return False

def pretty_print_xml(xml_content, filename=None):
    """
    Pretty print XML content and optionally save to file
    """
    try:
        # Parse and reformat XML
        root = ET.fromstring(xml_content)
        rough_string = ET.tostring(root, encoding='unicode')
        reparsed = minidom.parseString(rough_string)
        
        pretty_xml = reparsed.toprettyxml(indent="  ")
        # Remove empty lines
        lines = [line for line in pretty_xml.split('\n') if line.strip()]
        formatted_xml = '\n'.join(lines)
        
        print("=== XML (Pretty Printed) ===")
        print(formatted_xml)
        
        # Save to file if filename provided
        if filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            xml_filename = f"{filename}_{timestamp}.xml"
            with open(xml_filename, 'w', encoding='utf-8') as f:
                f.write(formatted_xml)
            print(f"✓ XML saved to: {xml_filename}")
        
        return True
        
    except ET.ParseError as e:
        print(f"Error parsing XML: {e}")
        return False

def convert_xml_to_json(xml_content, filename=None):
    """
    Convert XML to JSON format and optionally save to file
    """
    try:
        root = ET.fromstring(xml_content)
        
        # Convert to dictionary
        xml_dict = {root.tag: xml_to_dict(root)}
        
        json_output = json.dumps(xml_dict, indent=2, ensure_ascii=False)
        
        print("\n=== XML Converted to JSON ===")
        print(json_output)
        
        # Save to file if filename provided
        if filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            json_filename = f"{filename}_{timestamp}.json"
            with open(json_filename, 'w', encoding='utf-8') as f:
                f.write(json_output)
            print(f"✓ JSON saved to: {json_filename}")
        
        return xml_dict
        
    except ET.ParseError as e:
        print(f"Error converting XML to JSON: {e}")
        return None

def curl_website(url, timeout=10, output_format='both', filename=None):
    """
    Fetch website content and format output
    
    Args:
        url: Website URL
        timeout: Request timeout
        output_format: 'xml', 'json', 'csv', or 'both'
        filename: Base filename for saving (without extension)
    """
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        print(f"Fetching content from: {url}")
        print("=" * 60)
        
        # Make request
        response = requests.get(url, timeout=timeout, verify=False)
        response.raise_for_status()
        
        print(f"Status Code: {response.status_code}")
        print(f"Content Type: {response.headers.get('content-type', 'Unknown')}")
        print(f"Content Length: {len(response.text)} characters")
        print("-" * 60)
        
        content = response.text.strip()
        json_data = None
        
        # Check if content is XML
        if content.startswith('<'):
            if output_format in ['xml', 'both']:
                success = pretty_print_xml(content, filename)
                if not success:
                    print("Raw content:")
                    print(content)
            
            if output_format in ['json', 'csv', 'both']:
                json_data = convert_xml_to_json(content, filename)
                
            if output_format in ['csv', 'both'] and json_data:
                convert_json_to_csv(json_data, filename)
                
        elif content.startswith('{') or content.startswith('['):
            # Content appears to be JSON
            try:
                json_data = json.loads(content)
                print("=== JSON Content Detected ===")
                print(json.dumps(json_data, indent=2)[:1000] + "..." if len(str(json_data)) > 1000 else json.dumps(json_data, indent=2))
                
                if output_format in ['csv', 'both']:
                    convert_json_to_csv(json_data, filename)
                    
                # Save JSON if requested
                if output_format in ['json', 'both'] and filename:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    json_filename = f"{filename}_{timestamp}.json"
                    with open(json_filename, 'w', encoding='utf-8') as f:
                        json.dump(json_data, f, indent=2, ensure_ascii=False)
                    print(f"✓ JSON saved to: {json_filename}")
                    
            except json.JSONDecodeError:
                print("Content appears to be JSON but failed to parse:")
                print(content)
        else:
            print("Content doesn't appear to be XML or JSON:")
            print(content)
            
            # Save raw content if filename provided
            if filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                raw_filename = f"{filename}_{timestamp}.txt"
                with open(raw_filename, 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"✓ Raw content saved to: {raw_filename}")
        
        return response.text
        
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {str(e)}")
        return None

def main():
    # Static URL - modify this line with your actual URL
    url = "https://your-long-url-here.com/api/endpoint"
    
    # Command line arguments for format and filename only
    if len(sys.argv) < 2:
        format_choice = input("Output format (xml/json/csv/both) [both]: ").lower() or 'both'
        filename = input("Enter filename (without extension): ").strip() or None
    else:
        format_choice = sys.argv[1].lower() if len(sys.argv) > 1 else 'both'
        filename = sys.argv[2] if len(sys.argv) > 2 else None
    
    # Validate format choice
    if format_choice not in ['xml', 'json', 'csv', 'both']:
        format_choice = 'both'
    
    print(f"Using static URL: {url}")
    curl_website(url, output_format=format_choice, filename=filename)

if __name__ == "__main__":
    main()
