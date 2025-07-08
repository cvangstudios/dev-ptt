import requests
import urllib3
import json
import xml.etree.ElementTree as ET
from xml.dom import minidom
import sys
from datetime import datetime

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
        
        return True
        
    except ET.ParseError as e:
        print(f"Error converting XML to JSON: {e}")
        return False

def curl_website(url, timeout=10, output_format='both', filename=None):
    """
    Fetch website content and format output
    
    Args:
        url: Website URL
        timeout: Request timeout
        output_format: 'xml', 'json', or 'both'
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
        
        # Check if content is XML
        if content.startswith('<'):
            if output_format in ['xml', 'both']:
                success = pretty_print_xml(content, filename)
                if not success:
                    print("Raw content:")
                    print(content)
            
            if output_format in ['json', 'both']:
                convert_xml_to_json(content, filename)
        else:
            print("Content doesn't appear to be XML:")
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
        format_choice = input("Output format (xml/json/both) [both]: ").lower() or 'both'
        filename = input("Enter filename (without extension): ").strip() or None
    else:
        format_choice = sys.argv[1].lower() if len(sys.argv) > 1 else 'both'
        filename = sys.argv[2] if len(sys.argv) > 2 else None
    
    # Validate format choice
    if format_choice not in ['xml', 'json', 'both']:
        format_choice = 'both'
    
    print(f"Using static URL: {url}")
    curl_website(url, output_format=format_choice, filename=filename)

if __name__ == "__main__":
    main()
