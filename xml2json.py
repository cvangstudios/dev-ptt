import requests
import urllib3
import json
import xml.etree.ElementTree as ET
from xml.dom import minidom
import sys

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

def pretty_print_xml(xml_content):
    """
    Pretty print XML content
    """
    try:
        # Parse and reformat XML
        root = ET.fromstring(xml_content)
        rough_string = ET.tostring(root, encoding='unicode')
        reparsed = minidom.parseString(rough_string)
        
        print("=== XML (Pretty Printed) ===")
        pretty_xml = reparsed.toprettyxml(indent="  ")
        # Remove empty lines
        lines = [line for line in pretty_xml.split('\n') if line.strip()]
        print('\n'.join(lines))
        return True
        
    except ET.ParseError as e:
        print(f"Error parsing XML: {e}")
        return False

def convert_xml_to_json(xml_content):
    """
    Convert XML to JSON format
    """
    try:
        root = ET.fromstring(xml_content)
        
        # Convert to dictionary
        xml_dict = {root.tag: xml_to_dict(root)}
        
        print("\n=== XML Converted to JSON ===")
        print(json.dumps(xml_dict, indent=2, ensure_ascii=False))
        return True
        
    except ET.ParseError as e:
        print(f"Error converting XML to JSON: {e}")
        return False

def curl_website(url, timeout=10, output_format='both'):
    """
    Fetch website content and format output
    
    Args:
        url: Website URL
        timeout: Request timeout
        output_format: 'xml', 'json', or 'both'
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
                success = pretty_print_xml(content)
                if not success:
                    print("Raw content:")
                    print(content)
            
            if output_format in ['json', 'both']:
                convert_xml_to_json(content)
        else:
            print("Content doesn't appear to be XML:")
            print(content)
        
        return response.text
        
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {str(e)}")
        return None

def main():
    # Command line arguments
    if len(sys.argv) < 2:
        url = input("Enter website URL: ")
        format_choice = input("Output format (xml/json/both) [both]: ").lower() or 'both'
    else:
        url = sys.argv[1]
        format_choice = sys.argv[2].lower() if len(sys.argv) > 2 else 'both'
    
    # Validate format choice
    if format_choice not in ['xml', 'json', 'both']:
        format_choice = 'both'
    
    curl_website(url, output_format=format_choice)

if __name__ == "__main__":
    main()
