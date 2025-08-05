def extract_csv_data(serial_number, data, valid_serials):
    """
    Extract specific data fields for CSV export.
    Uses conditional logic: full extraction for valid ConfigurationIntent, basic extraction for null.
    
    Args:
        serial_number (str): Serial number
        data (dict): JSON data from API
        valid_serials (list): List of serials with valid ConfigurationIntent
        
    Returns:
        dict or None: Flattened data for CSV row, or None if extraction fails
    """
    
    try:
        # Check if data is None or empty
        if data is None:
            print(f"⚠️  No data received for {serial_number} - API returned None")
            return None
            
        if not isinstance(data, dict):
            print(f"⚠️  Invalid data type for {serial_number} - expected dict, got {type(data)}")
            return None
        
        csv_row = {
            'serial_number': serial_number
        }
        
        # =================================================================
        # CONDITIONAL EXTRACTION BASED ON CONFIGURATIONINTENT STATUS
        # =================================================================
        
        # Get ConfigurationIntent safely
        config_intent = data.get('ConfigurationIntent')
        
        if serial_number in valid_serials and config_intent is not None:
            # FULL EXTRACTION - Valid ConfigurationIntent
            csv_row['config_status'] = 'Valid'
            
            print(f"   Using FULL extraction for {serial_number} (valid ConfigurationIntent)")
            
            # CUSTOMIZE THIS SECTION - Add your specific field extractions for valid ConfigurationIntent devices
            # Safe extraction with null checking
            if isinstance(config_intent, dict):
                intent_data = config_intent.get('IntentData', {})
                
                # Add your specific field extractions here
                # Example:
                # csv_row.update({
                #     'your_field_1': intent_data.get('your_field_1', ''),
                #     'your_field_2': intent_data.get('your_field_2', ''),
                #     # Add more fields as needed
                # })
            
        else:
            # BASIC EXTRACTION - Null or Invalid ConfigurationIntent
            if config_intent is None:
                csv_row['config_status'] = 'Null ConfigurationIntent'
                print(f"   Using BASIC extraction for {serial_number} (null ConfigurationIntent)")
            else:
                csv_row['config_status'] = 'Invalid ConfigurationIntent'
                print(f"   Using BASIC extraction for {serial_number} (invalid ConfigurationIntent)")
            
            # CUSTOMIZE THIS SECTION - Add basic fields that exist regardless of ConfigurationIntent
            # These are fields at the root level of the data object
            # Example:
            # csv_row.update({
            #     'device_id': data.get('device_id', ''),
            #     'timestamp': data.get('timestamp', ''),
            #     'status': data.get('status', ''),
            #     # Add more basic fields as needed
            # })
        
        # =================================================================
        # COMMON FIELDS - Always extracted regardless of ConfigurationIntent status
        # =================================================================
        
        # Add fields that should always be extracted for both valid and null devices
        # These would be fields that exist at the root level for all devices
        # Example:
        # csv_row['api_version'] = data.get('api_version', '')
        # csv_row['device_serial'] = data.get('device_serial', serial_number)
        
        return csv_row
        
    except Exception as e:
        print(f"⚠️  CSV extraction failed for {serial_number}: {e}")
        print(f"   Data type: {type(data)}")
        if data:
            print(f"   Data keys: {list(data.keys())[:10]}")  # Show first 10 keys
        print(f"   Skipping CSV data for this serial number")
        return None
