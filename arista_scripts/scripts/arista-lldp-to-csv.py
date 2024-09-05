# $language = "python3"
# $interface = "1.0"

import os
import sys
import logging
import csv

# Add script directory to the Python path if not already present
script_dir = os.path.dirname(os.path.realpath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

# Import SecureCRT after updating sys.path
from SecureCRT import crt

# Import updated utility functions
from securecrt_tools import utilities
from securecrt_tools import textfsm_parse

# Ensure we're running on Python 3.8 or above
if sys.version_info < (3, 8):
    raise RuntimeError("This script requires Python 3.8 or newer")

# Set up logging
script_name = os.path.basename(__file__)
log = logging.getLogger(script_name)

def setup_logging():
    """Set up logging configuration"""
    log.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    log.addHandler(ch)

def main():
    """Main function to run the script."""
    setup_logging()
    log.info(f"Starting script: {script_name}")

    try:
        # Get the current tab
        tab = crt.GetScriptTab()
        if not tab.Session.Connected:
            raise RuntimeError("This script must be run on a connected tab.")

        # Capture LLDP neighbors output
        log.info("Capturing LLDP neighbors...")
        lldp_output = utilities.get_output(tab, "show lldp neighbors detail", "#", timeout=60)

        # Parse the LLDP output using TextFSM
        template_file = textfsm_parse.get_template_path("show lldp neighbors detail")
        parsed_lldp = textfsm_parse.parse_cli_output(template_file, lldp_output)

        if not parsed_lldp:
            raise ValueError("Failed to parse LLDP neighbors output.")

        # Create filename for CSV output
        csv_filename = utilities.create_output_filename(tab, "arista-lldp-neighbors", "csv")

        # Write parsed data to CSV
        with open(csv_filename, 'w', newline='') as csvfile:
            fieldnames = ['LOCAL_INTERFACE', 'CHASSIS_ID', 'NEIGHBOR_PORT', 'NEIGHBOR_INTERFACE', 'SYSTEM_NAME', 'MANAGEMENT_IP', 'CAPABILITIES']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for entry in parsed_lldp:
                writer.writerow({
                    'LOCAL_INTERFACE': entry.get('LOCAL_INTERFACE', ''),
                    'CHASSIS_ID': entry.get('CHASSIS_ID', ''),
                    'NEIGHBOR_PORT': entry.get('NEIGHBOR_PORT', ''),
                    'NEIGHBOR_INTERFACE': entry.get('NEIGHBOR_INTERFACE', ''),
                    'SYSTEM_NAME': entry.get('SYSTEM_NAME', ''),
                    'MANAGEMENT_IP': entry.get('MANAGEMENT_IP', ''),
                    'CAPABILITIES': entry.get('CAPABILITIES', '')
                })

        crt.Dialog.MessageBox(f"LLDP neighbors information has been exported to {csv_filename}")

    except Exception as e:
        log.exception(f"An error occurred: {str(e)}")
        crt.Dialog.MessageBox(f"An error occurred: {str(e)}")
    
    log.info("Script completed.")

if __name__ == "__main__":
    main()
