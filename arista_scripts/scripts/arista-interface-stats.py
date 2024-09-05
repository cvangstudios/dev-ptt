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

        # Capture interface statistics
        log.info("Capturing interface statistics...")
        interface_output = utilities.get_output(tab, "show interfaces", "#", timeout=60)

        # Parse the interface output using TextFSM
        template_file = os.path.join(script_dir, "textfsm_templates", "arista_eos_show_interfaces.textfsm")
        parsed_interfaces = textfsm_parse.parse_cli_output(template_file, interface_output)

        if not parsed_interfaces:
            raise ValueError("Failed to parse interface statistics output.")

        # Create filename for CSV output
        csv_filename = utilities.create_output_filename(tab, "arista-interface-stats", "csv")

        # Write parsed data to CSV
        with open(csv_filename, 'w', newline='') as csvfile:
            fieldnames = ['INTERFACE', 'LINK_STATUS', 'PROTOCOL_STATUS', 'HARDWARE_TYPE', 'ADDRESS', 'BIA', 'DESCRIPTION', 'IP_ADDRESS', 'MTU']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for interface in parsed_interfaces:
                writer.writerow({
                    'INTERFACE': interface.get('INTERFACE', ''),
                    'LINK_STATUS': interface.get('LINK_STATUS', ''),
                    'PROTOCOL_STATUS': interface.get('PROTOCOL_STATUS', ''),
                    'HARDWARE_TYPE': interface.get('HARDWARE_TYPE', ''),
                    'ADDRESS': interface.get('ADDRESS', ''),
                    'BIA': interface.get('BIA', ''),
                    'DESCRIPTION': interface.get('DESCRIPTION', ''),
                    'IP_ADDRESS': interface.get('IP_ADDRESS', ''),
                    'MTU': interface.get('MTU', '')
                })

        crt.Dialog.MessageBox(f"Arista interface statistics have been exported to {csv_filename}")

    except Exception as e:
        log.exception(f"An error occurred: {str(e)}")
        crt.Dialog.MessageBox(f"An error occurred: {str(e)}")
    
    log.info("Script completed.")

if __name__ == "__main__":
    main()
