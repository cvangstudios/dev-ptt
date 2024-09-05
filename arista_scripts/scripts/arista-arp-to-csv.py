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

        # Capture ARP table output
        log.info("Capturing ARP table...")
        arp_output = utilities.get_output(tab, "show ip arp", "#", timeout=30)

        # Parse the ARP output using TextFSM
        template_file = textfsm_parse.get_template_path("show ip arp")
        parsed_arp = textfsm_parse.parse_cli_output(template_file, arp_output)

        if not parsed_arp:
            raise ValueError("Failed to parse ARP table output.")

        # Create filename for CSV output
        csv_filename = utilities.create_output_filename(tab, "arista-arp-table", "csv")

        # Write parsed data to CSV
        with open(csv_filename, 'w', newline='') as csvfile:
            fieldnames = ['IP_ADDRESS', 'MAC_ADDRESS', 'INTERFACE', 'AGE']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for entry in parsed_arp:
                writer.writerow({
                    'IP_ADDRESS': entry.get('IP_ADDRESS', ''),
                    'MAC_ADDRESS': entry.get('MAC_ADDRESS', ''),
                    'INTERFACE': entry.get('INTERFACE', ''),
                    'AGE': entry.get('AGE', '')
                })

        crt.Dialog.MessageBox(f"ARP table has been exported to {csv_filename}")

    except Exception as e:
        log.exception(f"An error occurred: {str(e)}")
        crt.Dialog.MessageBox(f"An error occurred: {str(e)}")
    
    log.info("Script completed.")

if __name__ == "__main__":
    main()
