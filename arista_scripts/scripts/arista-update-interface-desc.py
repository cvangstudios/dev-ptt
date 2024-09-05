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

def update_interface_description(tab, interface, description):
    """Update interface description for Arista devices"""
    commands = [
        "configure terminal",
        f"interface {interface}",
        f"description {description}",
        "exit",
        "end"
    ]
    
    for cmd in commands:
        tab.Screen.Send(f"{cmd}\n")
        tab.Screen.WaitForString("#")

    log.info(f"Updated description for interface {interface}")

def main():
    """Main function to run the script."""
    setup_logging()
    log.info(f"Starting script: {script_name}")

    try:
        # Get the current tab
        tab = crt.GetScriptTab()
        if not tab.Session.Connected:
            raise RuntimeError("This script must be run on a connected tab.")

        # Prompt for CSV file with interface descriptions
        csv_file = utilities.prompt_user(crt, "Enter the path to the CSV file with interface descriptions:")
        if not csv_file or not os.path.exists(csv_file):
            raise ValueError("Invalid CSV file path.")

        # Read CSV file and update interface descriptions
        with open(csv_file, 'r') as f:
            csv_reader = csv.DictReader(f)
            for row in csv_reader:
                interface = row.get('interface')
                description = row.get('description')
                if interface and description:
                    update_interface_description(tab, interface, description)

        # Save the configuration
        tab.Screen.Send("copy running-config startup-config\n")
        tab.Screen.WaitForString("Copy completed successfully.")

        crt.Dialog.MessageBox("Arista interface descriptions updated and configuration saved.")

    except Exception as e:
        log.exception(f"An error occurred: {str(e)}")
        crt.Dialog.MessageBox(f"An error occurred: {str(e)}")
    
    log.info("Script completed.")

if __name__ == "__main__":
    main()
