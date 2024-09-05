# $language = "python3"
# $interface = "1.0"

import os
import sys
import logging

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

def collect_device_info(tab):
    """Collect various information about the Arista device"""
    commands = [
        "show version",
        "show inventory",
        "show interfaces",
        "show ip interface brief",
        "show lldp neighbors",
        "show vlan",
        "show running-config"
    ]
    
    device_info = {}
    for cmd in commands:
        output = utilities.get_output(tab, cmd, "#", timeout=30)
        device_info[cmd] = output
    
    return device_info

def main():
    """Main function to run the script."""
    setup_logging()
    log.info(f"Starting script: {script_name}")

    try:
        # Get the current tab
        tab = crt.GetScriptTab()
        if not tab.Session.Connected:
            raise RuntimeError("This script must be run on a connected tab.")

        # Collect device information
        log.info("Collecting device information...")
        device_info = collect_device_info(tab)

        # Create filename for documentation
        doc_filename = utilities.create_output_filename(tab, "arista-device-documentation", "txt")

        # Write collected information to file
        with open(doc_filename, 'w') as f:
            for cmd, output in device_info.items():
                f.write(f"==== {cmd} ====\n\n")
                f.write(output)
                f.write("\n\n")

        crt.Dialog.MessageBox(f"Arista device documentation has been saved to {doc_filename}")

    except Exception as e:
        log.exception(f"An error occurred: {str(e)}")
        crt.Dialog.MessageBox(f"An error occurred: {str(e)}")
    
    log.info("Script completed.")

if __name__ == "__main__":
    main()
