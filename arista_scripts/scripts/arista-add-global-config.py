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

def add_global_config(tab, config_lines):
    """Add global configuration to the Arista device"""
    tab.Screen.Send("configure terminal\n")
    tab.Screen.WaitForString("(config)#")
    
    for line in config_lines:
        tab.Screen.Send(f"{line}\n")
        tab.Screen.WaitForString("(config)#")
    
    tab.Screen.Send("end\n")
    tab.Screen.WaitForString("#")

def main():
    """Main function to run the script."""
    setup_logging()
    log.info(f"Starting script: {script_name}")

    try:
        # Get the current tab
        tab = crt.GetScriptTab()
        if not tab.Session.Connected:
            raise RuntimeError("This script must be run on a connected tab.")

        # Prompt for the configuration file
        config_file = utilities.prompt_user(crt, "Enter the path to the configuration file:")
        if not config_file or not os.path.exists(config_file):
            raise ValueError("Invalid configuration file path.")

        # Read configuration from file
        with open(config_file, 'r') as f:
            config_lines = f.read().splitlines()

        # Add global configuration
        add_global_config(tab, config_lines)

        # Save the configuration
        tab.Screen.Send("copy running-config startup-config\n")
        tab.Screen.WaitForString("Copy completed successfully.")

        crt.Dialog.MessageBox("Global configuration has been added and saved.")

    except Exception as e:
        log.exception(f"An error occurred: {str(e)}")
        crt.Dialog.MessageBox(f"An error occurred: {str(e)}")
    
    log.info("Script completed.")

if __name__ == "__main__":
    main()
