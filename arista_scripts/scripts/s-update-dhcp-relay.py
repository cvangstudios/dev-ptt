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

def update_dhcp_relay(tab, old_ip, new_ip):
    """Update DHCP relay configuration"""
    commands = [
        "configure terminal",
        f"no ip helper-address {old_ip}",
        f"ip helper-address {new_ip}",
        "end"
    ]
    
    for cmd in commands:
        tab.Screen.Send(f"{cmd}\n")
        tab.Screen.WaitForString("#")

    log.info(f"Updated DHCP relay from {old_ip} to {new_ip}")

def main():
    """Main function to run the script."""
    setup_logging()
    log.info(f"Starting script: {script_name}")

    try:
        # Get the current tab
        tab = crt.GetScriptTab()
        if not tab.Session.Connected:
            raise RuntimeError("This script must be run on a connected tab.")

        # Prompt for old and new DHCP server IPs
        old_ip = utilities.prompt_user(crt, "Enter the old DHCP server IP:")
        if not old_ip:
            raise ValueError("Old DHCP server IP is required.")

        new_ip = utilities.prompt_user(crt, "Enter the new DHCP server IP:")
        if not new_ip:
            raise ValueError("New DHCP server IP is required.")

        # Update DHCP relay configuration
        update_dhcp_relay(tab, old_ip, new_ip)

        # Save the configuration
        tab.Screen.Send("copy running-config startup-config\n")
        tab.Screen.WaitForString("Destination filename [startup-config]?")
        tab.Screen.Send("\n")
        tab.Screen.WaitForString("#")

        crt.Dialog.MessageBox(f"DHCP relay updated from {old_ip} to {new_ip} and configuration saved.")

    except Exception as e:
        log.exception(f"An error occurred: {str(e)}")
        crt.Dialog.MessageBox(f"An error occurred: {str(e)}")
    
    log.info("Script completed.")

if __name__ == "__main__":
    main()
