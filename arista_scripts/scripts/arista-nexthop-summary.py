# $language = "python3"
# $interface = "1.0"

import os
import sys
import logging
from collections import defaultdict

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

        # Capture routing table
        log.info("Capturing routing table...")
        route_output = utilities.get_output(tab, "show ip route", "#", timeout=30)

        # Parse the routing table output using TextFSM
        template_file = textfsm_parse.get_template_path("show ip route")
        parsed_routes = textfsm_parse.parse_cli_output(template_file, route_output)

        if not parsed_routes:
            raise ValueError("Failed to parse routing table output.")

        # Summarize next-hop information
        nexthop_summary = defaultdict(int)
        for route in parsed_routes:
            nexthop = route.get('NEXT_HOP', '')
            if nexthop:
                nexthop_summary[nexthop] += 1

        # Create summary output
        summary_output = "Next-hop Summary:\n\n"
        for nexthop, count in sorted(nexthop_summary.items(), key=lambda x: x[1], reverse=True):
            summary_output += f"Next-hop: {nexthop}, Routes: {count}\n"

        # Display summary
        crt.Dialog.MessageBox(summary_output)

        # Save summary to file
        filename = utilities.create_output_filename(tab, "arista-nexthop-summary", "txt")
        utilities.write_output_to_file(summary_output, filename)

        log.info(f"Arista next-hop summary saved to {filename}")

    except Exception as e:
        log.exception(f"An error occurred: {str(e)}")
        crt.Dialog.MessageBox(f"An error occurred: {str(e)}")
    
    log.info("Script completed.")

if __name__ == "__main__":
    main()
