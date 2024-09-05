# Module: securecrt_tools/textfsm_parse.py

import os
import sys
import logging
from typing import List, Dict, Any
import textfsm

# Ensure we're running on Python 3.8 or above
if sys.version_info < (3, 8):
    raise RuntimeError("This module requires Python 3.8 or newer")

# Set up logging
log = logging.getLogger(__name__)

def setup_logging(log_file: str = None):
    """Set up logging configuration"""
    log.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(formatter)
    log.addHandler(ch)
    
    # File handler (if log_file is provided)
    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)
        log.addHandler(fh)

def parse_cli_output(template_filename: str, device_output: str) -> List[Dict[str, Any]]:
    """
    This function parses CLI output with TextFSM and returns a list of dictionaries.
    """
    try:
        # Check if template file exists
        if not os.path.isfile(template_filename):
            raise FileNotFoundError(f"Template file not found: {template_filename}")

        # Parse output with TextFSM
        with open(template_filename, 'r', encoding='utf-8') as template_file:
            re_table = textfsm.TextFSM(template_file)
        
        # Parse the CLI output
        fsm_results = re_table.ParseText(device_output)

        # Convert to list of dictionaries
        result_list = [dict(zip(re_table.header, row)) for row in fsm_results]

        log.info(f"Successfully parsed output using template: {template_filename}")
        return result_list

    except textfsm.TextFSMError as e:
        log.error(f"TextFSM parsing error: {str(e)}")
        raise
    except Exception as e:
        log.error(f"Error parsing CLI output: {str(e)}")
        raise

def get_template_path(command: str, vendor: str = 'arista') -> str:
    """
    Returns the path to the appropriate TextFSM template based on the command and vendor.
    """
    script_dir = os.path.dirname(os.path.realpath(__file__))
    template_dir = os.path.join(script_dir, "..", "textfsm_templates")
    
    # Convert command to filename format
    filename = f"{vendor}_{command.replace(' ', '_')}.textfsm"
    
    template_path = os.path.join(template_dir, filename)
    
    if not os.path.exists(template_path):
        raise FileNotFoundError(f"Template not found for command: {command}")
    
    return template_path

# Initialize logging when the module is imported
setup_logging()
