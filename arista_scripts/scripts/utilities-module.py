# Module: securecrt_tools/utilities.py

import os
import sys
import logging
from typing import Optional, Union
from datetime import datetime

# Ensure we're running on Python 3.8 or above
if sys.version_info < (3, 8):
    raise RuntimeError("This module requires Python 3.8 or newer")

# Set up logging
log = logging.getLogger(__name__)

def setup_logging(log_file: Optional[str] = None):
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

def get_output(session, command: str, prompt: str, timeout: int = 30) -> str:
    """
    This function captures the output of a command sent to the remote device.
    """
    try:
        session.Screen.Send(f"{command}\n")
        session.Screen.WaitForString(f"{command}\n", timeout)
        result = session.Screen.ReadString(prompt, timeout)
        return result.strip()
    except Exception as e:
        log.error(f"Error getting output for command '{command}': {str(e)}")
        raise

def create_output_filename(session, suffix: str = "", ext: str = "txt") -> str:
    """
    Creates a filename for saving output, based on the current session.
    """
    try:
        hostname = session.Screen.Get(1, 1, session.Screen.CurrentRow - 1, session.Screen.CurrentColumn - 1)
        hostname = hostname.strip().split("\n")[-1]
        hostname = "".join([c for c in hostname if c.isalnum() or c in ".-_"])
        
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        if suffix:
            filename = f"{hostname}_{suffix}_{timestamp}.{ext}"
        else:
            filename = f"{hostname}_{timestamp}.{ext}"
        
        return filename
    except Exception as e:
        log.error(f"Error creating output filename: {str(e)}")
        raise

def write_output_to_file(output: str, filename: str) -> None:
    """
    Writes the provided output to a file.
    """
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(output)
        log.info(f"Output written to {filename}")
    except Exception as e:
        log.error(f"Error writing output to file: {str(e)}")
        raise

def prompt_user(crt, message: str, default: str = "") -> Union[str, None]:
    """
    Prompts the user for input using a SecureCRT dialog box.
    """
    try:
        result = crt.Dialog.Prompt(message, "User Input", default, False)
        return result if result else None
    except Exception as e:
        log.error(f"Error prompting user: {str(e)}")
        return None

# Initialize logging when the module is imported
setup_logging()
