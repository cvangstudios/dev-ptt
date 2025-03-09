"""
Script Class Module for SecureCRT with Python 3.x

This module contains a base class for script implementation based on Jamie Caesar's SecureCRT Scripts.
The CRTScript class provides common functionality and standardized methods for network scripts.

This implementation is designed for SecureCRT 9.0+ using external Python 3.x and libraries.
"""

import os
import sys
import re
import csv
import json
import logging
from pathlib import Path
from datetime import datetime

# Import external libraries - SecureCRT 9.0+ with Python 3.x supports these
import textfsm
from tabulate import tabulate
import pandas as pd

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger('CRTScript')


class CRTScript:
    """
    Base class for SecureCRT script implementation.
    Designed for SecureCRT 9.0+ with Python 3.x support.
    """
    
    # Script metadata (override in subclasses)
    SCRIPT_NAME = "Base Script"
    SCRIPT_VERSION = "1.0"
    SCRIPT_DESCRIPTION = "Base script class for SecureCRT Python 3.x scripts"
    OUTPUT_FORMAT = "csv"  # Default output format
    OUTPUT_FILENAME = "output"  # Default base filename
    
    def __init__(self, crt):
        """
        Initialize the script with the SecureCRT object.
        
        Args:
            crt: The SecureCRT object passed to the script
        """
        self.crt = crt
        self.session = crt.GetScriptTab().Screen  # SecureCRT screen object
        self.tab = crt.GetScriptTab()  # SecureCRT tab object
        
        # Determine script directory and setup paths
        self.script_dir = Path(os.path.dirname(os.path.dirname(os.path.abspath(crt.ScriptFullName))))
        self.init_paths()
        
        # Set device info
        self.hostname = self.extract_hostname()
        self.prompt = self.get_prompt()
        
        # Templates dir (first check for NetworkTNG templates)
        self.template_dir = self.find_template_dir()
    
    def init_paths(self):
        """Initialize output and template paths"""
        # Use Documents folder by default
        docs_path = None
        
        if sys.platform == "win32":
            # Windows
            docs_path = os.path.join(os.path.expanduser("~"), "Documents")
        elif sys.platform == "darwin":
            # macOS
            docs_path = os.path.join(os.path.expanduser("~"), "Documents")
        else:
            # Linux/Unix
            docs_path = os.path.expanduser("~")
        
        # Setup output directory
        self.output_dir = Path(docs_path) / "SecureCRTOutput"
        if not self.output_dir.exists():
            self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup user template directory
        self.user_template_dir = Path(docs_path) / "SecureCRTTemplates"
        if not self.user_template_dir.exists():
            self.user_template_dir.mkdir(parents=True, exist_ok=True)
    
    def find_template_dir(self):
        """
        Find TextFSM templates directory.
        Checks for NetworkTNG templates from ntc-templates package.
        
        Returns:
            Path: Path to templates directory
        """
        # First, try to get ntc-templates location (if installed)
        try:
            import ntc_templates
            ntc_dir = Path(ntc_templates.__file__).parent / "templates"
            if ntc_dir.exists():
                return ntc_dir
        except ImportError:
            pass
        
        # If not found, use built-in templates
        built_in_dir = self.script_dir / "lib" / "templates"
        if built_in_dir.exists():
            return built_in_dir
        
        # If still not found, use user template directory
        return self.user_template_dir
    
    def extract_hostname(self):
        """
        Extract hostname from session details or prompt.
        
        Returns:
            str: Hostname of the device
        """
        try:
            # First try to get from session
            session_name = self.tab.Session.Path
            if session_name:
                hostname = session_name.split('/')[-1]
                return hostname
            
            # If that fails, try to extract from prompt
            prompt = self.get_prompt()
            hostname_match = re.search(r'^([A-Za-z0-9\-\_\.]+)[#>]', prompt)
            if hostname_match:
                return hostname_match.group(1)
            
            # If all else fails, use a default
            return "device"
        except Exception as e:
            logger.error(f"Error extracting hostname: {str(e)}")
            return "device"
    
    def get_prompt(self):
        """
        Get the device prompt.
        
        Returns:
            str: Current device prompt
        """
        try:
            # Send a newline and wait for prompt
            self.session.Send("\n")
            self.session.WaitForString("\n")
            prompt = self.session.ReadString(["#", ">"])
            prompt_suffix = self.session.MatchIndex
            if prompt_suffix == 0:
                # Timeout - use a default
                return ">"
            
            if prompt_suffix == 1:
                prompt += "#"
            else:
                prompt += ">"
            
            return prompt.strip()
        except Exception as e:
            logger.error(f"Error getting prompt: {str(e)}")
            return "#"
    
    def is_connected(self):
        """
        Check if session is connected.
        
        Returns:
            bool: True if connected, False otherwise
        """
        try:
            connected = self.tab.Session.Connected
            return connected == 1 or connected is True
        except Exception:
            return False
    
    def send_command(self, command, wait_for_prompt=True, timeout=30):
        """
        Send a command to the device and get the output.
        
        Args:
            command (str): Command to send
            wait_for_prompt (bool): Whether to wait for prompt to return
            timeout (int): Timeout in seconds
            
        Returns:
            str: Command output
        """
        try:
            # Clear the screen buffer
            self.session.Clear()
            
            # Send the command
            self.session.Send(command + "\n")
            
            # Wait for the command to be echoed back
            self.session.WaitForString(command + "\n")
            
            # Read until prompt
            if wait_for_prompt:
                output = self.session.ReadString([self.prompt], timeout)
                if self.session.MatchIndex == 0:
                    logger.error(f"Timeout waiting for prompt after command: {command}")
                    return None
            else:
                # Wait a bit and get whatever is there
                self.crt.Sleep(1000)  # 1 second
                output = self.session.ReadString()
            
            return output
        except Exception as e:
            logger.error(f"Error sending command: {str(e)}")
            return None
    
    def enter_enable_mode(self):
        """
        Enter enable mode if not already there.
        
        Returns:
            bool: True if in enable mode, False otherwise
        """
        if "#" in self.prompt:
            # Already in enable mode
            return True
        
        try:
            # Send enable command
            self.session.Send("enable\n")
            result = self.session.WaitForStrings(["Password:", "#"], 5)
            
            if result == 1:
                # Password prompt
                self.session.Send(self.crt.Dialog.Prompt("Enter enable password:", "", True) + "\n")
                result = self.session.WaitForString("#", 5)
                if result == 0:
                    logger.error("Failed to enter enable mode")
                    return False
            
            # Update prompt
            self.prompt = self.get_prompt()
            return "#" in self.prompt
            
        except Exception as e:
            logger.error(f"Error entering enable mode: {str(e)}")
            return False
    
    def enter_config_mode(self):
        """
        Enter configuration mode.
        
        Returns:
            bool: True if in config mode, False otherwise
        """
        try:
            # Make sure we're in enable mode first
            if not self.enter_enable_mode():
                return False
            
            # Send config terminal command
            self.session.Send("configure terminal\n")
            result = self.session.WaitForString("(config)#", 5)
            
            if result == 0:
                logger.error("Failed to enter configuration mode")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error entering config mode: {str(e)}")
            return False
    
    def exit_config_mode(self):
        """
        Exit configuration mode.
        
        Returns:
            bool: True if exit successful, False otherwise
        """
        try:
            # Send end command
            self.session.Send("end\n")
            result = self.session.WaitForString("#", 5)
            
            if result == 0:
                logger.error("Failed to exit configuration mode")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error exiting config mode: {str(e)}")
            return False
    
    def get_output_filename(self, base_filename=None, file_ext=None):
        """
        Generate a standardized output filename with timestamp.
        
        Args:
            base_filename (str): Base filename (default from class config)
            file_ext (str): File extension without dot (default from class config)
            
        Returns:
            Path: Full path to the output file
        """
        base_filename = base_filename or self.OUTPUT_FILENAME
        file_ext = file_ext or self.OUTPUT_FORMAT
        
        # Clean hostname for use in filename
        hostname = self.hostname.replace('.', '_')
        
        # Generate timestamped filename
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"{hostname}_{base_filename}_{timestamp}.{file_ext}"
        
        return self.output_dir / filename
    
    def parse_with_textfsm(self, command_output, template_name):
        """
        Parse command output using a TextFSM template.
        
        Args:
            command_output (str): Command output to parse
            template_name (str): TextFSM template filename
            
        Returns:
            List[Dict]: List of dictionaries with parsed data
        """
        # Find the template file
        template_path = None
        
        # First check user template directory
        user_template = self.user_template_dir / template_name
        if user_template.exists():
            template_path = user_template
        
        # Then check the template directory
        if not template_path:
            template_dir_file = self.template_dir / template_name
            if template_dir_file.exists():
                template_path = template_dir_file
        
        # Then check built-in templates
        if not template_path:
            built_in_template = self.script_dir / "lib" / "templates" / template_name
            if built_in_template.exists():
                template_path = built_in_template
        
        if not template_path:
            logger.error(f"Template not found: {template_name}")
            return []
        
        try:
            # Parse with TextFSM
            with open(template_path, 'r') as f:
                template = textfsm.TextFSM(f)
            
            # Process the output
            parsed_results = template.ParseText(command_output)
            
            # Convert to list of dictionaries
            header = template.header
            parsed_data = []
            
            for row in parsed_results:
                entry = {}
                for index, value in enumerate(row):
                    entry[header[index]] = value
                parsed_data.append(entry)
            
            return parsed_data
            
        except Exception as e:
            logger.error(f"Error parsing with TextFSM: {str(e)}")
            return []
    
    def save_output(self, data, base_filename=None, output_format=None):
        """
        Save data to file with the appropriate format.
        
        Args:
            data: Data to save (text, list of dictionaries, etc.)
            base_filename (str): Base filename without extension
            output_format (str): Output format (txt, csv, json, xlsx)
            
        Returns:
            str: Path to the saved file
        """
        base_filename = base_filename or self.OUTPUT_FILENAME
        output_format = output_format or self.OUTPUT_FORMAT
        
        # Get output filepath
        output_file = self.get_output_filename(base_filename, output_format)
        
        try:
            # Handle different data formats
            if output_format == 'txt':
                # For text data
                if not isinstance(data, str):
                    data = str(data)
                
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(data)
                    
            elif output_format == 'csv':
                # For list of dictionaries
                if data and isinstance(data, list) and isinstance(data[0], dict):
                    fieldnames = data[0].keys()
                    
                    with open(output_file, 'w', encoding='utf-8', newline='') as f:
                        writer = csv.DictWriter(f, fieldnames=fieldnames)
                        writer.writeheader()
                        writer.writerows(data)
                else:
                    logger.error("CSV output requires a list of dictionaries")
                    return None
                    
            elif output_format == 'json':
                # For any data that can be serialized to JSON
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2)
                    
            elif output_format == 'xlsx':
                # For list of dictionaries
                if data and isinstance(data, list) and isinstance(data[0], dict):
                    df = pd.DataFrame(data)
                    df.to_excel(output_file, index=False)
                else:
                    logger.error("Excel output requires a list of dictionaries")
                    return None
            else:
                logger.error(f"Unsupported format: {output_format}")
                return None
            
            # Show success message
            self.crt.Dialog.MessageBox(f"Output saved to {output_file}")
            return str(output_file)
            
        except Exception as e:
            logger.error(f"Error saving output: {str(e)}")
            self.crt.Dialog.MessageBox(f"Error saving output: {str(e)}")
            return None
    
    def print_output(self, message):
        """
        Print output to the screen.
        
        Args:
            message (str): Message to print
        """
        try:
            self.crt.Dialog.MessageBox(message)
        except Exception:
            print(message)
    
    def display_table(self, data, headers=None, title=None):
        """
        Display a table in a dialog box.
        
        Args:
            data: List of dictionaries or list of lists
            headers: Column headers (used for list of lists)
            title: Dialog box title
        """
        try:
            if not data:
                self.crt.Dialog.MessageBox("No data to display")
                return
            
            title = title or f"{self.SCRIPT_NAME} Results"
            
            if isinstance(data[0], dict):
                # For list of dictionaries
                table = tabulate(data, headers='keys', tablefmt='grid')
            else:
                # For list of lists
                table = tabulate(data, headers=headers, tablefmt='grid')
            
            # Show in dialog box
            self.crt.Dialog.MessageBox(table, title)
            
        except Exception as e:
            logger.error(f"Error displaying table: {str(e)}")
            self.crt.Dialog.MessageBox(f"Error displaying table: {str(e)}")
    
    def select_item_from_list(self, items, prompt="Select an item", title="Selection"):
        """
        Prompt user to select an item from a list.
        
        Args:
            items (list): List of items to choose from
            prompt (str): Prompt text
            title (str): Dialog title
            
        Returns:
            any: Selected item or None if canceled
        """
        try:
            # Create list for dialog
            item_list = []
            for item in items:
                if isinstance(item, (str, int, float, bool)):
                    item_list.append(str(item))
                elif hasattr(item, '__str__'):
                    item_list.append(str(item))
                else:
                    item_list.append(repr(item))
            
            # Show dialog
            result = self.crt.Dialog.ListBox(item_list, prompt, title)
            
            if result.Button == "Cancel":
                return None
            
            index = int(result.Selection.split(":")[0]) - 1
            return items[index]
            
        except Exception as e:
            logger.error(f"Error displaying selection list: {str(e)}")
            return None
    
    def yes_no_dialog(self, message, title="Confirmation"):
        """
        Show a Yes/No dialog.
        
        Args:
            message (str): Dialog message
            title (str): Dialog title
            
        Returns:
            bool: True if Yes, False if No
        """
        try:
            result = self.crt.Dialog.MessageBox(message, title, 36)  # 36 = Yes/No
            return result == 6  # 6 = Yes
        except Exception:
            return False
    
    def main(self):
        """
        Main script logic. Override in subclasses.
        """
        raise NotImplementedError("Subclasses must implement main()")
