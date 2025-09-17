#!/usr/bin/env python3
"""
Test script for PyCharm - Run this first to check everything works!
Just click Run in PyCharm - no configuration needed.
"""

import sys
import subprocess
from pathlib import Path

def test_python_version():
    """Check Python version"""
    print("1. Checking Python version...")
    version = sys.version_info
    print(f"   Python {version.major}.{version.minor}.{version.micro}")
    
    if version.major >= 3 and version.minor >= 7:
        print("   ✓ Python version is good (3.7+)\n")
        return True
    else:
        print("   ✗ Python 3.7 or higher is required\n")
        return False

def test_imports():
    """Test if required packages can be imported"""
    print("2. Testing package imports...")
    
    packages = {
        'netdev': 'netdev',
        'textfsm': 'textfsm', 
        'ntc_templates': 'ntc-templates',
        'pandas': 'pandas (optional)',
        'rich': 'rich (optional)'
    }
    
    required_ok = True
    for module, name in packages.items():
        try:
            __import__(module)
            print(f"   ✓ {name} is installed")
        except ImportError:
            if 'optional' not in name:
                print(f"   ✗ {name} is NOT installed (REQUIRED)")
                required_ok = False
            else:
                print(f"   - {name} is not installed")
    
    print()
    return required_ok

def test_files():
    """Check if necessary files exist"""
    print("3. Checking files...")
    
    files_ok = True
    
    # Check main script
    if Path("network_collector.py").exists():
        print("   ✓ network_collector.py found")
    else:
        print("   ✗ network_collector.py NOT found")
        print("     Copy the main script to this directory")
        files_ok = False
    
    # Check device list
    if Path("devices.txt").exists():
        with open("devices.txt", 'r') as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]
        if lines:
            print(f"   ✓ devices.txt found ({len(lines)} devices)")
        else:
            print("   ⚠ devices.txt exists but is empty")
            print("     Add device IP addresses to the file")
    else:
        print("   ⚠ devices.txt not found (will be created)")
        # Create example
        with open("devices.txt", 'w') as f:
            f.write("# Add device IPs below (one per line)\n")
            f.write("# Example:\n")
            f.write("# 192.168.1.1\n")
            f.write("# 192.168.1.2\n")
        print("     Created example devices.txt - edit it!")
    
    print()
    return files_ok

def install_packages():
    """Offer to install missing packages"""
    print("4. Installation Instructions for PyCharm:")
    print("-" * 40)
    print("\nMethod 1 - PyCharm Package Manager (Easiest):")
    print("  1. Press Ctrl+Alt+S (File → Settings)")
    print("  2. Go to: Project → Python Interpreter")
    print("  3. Click the + button")
    print("  4. Search for and install:")
    print("     - netdev")
    print("     - textfsm")
    print("     - ntc-templates")
    print("\nMethod 2 - PyCharm Terminal:")
    print("  1. Open Terminal tab at bottom of PyCharm")
    print("  2. Run: pip install netdev textfsm ntc-templates")
    print("\nMethod 3 - Auto-install now:")
    
    response = input("\nWould you like to try auto-installing now? (y/n): ")
    if response.lower() == 'y':
        print("\nInstalling packages...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", 
                                 "netdev", "textfsm", "ntc-templates"])
            print("✓ Packages installed successfully!")
            return True
        except:
            print("✗ Auto-install failed. Please use Method 1 or 2 above.")
            return False
    return False

def create_simple_runner():
    """Create a simple runner script"""
    print("\n5. Creating simple runner script...")
    
    runner_code = '''# Simple runner - Edit credentials and run!
import asyncio
from network_collector import NetworkDeviceCollector, read_device_list

# EDIT THESE:
USERNAME = "admin"
PASSWORD = "your_password"

# Run collection
devices = read_device_list("devices.txt")
collector = NetworkDeviceCollector(USERNAME, PASSWORD, "network_data")
asyncio.run(collector.process_all_devices(devices, max_concurrent=10))
print("\\n✓ Collection complete! Check network_data folder.")
'''
    
    with open("simple_run.py", 'w') as f:
        f.write(runner_code)
    
    print("   ✓ Created simple_run.py")
    print("     Edit the USERNAME and PASSWORD, then run it!")

def main():
    """Main test function"""
    print("=" * 60)
    print("Network Device Collector - PyCharm Setup Test")
    print("=" * 60)
    print()
    
    # Run tests
    python_ok = test_python_version()
    imports_ok = test_imports()
    files_ok = test_files()
    
    # Summary
    print("=" * 60)
    if python_ok and imports_ok:
        print("✓ SETUP COMPLETE - Ready to use!")
        print("=" * 60)
        print("\nNext steps:")
        print("1. Edit devices.txt - add your device IPs")
        print("2. Run one of these:")
        print("   - run_in_pycharm.py (recommended)")
        print("   - simple_run.py (edit credentials first)")
        print("   - network_collector.py with parameters")
        
        create_simple_runner()
    else:
        print("✗ SETUP INCOMPLETE - Missing requirements")
        print("=" * 60)
        if not imports_ok:
            install_packages()
        else:
            print("\nPlease fix the issues above and run this test again.")
    
    print("\n" + "=" * 60)
    print("Press Enter to exit...")
    input()

if __name__ == "__main__":
    main()
