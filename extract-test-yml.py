import re
import argparse


def extract_connected_interfaces(log_file):
    connected_interfaces = []
    with open(log_file, 'r') as file:
        log_content = file.read()

        # Find the "show int status | inc connected" command output
        match = re.search(r'show int status \| inc connected\n(.*?)(?:\n\S|\Z)', log_content, re.DOTALL)
        if match:
            output = match.group(1)
            lines = output.strip().split('\n')
            for line in lines:
                interface = line.split()[0]
                connected_interfaces.append(interface)

    return connected_interfaces


def extract_interface_configs(log_file, connected_interfaces):
    interface_configs = {}
    with open(log_file, 'r') as file:
        log_content = file.read()

        # Find the "show run" command output
        match = re.search(r'show run\n(.*)', log_content, re.DOTALL)
        if match:
            output = match.group(1)
            for interface in connected_interfaces:
                # Extract the configuration section for each connected interface
                pattern = rf'interface {interface}\n(.*?)!'
                match = re.search(pattern, output, re.DOTALL)
                if match:
                    config = match.group(1).strip()
                    interface_configs[interface] = config

    return interface_configs


def save_configs_to_file(interface_configs, output_file):
    with open(output_file, 'w') as file:
        for interface, config in interface_configs.items():
            file.write(f"Interface: {interface}\n")
            file.write(config + "\n\n")


def main():
    # Create an argument parser
    parser = argparse.ArgumentParser(description='Extract connected interface configurations from a Cisco log file.')
    parser.add_argument('log_file', help='Path to the Cisco log file')
    parser.add_argument('output_file', help='Path to the output file')

    # Parse the command-line arguments
    args = parser.parse_args()

    # Extract connected interfaces from the log file
    connected_interfaces = extract_connected_interfaces(args.log_file)

    # Extract interface configurations for connected interfaces
    interface_configs = extract_interface_configs(args.log_file, connected_interfaces)

    # Save the interface configurations to a text file
    save_configs_to_file(interface_configs, args.output_file)

    print("Connected interface configurations saved to:", args.output_file)


if __name__ == '__main__':
    main()