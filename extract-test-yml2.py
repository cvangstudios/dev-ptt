import re
import argparse


def extract_connected_interfaces(log_file):
    connected_interfaces = []
    with open(log_file, 'r') as file:
        log_content = file.read()

        # Find the hostname
        match = re.search(r'(\S+)#', log_content)
        if match:
            hostname = match.group(1)
        else:
            return connected_interfaces

        # Find the "show int status | inc connected" command output
        match = re.search(rf'{hostname}# show int status \| inc connected\n(.*?)\n{hostname}#', log_content, re.DOTALL)
        if match:
            output = match.group(1)
            lines = output.strip().split('\n')
            for line in lines:
                interface = line.split()[0]
                connected_interfaces.append(interface)

    return connected_interfaces


def translate_interface_name(interface):
    if interface.startswith("Eth"):
        return interface.replace("Eth", "Ethernet")
    elif interface.startswith("Gi"):
        return interface.replace("Gi", "GigabitEthernet")
    elif interface.startswith("Hu"):
        return interface.replace("Hu", "HundredGigabitEthernet")
    elif interface.startswith("Te"):
        return interface.replace("Te", "TenGigabitEthernet")
    else:
        return interface


def extract_interface_configs(log_file, connected_interfaces):
    interface_configs = []
    with open(log_file, 'r') as file:
        log_content = file.read()

        # Find the "show run" command output
        match = re.search(r'show run\n(.*)', log_content, re.DOTALL)
        if match:
            output = match.group(1)
            for interface in connected_interfaces:
                # Extract the configuration section for each connected interface
                interface_name = translate_interface_name(interface)
                pattern = rf'interface {re.escape(interface_name)}\n(.*?)(?=\ninterface|\Z)'
                match = re.search(pattern, output, re.DOTALL)
                if match:
                    config = match.group(1).strip()
                    interface_configs.append(f"Interface: {interface_name}\n{config}\n")
                    print(f"Configuration found for interface: {interface_name}")
                else:
                    print(f"Configuration not found for interface: {interface_name}")

    return interface_configs


def save_configs_to_file(interface_configs, output_file):
    with open(output_file, 'w') as file:
        file.write('\n'.join(interface_configs))


def main():
    parser = argparse.ArgumentParser(description='Extract connected interface configurations from a Cisco log file.')
    parser.add_argument('log_file', help='Path to the Cisco log file')
    parser.add_argument('output_file', help='Path to the output text file')

    args = parser.parse_args()

    connected_interfaces = extract_connected_interfaces(args.log_file)
    interface_configs = extract_interface_configs(args.log_file, connected_interfaces)
    save_configs_to_file(interface_configs, args.output_file)

    print(f"Connected interface configurations saved to: {args.output_file}")


if __name__ == '__main__':
    main()