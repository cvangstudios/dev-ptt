import re
import argparse
import textfsm


def detect_device_type(log_file):
    with open(log_file, 'r') as file:
        log_content = file.read()

        # Find the "show version" command output
        match = re.search(r'show version\n(.*?)(?=\n\S+#)', log_content, re.DOTALL)
        if match:
            output = match.group(1)
            if re.search(r'Cisco IOS', output, re.IGNORECASE):
                print("Detected device type: IOS")
                return 'ios'
            elif re.search(r'Cisco Nexus', output, re.IGNORECASE):
                print("Detected device type: NX-OS")
                return 'nxos'

    return None


def extract_connected_interfaces(log_file, device_type):
    connected_interfaces = []
    with open(log_file, 'r') as file:
        log_content = file.read()

        # Find the hostname
        match = re.search(r'(\S+)#', log_content)
        if match:
            hostname = match.group(1)
        else:
            print("Hostname not found in the log file.")
            return connected_interfaces

        # Find the "show interface status" command output
        if device_type == 'ios':
            match = re.search(r'show interface status\n(.*?)(?=\n\S+#)', log_content, re.DOTALL)
        else:
            match = re.search(rf'{hostname}# show interface status\n(.*?)\n{hostname}#', log_content, re.DOTALL)

        if match:
            output = match.group(1)
            print(f"Found 'show interface status' output:\n{output}\n")
            template_name = 'cisco_ios_show_interfaces_status.textfsm' if device_type == 'ios' else 'cisco_nxos_show_interface_status.textfsm'
            template_path = r"C:/Users/Cher/Desktop/PingApplication/venv/lib/site-packages/ntc_templates/templates/" + template_name
            with open(template_path, 'r') as template_file:
                template = textfsm.TextFSM(template_file)
                parsed_output = template.ParseText(output)
                print(f"Parsed output:\n{parsed_output}\n")
                for interface_data in parsed_output:
                    print(f"Interface data: {interface_data}")
                    if interface_data[2] == 'connected':
                        connected_interfaces.append(interface_data[0])
                        print(f"Connected interface found: {interface_data[0]}")
        else:
            print("No 'show interface status' output found in the log file.")

    return connected_interfaces


def translate_interface_name(short_name):
    translation_map = {
        "Eth": "Ethernet",
        "Gi": "GigabitEthernet",
        "Te": "TenGigabitEthernet",
        "Fo": "FortyGigabitEthernet",
        "Tw": "TwoGigabitEthernet",
        "Fi": "FiveGigabitEthernet",
        "Twe": "TwentyFiveGigabitEthernet",
        "Hu": "HundredGigabitEthernet"
    }
    for short_form, full_form in translation_map.items():
        if short_name.startswith(short_form):
            return short_name.replace(short_form, full_form, 1)  # Replace first occurrence
    return short_name  # Return original if no translation found


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
                print(f"Searching for interface: {interface_name}")
                pattern = rf'interface {re.escape(interface_name)}\n(.*?)(?=\ninterface|\Z)'
                match = re.search(pattern, output, re.DOTALL)
                if match:
                    config = match.group(1).strip()
                    interface_configs.append(f"Interface: {interface_name}\n{config}\n")
                    print(f"Configuration found for interface: {interface_name}")
                else:
                    print(f"Configuration not found for interface: {interface_name}")
        else:
            print("No 'show run' output found in the log file.")

    return interface_configs


def save_configs_to_file(interface_configs, output_file):
    with open(output_file, 'w') as file:
        file.write('\n'.join(interface_configs))


def main():
    parser = argparse.ArgumentParser(description='Extract connected interface configurations from a Cisco log file.')
    parser.add_argument('log_file', help='Path to the Cisco log file')
    parser.add_argument('output_file', help='Path to the output text file')

    args = parser.parse_args()

    device_type = detect_device_type(args.log_file)
    if device_type:
        connected_interfaces = extract_connected_interfaces(args.log_file, device_type)
        print(f"Connected interfaces: {connected_interfaces}")
        interface_configs = extract_interface_configs(args.log_file, connected_interfaces)
        save_configs_to_file(interface_configs, args.output_file)
        print(f"Connected interface configurations saved to: {args.output_file}")
    else:
        print("Unable to detect the device type.")


if __name__ == '__main__':
    main()