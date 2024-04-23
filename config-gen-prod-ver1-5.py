import os
import argparse
import yaml
from jinja2 import Environment, FileSystemLoader
from datetime import datetime

def preprocess_data(data):
    for interface_type in data['interfaces'].values():
        for interface in interface_type:
            if 'fex' in interface and not interface['fex']:
                del interface['fex']
    return data

def generate_config(yaml_file, output_folder):
    yaml_folder = 'yamlTemplates'
    template_folder = 'jinjaTemplates'

    yaml_path = os.path.join(yaml_folder, yaml_file)
    with open(yaml_path, 'r') as file:
        data = yaml.safe_load(file)

    data = preprocess_data(data)

    template_file = data['template']

    env = Environment(loader=FileSystemLoader(template_folder))
    template = env.get_template(template_file)

    config = template.render(data)

    hostname = data['hostname']
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = f"{hostname}_93108_config_{timestamp}.txt"

    os.makedirs(output_folder, exist_ok=True)
    output_path = os.path.join(output_folder, output_file)

    with open(output_path, 'w') as file:
        file.write(config)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate configuration from YAML and Jinja2 templates.')
    parser.add_argument('-y', '--yaml', required=True, help='YAML file containing configuration data')
    args = parser.parse_args()

    yaml_file = args.yaml
    output_folder = 'config_builds'

    generate_config(yaml_file, output_folder)