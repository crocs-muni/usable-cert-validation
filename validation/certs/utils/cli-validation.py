import os
import sys
import yaml

out = {}
script_dir = sys.argv[1]
out_file = sys.argv[2]

for chain_name in os.listdir(script_dir):
    with open(script_dir + chain_name + '/vconfig.yml', 'r') as f:
        data = yaml.safe_load(f)
        out[chain_name] = {}
        for library, validation in data['verify'].items():
            if 'cli' in validation:
                out[chain_name][library] = validation['cli']

with open(out_file, 'w') as f:
    f.write(yaml.dump(out))
