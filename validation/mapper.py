import argparse
import yaml
import os


def main():
    # Parse the command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('--results_file')
    parser.add_argument('--errors_dir')
    parser.add_argument('--mapping_dir')
    args = parser.parse_args()

    # Load the validation data
    with open(args.results_file, 'r') as results_file:
        results_data = yaml.safe_load(results_file)

    # Prepare the main mapping object
    mapping_all = {}

    # Go through all libraries and match the chains to errors
    for library_filename in os.listdir(args.errors_dir):
        library_name = os.path.splitext(library_filename)[0]
        library_path = os.path.join(args.errors_dir, library_filename)

        with open(library_path, 'r') as library_file:
            error_data = yaml.safe_load(library_file)

        mapping_data = {}

        for error_info in error_data:
            error_name = error_info['code']

            if 'message' not in error_info:
                continue

            error_message = error_info['message'].replace('\n', '')

            mapping_data[error_name] = {}
            mapping_data[error_name]['chains'] = []

            for (chain, results) in results_data.items():

                if library_name not in results:
                    continue

                library_message = results[library_name]

                if len(library_message) < 5:
                    match = (error_message == library_message)
                else:
                    match = (error_message in library_message)

                if match:
                    mapping_data[error_name]['chains'].append(chain)

        mapping_all[library_name] = mapping_data

    # Based on common chains, match errors within libraries
    for (library_name, mapping_data) in mapping_all.items():
        for (error, error_mapping) in mapping_data.items():
            error_mapping['cooccurrence'] = {}

            for chain in error_mapping['chains']:
                for (other_name, other_data) in mapping_all.items():
                    if other_name == library_name:
                        continue
                    if other_name not in error_mapping['cooccurrence']:
                        error_mapping['cooccurrence'][other_name] = []
                    equal = error_mapping['cooccurrence'][other_name]

                    for (other_error, other_mapping) in other_data.items():
                        if other_error in equal:
                            continue
                        if chain in other_mapping['chains']:
                            equal.append(other_error)

    if not os.path.exists(args.mapping_dir):
        os.makedirs(args.mapping_dir)

    for (library_name, mapping) in mapping_all.items():
        mapping_path = args.mapping_dir + '/' + library_name + '.yml'
        with open(mapping_path, 'w+') as mapping_file:
            mapping_file.write(yaml.dump(mapping))


if __name__ == "__main__":
    main()
