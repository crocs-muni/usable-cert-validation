import sys
import re
from typing import List, TextIO
from os import makedirs

# usage: ./find_all_linked_errors.sh <library> <errors>
#       - library: library, from which the errors is
#       - error: error that we are trying to find linked errors to
# 
# searches through _data/mapping.txt and finds all the linked errors.
# right now, just focus on the ones that are equal, we can figure out
# the other possibilites later
#
# creates file _data/mapping/<library>/<error>.yml filled like this:
#
#       equal:
#         openssl:
#           - "LINKED OPENSSL ERROR 1"
#           - "LINKED OPENSSL ERROR 2"
#         botan:
#           - "LINKED BOTAN ERROR 1"
#       superset:
#         openss:
#           - "LINKED SUPERSET ERROR"
#
# and so on...
#
# check if script ran correctly, if return value is not 0 something went wrong

# prvni vyres equal links, a nezapomen hledat dal nez jeden krok (prohledavani
# grafu? :-)))


# functions

# finds all equal linked errors in list of lines with defined rules
# usage: find_all_equal_errors(<library>, <error>, <list of lines>)
# returns a sorted list of linked errors

def find_all_equal_errors(lib: str, err: str, data: List[str]) -> List[str]:
    patterns = [lib + "/" + err]
    ret_set = set(patterns)
    for pattern in patterns:
        # our error is on the left side
        for line in data:
            if re.search(pattern + "=", line):
                new_err = line.replace(pattern + "=", "")
                if new_err not in ret_set:
                    ret_set.add(new_err)
                    patterns.append(new_err)
        # our error is on the right side
        for line in data:
            if re.search("=" + pattern, line):
                new_err = line.replace("=" + pattern, "")
                if new_err not in ret_set:
                    ret_set.add(new_err)
                    patterns.append(new_err)
    ret_set.discard(lib + '/' + err)
    ret_list = list(ret_set)
    return sorted(ret_list)


# appends file correctly with provided errors as equals
# usage: append_file_equal(<list of lib/err strings>, <file object>)

def append_file_equal(errs: List[str], file: TextIO):
    file.write("equal:\n")
    prev_lib = ""
    for line in errs:
        lib, err = line.split('/')
        if prev_lib != lib:
            prev_lib = lib
            file.write("  {}:\n".format(lib))
        file.write('    - "{}"\n'.format(err))


# check input

if len(sys.argv) != 3:
    print("Usage: {} <library> <error>".format(sys.argv[0]))
    sys.exit(1)

# variables

library = sys.argv[1]
error = sys.argv[2]

mapping_file = open("_data/mapping.txt", "r")
mapping_data = mapping_file.read().split('\n')
mapping_file.close()

mapping_folder = "_data/mapping"

output_file = mapping_folder + "/" + library + "/" + error + ".yml"

# the script

makedirs(mapping_folder + "/" + library, exist_ok=True)
errors = find_all_equal_errors(library, error, mapping_data)

file = open(output_file, "w")
append_file_equal(errors, file)
file.close()
