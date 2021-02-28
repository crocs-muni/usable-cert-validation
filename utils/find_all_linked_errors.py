import sys
import re
from typing import List, TextIO, Set
from os import makedirs, remove, path

# usage: ./find_all_linked_errors.sh <library> <errors> <mapping file> <mapping folder>
#       - library: library, from which the errors is
#       - error: error that we are trying to find linked errors to
#       - mapping file: location of the file with all the mapping data
#       - mapping folder: folder, where the generated error files should be in.
# 
# searches through <mapping file> and finds all the linked errors.
#
# creates file <mapping folder>/<library>/<error>.yml filled like this:
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

def find_all_equal_errors(lib: str, err: str, data: List[str]) -> Set[str]:
    patterns = [lib + "/" + err]
    ret_set = set(patterns)
    for pattern in patterns:
        for line in data:
            line = remove_all_whitespace(line)
            # ignore commets (lines that start with #)
            if len(line) == 0 or line[0] == '#':
                continue
            # our error is on the left side
            if re.search(pattern + "=", line):
                new_err = line.replace(pattern + "=", "")
                if new_err not in ret_set:
                    ret_set.add(new_err)
                    patterns.append(new_err)
            # our error is on the right side
            if re.search("=" + pattern, line):
                new_err = line.replace("=" + pattern, "")
                if new_err not in ret_set:
                    ret_set.add(new_err)
                    patterns.append(new_err) 
    ret_set.discard(lib + '/' + err)
    return ret_set


# finds all directly connected supersetted/subsetted errors (no transitivity)
# usage: find_direct_sets(<library>, <error>, <list of lines>, <"super"/"sub">)
# returns a sorted list of linked errors

def find_direct_sets(err: str, data: List[str], decider: str) -> Set[str]:
    if decider == "super":
        pattern_left = err + '<'
        pattern_right = '>' + err
    elif decider == "sub":
        pattern_left = err + '>'
        pattern_right = '<' + err
    else:
        raise Exception("WrongArgument")
    ret_set = set()
    for line in data:
        line = remove_all_whitespace(line)
        if len(line) == 0 or line[0] == '#':
            continue
        # error is on the left side
        if re.search(pattern_left, line):
            new_err = line.replace(pattern_left, "")
            ret_set.add(new_err)
        # error is on the right side
        if re.search(pattern_right, line):
            new_err = line.replace(pattern_right, "")
            ret_set.add(new_err)
    return ret_set   


def find_all_supersetted(err: str, data: List[str]) -> Set[str]:
    ret_set = find_direct_sets(err, data, "super")
    for error in list(ret_set):
        lib, err = error.split('/')
        ret_set = ret_set.union(find_all_equal_errors(lib, err, data))
    for error in list(ret_set):
        ret_set = ret_set.union(find_all_supersetted(error, data))
    return ret_set


def find_all_subsetted(err: str, data: List[str]) -> Set[str]:
    ret_set = find_direct_sets(err, data, "sub")
    for error in list(ret_set):
        lib, err = error.split('/')
        ret_set = ret_set.union(find_all_equal_errors(lib, err, data))
    for error in list(ret_set):
        ret_set = ret_set.union(find_all_subsetted(error, data))
    return ret_set


def remove_all_whitespace(line: str) -> str:
    ret_line = ""
    for char in line:
        if char != ' ' and char != '\t':
            ret_line += char
    return ret_line


# appends file correctly with provided errors as equals
# usage: append_file_equal(<list of lib/err strings>, <file object>)

def append_file(errs: List[str], file: TextIO, category: str) -> None:
    if category not in ["equal", "superset", "subset"]:
        raise Exception("WrongArgument")
    file.write(category + ":\n")
    prev_lib = ""
    for line in errs:
        lib, err = line.split('/')
        if prev_lib != lib:
            prev_lib = lib
            file.write("  {}:\n".format(lib))
        file.write('    - "{}"\n'.format(err))


# check input

if len(sys.argv) != 5:
    print("Usage: {} <library> <error> <mapping file> <mapping folder>".format(sys.argv[0]))
    sys.exit(1)

# variables

library = sys.argv[1]
error = sys.argv[2]
mapping_file_location = sys.argv[3]
mapping_folder = sys.argv[4]

mapping_file = open(mapping_file_location, "r")
mapping_data = mapping_file.read().split('\n')
mapping_file.close()

output_file = mapping_folder + "/" + library + "/" + error + ".yml"

# the script

makedirs(mapping_folder + "/" + library, exist_ok=True)

# remove file if exists

if path.exists(output_file):
    remove(output_file)

file = None

# equal

errors_equal = sorted(list(find_all_equal_errors(library, error, mapping_data)))

if errors_equal:
    if not file:
        file = open(output_file, "w")
    append_file(errors_equal, file, "equal")

# superset

errors_set = find_all_supersetted(library + '/' + error, mapping_data)
for current in errors_equal:
    errors_set = errors_set.union(find_all_supersetted(current, mapping_data))
errors = sorted(list(errors_set))

if errors:
    if not file:
        file = open(output_file, "w")
    append_file(errors, file, "superset")
    
# superset

errors_set = find_all_subsetted(library + '/' + error, mapping_data)
for current in errors_equal:
    errors_set = errors_set.union(find_all_subsetted(current, mapping_data))
errors = sorted(list(errors_set))

if errors:
    if not file:
        file = open(output_file, "w")
    append_file(errors, file, "subset")

if file:
    file.close()
