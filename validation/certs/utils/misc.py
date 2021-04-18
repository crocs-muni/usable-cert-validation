import argparse
from datetime import datetime
from datetime import timedelta


def current_time():
    dt = datetime.now()
    return dt - timedelta(days=1, microseconds=dt.microsecond)


def current_time_offset(day_count):
    return current_time() + timedelta(days=day_count)


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('--asn_dir')
    parser.add_argument('--root_key_file')
    parser.add_argument('--build_dir')
    return parser.parse_args()
