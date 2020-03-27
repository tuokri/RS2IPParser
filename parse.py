# -*- coding: utf-8 -*-

"""
Parse suspicious IPs in Rising Storm 2: Vietnam server logs.

The output log file is in CSV format, where the first column
is the IP and the second column is the number of the matches
for the IP.

Number of matches equals the number of log lines the IP
was seen in the log file.

The script will automatically ignore IPs valid player
information (Steam ID) associated with them.
"""

import argparse
import re
from argparse import Namespace
from collections import defaultdict

IP_PATTERN = re.compile(r".*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*")
VALID_IP = re.compile(r".*PlayerIP:.*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*")


def parse_args() -> Namespace:
    ap = argparse.ArgumentParser(
        description=__doc__)
    ap.add_argument("file", help="file to parse")
    return ap.parse_args()


def main():
    ip_dict = defaultdict(int)
    args = parse_args()
    pf = args.file
    valid_ips = set()

    print(f"parsing '{pf}'")
    with open(pf, "r", encoding="latin-1") as f:
        for line in f:
            match = IP_PATTERN.search(line)
            is_valid = VALID_IP.search(line)
            if is_valid:
                valid_ips.add(is_valid.group(1))
            if match:
                ip = match.group(1)
                ip_dict[ip] += 1

    print(f"found {len(ip_dict)} total IPs")
    print(f"found {len(valid_ips)} valid IPs")
    for vi in valid_ips:
        try:
            ip_dict.pop(vi)
        except KeyError:
            pass

    out_file = f"{pf}.csv"

    print(f"writing results to {out_file}...")
    with open(out_file, "w") as csv_file:
        csv_file.write("IP,matches\n")
        for key, value in ip_dict.items():
            csv_file.write(f"{key},{value}\n")

    print("done")


if __name__ == "__main__":
    main()
